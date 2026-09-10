// Package search explores the desync strategy space and ranks what works.
//
// The search is two-pass on purpose. Screening runs every candidate once,
// which is cheap enough to cover the whole space in seconds; verification then
// re-runs only the survivors often enough for the timing to mean something.
// Doing it the other way round would spend the entire budget proving that
// strategies which never worked still do not work.
package search

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"dpi/internal/engine"
	"dpi/internal/measure"
	"dpi/internal/probe"
)

type Options struct {
	// ScreenAttempts is how many handshakes each candidate gets in the first
	// pass. One is usually enough to separate "does something" from "does
	// nothing"; the noise is dealt with in verification.
	ScreenAttempts int
	// VerifyAttempts is how many handshakes a survivor gets in the second pass.
	VerifyAttempts int
	// MaxTier caps how much risk the search is allowed to take.
	MaxTier Tier
	// Noise overrides the tie threshold. Leave it zero to derive the threshold
	// from the measurements themselves, which is what should normally happen.
	Noise time.Duration
	// Bandwidth measures actual transfer speed for the tied-fastest group and
	// reorders it, so a strategy that opens quickly but then throttles the
	// connection loses to one that does neither. Handshake latency cannot see
	// that difference.
	Bandwidth bool
	// BandwidthCandidates caps how many of the tied-fastest get measured.
	// Transfers cost far more than handshakes, so this stays small.
	BandwidthCandidates int
	// Concurrency is how many candidates are screened at once, each in its own
	// source-port lane. One means the serial arrangement every measurement in
	// CLAUDE.md was taken under.
	//
	// It only applies to screening, which asks a boolean question. Verification
	// measures time and stays serial: running it concurrently would measure the
	// candidates competing for the uplink rather than the cost of each strategy,
	// and the ranking's whole claim to honesty rests on that not happening.
	//
	// Raising it multiplies the number of live engine instances by this factor
	// (one per target, per lane), so it is capped at engine.MaxLanes and stays
	// at 1 until the concurrent path has been verified against a real engine.
	Concurrency int
	// OnCandidate, if set, is called after each screening attempt.
	OnCandidate func(c Candidate, survived bool, err error)
}

func (o Options) withDefaults() Options {
	if o.ScreenAttempts < 1 {
		o.ScreenAttempts = 1
	}
	if o.VerifyAttempts < 1 {
		// Ten rather than three: three attempts produced medians that
		// reordered the winner between consecutive searches.
		o.VerifyAttempts = 10
	}
	if o.MaxTier == 0 {
		o.MaxTier = TierAggressive
	}
	if o.BandwidthCandidates < 1 {
		o.BandwidthCandidates = 5
	}
	// Serial by default: the concurrent path has never run against the engine,
	// and a default that silently changes how every strategy is screened is not
	// something to switch on untested.
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
	if o.Concurrency > engine.MaxLanes {
		o.Concurrency = engine.MaxLanes
	}
	return o
}

type Report struct {
	Screened  int
	Survivors int
	// Ranked holds the verified survivors, best first.
	Ranked []Ranked
	// BandwidthMeasured is how many of the tied-fastest had their transfer
	// speed measured. Zero means the ranking rests on handshake latency alone.
	BandwidthMeasured int
	// Unverified counts candidates that survived screening but could not be
	// verified, so they are absent from Ranked. Reported rather than swallowed:
	// a transient engine start failure was measured dropping a candidate out of
	// the ranking with nothing to show it had ever been there.
	Unverified int
	// TiersSearched lists the tiers actually screened.
	TiersSearched []Tier
	// AggressiveSkipped is true when a safe tier produced a working strategy,
	// so the risky tier was never needed.
	AggressiveSkipped bool
	// Noise is the threshold that was used to group indistinguishable results.
	Noise time.Duration
}

// BestPerHost returns, for each host, the first ranked strategy that works for
// it on every attempt.
//
// Taking the first match is not a shortcut: Ranked is already ordered by
// coverage, then speed, then simplicity, so the earliest entry that fully
// covers a host is the best available choice for it. This is what makes
// per-host profiles possible when no single strategy covers everything — and
// when one does, every host maps to that same strategy and the caller ends up
// with one profile rather than many.
func (r Report) BestPerHost() map[string]Ranked {
	best := make(map[string]Ranked)
	for _, cand := range r.Ranked {
		for _, ts := range cand.Score.Targets {
			if _, done := best[ts.Domain]; done {
				continue
			}
			if ts.Attempts > 0 && ts.Successes == ts.Attempts {
				best[ts.Domain] = cand
			}
		}
	}
	return best
}

// Best returns the results that share the top group, i.e. every strategy that
// is as good as the best one within measurement error.
func (r Report) Best() []Ranked {
	var out []Ranked
	for _, x := range r.Ranked {
		if x.Group != 0 {
			break
		}
		out = append(out, x)
	}
	return out
}

// Ranked pairs a verified score with the candidate that produced it.
type Ranked struct {
	Candidate Candidate
	Score     measure.Score
	// Group collects results that cannot be told apart. Group 0 is the best
	// set; every member of it is an equally defensible choice.
	Group int
	// Throughput is the measured transfer rate in bytes per second, zero when
	// this candidate was not measured. Recorded because it proves data flowed;
	// **nothing is ordered by it** — it moves ~40% between runs of the same
	// configuration, which is wider than any gap between strategies.
	Throughput float64
	// TTFB is the measured time to first response byte, zero when unmeasured.
	// This is what the tied-fastest group is reordered by.
	TTFB time.Duration
}

// FullCoverage reports whether every target succeeded on every attempt.
func (r Ranked) FullCoverage() bool {
	return r.Score.Attempts > 0 && r.Score.Successes == r.Score.Attempts
}

// Run screens the space tier by tier and verifies the survivors.
//
// The safe tiers are always screened in full, even after something works,
// because a later safe candidate may be faster. The aggressive tier is screened
// only when the safe ones yielded nothing at all: its side effects are not
// worth paying for a marginal speed gain.
func Run(ctx context.Context, engCfg engine.Config, probeCfg probe.Config,
	targets []measure.Target, opts Options) (Report, error) {

	if len(targets) == 0 {
		return Report{}, errors.New("search: no targets")
	}
	opts = opts.withDefaults()
	space := Space()

	var report Report
	var survivors []Candidate

	safeTiers := []Tier{TierSplit, TierFake}
	for _, tier := range safeTiers {
		if tier > opts.MaxTier {
			continue
		}
		report.TiersSearched = append(report.TiersSearched, tier)
		found, err := screenTier(ctx, engCfg, probeCfg, targets, OfTier(space, tier), opts, &report)
		if err != nil {
			return report, err
		}
		survivors = append(survivors, found...)
	}

	if len(survivors) == 0 && opts.MaxTier >= TierAggressive {
		report.TiersSearched = append(report.TiersSearched, TierAggressive)
		found, err := screenTier(ctx, engCfg, probeCfg, targets, OfTier(space, TierAggressive), opts, &report)
		if err != nil {
			return report, err
		}
		survivors = append(survivors, found...)
	} else if len(survivors) > 0 && opts.MaxTier >= TierAggressive {
		report.AggressiveSkipped = true
	}

	report.Survivors = len(survivors)

	for _, c := range survivors {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		// One retry, because a candidate that just screened successfully almost
		// never fails for a reason of its own: killing an instance returns
		// before the kernel has released its WinDivert handle, and the next
		// start can fail on that. Measured 2026-09-04 — a candidate vanished
		// from the ranking this way even with engine.startRetries in place.
		var score measure.Score
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			score, err = measure.Strategy(ctx, engCfg, probeCfg, c.Stages, targets, opts.VerifyAttempts)
			if err == nil {
				break
			}
			// Something else owns the traffic; every further candidate would
			// fail the same way, so this one is fatal rather than skippable.
			if errors.Is(err, engine.ErrFilterBusy) {
				return report, err
			}
		}
		if err != nil {
			// Counted, not swallowed: a candidate that screened and then could
			// not be verified is missing from the ranking, and the caller has
			// to be able to say so.
			report.Unverified++
			continue
		}
		if score.Successes > 0 {
			report.Ranked = append(report.Ranked, Ranked{Candidate: c, Score: score})
		}
	}

	report.Noise = opts.Noise
	if report.Noise == 0 {
		report.Noise = noiseFromSpreads(report.Ranked)
	}
	rank(report.Ranked, report.Noise)

	if opts.Bandwidth {
		// Only the tied-fastest are worth measuring: anything in a slower
		// group already lost on latency, and a transfer costs far more than a
		// handshake.
		if err := measureBandwidth(ctx, engCfg, probeCfg, &report, targets, opts); err != nil {
			if errors.Is(err, engine.ErrFilterBusy) {
				return report, err
			}
			// A failed bandwidth pass leaves the latency ranking intact, which
			// is a worse ranking rather than no ranking.
		}
	}
	return report, nil
}

// measureBandwidth measures post-handshake cost for the top group and reorders
// it by **time to first byte**.
//
// Not by throughput. Sustained throughput was measured (2026-09-04) to move
// 37-45% between runs of the *same* configuration, which is wider than any gap
// between strategies — ordering on it would make consecutive searches disagree
// again, the exact problem the latency grouping was introduced to fix. Time to
// first byte moves 28-31%, and a strategy that really costs something clears
// that: `wssize` measured 251-263ms against 126-166ms for everything else.
//
// The throughput number is still recorded, because it is what proves data
// actually flowed, but nothing is ordered by it.
func measureBandwidth(ctx context.Context, engCfg engine.Config, probeCfg probe.Config,
	report *Report, targets []measure.Target, opts Options) error {

	// The candidates to measure are a *prefix* of Ranked, and the reorder below
	// depends on that: it sorts Ranked[:n] in place. rank() puts full coverage
	// before partial, so the fully-covering members of group 0 are exactly the
	// first n entries — but that invariant is held at a distance, so stop at
	// the first entry that breaks it rather than skipping past it and sorting a
	// window that does not match what was measured.
	limit := opts.BandwidthCandidates
	n := 0
	for _, r := range report.Ranked {
		// A partial result cannot be improved by being fast; leave it ranked
		// where coverage put it, and stop.
		if r.Group != 0 || !r.FullCoverage() || n >= limit {
			break
		}
		n++
	}
	if n < 2 {
		// With one candidate there is nothing to reorder, and measuring it
		// would only cost time.
		return nil
	}

	for i := 0; i < n; i++ {
		score, err := measure.Bandwidth(ctx, engCfg, probeCfg,
			report.Ranked[i].Candidate.Stages, targets, 1)
		if err != nil {
			return err
		}
		report.Ranked[i].Throughput = score.MedianThroughput
		report.Ranked[i].TTFB = score.MedianTTFB
		report.BandwidthMeasured++
	}

	measured := report.Ranked[:n]
	sort.SliceStable(measured, func(a, b int) bool {
		x, y := measured[a], measured[b]
		if measure.QuickerThan(x.TTFB, y.TTFB) {
			return true
		}
		if measure.QuickerThan(y.TTFB, x.TTFB) {
			return false
		}
		// Indistinguishable timings fall back to the tie rule that already
		// decided the group: fewer stages, then lower tier.
		if len(x.Candidate.Stages) != len(y.Candidate.Stages) {
			return len(x.Candidate.Stages) < len(y.Candidate.Stages)
		}
		return x.Candidate.Tier < y.Candidate.Tier
	})
	return nil
}

// noiseFromSpreads estimates the measurement noise from the results
// themselves: the median of the candidates' own interquartile ranges.
//
// Calibrating against a separate unblocked control host was tried first and
// measured wrong. An unblocked CDN edge was far more stable (2-9ms spread) than
// the candidates actually being ranked (5-29ms), so it under-estimated the
// noise and the ranking went on ordering differences it could not really see.
// The candidates are the population being compared, so their own variability is
// the honest yardstick.
//
// This is deliberately conservative: the standard error of a median is smaller
// than the spread it comes from, so some genuinely different strategies will be
// reported as tied. Erring that way costs a user nothing — any member of a tied
// group is a fine choice — whereas erring the other way presents noise as a
// ranking.
func noiseFromSpreads(rs []Ranked) time.Duration {
	spreads := make([]time.Duration, 0, len(rs))
	for _, r := range rs {
		if r.Score.SpreadTLS > 0 {
			spreads = append(spreads, r.Score.SpreadTLS)
		}
	}
	if len(spreads) == 0 {
		return 0
	}
	sort.Slice(spreads, func(i, j int) bool { return spreads[i] < spreads[j] })
	n := len(spreads)
	if n%2 == 1 {
		return spreads[n/2]
	}
	return (spreads[n/2-1] + spreads[n/2]) / 2
}

// screenTier runs every candidate of one tier once and returns those that made
// at least one handshake succeed.
//
// Candidates are distributed over opts.Concurrency lanes. Screening is the only
// phase where that is sound: it asks a boolean question, so the uplink
// contention between concurrent measurements cannot corrupt the answer. Timing
// is measured later, serially, for the survivors alone — running that
// concurrently would measure the candidates competing with each other rather
// than the cost of each strategy.
//
// Survivors keep the candidate order regardless of which lane finished first,
// so two identical searches screen to the same list.
func screenTier(ctx context.Context, engCfg engine.Config, probeCfg probe.Config,
	targets []measure.Target, candidates []Candidate, opts Options, report *Report) ([]Candidate, error) {

	lanes := opts.Concurrency
	if lanes < 1 {
		lanes = 1
	}
	if lanes > len(candidates) {
		lanes = len(candidates)
	}

	results, fatal := runLanes(ctx, lanes, len(candidates),
		func(lane, i int) (bool, error) {
			// With a single lane the prober keeps the operating system's choice
			// of source port and the engine pin stays address-only — exactly the
			// arrangement every existing measurement was taken under. Only a
			// genuinely concurrent run narrows the pins, because only then is
			// there another instance to stay out of the way of.
			cfg := probeCfg
			if lanes > 1 {
				lo, hi := engine.LanePorts(lane)
				cfg.LocalPorts = probe.PortWindow{Lo: lo, Hi: hi}
			}
			score, err := measure.Strategy(ctx, engCfg, cfg, candidates[i].Stages, targets, opts.ScreenAttempts)
			if err != nil {
				// A rejected candidate is its own problem, most often a stage
				// the engine will not parse. Recorded, not fatal.
				return false, err
			}
			return score.Successes > 0, nil
		},
		// ErrFilterBusy means something else owns this traffic; every further
		// candidate would fail the same way, so stop the tier rather than
		// reporting the whole space as broken.
		func(err error) bool { return errors.Is(err, engine.ErrFilterBusy) })

	// Counting and callbacks happen afterwards, in candidate order, so neither
	// the counters nor the reported sequence depend on lane scheduling.
	var survivors []Candidate
	for i, c := range candidates {
		r := results[i]
		if !r.screened {
			continue // the tier stopped before reaching this one
		}
		report.Screened++
		if r.survived {
			survivors = append(survivors, c)
		}
		if opts.OnCandidate != nil {
			opts.OnCandidate(c, r.survived, r.err)
		}
	}
	return survivors, fatal
}

// screenOutcome is one item's result, kept separate from the work so that the
// scheduling can be tested without an engine.
type screenOutcome struct {
	screened bool
	survived bool
	err      error
}

// runLanes distributes n items over the given number of lanes and returns each
// item's outcome in item order.
//
// A lane takes the next unclaimed item as soon as it is free, so one slow item
// does not stall the others — but the outcomes are still reported in item
// order, because two identical searches must produce the same list regardless
// of which lane happened to finish first.
//
// fatalErr decides which errors doom the remaining items. When one occurs the
// unclaimed items are abandoned rather than each failing the same way, and the
// error is returned alongside whatever did complete.
func runLanes(ctx context.Context, lanes, n int,
	work func(lane, item int) (survived bool, err error),
	fatalErr func(error) bool) ([]screenOutcome, error) {

	// Each lane writes only the indexes it claimed, so the slice needs no lock.
	results := make([]screenOutcome, n)

	var (
		mu    sync.Mutex
		next  int
		fatal error
	)
	take := func() (int, bool) {
		mu.Lock()
		defer mu.Unlock()
		if fatal != nil || next >= n {
			return 0, false
		}
		i := next
		next++
		return i, true
	}
	abort := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if fatal == nil {
			fatal = err
		}
	}

	var wg sync.WaitGroup
	for lane := 0; lane < lanes; lane++ {
		wg.Add(1)
		go func(lane int) {
			defer wg.Done()
			for {
				i, ok := take()
				if !ok {
					return
				}
				if err := ctx.Err(); err != nil {
					abort(err)
					return
				}
				survived, err := work(lane, i)
				results[i] = screenOutcome{screened: true, survived: survived, err: err}
				if err != nil && fatalErr != nil && fatalErr(err) {
					abort(err)
					return
				}
			}
		}(lane)
	}
	wg.Wait()

	return results, fatal
}

// rank orders results best-first and then groups the ones that cannot be told
// apart.
//
// Ordering: full coverage before partial, then fastest median handshake, then
// the simplest strategy. Coverage outranks speed because a fast strategy that
// only fixes some targets is not a solution. Simplicity breaks ties because
// every extra stage is another thing that can stop working when the censor
// updates.
//
// Grouping: results are compared against the first member of their group
// rather than their immediate predecessor, so a group's total width never
// exceeds the noise threshold. Chaining neighbour-to-neighbour comparisons
// would let a long run of small steps merge two genuinely different speeds.
func rank(rs []Ranked, noise time.Duration) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if af, bf := a.FullCoverage(), b.FullCoverage(); af != bf {
			return af
		}
		if a.Score.SuccessRate() != b.Score.SuccessRate() {
			return a.Score.SuccessRate() > b.Score.SuccessRate()
		}
		if a.Score.MedianTLS != b.Score.MedianTLS {
			return a.Score.MedianTLS < b.Score.MedianTLS
		}
		return len(a.Candidate.Stages) < len(b.Candidate.Stages)
	})

	group, anchor := 0, 0
	for i := range rs {
		if i > 0 && !indistinguishable(rs[anchor], rs[i], noise) {
			group++
			anchor = i
		}
		rs[i].Group = group
	}
}

// indistinguishable reports whether two results are equivalent given the
// measurement noise. Different coverage is always a real difference, however
// small the timing gap.
func indistinguishable(a, b Ranked, noise time.Duration) bool {
	if a.Score.SuccessRate() != b.Score.SuccessRate() {
		return false
	}
	gap := b.Score.MedianTLS - a.Score.MedianTLS
	if gap < 0 {
		gap = -gap
	}
	return gap <= noise
}
