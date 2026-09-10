package search

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpi/internal/engine"
	"dpi/internal/measure"
)

func ranked(stages []string, attempts, successes int, medianMs int) Ranked {
	return Ranked{
		Candidate: Candidate{Stages: stages},
		Score: measure.Score{
			Attempts:  attempts,
			Successes: successes,
			MedianTLS: time.Duration(medianMs) * time.Millisecond,
		},
	}
}

func TestRank(t *testing.T) {
	// Coverage must outrank speed: a strategy that fixes only half the targets
	// is not a solution, however fast it is.
	t.Run("full coverage beats a faster partial result", func(t *testing.T) {
		rs := []Ranked{
			ranked([]string{"fast-but-partial"}, 6, 3, 20),
			ranked([]string{"complete"}, 6, 6, 90),
		}
		rank(rs, 0)
		if rs[0].Candidate.Stages[0] != "complete" {
			t.Errorf("expected complete first, got %q", rs[0].Candidate.Stages[0])
		}
	})

	t.Run("among complete results the fastest wins", func(t *testing.T) {
		rs := []Ranked{
			ranked([]string{"slow"}, 4, 4, 80),
			ranked([]string{"quick"}, 4, 4, 40),
			ranked([]string{"middling"}, 4, 4, 60),
		}
		rank(rs, 0)
		got := []string{rs[0].Candidate.Stages[0], rs[1].Candidate.Stages[0], rs[2].Candidate.Stages[0]}
		want := []string{"quick", "middling", "slow"}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("position %d = %q, want %q (full order %v)", i, got[i], want[i], got)
			}
		}
	})

	// Every extra stage is another thing that breaks when the censor updates,
	// so equal speed should prefer the simpler strategy.
	t.Run("equal speed prefers fewer stages", func(t *testing.T) {
		rs := []Ranked{
			ranked([]string{"a", "b", "c"}, 2, 2, 50),
			ranked([]string{"a"}, 2, 2, 50),
		}
		rank(rs, 0)
		if len(rs[0].Candidate.Stages) != 1 {
			t.Errorf("expected the single-stage strategy first, got %v", rs[0].Candidate.Stages)
		}
	})

	t.Run("partial results order by success rate", func(t *testing.T) {
		rs := []Ranked{
			ranked([]string{"worse"}, 6, 1, 10),
			ranked([]string{"better"}, 6, 4, 70),
		}
		rank(rs, 0)
		if rs[0].Candidate.Stages[0] != "better" {
			t.Errorf("expected the higher success rate first, got %q", rs[0].Candidate.Stages[0])
		}
	})
}

// Grouping is what keeps the ranking honest: two consecutive real searches
// disagreed about the winner because their medians differed by less than the
// link's own variability.
func TestRankGrouping(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	t.Run("differences within the noise share a group", func(t *testing.T) {
		rs := []Ranked{
			ranked([]string{"a"}, 4, 4, 50),
			ranked([]string{"b"}, 4, 4, 54),
			ranked([]string{"c"}, 4, 4, 90),
		}
		rank(rs, ms(10))
		if rs[0].Group != 0 || rs[1].Group != 0 {
			t.Errorf("50ms and 54ms should tie under 10ms noise, got groups %d and %d", rs[0].Group, rs[1].Group)
		}
		if rs[2].Group == 0 {
			t.Error("90ms is well outside the noise and must not share the top group")
		}
	})

	// A group's width must stay within the noise. Comparing each result to its
	// neighbour instead of to the group's anchor would let 50/58/66/74ms all
	// merge under a 10ms threshold, hiding a 24ms difference.
	t.Run("a chain of small steps does not merge into one group", func(t *testing.T) {
		rs := []Ranked{
			ranked([]string{"a"}, 4, 4, 50),
			ranked([]string{"b"}, 4, 4, 58),
			ranked([]string{"c"}, 4, 4, 66),
			ranked([]string{"d"}, 4, 4, 74),
		}
		rank(rs, ms(10))
		if rs[0].Group == rs[3].Group {
			t.Errorf("50ms and 74ms must not share a group under 10ms noise (groups: %d %d %d %d)",
				rs[0].Group, rs[1].Group, rs[2].Group, rs[3].Group)
		}
	})

	t.Run("different coverage is never a tie", func(t *testing.T) {
		rs := []Ranked{
			ranked([]string{"complete"}, 4, 4, 50),
			ranked([]string{"partial"}, 4, 2, 51),
		}
		rank(rs, ms(10))
		if rs[0].Group == rs[1].Group {
			t.Error("a partial result must not tie with a complete one, however close the timing")
		}
	})

	t.Run("zero noise means every distinct median is its own group", func(t *testing.T) {
		rs := []Ranked{
			ranked([]string{"a"}, 4, 4, 50),
			ranked([]string{"b"}, 4, 4, 51),
		}
		rank(rs, 0)
		if rs[0].Group == rs[1].Group {
			t.Error("with no noise allowance, 50ms and 51ms are distinguishable")
		}
	})
}

// The noise threshold must come from the candidates being compared. An earlier
// version derived it from a separate unblocked control host and measured it
// four times too small, which let the ranking order differences it could not
// actually resolve.
func TestNoiseFromSpreads(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	withSpread := func(medianMs, spreadMs int) Ranked {
		r := ranked([]string{"s"}, 4, 4, medianMs)
		r.Score.SpreadTLS = ms(spreadMs)
		return r
	}

	t.Run("median of the observed spreads", func(t *testing.T) {
		rs := []Ranked{withSpread(50, 10), withSpread(52, 20), withSpread(54, 30)}
		if got := noiseFromSpreads(rs); got != ms(20) {
			t.Errorf("noiseFromSpreads() = %v, want %v", got, ms(20))
		}
	})

	// One erratic strategy must not widen the threshold enough to declare the
	// whole field tied.
	t.Run("one erratic candidate does not dominate", func(t *testing.T) {
		rs := []Ranked{withSpread(50, 5), withSpread(51, 6), withSpread(52, 7), withSpread(53, 400)}
		got := noiseFromSpreads(rs)
		if got > ms(20) {
			t.Errorf("noiseFromSpreads() = %v; a single 400ms outlier should not drive the threshold", got)
		}
	})

	t.Run("no usable spreads yields no allowance", func(t *testing.T) {
		if got := noiseFromSpreads(nil); got != 0 {
			t.Errorf("noiseFromSpreads(nil) = %v, want 0", got)
		}
		if got := noiseFromSpreads([]Ranked{withSpread(50, 0)}); got != 0 {
			t.Errorf("a zero spread carries no information, got %v", got)
		}
	})
}

// Per-host selection is what makes it possible to unblock two names that need
// different strategies. It must also collapse back to one choice when a single
// strategy covers everything, or every install would grow needless profiles.
func TestBestPerHost(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	withTargets := func(stage string, medianMs int, ts ...measure.TargetScore) Ranked {
		total, ok := 0, 0
		for _, t := range ts {
			total += t.Attempts
			ok += t.Successes
		}
		return Ranked{
			Candidate: Candidate{Stages: []string{stage}},
			Score: measure.Score{
				Attempts: total, Successes: ok,
				MedianTLS: ms(medianMs),
				Targets:   ts,
			},
		}
	}
	full := func(d string) measure.TargetScore {
		return measure.TargetScore{Domain: d, Attempts: 4, Successes: 4}
	}
	partial := func(d string) measure.TargetScore {
		return measure.TargetScore{Domain: d, Attempts: 4, Successes: 1}
	}

	t.Run("one strategy covering both hosts is chosen for both", func(t *testing.T) {
		r := Report{Ranked: []Ranked{withTargets("covers-both", 50, full("a"), full("b"))}}
		got := r.BestPerHost()
		if got["a"].Candidate.Stages[0] != "covers-both" || got["b"].Candidate.Stages[0] != "covers-both" {
			t.Errorf("expected the same strategy for both hosts, got %v", got)
		}
	})

	// The real reason this exists: the first-ranked strategy fixes only one
	// host, and the other host must get the strategy that actually works for it.
	t.Run("each host gets a strategy that fully works for it", func(t *testing.T) {
		r := Report{Ranked: []Ranked{
			withTargets("good-for-a", 40, full("a"), partial("b")),
			withTargets("good-for-b", 90, partial("a"), full("b")),
		}}
		got := r.BestPerHost()
		if got["a"].Candidate.Stages[0] != "good-for-a" {
			t.Errorf("host a got %v", got["a"].Candidate.Stages)
		}
		if got["b"].Candidate.Stages[0] != "good-for-b" {
			t.Errorf("host b got %v", got["b"].Candidate.Stages)
		}
	})

	// A partially working strategy must not be recorded as that host's answer,
	// otherwise the install would claim to cover a host it does not.
	t.Run("hosts nothing fully covers are absent", func(t *testing.T) {
		r := Report{Ranked: []Ranked{withTargets("partial-only", 50, partial("a"))}}
		if _, ok := r.BestPerHost()["a"]; ok {
			t.Error("a host with no fully working strategy must not appear")
		}
	})

	t.Run("empty report yields no choices", func(t *testing.T) {
		if len(Report{}.BestPerHost()) != 0 {
			t.Error("expected no choices from an empty report")
		}
	})
}

func TestReportBest(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	rs := []Ranked{
		ranked([]string{"a"}, 4, 4, 50),
		ranked([]string{"b"}, 4, 4, 52),
		ranked([]string{"c"}, 4, 4, 95),
	}
	rank(rs, ms(10))
	best := Report{Ranked: rs}.Best()
	if len(best) != 2 {
		t.Errorf("expected the two tied results, got %d", len(best))
	}
	if len(Report{}.Best()) != 0 {
		t.Error("an empty report has no best result")
	}
}

func TestFullCoverage(t *testing.T) {
	if ranked(nil, 0, 0, 0).FullCoverage() {
		t.Error("a score with no attempts must not count as full coverage")
	}
	if !ranked(nil, 3, 3, 0).FullCoverage() {
		t.Error("3/3 should be full coverage")
	}
	if ranked(nil, 3, 2, 0).FullCoverage() {
		t.Error("2/3 must not be full coverage")
	}
}

func TestSpaceTierOrdering(t *testing.T) {
	space := Space()
	if len(space) == 0 {
		t.Fatal("strategy space is empty")
	}

	// The space must be emitted in tier order so that a caller streaming it
	// never sees a risky candidate before a safe one.
	last := TierSplit
	for i, c := range space {
		if c.Tier < last {
			t.Fatalf("candidate %d (%s) is tier %s after tier %s", i, c, c.Tier, last)
		}
		last = c.Tier
	}

	for _, tier := range []Tier{TierSplit, TierFake, TierAggressive} {
		if len(OfTier(space, tier)) == 0 {
			t.Errorf("tier %s has no candidates", tier)
		}
	}
}

// The tier boundary is a safety contract, not a naming convention: nothing that
// manipulates TTL may sit in a tier the search treats as harmless.
func TestSafeTiersContainNoTTLTricks(t *testing.T) {
	for _, c := range Space() {
		if c.Tier == TierAggressive {
			continue
		}
		for _, stage := range c.Stages {
			for _, banned := range []string{"ip_autottl", "ip_ttl", "ip6_autottl"} {
				if strings.Contains(stage, banned) {
					t.Errorf("tier %s candidate %q uses %s, which belongs in the aggressive tier",
						c.Tier, c, banned)
				}
			}
		}
	}
}

// An injected RST, SYN+ACK or SYN payload must always carry a rejection
// method. Without one the *server* accepts the forged packet, which for a RST
// means the connection really is torn down — the tool would be doing the
// censor's job. The safe tiers must only ever use rejection methods that cost
// nothing if the packet arrives.
// Concurrent screening must not change *what* the search finds, only how long
// it takes. Every item is worked exactly once, and the outcomes come back in
// item order however the lanes interleave — otherwise two identical searches
// would disagree, which is the one thing the ranking cannot survive.
func TestRunLanesVisitsEveryItemInOrder(t *testing.T) {
	for _, lanes := range []int{1, 2, 3, 8} {
		const n = 20
		var mu sync.Mutex
		visits := make([]int, n)
		lanesUsed := map[int]struct{}{}

		results, err := runLanes(context.Background(), lanes, n,
			func(lane, item int) (bool, error) {
				mu.Lock()
				visits[item]++
				lanesUsed[lane] = struct{}{}
				mu.Unlock()
				// Odd items "work", so the outcome depends on the item rather
				// than on the lane that happened to pick it up.
				return item%2 == 1, nil
			}, nil)
		if err != nil {
			t.Fatalf("lanes=%d: unexpected error %v", lanes, err)
		}
		if len(results) != n {
			t.Fatalf("lanes=%d: got %d results, want %d", lanes, len(results), n)
		}
		for i, r := range results {
			if visits[i] != 1 {
				t.Errorf("lanes=%d: item %d worked %d times, want once", lanes, i, visits[i])
			}
			if !r.screened {
				t.Errorf("lanes=%d: item %d not marked screened", lanes, i)
			}
			if want := i%2 == 1; r.survived != want {
				t.Errorf("lanes=%d: item %d survived=%v, want %v (results are out of order)",
					lanes, i, r.survived, want)
			}
		}
		if len(lanesUsed) > lanes {
			t.Errorf("lanes=%d: work ran on %d distinct lanes", lanes, len(lanesUsed))
		}
	}
}

// Lane utilisation cannot be asserted from instant work items: one lane may
// legitimately drain the whole queue before the others are scheduled. Proving
// the lanes really do run at once needs a barrier — every lane must be in
// flight simultaneously for the work to complete.
//
// A serial implementation fails this instead of hanging: the wait gives up on
// its own, peak concurrency stays at one, and the assertion reports it.
func TestRunLanesActuallyRunsConcurrently(t *testing.T) {
	const lanes = 3

	var mu sync.Mutex
	inFlight, peak := 0, 0
	ready := make(chan struct{})
	var once sync.Once

	_, err := runLanes(context.Background(), lanes, lanes*4,
		func(_, _ int) (bool, error) {
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			n := inFlight
			mu.Unlock()

			if n >= lanes {
				once.Do(func() { close(ready) })
			}
			select {
			case <-ready:
			case <-time.After(200 * time.Millisecond):
			}

			mu.Lock()
			inFlight--
			mu.Unlock()
			return true, nil
		}, nil)

	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if peak < lanes {
		t.Errorf("peak concurrency was %d, want %d: the lanes are not running in parallel", peak, lanes)
	}
}

// A fatal error means every remaining item would fail the same way. Abandoning
// them is the point: the alternative is a report claiming the whole space was
// screened and found wanting.
func TestRunLanesStopsOnFatalError(t *testing.T) {
	boom := errors.New("filter busy")
	var worked atomic.Int64

	results, err := runLanes(context.Background(), 1, 50,
		func(_, item int) (bool, error) {
			worked.Add(1)
			if item == 3 {
				return false, boom
			}
			return true, nil
		},
		func(err error) bool { return errors.Is(err, boom) })

	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the fatal error", err)
	}
	if n := worked.Load(); n > 4 {
		t.Errorf("worked on %d items after a fatal error at item 3", n)
	}
	// What did complete is still reported, so a partial tier is not lost.
	if !results[0].survived || !results[0].screened {
		t.Errorf("results before the failure must survive: %+v", results[0])
	}
	if results[3].err == nil {
		t.Error("the failing item must carry its error")
	}
	// Items never reached stay unscreened rather than counting as failures.
	if results[40].screened {
		t.Error("an abandoned item must not be marked screened")
	}
}

// A non-fatal error is one candidate's own problem — usually a stage the engine
// will not parse — and must not cut the tier short.
func TestRunLanesContinuesPastOrdinaryErrors(t *testing.T) {
	results, err := runLanes(context.Background(), 2, 10,
		func(_, item int) (bool, error) {
			if item%3 == 0 {
				return false, errors.New("rejected")
			}
			return true, nil
		},
		func(error) bool { return false })

	if err != nil {
		t.Fatalf("ordinary errors must not be returned as fatal: %v", err)
	}
	for i, r := range results {
		if !r.screened {
			t.Errorf("item %d was skipped", i)
		}
		if (r.err != nil) != (i%3 == 0) {
			t.Errorf("item %d: err=%v", i, r.err)
		}
	}
}

func TestRunLanesHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := runLanes(ctx, 2, 10,
		func(_, _ int) (bool, error) { return true, nil }, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	for i, r := range results {
		if r.screened {
			t.Errorf("item %d ran despite a cancelled context", i)
		}
	}
}

// Concurrency is clamped rather than trusted: a lane beyond MaxLanes would draw
// source ports from the ephemeral range, where a bind failure in the middle of
// a measurement looks exactly like a censored connection.
func TestConcurrencyIsClamped(t *testing.T) {
	if got := (Options{}).withDefaults().Concurrency; got != 1 {
		t.Errorf("default Concurrency = %d, want 1 (the arrangement everything was measured under)", got)
	}
	if got := (Options{Concurrency: -5}).withDefaults().Concurrency; got != 1 {
		t.Errorf("Concurrency = %d for a negative request, want 1", got)
	}
	if got := (Options{Concurrency: engine.MaxLanes + 100}).withDefaults().Concurrency; got != engine.MaxLanes {
		t.Errorf("Concurrency = %d, want it clamped to %d", got, engine.MaxLanes)
	}
}

func TestInjectedPacketsAlwaysCarryRejection(t *testing.T) {
	injectors := []string{"rst:", "rst ", "synack:", "syndata:", "fake:"}
	safeRejections := []string{"tcp_md5", "badsum", "tcp_seq", "tcp_ts"}
	ttlRejections := []string{"ip_autottl", "ip_ttl", "ip6_autottl"}

	for _, c := range Space() {
		for _, stage := range c.Stages {
			isInjector := false
			for _, p := range injectors {
				if strings.HasPrefix(stage, p) || stage == strings.TrimSuffix(p, ":") {
					isInjector = true
					break
				}
			}
			if !isInjector {
				continue
			}

			hasSafe, hasTTL := false, false
			for _, r := range safeRejections {
				if strings.Contains(stage, r) {
					hasSafe = true
				}
			}
			for _, r := range ttlRejections {
				if strings.Contains(stage, r) {
					hasTTL = true
				}
			}

			if !hasSafe && !hasTTL {
				t.Errorf("tier %s: %q injects a packet with no rejection method; "+
					"the server would accept it", c.Tier, stage)
			}
			// TTL expiry depends on network topology, which is what makes the
			// aggressive tier aggressive.
			if hasTTL && c.Tier != TierAggressive {
				t.Errorf("tier %s: %q relies on TTL expiry and belongs in the aggressive tier", c.Tier, stage)
			}
			// A TTL argument covers one address family only: ip_autottl sets the
			// IPv4 TTL and ip6_autottl the IPv6 hop limit. The kernel filter
			// covers both families, so naming only one lets the fake reach the
			// server untouched on connections of the other — the fake then
			// breaks the connection itself instead of the censor's view of it.
			if strings.Contains(stage, "ip_autottl") != strings.Contains(stage, "ip6_autottl") {
				t.Errorf("tier %s: %q limits the TTL of one address family only; "+
					"pair ip_autottl with ip6_autottl", c.Tier, stage)
			}
			if strings.Contains(stage, "ip_ttl=") != strings.Contains(stage, "ip6_ttl=") {
				t.Errorf("tier %s: %q sets a fixed TTL for one address family only", c.Tier, stage)
			}
		}
	}
}

// Window manipulation injects nothing, so gating it behind the aggressive tier
// would withhold a harmless option. Its real cost is transfer speed, which the
// bandwidth measurement reports rather than the tier system guessing at.
func TestWindowManipulationIsNotGated(t *testing.T) {
	found := false
	for _, c := range Space() {
		for _, stage := range c.Stages {
			if !strings.HasPrefix(stage, "wsize:") && !strings.HasPrefix(stage, "wssize:") {
				continue
			}
			found = true
			if c.Tier == TierAggressive {
				t.Errorf("%q injects nothing and should not sit in the aggressive tier", stage)
			}
		}
	}
	if !found {
		t.Error("expected window-manipulation candidates in the space")
	}
}

// Every candidate must have at least one stage, or engine.Start rejects it and
// the whole entry is wasted screening time.
func TestSpaceCandidatesAreWellFormed(t *testing.T) {
	for i, c := range Space() {
		if len(c.Stages) == 0 {
			t.Errorf("candidate %d has no stages", i)
		}
		for _, s := range c.Stages {
			if s == "" {
				t.Errorf("candidate %d (%s) has an empty stage", i, c)
			}
		}
	}
}

// Options.MaxTier treats the zero value as "unset" and widens it to the
// riskiest tier. If TierSplit were zero, a caller asking for the safest tier
// would silently receive the riskiest — the tier system is a safety contract,
// so its numbering must not collide with that sentinel.
func TestTierZeroValueIsNotATier(t *testing.T) {
	if TierSplit == 0 {
		t.Fatal("TierSplit must not be the zero value: Options.MaxTier uses zero as 'unset'")
	}
	for _, tier := range []Tier{TierSplit, TierFake, TierAggressive} {
		if tier == 0 {
			t.Errorf("tier %s is the zero value", tier)
		}
	}

	// Asking for the safest tier must be honoured, not widened.
	got := Options{MaxTier: TierSplit}.withDefaults()
	if got.MaxTier != TierSplit {
		t.Errorf("MaxTier=TierSplit became %s; the safety cap was overridden", got.MaxTier)
	}

	// Leaving it unset still means "no cap".
	if unset := (Options{}).withDefaults(); unset.MaxTier != TierAggressive {
		t.Errorf("unset MaxTier = %s, want %s", unset.MaxTier, TierAggressive)
	}
}

func TestTierString(t *testing.T) {
	if TierSplit.String() != "split" || TierFake.String() != "fake" || TierAggressive.String() != "aggressive" {
		t.Error("tier names must stay stable: they appear in user-facing output")
	}
}
