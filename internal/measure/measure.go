// Package measure scores a desync strategy against known-blocked targets.
//
// Two properties are measured, because "works" and "fast" are different
// questions and a strategy can win one while losing the other:
//
//   - success rate across repeated attempts, since a single successful
//     handshake proves nothing on a lossy path;
//   - median TLS handshake time of the successful attempts, which is where a
//     strategy's cost actually shows up (extra fake packets, retransmit-driven
//     modes, artificial delays).
package measure

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"dpi/internal/engine"
	"dpi/internal/probe"
)

// NoStrategy labels a baseline run, where the engine is not involved at all.
const NoStrategy = "(none)"

// Target is a domain paired with the address its traffic should be sent to.
// The address comes from an encrypted resolver, never from the system one.
type Target struct {
	Domain string
	Addr   string
}

// TargetScore is one domain's outcome under a single strategy.
type TargetScore struct {
	Domain    string
	Attempts  int
	Successes int
	MedianTLS time.Duration
	// SpreadTLS is the interquartile range of the successful handshakes. It is
	// reported alongside the median because a median without its spread invites
	// the reader to order two numbers that are not actually distinguishable.
	SpreadTLS time.Duration
	Outcomes  map[probe.PathStatus]int
}

func (t TargetScore) SuccessRate() float64 {
	if t.Attempts == 0 {
		return 0
	}
	return float64(t.Successes) / float64(t.Attempts)
}

// Score is the aggregate result for one strategy.
type Score struct {
	Strategy  string
	Targets   []TargetScore
	Attempts  int
	Successes int
	MedianTLS time.Duration
	SpreadTLS time.Duration
}

func (s Score) SuccessRate() float64 {
	if s.Attempts == 0 {
		return 0
	}
	return float64(s.Successes) / float64(s.Attempts)
}

// Baseline measures the targets with no strategy applied, establishing what
// the censor does by default. Without it a "working" strategy cannot be
// distinguished from a target that was never blocked.
func Baseline(ctx context.Context, probeCfg probe.Config, targets []Target, attempts int) Score {
	return runTrials(ctx, probeCfg, NoStrategy, targets, attempts)
}

// Strategy applies the desync stages and measures them. Each target gets its
// own engine instance pinned to that target's address, which is what allows
// them to run concurrently; the instances are always stopped before returning.
func Strategy(ctx context.Context, engCfg engine.Config, probeCfg probe.Config,
	stages []string, targets []Target, attempts int) (Score, error) {

	if len(targets) == 0 {
		return Score{}, errors.New("measure: no targets")
	}

	var insts []*engine.Instance
	defer func() {
		for _, in := range insts {
			_ = in.Stop()
		}
	}()

	for _, t := range targets {
		// The pin carries the prober's port window when one is configured, so
		// that this instance sees exactly the connections this measurement
		// opens — and not those of a candidate being screened beside it.
		pin := engine.Pin{Addr: t.Addr}
		if w := probeCfg.LocalPorts; !w.IsZero() {
			pin.PortLo, pin.PortHi = w.Lo, w.Hi
		}
		in, err := engine.Start(ctx, engCfg, stages, pin)
		if err != nil {
			return Score{}, fmt.Errorf("measure: engine for %s: %w", t.Domain, err)
		}
		insts = append(insts, in)
	}

	score := runTrials(ctx, probeCfg, engine.FormatStages(stages), targets, attempts)

	// An unresolvable stage is reported by the engine only after it has started
	// capturing, so it cannot be caught at start time. Checked here instead:
	// without this the instance would have died on the first packet, every
	// attempt would have failed, and the candidate would be scored as "does not
	// work" instead of being reported as not a real strategy at all.
	for _, in := range insts {
		if msg := in.Rejected(); msg != "" {
			return Score{}, fmt.Errorf("measure: engine rejected the strategy: %s", msg)
		}
	}
	return score, nil
}

type trial struct {
	status probe.PathStatus
	dur    time.Duration
}

// runTrials probes targets concurrently but repeats attempts for a single
// target serially, so that repeated attempts do not contend with each other
// and distort the timing they are meant to measure.
func runTrials(ctx context.Context, probeCfg probe.Config, strategy string,
	targets []Target, attempts int) Score {

	if attempts < 1 {
		attempts = 1
	}
	perTarget := make([][]trial, len(targets))

	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			trials := make([]trial, 0, attempts)
			for a := 0; a < attempts; a++ {
				status, dur, _ := probe.CheckPath(ctx, probeCfg, t.Domain, t.Addr)
				trials = append(trials, trial{status: status, dur: dur})
			}
			perTarget[i] = trials
		}(i, t)
	}
	wg.Wait()

	score := Score{Strategy: strategy}
	var allDurations []time.Duration
	for i, t := range targets {
		ts := TargetScore{Domain: t.Domain, Outcomes: map[probe.PathStatus]int{}}
		var durations []time.Duration
		for _, tr := range perTarget[i] {
			ts.Attempts++
			ts.Outcomes[tr.status]++
			if tr.status == probe.PathOk {
				ts.Successes++
				durations = append(durations, tr.dur)
				allDurations = append(allDurations, tr.dur)
			}
		}
		ts.MedianTLS = median(durations)
		ts.SpreadTLS = iqr(durations)
		score.Targets = append(score.Targets, ts)
		score.Attempts += ts.Attempts
		score.Successes += ts.Successes
	}
	score.MedianTLS = median(allDurations)
	score.SpreadTLS = iqr(allDurations)
	return score
}

// median of the successful handshake times. The median rather than the mean
// because a single retransmit-stalled attempt would drag an average far away
// from what the strategy typically costs.
func median(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	return medianSorted(s)
}

func medianSorted(s []time.Duration) time.Duration {
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// iqr is the interquartile range, used as the spread estimate. It ignores the
// extreme quarters, so one stalled handshake widens it far less than a
// min-to-max range would while still reflecting real variability.
//
// With very few samples the quartiles are coarse; that is honest rather than
// harmful, since a coarse spread simply refuses to distinguish close medians.
func iqr(ds []time.Duration) time.Duration {
	if len(ds) < 2 {
		return 0
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	half := len(s) / 2
	lower := medianSorted(s[:half])
	upper := medianSorted(s[len(s)-half:])
	if upper < lower {
		return 0
	}
	return upper - lower
}
