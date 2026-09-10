package measure

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"dpi/internal/engine"
	"dpi/internal/probe"
)

// BandwidthScore is how much a strategy costs once the connection is open.
//
// Handshake latency answers "does the site open quickly"; this answers "does the
// first byte then arrive quickly". They are different questions and a strategy
// can win one while losing the other: `wssize` shrinks the TCP window
// deliberately, and measured 251-263ms to first byte against 126-166ms for
// everything else on the same link, while its handshake looked ordinary.
//
// MedianThroughput is recorded but is **not** a ranking input — see
// TTFBTolerance for the measurement that settled that.
type BandwidthScore struct {
	Strategy string
	Targets  []TargetBandwidth
	// MedianThroughput across every successful transfer, in bytes per second.
	MedianThroughput float64
	// MedianTTFB is the time to first response byte.
	MedianTTFB time.Duration
	Attempts   int
	Successes  int
}

// TargetBandwidth is one host's transfer result.
type TargetBandwidth struct {
	Domain           string
	Attempts         int
	Successes        int
	MedianThroughput float64
	MedianTTFB       time.Duration
	Bytes            int64
}

// Bandwidth applies the stages and measures actual transfer speed.
//
// It is meant for a handful of finalists, not the whole strategy space:
// downloading a page per attempt per target costs far more than a handshake,
// and the point is only to break ties that latency cannot.
func Bandwidth(ctx context.Context, engCfg engine.Config, probeCfg probe.Config,
	stages []string, targets []Target, attempts int) (BandwidthScore, error) {

	if len(targets) == 0 {
		return BandwidthScore{}, errors.New("measure: no targets")
	}
	if attempts < 1 {
		attempts = 1
	}

	var insts []*engine.Instance
	defer func() {
		for _, in := range insts {
			_ = in.Stop()
		}
	}()
	for _, t := range targets {
		// Address-only pins, with no port window: Fetch lets the OS choose the
		// source port, and this measurement is serial by design, so there is no
		// second instance on the same address to stay out of the way of.
		in, err := engine.Start(ctx, engCfg, stages, engine.Pin{Addr: t.Addr})
		if err != nil {
			return BandwidthScore{}, fmt.Errorf("measure: engine for %s: %w", t.Domain, err)
		}
		insts = append(insts, in)
	}

	score := BandwidthScore{Strategy: engine.FormatStages(stages)}
	var allRates []float64
	var allTTFB []time.Duration

	// Transfers run one target at a time on purpose: concurrent downloads share
	// the same uplink and would measure contention between the measurements
	// rather than the cost of the strategy.
	for _, t := range targets {
		trs := make([]probe.Transfer, 0, attempts)
		for a := 0; a < attempts; a++ {
			trs = append(trs, probe.Fetch(ctx, probeCfg, t.Domain, t.Addr))
		}
		tb := summariseTransfers(t.Domain, trs)
		for _, tr := range trs {
			if tr.Status != probe.PathOk {
				continue
			}
			allTTFB = append(allTTFB, tr.TTFB)
			if r := tr.Throughput(); r > 0 {
				allRates = append(allRates, r)
			}
		}
		score.Targets = append(score.Targets, tb)
		score.Attempts += tb.Attempts
		score.Successes += tb.Successes
	}
	score.MedianThroughput = medianFloat(allRates)
	score.MedianTTFB = median(allTTFB)
	return score, nil
}

// summariseTransfers reduces one host's transfers to its score.
//
// A transfer counts as successful on its status alone. It must not depend on a
// throughput being computable: a small response read in under a millisecond
// leaves Body at zero, Throughput() then refuses to divide and returns zero,
// and the attempt would be discarded as a failure — measured on cloudflare.com,
// which answers the site root with 151 bytes. That also threw away the time to
// first byte, which is the value the ranking actually uses.
func summariseTransfers(domain string, trs []probe.Transfer) TargetBandwidth {
	tb := TargetBandwidth{Domain: domain}
	var rates []float64
	var ttfbs []time.Duration
	for _, tr := range trs {
		tb.Attempts++
		if tr.Status != probe.PathOk {
			continue
		}
		tb.Successes++
		tb.Bytes = tr.Bytes
		ttfbs = append(ttfbs, tr.TTFB)
		// Throughput stays optional: it is recorded when it means something and
		// left out when it does not, rather than deciding whether the transfer
		// happened at all.
		if r := tr.Throughput(); r > 0 {
			rates = append(rates, r)
		}
	}
	tb.MedianThroughput = medianFloat(rates)
	tb.MedianTTFB = median(ttfbs)
	return tb
}

// medianFloat is the median of a rate sample. The median rather than the mean
// for the same reason as elsewhere: one stalled transfer should not decide the
// result.
func medianFloat(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// TTFBTolerance is the relative gap below which two time-to-first-byte
// measurements are treated as equal.
//
// It is wide because the measurement is wide. Measured 2026-09-04 on github.com,
// three interleaved rounds of the same configuration: time to first byte moved
// by 28-31% between rounds, and sustained throughput by 37-45%. So the band has
// to sit above the former, and no band can rescue the latter.
//
// **Do not rank on throughput.** That was tried and measured wrong: with a 15%
// tolerance and 37-45% run-to-run spread, the ordering came out of the noise —
// the same mistake the handshake grouping exists to prevent. Two consecutive
// runs put the baseline at 6.0 MB/s and then 4.1 MB/s, which is larger than any
// gap between strategies. Time to first byte survives the same test: on that
// link `wssize:wsize=1:scale=6` cost 251-263ms against 126-166ms for everything
// else, a separation wider than its own noise.
const TTFBTolerance = 0.35

// QuickerThan reports whether a's time to first byte is meaningfully lower than
// b's. A zero measurement means nothing was measured, and never wins.
func QuickerThan(a, b time.Duration) bool {
	if a <= 0 || b <= 0 {
		return b <= 0 && a > 0
	}
	return float64(b-a)/float64(a) > TTFBTolerance
}
