package measure

import (
	"testing"
	"time"

	"dpi/internal/probe"
)

func TestMedianFloat(t *testing.T) {
	cases := []struct {
		name string
		in   []float64
		want float64
	}{
		{"empty", nil, 0},
		{"single", []float64{100}, 100},
		{"odd count", []float64{300, 100, 200}, 200},
		{"even count averages the middles", []float64{100, 200, 300, 400}, 250},
		// The reason for a median: one stalled transfer must not decide the
		// reported rate.
		{"outlier does not drag it", []float64{1000, 1010, 1020, 1030, 1}, 1010},
	}
	for _, c := range cases {
		if got := medianFloat(c.in); got != c.want {
			t.Errorf("%s: medianFloat(%v) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

// Ordering must come from a gap the measurement can actually resolve. Time to
// first byte was measured moving 28-31% between interleaved runs of the *same*
// configuration, so anything inside the tolerance is a tie — while a strategy
// that genuinely costs something (wssize, at roughly double) still clears it.
//
// Throughput is deliberately not what this compares: it moved 37-45% between
// runs of one configuration, wider than any gap between strategies, so ordering
// on it reintroduced the instability the latency grouping was added to fix.
func TestQuickerThanIgnoresNoise(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	cases := []struct {
		name string
		a, b time.Duration
		want bool
	}{
		{"clearly quicker", ms(126), ms(260), true},
		{"clearly slower", ms(260), ms(126), false},
		{"identical", ms(130), ms(130), false},
		{"inside the noise band", ms(126), ms(150), false},
		{"just under the band", ms(100), ms(134), false},
		{"just over the band", ms(100), ms(136), true},
		// An unmeasured candidate must not win by default, and must not beat a
		// measured one on a zero.
		{"measured beats unmeasured", ms(130), 0, true},
		{"unmeasured does not beat measured", 0, ms(130), false},
		{"both unmeasured", 0, 0, false},
	}
	for _, c := range cases {
		if got := QuickerThan(c.a, c.b); got != c.want {
			t.Errorf("%s: QuickerThan(%v, %v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}

// The tolerance is a measured value, not an accident: a test pins it so that
// changing it is a decision rather than a drift.
func TestTTFBToleranceIsSane(t *testing.T) {
	if TTFBTolerance <= 0 || TTFBTolerance >= 1 {
		t.Fatalf("TTFBTolerance = %v; a relative gap must sit between 0 and 1", TTFBTolerance)
	}
	// It has to sit above the measured run-to-run spread of what it compares
	// (28-31%), or the ranking orders noise; and below the separation a real
	// cost produces (about 2x), or nothing is ever ordered at all.
	if TTFBTolerance < 0.31 || TTFBTolerance > 0.6 {
		t.Errorf("TTFBTolerance = %v is outside the range the measurement supports", TTFBTolerance)
	}
}

// A small response read in under a millisecond leaves Body at zero, so
// Throughput() refuses to divide and returns zero. That must not be read as a
// failed transfer: measured on cloudflare.com, whose site root answers with 151
// bytes, the attempt was discarded and its time to first byte — the value the
// ranking uses — went with it.
func TestSummariseTransfersKeepsFastSmallResponses(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	tb := summariseTransfers("cloudflare.com", []probe.Transfer{
		{Status: probe.PathOk, TTFB: ms(206), Bytes: 151, Body: 0},
		{Status: probe.PathOk, TTFB: ms(210), Bytes: 151, Body: 0},
	})
	if tb.Successes != 2 || tb.Attempts != 2 {
		t.Errorf("Successes/Attempts = %d/%d, want 2/2", tb.Successes, tb.Attempts)
	}
	if tb.MedianTTFB != ms(208) {
		t.Errorf("MedianTTFB = %v, want 208ms: the ranking input must survive", tb.MedianTTFB)
	}
	// No usable rate is honest here — but it must be the only thing missing.
	if tb.MedianThroughput != 0 {
		t.Errorf("MedianThroughput = %v, want 0 for an unmeasurable rate", tb.MedianThroughput)
	}
}

// A failed transfer must not contribute a timing, or a broken attempt would
// pull the median towards whatever it managed before failing.
func TestSummariseTransfersIgnoresFailures(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	tb := summariseTransfers("x.com", []probe.Transfer{
		{Status: probe.PathReset, TTFB: ms(5), Bytes: 10, Body: ms(1)},
		{Status: probe.PathOk, TTFB: ms(100), Bytes: 1 << 20, Body: ms(200)},
		{Status: probe.PathTimeout},
	})
	if tb.Attempts != 3 || tb.Successes != 1 {
		t.Errorf("Attempts/Successes = %d/%d, want 3/1", tb.Attempts, tb.Successes)
	}
	if tb.MedianTTFB != ms(100) {
		t.Errorf("MedianTTFB = %v, want only the successful attempt's 100ms", tb.MedianTTFB)
	}
	if tb.MedianThroughput <= 0 {
		t.Errorf("MedianThroughput = %v, want the successful attempt's rate", tb.MedianThroughput)
	}
}

// Nothing measured at all must stay zero rather than becoming a small number
// that would then win a comparison.
func TestSummariseTransfersWithNothingUsable(t *testing.T) {
	tb := summariseTransfers("x.com", nil)
	if tb.Attempts != 0 || tb.Successes != 0 || tb.MedianTTFB != 0 || tb.MedianThroughput != 0 {
		t.Errorf("expected an empty score, got %+v", tb)
	}
	if QuickerThan(tb.MedianTTFB, 100*time.Millisecond) {
		t.Error("an unmeasured candidate must never win a comparison")
	}
}
