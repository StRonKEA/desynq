package measure

import (
	"slices"
	"testing"
	"time"
)

func TestMedian(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	cases := []struct {
		name string
		in   []time.Duration
		want time.Duration
	}{
		{"no successful attempts", nil, 0},
		{"single value", []time.Duration{ms(50)}, ms(50)},
		{"odd count takes the middle", []time.Duration{ms(30), ms(10), ms(20)}, ms(20)},
		{"even count averages the two middles", []time.Duration{ms(10), ms(20), ms(30), ms(40)}, ms(25)},
		// The reason for using a median at all: one stalled attempt must not
		// move the reported cost of the strategy.
		{"outlier does not drag the result", []time.Duration{ms(40), ms(42), ms(44), ms(46), ms(5000)}, ms(44)},
	}
	for _, c := range cases {
		if got := median(c.in); got != c.want {
			t.Errorf("%s: median() = %v, want %v", c.name, got, c.want)
		}
	}
}

// median must not reorder the caller's slice: callers keep their own copies for
// per-target reporting after the aggregate has been computed.
func TestMedianDoesNotMutateInput(t *testing.T) {
	in := []time.Duration{3, 1, 2}
	_ = median(in)
	if in[0] != 3 || in[1] != 1 || in[2] != 2 {
		t.Errorf("input was reordered: %v", in)
	}
}

func TestIQR(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	cases := []struct {
		name string
		in   []time.Duration
		want time.Duration
	}{
		{"no samples", nil, 0},
		{"one sample cannot show spread", []time.Duration{ms(50)}, 0},
		{"identical samples have no spread", []time.Duration{ms(50), ms(50), ms(50), ms(50)}, 0},
		{"two samples", []time.Duration{ms(40), ms(60)}, ms(20)},
		{"four samples: upper pair median minus lower pair median",
			[]time.Duration{ms(10), ms(20), ms(30), ms(40)}, ms(20)},
	}
	for _, c := range cases {
		if got := iqr(c.in); got != c.want {
			t.Errorf("%s: iqr() = %v, want %v", c.name, got, c.want)
		}
	}
}

// The point of using the interquartile range instead of min-to-max: a single
// stalled handshake must not inflate the spread and thereby make every
// strategy look indistinguishable from every other.
func TestIQRResistsASingleOutlier(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	tight := []time.Duration{ms(50), ms(51), ms(52), ms(53), ms(54), ms(55)}
	withOutlier := append(slices.Clone(tight), ms(5000))

	a, b := iqr(tight), iqr(withOutlier)
	spread := b - a
	if spread < 0 {
		spread = -spread
	}
	if spread > ms(20) {
		t.Errorf("one outlier moved the spread from %v to %v; the IQR should absorb it", a, b)
	}
}

func TestIQRDoesNotMutateInput(t *testing.T) {
	in := []time.Duration{3, 1, 2}
	_ = iqr(in)
	if in[0] != 3 || in[1] != 1 || in[2] != 2 {
		t.Errorf("input was reordered: %v", in)
	}
}

func TestSuccessRate(t *testing.T) {
	t.Run("zero attempts is not a division by zero", func(t *testing.T) {
		if got := (Score{}).SuccessRate(); got != 0 {
			t.Errorf("Score.SuccessRate() = %v, want 0", got)
		}
		if got := (TargetScore{}).SuccessRate(); got != 0 {
			t.Errorf("TargetScore.SuccessRate() = %v, want 0", got)
		}
	})

	t.Run("partial success", func(t *testing.T) {
		if got := (Score{Attempts: 4, Successes: 3}).SuccessRate(); got != 0.75 {
			t.Errorf("Score.SuccessRate() = %v, want 0.75", got)
		}
		if got := (TargetScore{Attempts: 2, Successes: 1}).SuccessRate(); got != 0.5 {
			t.Errorf("TargetScore.SuccessRate() = %v, want 0.5", got)
		}
	})
}
