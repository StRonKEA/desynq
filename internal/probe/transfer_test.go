package probe

import (
	"testing"
	"time"
)

func TestTransferThroughput(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	cases := []struct {
		name string
		in   Transfer
		want float64
	}{
		{"one megabyte in one second", Transfer{Bytes: 1 << 20, Body: time.Second}, 1 << 20},
		{"half a second doubles the rate", Transfer{Bytes: 1000, Body: ms(500)}, 2000},
		// A rate needs both a size and a duration. Reporting a huge number for
		// a zero-duration read would put a meaningless value into the ranking.
		{"no bytes read", Transfer{Bytes: 0, Body: time.Second}, 0},
		{"no time elapsed", Transfer{Bytes: 1000, Body: 0}, 0},
		{"negative bytes are ignored", Transfer{Bytes: -1, Body: time.Second}, 0},
		{"zero value", Transfer{}, 0},
	}
	for _, c := range cases {
		if got := c.in.Throughput(); got != c.want {
			t.Errorf("%s: Throughput() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFormatThroughput(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "-"},
		{-1, "-"},
		{512, "512 B/s"},
		{2048, "2 KB/s"},
		{1 << 20, "1.0 MB/s"},
		{3 * (1 << 20), "3.0 MB/s"},
	}
	for _, c := range cases {
		if got := FormatThroughput(c.in); got != c.want {
			t.Errorf("FormatThroughput(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A transfer that fails partway must not be reported as a success just because
// some bytes arrived: the rate up to the failure says nothing about a
// connection the censor tore down.
func TestClassifyTransferErrorUsesPathVocabulary(t *testing.T) {
	// The classifiers themselves are covered in probe_test.go; this pins the
	// mapping so a failed transfer reads like a failed handshake.
	if got := classifyTransferError(errTimeoutStub{}); got != PathTimeout {
		t.Errorf("timeout mapped to %q, want %q", got, PathTimeout)
	}
}

type errTimeoutStub struct{}

func (errTimeoutStub) Error() string { return "i/o timeout" }
func (errTimeoutStub) Timeout() bool { return true }
func (errTimeoutStub) Temporary() bool {
	return true
}
