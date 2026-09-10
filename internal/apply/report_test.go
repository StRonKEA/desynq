package apply

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestReportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := SearchReport{
		TakenAt:    time.Date(2026, 9, 5, 17, 0, 0, 0, time.UTC),
		Hosts:      []string{"discord.com"},
		Chosen:     []string{"fake:tcp_md5", "multisplit:pos=1"},
		Screened:   77,
		Survivors:  44,
		Unverified: 1,
		NoiseMS:    21.5,
		Entries: []ReportEntry{
			{Strategy: "multidisorder:pos=1", Group: 0, Tier: "safe", MedianMS: 70, SpreadMS: 21, Successes: 20, Attempts: 20},
			{Strategy: "fake:tcp_md5 | multisplit:pos=1", Group: 0, Tier: "safe", MedianMS: 72, SpreadMS: 19, Successes: 20, Attempts: 20},
			{Strategy: "wssize:wsize=1:scale=6", Group: 3, Tier: "safe", MedianMS: 378, SpreadMS: 44, Successes: 20, Attempts: 20},
		},
	}
	if err := SaveReport(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TakenAt.Equal(want.TakenAt) {
		t.Errorf("TakenAt = %v, want %v", got.TakenAt, want.TakenAt)
	}
	if got.Screened != 77 || got.Survivors != 44 || got.Unverified != 1 {
		t.Errorf("counts did not survive: %+v", got)
	}
	if got.NoiseMS != 21.5 {
		t.Errorf("NoiseMS = %v, want 21.5", got.NoiseMS)
	}
}

// The tied group is the whole point of the record: on a real link most working
// strategies are indistinguishable, and a "fastest" without its group is the
// most misleading thing this tool could show.
func TestReportTiedIsGroupZeroOnly(t *testing.T) {
	r := SearchReport{Entries: []ReportEntry{
		{Strategy: "a", Group: 0},
		{Strategy: "b", Group: 0},
		{Strategy: "c", Group: 1},
	}}
	tied := r.Tied()
	if len(tied) != 2 || tied[0].Strategy != "a" || tied[1].Strategy != "b" {
		t.Errorf("Tied() = %+v", tied)
	}
}

// Best matches by name rather than position, so a reordered or hand-edited file
// cannot make the window attribute someone else's numbers to the chosen one.
func TestReportBestMatchesByName(t *testing.T) {
	r := SearchReport{
		Chosen: []string{"fake:tcp_md5", "multisplit:pos=1"},
		Entries: []ReportEntry{
			{Strategy: "multidisorder:pos=1", MedianMS: 70},
			{Strategy: "fake:tcp_md5 | multisplit:pos=1", MedianMS: 72},
		},
	}
	best, ok := r.Best()
	if !ok {
		t.Fatal("Best() found nothing for a strategy that is present")
	}
	if best.MedianMS != 72 {
		t.Errorf("Best().MedianMS = %v, want 72 (it took the wrong row)", best.MedianMS)
	}

	r.Chosen = []string{"something-never-measured"}
	if _, ok := r.Best(); ok {
		t.Error("Best() claimed a match for a strategy that is not in the table")
	}
}

func TestLoadReportReportsAMissingFileAsNotExist(t *testing.T) {
	if _, err := LoadReport(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist", err)
	}
}

func TestLoadReportRejectsBrokenContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(ReportPath(dir), []byte("{nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(dir); err == nil {
		t.Fatal("expected an error for unreadable JSON")
	} else if errors.Is(err, os.ErrNotExist) {
		t.Errorf("a broken file must not read as a missing one: %v", err)
	}
}
