package apply

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"dpi/internal/engine"
)

// reportFile records what a search concluded.
//
// The search is the expensive part of this tool and its result used to be
// printed and thrown away, so nothing could answer "why this strategy?" once
// the command had scrolled off — and a window has no scrollback to read at all.
//
// This is a record of one measurement, not configuration: it is true of the
// link as it was at TakenAt and goes stale when the link changes. That is why
// it carries its own timestamp and the strategy it chose, so a reader can tell
// whether it still describes what is installed.
const reportFile = "report.json"

// SearchReport is one search, written down.
type SearchReport struct {
	TakenAt time.Time `json:"taken_at"`
	Hosts   []string  `json:"hosts"`
	// Chosen is the strategy that was picked, one stage per entry.
	Chosen []string `json:"chosen"`
	// Screened and Survivors describe how much of the space was explored.
	Screened  int `json:"screened"`
	Survivors int `json:"survivors"`
	// Unverified counts survivors that could not be measured, so they are
	// absent from Entries. Recorded rather than dropped: a transient engine
	// failure was measured silently removing a candidate from a ranking.
	Unverified int `json:"unverified"`
	// NoiseMS is the threshold within which two medians were treated as
	// indistinguishable. Without it the numbers below invite false precision.
	NoiseMS float64       `json:"noise_ms"`
	Entries []ReportEntry `json:"entries"`
}

// ReportEntry is one measured strategy.
type ReportEntry struct {
	Strategy string `json:"strategy"`
	// Group 0 is the tied-fastest set; every member of it was an equally
	// defensible choice.
	Group     int     `json:"group"`
	Tier      string  `json:"tier"`
	MedianMS  float64 `json:"median_ms"`
	SpreadMS  float64 `json:"spread_ms"`
	Successes int     `json:"successes"`
	Attempts  int     `json:"attempts"`
	TTFBMS    float64 `json:"ttfb_ms"`
}

// Tied returns the entries that could not be told apart from the best.
func (r SearchReport) Tied() []ReportEntry {
	var out []ReportEntry
	for _, e := range r.Entries {
		if e.Group == 0 {
			out = append(out, e)
		}
	}
	return out
}

// Best is the entry the search settled on, found by name rather than position
// so a reordered file cannot make this lie.
func (r SearchReport) Best() (ReportEntry, bool) {
	want := engine.FormatStages(r.Chosen)
	for _, e := range r.Entries {
		if e.Strategy == want {
			return e, true
		}
	}
	return ReportEntry{}, false
}

// ReportPath is where the record lives for a given config directory.
func ReportPath(configDir string) string { return filepath.Join(configDir, reportFile) }

// SaveReport writes the record.
func SaveReport(configDir string, r SearchReport) error {
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("apply: create config dir: %w", err)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("apply: encode report: %w", err)
	}
	if err := os.WriteFile(ReportPath(configDir), append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("apply: write report: %w", err)
	}
	return nil
}

// LoadReport reads it back. A missing file is reported as os.ErrNotExist, which
// is the normal state before the first search.
func LoadReport(configDir string) (SearchReport, error) {
	b, err := os.ReadFile(ReportPath(configDir))
	if err != nil {
		return SearchReport{}, err
	}
	var r SearchReport
	if err := json.Unmarshal(b, &r); err != nil {
		return SearchReport{}, fmt.Errorf("apply: report file is not readable JSON: %w", err)
	}
	return r, nil
}
