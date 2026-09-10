package apply

import (
	"strings"
	"testing"
)

func TestCompareAddresses(t *testing.T) {
	cases := []struct {
		name      string
		installed []string
		current   []string
		missing   string
		stale     string
		degraded  bool
	}{
		{
			name:      "unchanged",
			installed: []string{"1.1.1.1", "2.2.2.2"},
			current:   []string{"2.2.2.2", "1.1.1.1"},
		},
		{
			// The case this exists for: the host moved and the filter does not
			// know, so its traffic passes the driver untouched.
			name:      "host moved",
			installed: []string{"1.1.1.1"},
			current:   []string{"3.3.3.3"},
			missing:   "3.3.3.3",
			stale:     "1.1.1.1",
			degraded:  true,
		},
		{
			// A CDN handing out one more edge than the filter covers is
			// degraded too: that edge is a coin flip away from being used.
			name:      "one new edge",
			installed: []string{"1.1.1.1", "2.2.2.2"},
			current:   []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
			missing:   "3.3.3.3",
			degraded:  true,
		},
		{
			// A filter wider than current resolution still covers everything
			// live, so nothing escapes and nothing needs doing.
			name:      "filter wider than reality",
			installed: []string{"1.1.1.1", "2.2.2.2"},
			current:   []string{"1.1.1.1"},
			stale:     "2.2.2.2",
		},
		{
			// No filter means the service captures everything, so no address
			// can escape it. Listing them all as missing would report a
			// -all-traffic install as broken.
			name:      "unrestricted filter",
			installed: nil,
			current:   []string{"1.1.1.1", "9.9.9.9"},
		},
		{
			// Resolution failing entirely is not drift; there is nothing to
			// compare against, and the addresses in the filter may be fine.
			name:      "resolution returned nothing",
			installed: []string{"1.1.1.1"},
			current:   nil,
			stale:     "1.1.1.1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CompareAddresses(c.installed, c.current)
			if s := strings.Join(got.Missing, ","); s != c.missing {
				t.Errorf("Missing = %q, want %q", s, c.missing)
			}
			if s := strings.Join(got.Stale, ","); s != c.stale {
				t.Errorf("Stale = %q, want %q", s, c.stale)
			}
			if got.Degraded() != c.degraded {
				t.Errorf("Degraded() = %v, want %v", got.Degraded(), c.degraded)
			}
		})
	}
}

// Duplicate addresses are normal input: every host of a profile contributes its
// own list and CDNs share edges between names.
func TestCompareAddressesToleratesDuplicates(t *testing.T) {
	got := CompareAddresses(
		[]string{"1.1.1.1", "1.1.1.1"},
		[]string{"1.1.1.1", "3.3.3.3", "3.3.3.3"},
	)
	if strings.Join(got.Missing, ",") != "3.3.3.3" {
		t.Errorf("Missing = %v, want 3.3.3.3 once", got.Missing)
	}
	if len(got.Stale) != 0 {
		t.Errorf("Stale = %v, want none", got.Stale)
	}
}
