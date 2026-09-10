package apply

import "sort"

// AddressDrift compares the addresses an installed service filters on against
// the addresses its hosts resolve to now.
//
// This exists because a targeted scope is a fixed address list captured at
// install time. A CDN that moves its hosts to new addresses leaves the filter
// pointing at addresses nobody uses any more: the traffic passes the driver
// untouched and the site is blocked again, while the service still reports
// itself as running. Nothing in the service state reveals that, so it has to be
// diagnosed by comparison.
type AddressDrift struct {
	// Installed is what the service currently filters on.
	Installed []string
	// Current is what the hosts resolve to now.
	Current []string
	// Missing are current addresses the filter does not cover. These are the
	// harmful ones: traffic to them escapes the strategy entirely.
	Missing []string
	// Stale are filtered addresses no host resolves to any more. Harmless in
	// itself — a filter term that never matches costs nothing — but a useful
	// signal that the host has moved.
	Stale []string
}

// Degraded reports whether traffic is escaping the strategy. Stale entries
// alone are not degradation; only uncovered live addresses are.
func (d AddressDrift) Degraded() bool { return len(d.Missing) > 0 }

// CompareAddresses computes the drift between an installed filter and current
// resolution.
//
// An empty installed list means the service captures everything, so nothing can
// escape it and there is no drift to report — otherwise every address would be
// listed as "missing" for a service that already covers them all.
func CompareAddresses(installed, current []string) AddressDrift {
	d := AddressDrift{Installed: installed, Current: current}
	if len(installed) == 0 {
		return d
	}

	inFilter := make(map[string]struct{}, len(installed))
	for _, a := range installed {
		inFilter[a] = struct{}{}
	}
	live := make(map[string]struct{}, len(current))
	for _, a := range current {
		live[a] = struct{}{}
	}

	for a := range live {
		if _, ok := inFilter[a]; !ok {
			d.Missing = append(d.Missing, a)
		}
	}
	for a := range inFilter {
		if _, ok := live[a]; !ok {
			d.Stale = append(d.Stale, a)
		}
	}
	sort.Strings(d.Missing)
	sort.Strings(d.Stale)
	return d
}
