package main

import "testing"

func TestNextStepAsksForASiteFirst(t *testing.T) {
	got := nextStep(Snapshot{})
	if got.Action != actionAdd {
		t.Errorf("Action = %q, want %q", got.Action, actionAdd)
	}
}

// A stray engine outranks everything: it alters traffic on its own, so any
// measurement taken while one is running is measuring the stray.
func TestNextStepReportsStrayEnginesBeforeAnythingElse(t *testing.T) {
	s := Snapshot{
		Strays: 1,
		Sites:  []SiteView{{Host: "a.com", Measured: true, Path: "RESET", System: "RESET"}},
	}
	got := nextStep(s)
	if got.Tone != "bad" || got.Action != "" {
		t.Errorf("got %+v, want a bad-tone warning with no button", got)
	}
	if got.Title == "" || got.Detail == "" {
		t.Error("a stray engine must be explained, not just flagged")
	}
}

func TestNextStepMeasuresBeforeInstalling(t *testing.T) {
	s := Snapshot{Sites: []SiteView{{Host: "a.com"}, {Host: "b.com"}}}
	if got := nextStep(s); got.Action != actionCheck {
		t.Errorf("Action = %q, want %q", got.Action, actionCheck)
	}
}

// The order that matters most. A host outside the kernel filter fails exactly
// as a dead strategy does, and the two remedies are opposite — refresh the
// address list, or search for a new strategy. Reporting effectiveness first
// sends the user to rebuild a strategy that was never broken.
func TestNextStepReportsScopeDriftBeforeEffectiveness(t *testing.T) {
	s := Snapshot{
		Installed: true,
		Running:   true,
		Sites: []SiteView{{
			Host: "a.com", Measured: true,
			Path: "RESET", System: "RESET",
			Covered: false, Missing: []string{"1.2.3.4"},
		}},
	}
	got := nextStep(s)
	if got.Action != actionRefresh {
		t.Errorf("Action = %q, want %q — drift must be reported before effectiveness", got.Action, actionRefresh)
	}
}

func TestNextStepInstallsForAPathBlock(t *testing.T) {
	s := Snapshot{Sites: []SiteView{{
		Host: "a.com", Measured: true, DNS: "OK", Path: "RESET", System: "RESET", Covered: true,
	}}}
	if got := nextStep(s); got.Action != actionInstall {
		t.Errorf("Action = %q, want %q", got.Action, actionInstall)
	}
}

// A forged answer is not something a desync strategy can fix, so the step must
// send the user to the DNS remedy rather than to another search.
func TestNextStepPinsForAForgedAnswer(t *testing.T) {
	s := Snapshot{Sites: []SiteView{{
		Host: "a.com", Measured: true,
		DNS: "HIJACKED", Path: "OK", System: "CERT-BAD", Covered: true,
	}}}
	got := nextStep(s)
	if got.Action != actionPin {
		t.Errorf("Action = %q, want %q", got.Action, actionPin)
	}
}

// Already pinned and still broken must not offer to pin again.
func TestNextStepDoesNotRepeatAPinThatIsAlreadyThere(t *testing.T) {
	s := Snapshot{Sites: []SiteView{{
		Host: "a.com", Measured: true,
		DNS: "HIJACKED", Path: "OK", System: "CERT-BAD", Covered: true, Pinned: true,
	}}}
	if got := nextStep(s); got.Action == actionPin {
		t.Errorf("offered to pin a name that is already pinned: %+v", got)
	}
}

func TestNextStepSaysNothingToDoWhenEverythingWorks(t *testing.T) {
	s := Snapshot{
		Installed: true, Running: true,
		Sites: []SiteView{
			{Host: "a.com", Measured: true, DNS: "OK", Path: "OK", System: "OK", Covered: true},
			{Host: "b.com", Measured: true, DNS: "OK", Path: "OK", System: "OK", Covered: true},
		},
	}
	got := nextStep(s)
	if got.Tone != "ok" || got.Action != actionCheck {
		t.Errorf("got %+v, want an ok tone offering another check", got)
	}
}

// Every step must be actionable or explained. A card with no button and no
// detail leaves the user exactly where the old window left them.
func TestEveryStepIsActionableOrExplained(t *testing.T) {
	cases := map[string]Snapshot{
		"empty":      {},
		"unmeasured": {Sites: []SiteView{{Host: "a.com"}}},
		"stray":      {Strays: 2, Sites: []SiteView{{Host: "a.com"}}},
		"blocked":    {Sites: []SiteView{{Host: "a.com", Measured: true, Path: "RESET", System: "RESET", Covered: true}}},
		"forged":     {Sites: []SiteView{{Host: "a.com", Measured: true, DNS: "HIJACKED", Path: "OK", System: "CERT-BAD", Covered: true}}},
		"mixed": {Sites: []SiteView{
			{Host: "a.com", Measured: true, DNS: "OK", Path: "OK", System: "OK", Covered: true},
			{Host: "b.com", Measured: true, DNS: "OK", Path: "IP-BLOCK", System: "IP-BLOCK", Covered: true},
		}},
		"healthy": {Installed: true, Running: true, Sites: []SiteView{
			{Host: "a.com", Measured: true, DNS: "OK", Path: "OK", System: "OK", Covered: true}}},
	}
	for name, s := range cases {
		got := nextStep(s)
		if got.Title == "" {
			t.Errorf("%s: no title", name)
		}
		if got.Action == "" && got.Detail == "" {
			t.Errorf("%s: neither a button nor an explanation: %+v", name, got)
		}
		if got.Action != "" && got.Label == "" {
			t.Errorf("%s: action %q has no button label", name, got.Action)
		}
	}
}

// The window shows a badge saying machine-wide scope is "free on this
// connection". That is a claim about the provider, and making it before
// anything has been measured is the unproven-claim failure this project keeps
// re-learning. Diagnosis.Measured is what the window gates the badge on.
func TestDiagnosisIsNotMeasuredUntilSomethingIs(t *testing.T) {
	if diagnose(Snapshot{}).Measured {
		t.Error("an empty snapshot reported itself as measured")
	}
	unmeasured := Snapshot{Sites: []SiteView{{Host: "a.com"}}}
	if diagnose(unmeasured).Measured {
		t.Error("a site that was never probed reported itself as measured")
	}
}

func TestDiagnosisNamesTheLayers(t *testing.T) {
	both := diagnose(Snapshot{Sites: []SiteView{{
		Host: "a.com", Measured: true, DNS: "HIJACKED", Path: "RESET", System: "CERT-BAD",
	}}})
	if both.Layers != 2 || !both.Measured {
		t.Errorf("both layers censored = %+v", both)
	}

	dnsOnly := diagnose(Snapshot{Sites: []SiteView{{
		Host: "a.com", Measured: true, DNS: "HIJACKED", Path: "OK", System: "CERT-BAD",
	}}})
	if dnsOnly.Layers != 1 {
		t.Errorf("DNS-only = %+v, want Layers 1", dnsOnly)
	}

	// SUSPECT + browser failure + honest path used to read as "nothing blocked"
	// while Next still offered Pin DNS — the freeze-screen false calm.
	suspect := diagnose(Snapshot{Sites: []SiteView{{
		Host: "discord.com", Measured: true, DNS: "SUSPECT", Path: "OK", System: "IP-BLOCK",
	}}})
	if suspect.Layers != 1 || suspect.Tone != "bad" {
		t.Errorf("suspect DNS with browser IP-BLOCK = %+v, want DNS-layer bad", suspect)
	}

	pathOnly := diagnose(Snapshot{Sites: []SiteView{{
		Host: "a.com", Measured: true, DNS: "OK", Path: "RESET", System: "RESET",
	}}})
	if pathOnly.Layers != 1 {
		t.Errorf("path-only = %+v, want Layers 1", pathOnly)
	}

	clean := diagnose(Snapshot{Sites: []SiteView{{
		Host: "a.com", Measured: true, DNS: "OK", Path: "OK", System: "OK",
	}}})
	if clean.Layers != 0 || clean.Tone != "ok" || !clean.Measured {
		t.Errorf("clean = %+v", clean)
	}
}
