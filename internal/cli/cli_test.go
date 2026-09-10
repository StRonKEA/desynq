package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dpi/internal/apply"
	"dpi/internal/measure"
	"dpi/internal/probe"
	"dpi/internal/search"
)

// A repeated domain is not merely redundant: two targets with the same address
// make the second engine instance claim a filter the first already holds, which
// surfaces as ErrFilterBusy and aborts the entire search. Cleaning the input is
// the cheapest place to prevent it.
func TestUniqueDomains(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"repeats collapse", []string{"a.com", "a.com"}, "a.com"},
		{"order is preserved", []string{"b.com", "a.com", "b.com"}, "b.com,a.com"},
		{"case is normalised", []string{"A.com", "a.COM"}, "a.com"},
		{"whitespace is trimmed", []string{" a.com ", "a.com"}, "a.com"},
		{"blanks are dropped", []string{"", "  ", "a.com"}, "a.com"},
		{"nothing usable", []string{"", " "}, ""},
		{"nil input", nil, ""},
	}
	for _, c := range cases {
		if got := strings.Join(uniqueDomains(c.in), ","); got != c.want {
			t.Errorf("%s: uniqueDomains(%v) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func ranked(stage string, targets ...measure.TargetScore) search.Ranked {
	return search.Ranked{
		Candidate: search.Candidate{Stages: []string{stage}},
		Score:     measure.Score{Targets: targets},
	}
}

func full(domain string) measure.TargetScore {
	return measure.TargetScore{Domain: domain, Attempts: 4, Successes: 4}
}

func partial(domain string) measure.TargetScore {
	return measure.TargetScore{Domain: domain, Attempts: 4, Successes: 1}
}

func TestCoversAll(t *testing.T) {
	r := ranked("s", full("a"), partial("b"))

	if !coversAll(r, []string{"a"}) {
		t.Error("a fully covered host should count as covered")
	}
	if coversAll(r, []string{"a", "b"}) {
		t.Error("a partially covered host must not count as covered")
	}
	// A host the strategy was never measured against cannot be claimed as
	// covered, or the plan would install a strategy for it on no evidence.
	if coversAll(r, []string{"a", "unmeasured"}) {
		t.Error("an unmeasured host must not count as covered")
	}
	if coversAll(r, nil) {
		t.Error("an empty host list is not coverage")
	}
}

// buildProfiles must group hosts by strategy, and must install the strategy
// that was reported as chosen when that one already covers everything.
func TestBuildProfiles(t *testing.T) {
	blocked := func(domain string, addrs ...string) probe.Result {
		return probe.Result{Domain: domain, RealIPs: addrs, Path: probe.PathReset}
	}

	t.Run("chosen strategy covering all hosts yields one profile", func(t *testing.T) {
		chosen := ranked("covers-both", full("a.com"), full("b.com"))
		report := search.Report{Ranked: []search.Ranked{chosen}}
		results := []probe.Result{blocked("a.com", "1.1.1.1"), blocked("b.com", "2.2.2.2")}

		profs := buildProfiles(report, results, chosen, false)
		if len(profs) != 1 {
			t.Fatalf("expected one profile, got %d", len(profs))
		}
		if profs[0].Stages[0] != "covers-both" {
			t.Errorf("installed %q instead of the chosen strategy", profs[0].Stages[0])
		}
		if len(profs[0].Hosts) != 2 || len(profs[0].Addrs) != 2 {
			t.Errorf("profile should carry both hosts and both addresses: %+v", profs[0])
		}
	})

	// Every address of a host must reach the filter. A CDN rotates between its
	// A records, and a filter built from one address stops matching the moment
	// the resolver hands out another.
	t.Run("all addresses of a host are carried", func(t *testing.T) {
		chosen := ranked("s", full("a.com"))
		report := search.Report{Ranked: []search.Ranked{chosen}}
		results := []probe.Result{blocked("a.com", "1.1.1.1", "1.1.1.2", "1.1.1.3")}

		profs := buildProfiles(report, results, chosen, false)
		if len(profs) != 1 || len(profs[0].Addrs) != 3 {
			t.Errorf("expected all three addresses, got %+v", profs)
		}
	})

	t.Run("hosts needing different strategies get separate profiles", func(t *testing.T) {
		goodForA := ranked("good-for-a", full("a.com"), partial("b.com"))
		goodForB := ranked("good-for-b", partial("a.com"), full("b.com"))
		report := search.Report{Ranked: []search.Ranked{goodForA, goodForB}}
		results := []probe.Result{blocked("a.com", "1.1.1.1"), blocked("b.com", "2.2.2.2")}

		profs := buildProfiles(report, results, goodForA, false)
		if len(profs) != 2 {
			t.Fatalf("expected two profiles, got %d: %+v", len(profs), profs)
		}
		byStage := map[string][]string{}
		for _, p := range profs {
			byStage[p.Stages[0]] = p.Hosts
		}
		if got := byStage["good-for-a"]; len(got) != 1 || got[0] != "a.com" {
			t.Errorf("good-for-a should own a.com, got %v", got)
		}
		if got := byStage["good-for-b"]; len(got) != 1 || got[0] != "b.com" {
			t.Errorf("good-for-b should own b.com, got %v", got)
		}
	})

	// Names that were never blocked must stay out of the capture entirely.
	t.Run("unblocked names are excluded", func(t *testing.T) {
		chosen := ranked("s", full("a.com"))
		report := search.Report{Ranked: []search.Ranked{chosen}}
		results := []probe.Result{
			blocked("a.com", "1.1.1.1"),
			{Domain: "open.com", RealIPs: []string{"3.3.3.3"}, Path: probe.PathOk},
		}

		profs := buildProfiles(report, results, chosen, false)
		for _, p := range profs {
			for _, h := range p.Hosts {
				if h == "open.com" {
					t.Error("an unblocked name must not be added to a profile")
				}
			}
			for _, a := range p.Addrs {
				if a == "3.3.3.3" {
					t.Error("an unblocked address must not enter the kernel filter")
				}
			}
		}
	})

	// A profile shared by several hosts may only rotate to a strategy that
	// covers all of them. Rotating to one that fixes a single host would leave
	// the others broken until the next failure threshold.
	t.Run("shared profile only takes fallbacks that cover every host", func(t *testing.T) {
		chosen := ranked("primary", full("a.com"), full("b.com"))
		coversBoth := ranked("covers-both", full("a.com"), full("b.com"))
		onlyA := ranked("only-a", full("a.com"), partial("b.com"))
		report := search.Report{Ranked: []search.Ranked{chosen, coversBoth, onlyA}}
		results := []probe.Result{blocked("a.com", "1.1.1.1"), blocked("b.com", "2.2.2.2")}

		profs := buildProfiles(report, results, chosen, true)
		if len(profs) != 1 {
			t.Fatalf("expected one profile, got %d", len(profs))
		}
		if len(profs[0].Fallbacks) != 1 {
			t.Fatalf("expected exactly one usable fallback, got %v", profs[0].Fallbacks)
		}
		if profs[0].Fallbacks[0][0] != "covers-both" {
			t.Errorf("fallback = %q, want covers-both", profs[0].Fallbacks[0][0])
		}
	})

	// Rotation must be opt-in: it doubles the kernel filter and installs
	// strategies the user did not see chosen.
	t.Run("rotation off means no fallbacks", func(t *testing.T) {
		chosen := ranked("primary", full("a.com"))
		other := ranked("other", full("a.com"))
		report := search.Report{Ranked: []search.Ranked{chosen, other}}
		results := []probe.Result{blocked("a.com", "1.1.1.1")}

		profs := buildProfiles(report, results, chosen, false)
		if len(profs) != 1 || len(profs[0].Fallbacks) != 0 {
			t.Errorf("expected no fallbacks with rotation off, got %+v", profs)
		}
	})

	// The primary must never appear as its own fallback, or a rotation step
	// would be a no-op.
	t.Run("primary is not its own fallback", func(t *testing.T) {
		chosen := ranked("primary", full("a.com"))
		report := search.Report{Ranked: []search.Ranked{chosen}}
		results := []probe.Result{blocked("a.com", "1.1.1.1")}

		profs := buildProfiles(report, results, chosen, true)
		if len(profs) != 1 {
			t.Fatalf("expected one profile, got %d", len(profs))
		}
		for _, fb := range profs[0].Fallbacks {
			if fb[0] == "primary" {
				t.Error("the primary strategy must not be listed as a fallback")
			}
		}
	})

	// A host with no address cannot be targeted, so it must not silently widen
	// the plan by contributing a host entry with no filter term.
	t.Run("hosts without an address are skipped", func(t *testing.T) {
		chosen := ranked("s", full("a.com"))
		report := search.Report{Ranked: []search.Ranked{chosen}}
		results := []probe.Result{{Domain: "a.com", Path: probe.PathReset}}

		if profs := buildProfiles(report, results, chosen, false); len(profs) != 0 {
			t.Errorf("expected no profiles, got %+v", profs)
		}
	})
}

// A host that never produced a result must count as blocked. Its zero value
// carries an empty path status, which DesyncApplies reads as "not a desync
// case" — so a map treated as complete would turn a host that never answered
// into a host that works, and doctor would report a dead install as healthy.
func TestCountProblemsTreatsMissingResultsAsBlocked(t *testing.T) {
	hosts := []string{"open.com", "blocked.com", "never-answered.com"}
	final := map[string]probe.Result{
		"open.com":    {Domain: "open.com", Path: probe.PathOk, DNS: probe.DNSOk},
		"blocked.com": {Domain: "blocked.com", Path: probe.PathReset, DNS: probe.DNSHijacked},
	}

	stillBlocked, dnsForged, dnsSuspect := countProblems(hosts, final)
	if stillBlocked != 2 {
		t.Errorf("stillBlocked = %d, want 2 (the reset one and the missing one)", stillBlocked)
	}
	if dnsForged != 1 {
		t.Errorf("dnsForged = %d, want 1", dnsForged)
	}
	if dnsSuspect != 0 {
		t.Errorf("dnsSuspect = %d, want 0", dnsSuspect)
	}
}

// A suspect answer must be counted apart from a proven one. It is deliberately
// not a conviction — one observation cannot tell a block page from a CDN edge —
// but it must not vanish either: whether it ever gets convicted depends on how
// many names happen to be probed together, and a browser follows the system
// resolver eitherway.
func TestCountProblemsSeparatesSuspectFromForged(t *testing.T) {
	hosts := []string{"forged.com", "suspect.com", "clean.com"}
	final := map[string]probe.Result{
		"forged.com":  {Domain: "forged.com", Path: probe.PathOk, DNS: probe.DNSHijacked},
		"suspect.com": {Domain: "suspect.com", Path: probe.PathOk, DNS: probe.DNSSuspect},
		"clean.com":   {Domain: "clean.com", Path: probe.PathOk, DNS: probe.DNSOk},
	}

	stillBlocked, dnsForged, dnsSuspect := countProblems(hosts, final)
	if stillBlocked != 0 {
		t.Errorf("stillBlocked = %d, want 0", stillBlocked)
	}
	if dnsForged != 1 {
		t.Errorf("dnsForged = %d, want 1", dnsForged)
	}
	if dnsSuspect != 1 {
		t.Errorf("dnsSuspect = %d, want 1", dnsSuspect)
	}
}

func TestInstalledHosts(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "hostlist-1.txt")
	two := filepath.Join(dir, "hostlist-2.txt")
	if err := os.WriteFile(one, []byte("a.com\nb.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, []byte("b.com\nc.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	inst := apply.Installed{Profiles: []apply.InstalledProfile{
		{Hostlist: one},
		{Hostlist: two},
		{Hostlist: filepath.Join(dir, "gone.txt")},
		{}, // a profile with no host list applies to whatever the filter allows
	}}

	hosts, unreadable := installedHosts(inst)
	if strings.Join(hosts, ",") != "a.com,b.com,c.com" {
		t.Errorf("hosts = %v, want the union without repeats", hosts)
	}
	// An unreadable list is a real fault: the engine treats a missing file as an
	// empty list, so that profile silently matches nothing.
	if len(unreadable) != 1 || !strings.HasSuffix(unreadable[0], "gone.txt") {
		t.Errorf("unreadable = %v, want the missing file", unreadable)
	}
}

// Refresh rebuilds what is installed, so each profile must keep its own
// strategy, its own hosts and only their addresses. Mixing them up would
// install a working strategy against the wrong names, which looks healthy and
// fixes nothing.
func TestRebuildProfiles(t *testing.T) {
	inst := apply.Installed{Profiles: []apply.InstalledProfile{
		{Strategies: [][]string{{"multisplit:pos=1"}}},
		{
			Strategies: [][]string{{"fake:tcp_md5", "multisplit:pos=3"}, {"oob:urp=b"}},
			Rotating:   true,
		},
	}}
	profHosts := [][]string{{"a.com"}, {"b.com", "c.com"}}
	addrsOf := map[string][]string{
		"a.com": {"1.1.1.1"},
		"b.com": {"2.2.2.2", "2.2.2.3"},
		"c.com": {"3.3.3.3"},
	}

	got := rebuildProfiles(inst, profHosts, addrsOf)
	if len(got) != 2 {
		t.Fatalf("expected two profiles, got %+v", got)
	}

	if strings.Join(got[0].Stages, "|") != "multisplit:pos=1" {
		t.Errorf("profile 1 stages = %v", got[0].Stages)
	}
	if strings.Join(got[0].Addrs, ",") != "1.1.1.1" {
		t.Errorf("profile 1 addrs = %v, want only its own host's address", got[0].Addrs)
	}
	// A profile installed without rotation must not gain fallbacks: that would
	// double the kernel filter behind the user's back.
	if len(got[0].Fallbacks) != 0 {
		t.Errorf("profile 1 fallbacks = %v, want none", got[0].Fallbacks)
	}

	// Both stages of the rotating profile's primary belong together.
	if strings.Join(got[1].Stages, "|") != "fake:tcp_md5|multisplit:pos=3" {
		t.Errorf("profile 2 stages = %v", got[1].Stages)
	}
	if len(got[1].Fallbacks) != 1 || got[1].Fallbacks[0][0] != "oob:urp=b" {
		t.Errorf("profile 2 fallbacks = %v", got[1].Fallbacks)
	}
	// Every address of every host of that profile, and nothing from the other.
	if strings.Join(got[1].Addrs, ",") != "2.2.2.2,2.2.2.3,3.3.3.3" {
		t.Errorf("profile 2 addrs = %v", got[1].Addrs)
	}
}

func TestCurrentAddresses(t *testing.T) {
	got := currentAddresses(map[string]probe.Result{
		"a.com": {Domain: "a.com", RealIPs: []string{"2.2.2.2", "1.1.1.1"}},
		"b.com": {Domain: "b.com", RealIPs: []string{"3.3.3.3"}},
		"c.com": {Domain: "c.com"},
	})
	if strings.Join(got, ",") != "1.1.1.1,2.2.2.2,3.3.3.3" {
		t.Errorf("currentAddresses = %v, want every address sorted", got)
	}
}

// The search pins an engine to this address, so it must be one the encrypted
// resolver vouched for. An IPv6-only name has to be searched rather than
// skipped — the engine pin and the prober both handle it — and the system
// answer must never stand in, because under a hijack it is the block page and
// the search would score strategies against the censor's own server.
func TestSearchAddr(t *testing.T) {
	cases := []struct {
		name string
		in   probe.Result
		want string
	}{
		{"ipv4 preferred", probe.Result{
			RealIPs:  []string{"1.1.1.1", "2.2.2.2"},
			RealIPs6: []string{"2606:4700::1"},
		}, "1.1.1.1"},
		{"ipv6 only name is still searchable", probe.Result{
			RealIPs6: []string{"2606:4700::1"},
		}, "2606:4700::1"},
		{"system answer is never used", probe.Result{
			SysIPs: []string{"195.175.254.2"},
		}, ""},
		{"nothing at all", probe.Result{}, ""},
	}
	for _, c := range cases {
		if got := searchAddr(c.in); got != c.want {
			t.Errorf("%s: searchAddr() = %q, want %q", c.name, got, c.want)
		}
	}
}
