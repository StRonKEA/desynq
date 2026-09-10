package apply

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// Real `sc qc` output, captured from an installed service on 2026-09-04. The
// long binPath is one line in the actual output; only the terminal wrapped it.
const scQCTargeted = `[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: dpi-bypass
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "D:\Proje\dpi\tools\zapret-winws\winws2.exe" --wf-tcp-out=443 "--wf-raw-filter=ip.DstAddr==162.159.128.233 or ip.DstAddr==66.254.114.41" --lua-init=@D:\Proje\dpi\tools\zapret-winws\lua\zapret-lib.lua --lua-init=@D:\Proje\dpi\tools\zapret-winws\lua\zapret-antidpi.lua --filter-tcp=443 --filter-l7=tls --hostlist=D:\Proje\dpi\config\hostlist-1.txt --payload=tls_client_hello --lua-desync=multidisorder:pos=1
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : DPI bypass (dpi-bypass)
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
`

func TestParseServiceConfig(t *testing.T) {
	got := parseServiceConfig(scQCTargeted)

	if got.BinaryPath != `D:\Proje\dpi\tools\zapret-winws\winws2.exe` {
		t.Errorf("BinaryPath = %q", got.BinaryPath)
	}
	// The library directory is recovered so a rebuilt plan keeps pointing at
	// the same files rather than at whatever the default is today.
	if got.LuaDir != `D:\Proje\dpi\tools\zapret-winws\lua` {
		t.Errorf("LuaDir = %q", got.LuaDir)
	}
	if len(got.Profiles) != 1 {
		t.Fatalf("expected one profile, got %v", got.Profiles)
	}
	prof := got.Profiles[0]
	if len(prof.Stages()) != 1 || prof.Stages()[0] != "multidisorder:pos=1" {
		t.Errorf("Stages() = %v", prof.Stages())
	}
	if prof.Rotating || got.Rotating() {
		t.Error("a plain install must not report rotation")
	}
	if strings.Join(got.Addresses, ",") != "162.159.128.233,66.254.114.41" {
		t.Errorf("Addresses = %v", got.Addresses)
	}
	if got.Scope() != ScopeTargeted {
		t.Errorf("Scope() = %q, want targeted", got.Scope())
	}
	if hl := got.Hostlists(); len(hl) != 1 || !strings.HasSuffix(hl[0], "hostlist-1.txt") {
		t.Errorf("Hostlists() = %v", hl)
	}
}

// Per-host installs put each strategy in its own --new profile with its own
// host list. Reading them back as one profile would report a strategy nobody
// installed — the stages of two unrelated profiles joined into one chain — and
// would lose which hosts each applies to.
func TestParseServiceConfigSeparatesProfiles(t *testing.T) {
	cmdline := `        BINARY_PATH_NAME   : "C:\app\winws2.exe" --wf-tcp-out=443 ` +
		`"--wf-raw-filter=ip.DstAddr==1.1.1.1 or ip.DstAddr==2.2.2.2" ` +
		`--filter-tcp=443 --filter-l7=tls --hostlist=C:\cfg\hostlist-1.txt ` +
		`--payload=tls_client_hello --lua-desync=multisplit:pos=1 ` +
		`--new --filter-tcp=443 --filter-l7=tls --hostlist=C:\cfg\hostlist-2.txt ` +
		`--payload=tls_client_hello --lua-desync=fake:tcp_md5 --lua-desync=multisplit:pos=3`
	got := parseServiceConfig(cmdline)

	if len(got.Profiles) != 2 {
		t.Fatalf("expected two profiles, got %v", got.Profiles)
	}
	if s := got.Profiles[0].Stages(); len(s) != 1 || s[0] != "multisplit:pos=1" {
		t.Errorf("profile 1 stages = %v", s)
	}
	if got.Profiles[0].Hostlist != `C:\cfg\hostlist-1.txt` {
		t.Errorf("profile 1 hostlist = %q", got.Profiles[0].Hostlist)
	}
	// Two stages in the same profile are one strategy, not two.
	if s := got.Profiles[1].Stages(); len(s) != 2 ||
		s[0] != "fake:tcp_md5" || s[1] != "multisplit:pos=3" {
		t.Errorf("profile 2 stages = %v", s)
	}
	if got.Profiles[1].Hostlist != `C:\cfg\hostlist-2.txt` {
		t.Errorf("profile 2 hostlist = %q", got.Profiles[1].Hostlist)
	}
	if len(got.Profiles[0].Fallbacks()) != 0 || len(got.Profiles[1].Fallbacks()) != 0 {
		t.Error("profiles without rotation have no fallbacks")
	}
}

// Reading IPv6 back matters as much as writing it: doctor compares the
// installed addresses against current resolution, and an IPv6 address it cannot
// see would be reported as missing on every run — or, worse, an install that
// covers IPv6 would look IPv4-only.
func TestParseServiceConfigReadsIPv6Addresses(t *testing.T) {
	cmdline := `        BINARY_PATH_NAME   : "C:\app\winws2.exe" --wf-tcp-out=443 --wf-l3=ipv4,ipv6 ` +
		`"--wf-raw-filter=ip.DstAddr==1.1.1.1 or ipv6.DstAddr==2606:4700::6810:85E5 or ipv6.SrcAddr==2606:4700::6810:85e5" ` +
		`--lua-desync=multisplit:pos=1`
	got := parseServiceConfig(cmdline)

	// Three terms, two distinct addresses: the source form of an address
	// already listed is the same address, and the differing hex case is the
	// same address too. Reporting either twice would show phantom coverage.
	if len(got.Addresses) != 2 {
		t.Fatalf("Addresses = %v, want the two distinct addresses", got.Addresses)
	}
	if got.Addresses[0] != "1.1.1.1" {
		t.Errorf("Addresses[0] = %q", got.Addresses[0])
	}
	// Normalised through net.IP, so it compares equal to what this tool writes
	// regardless of how it was spelled in the command line.
	if got.Addresses[1] != "2606:4700::6810:85e5" {
		t.Errorf("Addresses[1] = %q, want the normalised IPv6 form", got.Addresses[1])
	}
	if got.Scope() != ScopeTargeted {
		t.Errorf("Scope() = %q, want targeted", got.Scope())
	}
}

// A service with no address filter captures every connection on the machine.
// Reporting that as "targeted" would hide exactly the situation a user running
// anti-cheat software needs to know about.
func TestParseServiceConfigDetectsBroadCapture(t *testing.T) {
	out := strings.Replace(scQCTargeted,
		` "--wf-raw-filter=ip.DstAddr==162.159.128.233 or ip.DstAddr==66.254.114.41"`, "", 1)
	got := parseServiceConfig(out)

	if len(got.Addresses) != 0 {
		t.Errorf("expected no addresses, got %v", got.Addresses)
	}
	if got.Scope() != ScopeAll {
		t.Errorf("Scope() = %q, want all", got.Scope())
	}
}

// Rotation must be recovered in the order the engine cycles through, because
// that is the order a user needs to read it in.
func TestParseServiceConfigRotation(t *testing.T) {
	cmdline := `        BINARY_PATH_NAME   : "C:\app\winws2.exe" --wf-tcp-out=443 ` +
		`"--wf-raw-filter=ip.DstAddr==1.1.1.1 or ip.SrcAddr==1.1.1.1" ` +
		`--lua-desync=circular:fails=3 ` +
		`--lua-desync=fake:tcp_md5:strategy=1 ` +
		`--lua-desync=multisplit:pos=1:strategy=1 ` +
		`--lua-desync=multidisorder:pos=1:strategy=2 ` +
		`--lua-desync=fakedsplit:pos=2:tcp_md5:strategy=3`
	got := parseServiceConfig(cmdline)

	if !got.Rotating() {
		t.Error("circular in the command line means the service rotates")
	}
	if len(got.Profiles) != 1 {
		t.Fatalf("expected one profile, got %v", got.Profiles)
	}
	prof := got.Profiles[0]
	if len(prof.Strategies) != 3 {
		t.Fatalf("expected three rotation steps, got %v", prof.Strategies)
	}
	// Both stages of step 1 belong together: one strategy, two stages.
	if s := prof.Stages(); len(s) != 2 || s[0] != "fake:tcp_md5" || s[1] != "multisplit:pos=1" {
		t.Errorf("step 1 = %v, want both stages of the primary", s)
	}
	fb := prof.Fallbacks()
	if len(fb) != 2 {
		t.Fatalf("expected two fallbacks, got %v", fb)
	}
	if fb[0][0] != "multidisorder:pos=1" {
		t.Errorf("fallback 1 = %v", fb[0])
	}
	if fb[1][0] != "fakedsplit:pos=2:tcp_md5" {
		t.Errorf("fallback 2 = %v", fb[1])
	}

	// The tag must be stripped from the stage, or the reported strategy would
	// not be the one a user could paste back into `dpi test`.
	for _, stages := range prof.Strategies {
		for _, s := range stages {
			if strings.Contains(s, ":strategy=") {
				t.Errorf("strategy tag leaked into the stage: %q", s)
			}
		}
	}

	// A rotating filter names both directions; the address is still listed once.
	if len(got.Addresses) != 1 || got.Addresses[0] != "1.1.1.1" {
		t.Errorf("Addresses = %v, want the address once", got.Addresses)
	}
}

func TestParseServiceConfigHandlesMissingOrOddInput(t *testing.T) {
	t.Run("no binary path line", func(t *testing.T) {
		got := parseServiceConfig("SERVICE_NAME: x\n        TYPE : 10\n")
		if got.BinaryPath != "" || len(got.Profiles) != 0 {
			t.Errorf("expected an empty result, got %+v", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := parseServiceConfig(""); got.BinaryPath != "" {
			t.Errorf("expected an empty result, got %+v", got)
		}
	})

	// A command line with no desync arguments must report no profiles rather
	// than one empty profile, which would read as an installed strategy.
	t.Run("no desync arguments", func(t *testing.T) {
		got := parseServiceConfig(`        BINARY_PATH_NAME   : "x.exe" --wf-tcp-out=443`)
		if len(got.Profiles) != 0 {
			t.Errorf("expected no profiles, got %v", got.Profiles)
		}
	})

	// A malformed tag must not be silently dropped: better to report the stage
	// as untagged than to lose it from the listing entirely.
	t.Run("malformed strategy tag keeps the stage", func(t *testing.T) {
		got := parseServiceConfig(`        BINARY_PATH_NAME   : "x.exe" --lua-desync=multisplit:pos=1:strategy=abc`)
		if len(got.Profiles) != 1 || len(got.Profiles[0].Stages()) != 1 {
			t.Fatalf("stage was lost: %v", got.Profiles)
		}
		if got.Profiles[0].Stages()[0] != "multisplit:pos=1:strategy=abc" {
			t.Errorf("stage = %q", got.Profiles[0].Stages()[0])
		}
	})
}

// The quoted address filter is the argument this parser exists for: without
// quote awareness it would split at every space and lose all but one address.
func TestSplitArgs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"plain", `a b c`, []string{"a", "b", "c"}},
		{"quoted executable", `"C:\Program Files\x.exe" --flag`,
			[]string{`C:\Program Files\x.exe`, "--flag"}},
		{"quoted value with spaces", `x.exe "--filter=a or b" --next`,
			[]string{"x.exe", "--filter=a or b", "--next"}},
		{"escaped quotes are literal", `x.exe --v=\"q\"`,
			[]string{"x.exe", `--v="q"`}},
		{"collapses runs of spaces", `a    b`, []string{"a", "b"}},
		{"tabs separate too", "a\tb", []string{"a", "b"}},
		{"empty", ``, nil},
	}
	for _, c := range cases {
		got := splitArgs(c.in)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: splitArgs(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// IPv6 cannot be exercised on the wire here — no test link hands out a global
// IPv6 address — so the guarantee has to come from a round trip instead: every
// address this tool writes into a filter must read back as the same address.
//
// It matters because the two sides are compared. An address that is written but
// not parsed back shows up in CompareAddresses as permanently Missing, so
// doctor reports drift on every run and refresh reinstalls the same filter
// forever. A stricter pattern used to do exactly that for a trailing "::".
func TestFilterAddressesRoundTrip(t *testing.T) {
	addrs := []string{
		"162.159.128.233",
		"2606:4700::6810:85e5",               // ordinary, compressed
		"2606:4700::",                        // trailing run, a real network address
		"::1",                                // all-zero prefix
		"2a03:2880:f10c:83:face:b00c:0:25de", // no compression at all
		"fd00::1",                            // unique local
		"2001:db8:0:0:1:0:0:1",               // a form net.IP.String() will compress
	}

	p := testPlan()
	p.Profiles = []Profile{{Addrs: addrs}}
	arg := "--wf-raw-filter=" + p.addressFilter()

	got := filterAddresses(arg, map[string]struct{}{})

	// Compare in canonical form: the parser normalises, and so does anything
	// that produced these addresses in the first place.
	want := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		want[net.ParseIP(a).String()] = true
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("parsed an address that was never written: %q", g)
		}
		delete(want, g)
	}
	for missing := range want {
		t.Errorf("address written into the filter but not read back: %q", missing)
	}
}

// The parser must not invent addresses out of neighbouring text, or doctor
// would compare against things the filter never named.
func TestFilterAddressesRejectsNonAddresses(t *testing.T) {
	arg := `--wf-raw-filter=ipv6.DstAddr==not:an:address or ip.DstAddr==999.1.1.1 or ` +
		`ipv6.DstAddr==2606:4700::1 or tcp.SrcPort>=40000 and tcp.SrcPort<=40127`
	got := filterAddresses(arg, map[string]struct{}{})
	if len(got) != 1 || got[0] != "2606:4700::1" {
		t.Errorf("filterAddresses = %v, want only the one valid address", got)
	}
}

// A rotating IPv6 filter is the longest thing this tool can emit: every address
// appears twice and an IPv6 literal is far longer than a dotted quad. The limit
// has to be enforced against that shape, not against the IPv4 one.
func TestIPv6RotatingFilterStaysWithinTheLimit(t *testing.T) {
	var addrs []string
	for i := 0; i < 120; i++ {
		addrs = append(addrs, net.IP{
			0x2a, 0x03, 0x28, 0x80, 0xf1, 0x0c, 0x00, 0x83,
			0xfa, 0xce, 0xb0, 0x0c, byte(i >> 8), byte(i), 0x25, 0xde,
		}.String())
	}
	p := testPlan()
	p.Profiles = []Profile{{
		Stages:    []string{"multisplit:pos=1"},
		Fallbacks: [][]string{{"oob:urp=b"}},
		Addrs:     addrs,
	}}

	f := p.addressFilter()
	if n := strings.Count(f, "ipv6.DstAddr=="); n != len(addrs) {
		t.Errorf("destination terms = %d, want %d", n, len(addrs))
	}
	if n := strings.Count(f, "ipv6.SrcAddr=="); n != len(addrs) {
		t.Errorf("source terms = %d, want %d (rotation needs the replies)", n, len(addrs))
	}
	if strings.Contains(f, "ip.DstAddr==") {
		t.Error("an IPv6 address must never be emitted in the IPv4 namespace")
	}

	// Whatever the verdict, it must be a decision rather than a silent
	// oversized filter the engine refuses at start time.
	err := p.Validate()
	if len(f) > maxFilterBytes && !errors.Is(err, ErrFilterTooLarge) {
		t.Errorf("filter is %d bytes but Validate() = %v", len(f), err)
	}
	if len(f) <= maxFilterBytes && err != nil {
		t.Errorf("filter is %d bytes, within the limit, but Validate() = %v", len(f), err)
	}
	t.Logf("120 rotating IPv6 addresses = %d bytes of the %d limit", len(f), maxFilterBytes)
}
