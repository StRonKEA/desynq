package engine

import (
	"strings"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	cfg := Config{BinaryPath: "winws2.exe", LuaDir: "lua"}

	t.Run("pinned instance carries a destination filter", func(t *testing.T) {
		args := buildArgs(cfg, []string{"multidisorder:pos=midsld"}, Pin{Addr: "1.2.3.4"})
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--wf-raw-filter=ip.DstAddr==1.2.3.4") {
			t.Errorf("missing destination pin in %q", joined)
		}
		if !strings.Contains(joined, "--lua-desync=multidisorder:pos=midsld") {
			t.Errorf("missing strategy in %q", joined)
		}
	})

	// Without a pin the filter covers all of port 443, which is exactly the
	// case that makes a second concurrent instance impossible. Asserting the
	// absence keeps that distinction explicit.
	t.Run("unpinned instance carries no destination filter", func(t *testing.T) {
		args := buildArgs(cfg, []string{"multisplit:pos=1"}, Pin{})
		for _, a := range args {
			if strings.HasPrefix(a, "--wf-raw-filter") {
				t.Errorf("unexpected destination pin: %q", a)
			}
		}
	})

	// winws2 parses positionally: WinDivert-level filters must precede the Lua
	// initialisation, which must precede the profile that uses the libraries.
	t.Run("filters precede lua init which precedes the profile", func(t *testing.T) {
		args := buildArgs(cfg, []string{"fake:tcp_md5"}, Pin{Addr: "9.9.9.9"})
		idx := func(prefix string) int {
			for i, a := range args {
				if strings.HasPrefix(a, prefix) {
					return i
				}
			}
			return -1
		}
		wfRaw, luaInit, desync := idx("--wf-raw-filter"), idx("--lua-init"), idx("--lua-desync")
		if wfRaw < 0 || luaInit < 0 || desync < 0 {
			t.Fatalf("expected all three argument kinds, got %v", args)
		}
		if wfRaw >= luaInit || luaInit >= desync {
			t.Errorf("wrong order: wf-raw=%d lua-init=%d lua-desync=%d in %v", wfRaw, luaInit, desync, args)
		}
	})
}

// WinDivert keeps the address families in separate namespaces, so a term must
// name the one its address belongs to. Writing `ip.DstAddr` for an IPv6 address
// produces a filter that matches nothing — the packets pass the driver
// untouched while the engine looks healthy, which is the exact failure this
// helper exists to prevent.
func TestFilterAddressTerm(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"1.2.3.4", "ip.DstAddr==1.2.3.4"},
		{"162.159.128.233", "ip.DstAddr==162.159.128.233"},
		{"2606:4700::6810:85e5", "ipv6.DstAddr==2606:4700::6810:85e5"},
		{"2a03:2880:f10c:83:face:b00c:0:25de", "ipv6.DstAddr==2a03:2880:f10c:83:face:b00c:0:25de"},
		// Not an address at all: fall back to the IPv4 namespace rather than
		// inventing an IPv6 term, and let the engine reject it loudly.
		{"nonsense", "ip.DstAddr==nonsense"},
	}
	for _, c := range cases {
		if got := FilterAddressTerm("DstAddr", c.addr); got != c.want {
			t.Errorf("FilterAddressTerm(DstAddr, %q) = %q, want %q", c.addr, got, c.want)
		}
	}
	if got := FilterAddressTerm("SrcAddr", "2606:4700::1"); got != "ipv6.SrcAddr==2606:4700::1" {
		t.Errorf("SrcAddr direction not honoured: %q", got)
	}
}

// The L3 selection is passed explicitly because the engine's default is
// undocumented, and an IPv4-only kernel filter lets a v6-preferring browser
// walk around the strategy invisibly.
func TestBuildArgsSelectsBothAddressFamilies(t *testing.T) {
	args := buildArgs(Config{BinaryPath: "winws2.exe", LuaDir: "lua"},
		[]string{"multisplit:pos=1"}, Pin{Addr: "1.2.3.4"})
	found := false
	for _, a := range args {
		if a == L3Both {
			found = true
		}
	}
	if !found {
		t.Errorf("missing %s in %v", L3Both, args)
	}
}

func TestPinFilter(t *testing.T) {
	cases := []struct {
		name string
		pin  Pin
		want string
	}{
		{"address only", Pin{Addr: "1.2.3.4"}, "ip.DstAddr==1.2.3.4"},
		{"ipv6 address only", Pin{Addr: "2606:4700::1"}, "ipv6.DstAddr==2606:4700::1"},
		{"address and port window", Pin{Addr: "1.2.3.4", PortLo: 40000, PortHi: 40127},
			"ip.DstAddr==1.2.3.4 and tcp.SrcPort>=40000 and tcp.SrcPort<=40127"},
		{"port window alone", Pin{PortLo: 40000, PortHi: 40127},
			"tcp.SrcPort>=40000 and tcp.SrcPort<=40127"},
		{"zero pin filters nothing", Pin{}, ""},
		// A half-set window would produce a filter matching a single port or
		// none at all, so it is ignored rather than half-applied.
		{"incomplete window is ignored", Pin{Addr: "1.2.3.4", PortLo: 40000}, "ip.DstAddr==1.2.3.4"},
		{"inverted window is ignored", Pin{Addr: "1.2.3.4", PortLo: 500, PortHi: 400}, "ip.DstAddr==1.2.3.4"},
	}
	for _, c := range cases {
		if got := c.pin.Filter(); got != c.want {
			t.Errorf("%s: Filter() = %q, want %q", c.name, got, c.want)
		}
	}

	// --wf-raw-filter refuses parentheses, so every term must be a flat AND.
	f := Pin{Addr: "1.2.3.4", PortLo: 40000, PortHi: 40127}.Filter()
	if strings.ContainsAny(f, "()") {
		t.Errorf("filter must not contain parentheses: %q", f)
	}
	if strings.Contains(f, " or ") {
		t.Errorf("a pin only ever narrows, so it must not or-join: %q", f)
	}
}

// Lanes exist so several candidates can be screened against one address at
// once. That only works if their filters are disjoint: two engines that both
// match a packet would each desync it, producing a strategy neither of them
// describes and no error to show for it.
func TestLanesDoNotOverlap(t *testing.T) {
	seen := map[int]int{} // port -> lane that owns it

	for lane := 0; lane < MaxLanes; lane++ {
		lo, hi := LanePorts(lane)
		pin := Pin{Addr: "1.2.3.4", PortLo: lo, PortHi: hi}
		if !pin.HasPortWindow() {
			t.Fatalf("lane %d carries no port window, so it would overlap every other lane", lane)
		}
		for port := lo; port <= hi; port++ {
			if other, dup := seen[port]; dup {
				t.Fatalf("port %d claimed by lanes %d and %d", port, other, lane)
			}
			seen[port] = lane
		}
	}

	// Windows' default dynamic port range starts at 49152. A lane reaching into
	// it would fight the rest of the machine for ports, and a bind failure in
	// the middle of a measurement looks just like a censored connection.
	_, lastHi := LanePorts(MaxLanes - 1)
	if lastHi >= 49152 {
		t.Errorf("lane %d reaches into the ephemeral range: %d", MaxLanes-1, lastHi)
	}
	if MaxLanes < 8 {
		t.Errorf("MaxLanes = %d, too few for concurrent screening to be worth it", MaxLanes)
	}
}

// Stage order is semantic in zapret2: a fake packet must be emitted before the
// split it is meant to hide. Reordering the flags would change the strategy.
func TestBuildArgsPreservesStageOrder(t *testing.T) {
	cfg := Config{BinaryPath: "winws2.exe", LuaDir: "lua"}
	stages := []string{"fake:tcp_md5:repeats=6", "multidisorder:pos=midsld"}
	args := buildArgs(cfg, stages, Pin{Addr: "1.2.3.4"})

	var got []string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--lua-desync="); ok {
			got = append(got, v)
		}
	}
	if len(got) != len(stages) {
		t.Fatalf("expected %d desync flags, got %d: %v", len(stages), len(got), got)
	}
	for i := range stages {
		if got[i] != stages[i] {
			t.Errorf("stage %d = %q, want %q", i, got[i], stages[i])
		}
	}
}

func TestFormatStages(t *testing.T) {
	if got := FormatStages([]string{"a", "b"}); got != "a | b" {
		t.Errorf("FormatStages() = %q, want %q", got, "a | b")
	}
	if got := FormatStages(nil); got != "" {
		t.Errorf("FormatStages(nil) = %q, want empty", got)
	}
}

func TestLastLine(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"empty", nil, "no output"},
		{"only blanks", []string{"", "   ", ""}, "no output"},
		{"skips trailing blanks", []string{"first", "boom", "", "  "}, "boom"},
		{"single line", []string{"only"}, "only"},
	}
	for _, c := range cases {
		if got := lastLine(c.in); got != c.want {
			t.Errorf("%s: lastLine() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestConfigWithDefaults(t *testing.T) {
	got := Config{BinaryPath: "custom.exe"}.withDefaults()
	if got.BinaryPath != "custom.exe" {
		t.Errorf("explicit BinaryPath was overwritten: %q", got.BinaryPath)
	}
	if got.LuaDir == "" || got.ReadyTimeout == 0 {
		t.Errorf("unset fields were not filled: %+v", got)
	}
}
