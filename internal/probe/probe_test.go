package probe

import (
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// Attempts must step through the window instead of reusing one port: a socket
// that just closed sits in TIME_WAIT and cannot be bound again for minutes, so
// a fixed port would fail on the second attempt of every measurement.
func TestPortWindowCycles(t *testing.T) {
	w := PortWindow{Lo: 40000, Hi: 40002}

	got := []int{w.port(0), w.port(1), w.port(2), w.port(3)}
	want := []int{40000, 40001, 40002, 40000}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("port(%d) = %d, want %d", i, got[i], want[i])
		}
	}

	// The cursor is a wrapping counter, so a negative index must still land
	// inside the window rather than below it.
	if p := w.port(-1); p < w.Lo || p > w.Hi {
		t.Errorf("port(-1) = %d, outside the window", p)
	}

	t.Run("single port window", func(t *testing.T) {
		one := PortWindow{Lo: 40000, Hi: 40000}
		if p := one.port(7); p != 40000 {
			t.Errorf("port(7) = %d, want 40000", p)
		}
	})

	t.Run("zero detection", func(t *testing.T) {
		for _, w := range []PortWindow{{}, {Lo: 0, Hi: 100}, {Lo: 500, Hi: 400}, {Lo: -1, Hi: 10}} {
			if !w.IsZero() {
				t.Errorf("%+v should be treated as unset", w)
			}
		}
		if (PortWindow{Lo: 40000, Hi: 40000}).IsZero() {
			t.Error("a one-port window is set, not unset")
		}
	})
}

// The kernel filter is built from this, so it must carry every address of both
// families. An address it omits is a connection the strategy never touches.
func TestAllRealIPs(t *testing.T) {
	r := Result{
		RealIPs:  []string{"1.1.1.1", "2.2.2.2"},
		RealIPs6: []string{"2606:4700::1"},
	}
	if got := strings.Join(r.AllRealIPs(), ","); got != "1.1.1.1,2.2.2.2,2606:4700::1" {
		t.Errorf("AllRealIPs() = %q", got)
	}

	// Appending must not write into the caller's slice: RealIPs is also what
	// the search pins an engine instance to.
	if len(r.RealIPs) != 2 {
		t.Errorf("RealIPs was mutated: %v", r.RealIPs)
	}
	if got := (Result{}).AllRealIPs(); len(got) != 0 {
		t.Errorf("empty result should yield no addresses, got %v", got)
	}
}

func TestClassifyDNS(t *testing.T) {
	cases := []struct {
		name         string
		sysIPs       []string
		realIPs      []string
		dohFailed    bool
		dohNoRecords bool
		comparable   bool
		want         DNSStatus
	}{
		{"agreeing resolvers",
			[]string{"1.1.1.1"}, []string{"1.1.1.1"}, false, false, true, DNSOk},
		{"overlapping answer sets",
			[]string{"1.1.1.1", "2.2.2.2"}, []string{"2.2.2.2", "3.3.3.3"}, false, false, true, DNSOk},
		{"disjoint answers are only suspected, never convicted here",
			[]string{"195.175.254.2"}, []string{"162.159.136.232"}, false, false, true, DNSSuspect},
		{"system resolver withholds a name the encrypted one has",
			nil, []string{"1.1.1.1"}, false, false, true, DNSAbsent},
		{"nobody has it: dead domain, not censorship",
			nil, nil, false, true, true, DNSDead},
		{"encrypted resolver empty but system answers: do not accuse",
			[]string{"1.1.1.1"}, nil, false, true, true, DNSUnknown},
		{"no reference available: refuse to judge",
			[]string{"1.1.1.1"}, nil, true, false, true, DNSUnknown},
		// The system resolver is asked for IPv4 only, so an IPv6-only name
		// leaves it silent for a reason of our own making. Reporting DNSAbsent
		// would make NeedsEncryptedDNS treat it as forged, and the install path
		// would tell the user their resolver is lying about a name it was never
		// asked about.
		{"ipv6-only name was never comparable",
			nil, nil, false, false, false, DNSUnknown},
	}
	for _, c := range cases {
		got := classifyDNS(c.sysIPs, c.realIPs, c.dohFailed, c.dohNoRecords, c.comparable)
		if got != c.want {
			t.Errorf("%s: classifyDNS() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClassifyPath(t *testing.T) {
	cases := []struct {
		name string
		in   pathSignals
		want PathStatus
	}{
		{"no address to test", pathSignals{}, PathSkipped},
		{"clean handshake", pathSignals{tested: true, tcpOk: true, tlsOk: true}, PathOk},
		{"tcp never establishes", pathSignals{tested: true, tcpTimeout: true}, PathIPBlock},
		{"wrong identity outranks transport noise",
			pathSignals{tested: true, tcpOk: true, certBad: true, tlsReset: true}, PathCertBad},
		{"handshake killed by reset", pathSignals{tested: true, tcpOk: true, tlsReset: true}, PathReset},
		{"handshake silently dropped", pathSignals{tested: true, tcpOk: true, tlsTimeout: true}, PathTimeout},
		{"failed for no recognised reason", pathSignals{tested: true, tcpOk: true}, PathUnknown},
		// A fault on this machine must never be reported as the censor's work.
		// Without this the exhausted port window of a screening lane would look
		// exactly like an IP-level block, and a working strategy would be
		// scored as broken.
		{"local bind failure is not a network verdict",
			pathSignals{tested: true, localFail: true}, PathLocalFail},
		{"a local failure outranks the transport signals it produces",
			pathSignals{tested: true, localFail: true, tcpTimeout: true}, PathLocalFail},
	}
	for _, c := range cases {
		if got := classifyPath(c.in); got != c.want {
			t.Errorf("%s: classifyPath() = %q, want %q", c.name, got, c.want)
		}
	}

	// A local failure says nothing about the censor, so it must not send the
	// search off looking for a strategy to fix it.
	if (Result{Path: PathLocalFail}).DesyncApplies() {
		t.Error("PathLocalFail must not count as a desync case")
	}
}

// One address handed out for several unrelated names is the censor's signature.
// A single suspect name must stay suspect, because there is nothing to
// correlate it against and a guess would read as a finding.
func TestMarkSharedAddresses(t *testing.T) {
	t.Run("shared address convicts every name using it", func(t *testing.T) {
		in := []Result{
			{Domain: "discord.com", SysIPs: []string{"195.175.254.2"}, DNS: DNSSuspect},
			{Domain: "pornhub.com", SysIPs: []string{"195.175.254.2"}, DNS: DNSSuspect},
			{Domain: "google.com", SysIPs: []string{"172.217.20.78"}, DNS: DNSOk},
		}
		markSharedAddresses(in)
		if in[0].DNS != DNSHijacked || in[1].DNS != DNSHijacked {
			t.Errorf("names sharing a block page should be HIJACKED, got %q and %q", in[0].DNS, in[1].DNS)
		}
		if in[2].DNS != DNSOk {
			t.Errorf("an unrelated healthy name must be left alone, got %q", in[2].DNS)
		}
	})

	t.Run("a lone suspect stays suspect", func(t *testing.T) {
		in := []Result{{Domain: "discord.com", SysIPs: []string{"195.175.254.2"}, DNS: DNSSuspect}}
		markSharedAddresses(in)
		if in[0].DNS != DNSSuspect {
			t.Errorf("one observation cannot prove a hijack, got %q", in[0].DNS)
		}
	})

	// The rule is "one address for several *unrelated* names". Probing the same
	// name twice must not let it corroborate itself into a conviction.
	t.Run("the same name twice is still one observation", func(t *testing.T) {
		in := []Result{
			{Domain: "discord.com", SysIPs: []string{"195.175.254.2"}, DNS: DNSSuspect},
			{Domain: "discord.com", SysIPs: []string{"195.175.254.2"}, DNS: DNSSuspect},
		}
		markSharedAddresses(in)
		for _, r := range in {
			if r.DNS != DNSSuspect {
				t.Errorf("a repeated name must not prove a shared block page, got %q", r.DNS)
			}
		}
	})

	t.Run("distinct addresses stay suspect", func(t *testing.T) {
		in := []Result{
			{Domain: "a.example", SysIPs: []string{"10.0.0.1"}, DNS: DNSSuspect},
			{Domain: "b.example", SysIPs: []string{"10.0.0.2"}, DNS: DNSSuspect},
		}
		markSharedAddresses(in)
		for _, r := range in {
			if r.DNS != DNSSuspect {
				t.Errorf("%s: different addresses are not a shared block page, got %q", r.Domain, r.DNS)
			}
		}
	})

	t.Run("already-healthy names are never promoted", func(t *testing.T) {
		in := []Result{
			{Domain: "a.example", SysIPs: []string{"10.0.0.1"}, DNS: DNSOk},
			{Domain: "b.example", SysIPs: []string{"10.0.0.1"}, DNS: DNSOk},
		}
		markSharedAddresses(in)
		for _, r := range in {
			if r.DNS != DNSOk {
				t.Errorf("%s: a shared CDN address that matched DoH must stay OK, got %q", r.Domain, r.DNS)
			}
		}
	})
}

// Regression guard for a Windows trap that made every blocked domain report
// UNKNOWN instead of RESET: syscall.ECONNRESET is a POSIX-compatibility
// constant that never appears in a real Winsock error, and the error *text* is
// localised, so neither can be used for detection.
func TestIsResetUsesWinsockErrno(t *testing.T) {
	wrap := func(errno syscall.Errno) error {
		return &net.OpError{
			Op:  "read",
			Net: "tcp",
			Err: &os.SyscallError{Syscall: "wsarecv", Err: errno},
		}
	}
	if !isReset(wrap(syscall.WSAECONNRESET)) {
		t.Error("WSAECONNRESET must be detected as a reset")
	}
	if !isReset(wrap(syscall.WSAECONNABORTED)) {
		t.Error("WSAECONNABORTED must be detected as a reset")
	}
	// 10060 is WSAETIMEDOUT, which Go does not expose as a named constant on
	// Windows; the literal keeps the negative case honest.
	if isReset(wrap(syscall.Errno(10060))) {
		t.Error("a timeout errno must not be reported as a reset")
	}
	if syscall.ECONNRESET == syscall.WSAECONNRESET {
		t.Skip("platform aliases the two constants; the trap does not apply here")
	}
	if isReset(wrap(0)) {
		t.Error("a zero errno must not be reported as a reset")
	}
}

// A desync strategy can only address path-layer interference. Reporting a DNS
// hijack or an IP block as fixable would send the search after something it
// cannot possibly repair.
func TestDesyncApplies(t *testing.T) {
	applies := []PathStatus{PathReset, PathTimeout, PathUnknown}
	doesNot := []PathStatus{PathOk, PathIPBlock, PathCertBad, PathSkipped}
	for _, p := range applies {
		if !(Result{Path: p}).DesyncApplies() {
			t.Errorf("path %q should be a desync candidate", p)
		}
	}
	for _, p := range doesNot {
		if (Result{Path: p}).DesyncApplies() {
			t.Errorf("path %q must not be reported as a desync candidate", p)
		}
	}
}

func TestNeedsEncryptedDNS(t *testing.T) {
	needs := []DNSStatus{DNSHijacked, DNSAbsent}
	doesNot := []DNSStatus{DNSOk, DNSDead, DNSUnknown}
	for _, d := range needs {
		if !(Result{DNS: d}).NeedsEncryptedDNS() {
			t.Errorf("dns %q should call for encrypted DNS", d)
		}
	}
	for _, d := range doesNot {
		if (Result{DNS: d}).NeedsEncryptedDNS() {
			t.Errorf("dns %q must not call for encrypted DNS", d)
		}
	}
}

func TestSameNetwork(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		// The case that motivated this: one CDN, two edges, agreeing only at /16.
		{"CDN edges of the same operator",
			[]string{"192.178.194.136"}, []string{"192.178.24.174"}, true},
		{"a block page is nowhere near the real host",
			[]string{"195.175.254.2"}, []string{"162.159.128.233"}, false},
		{"adjacent addresses",
			[]string{"140.82.121.3"}, []string{"140.82.121.4"}, true},
		{"any pair matching is enough",
			[]string{"9.9.9.9", "192.178.1.1"}, []string{"192.178.250.250"}, true},
		{"no addresses", nil, []string{"1.1.1.1"}, false},
		{"garbage is ignored rather than matched",
			[]string{"not-an-ip"}, []string{"1.1.1.1"}, false},
	}
	for _, c := range cases {
		if got := sameNetwork(c.a, c.b); got != c.want {
			t.Errorf("%s: sameNetwork(%v, %v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}

// The CDN allowance must only soften an unproven suspicion. If the aggregate
// already convicted a name, a coincidental network match must not clear it.
func TestRelaxCDNRotationCannotOverturnEvidence(t *testing.T) {
	t.Run("suspect in the same network is cleared", func(t *testing.T) {
		in := []Result{{
			Domain:  "youtube.com",
			SysIPs:  []string{"192.178.194.136"},
			RealIPs: []string{"192.178.24.174"},
			DNS:     DNSSuspect,
		}}
		relaxCDNRotation(in)
		if in[0].DNS != DNSOk {
			t.Errorf("CDN rotation should clear the suspicion, got %q", in[0].DNS)
		}
	})

	t.Run("already hijacked stays hijacked", func(t *testing.T) {
		in := []Result{{
			Domain:  "blocked.example",
			SysIPs:  []string{"10.1.2.3"},
			RealIPs: []string{"10.1.9.9"}, // same /16 by coincidence
			DNS:     DNSHijacked,
		}}
		relaxCDNRotation(in)
		if in[0].DNS != DNSHijacked {
			t.Errorf("proven hijack must not be relaxed, got %q", in[0].DNS)
		}
	})

	t.Run("suspect in a different network stays suspect", func(t *testing.T) {
		in := []Result{{
			Domain:  "x.example",
			SysIPs:  []string{"195.175.254.2"},
			RealIPs: []string{"162.159.128.233"},
			DNS:     DNSSuspect,
		}}
		relaxCDNRotation(in)
		if in[0].DNS != DNSSuspect {
			t.Errorf("unrelated networks must stay suspect, got %q", in[0].DNS)
		}
	})
}

func TestOverlaps(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"1.1.1.1"}, []string{"1.1.1.1"}, true},
		{[]string{"1.1.1.1", "2.2.2.2"}, []string{"2.2.2.2", "3.3.3.3"}, true},
		{[]string{"1.1.1.1"}, []string{"9.9.9.9"}, false},
		{nil, []string{"1.1.1.1"}, false},
		{[]string{"1.1.1.1"}, nil, false},
		{nil, nil, false},
	}
	for _, c := range cases {
		if got := overlaps(c.a, c.b); got != c.want {
			t.Errorf("overlaps(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
