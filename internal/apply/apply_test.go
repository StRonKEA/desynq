package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPlan() Plan {
	return Plan{
		Profiles: []Profile{{
			Stages: []string{"multidisorder:pos=1"},
			Hosts:  []string{"discord.com"},
			Addrs:  []string{"162.159.128.233"},
		}},
		BinaryPath: `C:\app\winws2.exe`,
		LuaDir:     `C:\app\lua`,
		ConfigDir:  `C:\app\config`,
	}
}

func desyncStages(args []string) []string {
	var out []string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--lua-desync="); ok {
			out = append(out, v)
		}
	}
	return out
}

func rawFilter(args []string) (string, bool) {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--wf-raw-filter="); ok {
			return v, true
		}
	}
	return "", false
}

// The installed command line must carry exactly the stages that were measured,
// in the same order, or the installation is not the thing that was verified.
func TestEngineArgsCarriesMeasuredStages(t *testing.T) {
	p := testPlan()
	p.Profiles[0].Stages = []string{"fake:blob=fake_default_tls:tcp_md5", "multisplit:pos=2"}

	got := desyncStages(p.EngineArgs())
	want := p.Profiles[0].Stages
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("installed stages = %v, want %v", got, want)
	}
}

// --out-range limits the engine to the first packets of a connection. It is a
// reasonable production setting but was never part of any measurement, so it
// must not appear in an installed command line.
func TestEngineArgsAddsNothingUnmeasured(t *testing.T) {
	for _, a := range testPlan().EngineArgs() {
		for _, banned := range []string{"--out-range", "--repeats"} {
			if strings.HasPrefix(a, banned) {
				t.Errorf("installed command line contains unmeasured option %q", a)
			}
		}
	}
}

// Narrowing the kernel filter is the whole point of ScopeTargeted: an
// all-of-port-443 filter routes every connection on the machine through the
// WinDivert driver, which anti-cheat systems can read as interference.
func TestScopeTargetedNarrowsTheKernelFilter(t *testing.T) {
	t.Run("targeted restricts to the plan addresses", func(t *testing.T) {
		p := testPlan()
		p.Scope = ScopeTargeted
		f, ok := rawFilter(p.EngineArgs())
		if !ok {
			t.Fatal("targeted scope must emit a raw filter")
		}
		if !strings.Contains(f, "ip.DstAddr==162.159.128.233") {
			t.Errorf("filter does not name the target address: %q", f)
		}
	})

	t.Run("targeted is the default", func(t *testing.T) {
		p := testPlan() // Scope left empty
		if _, ok := rawFilter(p.EngineArgs()); !ok {
			t.Error("an unset scope must default to targeted, not to capturing everything")
		}
	})

	t.Run("all captures everything and emits no address filter", func(t *testing.T) {
		p := testPlan()
		p.Scope = ScopeAll
		if f, ok := rawFilter(p.EngineArgs()); ok {
			t.Errorf("ScopeAll must not restrict addresses, got %q", f)
		}
	})

	// With no known addresses there is nothing to narrow to. Emitting an empty
	// filter would be a syntax error; falling back to the broad capture is the
	// only working behaviour, and it must not be silent about it.
	t.Run("targeted with no addresses emits no filter", func(t *testing.T) {
		p := testPlan()
		p.Profiles[0].Addrs = nil
		if f, ok := rawFilter(p.EngineArgs()); ok {
			t.Errorf("expected no filter when no addresses are known, got %q", f)
		}
	})
}

// Rotation is expressed as a `circular` orchestrator plus strategies tagged
// strategy=N. The engine raises an error unless N starts at 1 and increments
// without gaps, so the numbering is a hard contract rather than a convention.
func TestRotationArguments(t *testing.T) {
	p := testPlan()
	p.Profiles[0].Stages = []string{"fake:tcp_md5", "multisplit:pos=1"}
	p.Profiles[0].Fallbacks = [][]string{
		{"multidisorder:pos=1"},
		{"fakedsplit:pos=2:tcp_md5"},
	}
	args := p.EngineArgs()
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--lua-desync=circular:fails=") {
		t.Errorf("rotation needs the circular orchestrator: %s", joined)
	}

	// Both stages of the primary strategy must share strategy=1: they are one
	// rotation step, not two.
	for _, want := range []string{
		"--lua-desync=fake:tcp_md5:strategy=1",
		"--lua-desync=multisplit:pos=1:strategy=1",
		"--lua-desync=multidisorder:pos=1:strategy=2",
		"--lua-desync=fakedsplit:pos=2:tcp_md5:strategy=3",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}

	// Numbers must be 1..N with no gaps, in order.
	var nums []string
	for _, a := range args {
		if i := strings.LastIndex(a, ":strategy="); i >= 0 {
			nums = append(nums, a[i+len(":strategy="):])
		}
	}
	if got := strings.Join(nums, ","); got != "1,1,2,3" {
		t.Errorf("strategy numbering = %q, want %q", got, "1,1,2,3")
	}

	// The orchestration library has to be loaded, or `circular` is undefined.
	if !strings.Contains(joined, "zapret-auto.lua") {
		t.Errorf("rotation needs zapret-auto.lua loaded: %s", joined)
	}

	// Rotation counts inbound RSTs, which a destination-only filter hides.
	t.Run("filter covers both directions when rotating", func(t *testing.T) {
		f, ok := rawFilter(args)
		if !ok {
			t.Fatal("expected a raw filter")
		}
		if !strings.Contains(f, "ip.SrcAddr==162.159.128.233") {
			t.Errorf("rotation needs inbound packets; filter has no SrcAddr term: %q", f)
		}
	})

	// Without fallbacks nothing changes: no orchestrator, no tags, and the
	// filter stays half the size.
	t.Run("no fallbacks means no rotation machinery", func(t *testing.T) {
		q := testPlan()
		qa := strings.Join(q.EngineArgs(), " ")
		if strings.Contains(qa, "circular") || strings.Contains(qa, ":strategy=") {
			t.Errorf("unexpected rotation machinery: %s", qa)
		}
		if strings.Contains(qa, "zapret-auto.lua") {
			t.Errorf("orchestration library loaded without need: %s", qa)
		}
		if f, _ := rawFilter(q.EngineArgs()); strings.Contains(f, "SrcAddr") {
			t.Errorf("non-rotating plan should not capture inbound: %q", f)
		}
	})
}

// A targeted plan with no addresses produces no filter, which leaves
// --wf-tcp-out=443 standing alone and captures every connection on the machine
// — the opposite of what targeted scope promises, and exactly what anti-cheat
// software reacts to. Installing that silently is worse than refusing.
func TestValidateRejectsUnboundedTargetedScope(t *testing.T) {
	t.Run("no addresses is refused", func(t *testing.T) {
		p := testPlan()
		p.Profiles[0].Addrs = nil
		err := p.Validate()
		if !errors.Is(err, ErrScopeUnbounded) {
			t.Errorf("Validate() = %v, want ErrScopeUnbounded", err)
		}
	})

	// The same emptiness is fine when the caller asked for it explicitly.
	t.Run("all-traffic scope needs no addresses", func(t *testing.T) {
		p := testPlan()
		p.Profiles[0].Addrs = nil
		p.Scope = ScopeAll
		if err := p.Validate(); err != nil {
			t.Errorf("ScopeAll should validate without addresses, got %v", err)
		}
	})

	t.Run("a targeted plan with addresses passes", func(t *testing.T) {
		if err := testPlan().Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})

	t.Run("no profiles is refused", func(t *testing.T) {
		if err := (Plan{}).Validate(); err == nil {
			t.Error("a plan with no profiles must not validate")
		}
	})
}

// An oversized filter is refused by WinDivert, and the engine then fails to
// start for a reason the user cannot see. Catching it here names the cause.
func TestValidateRejectsOversizedFilter(t *testing.T) {
	p := testPlan()
	addrs := make([]string, 0, 1200)
	for i := range 1200 {
		addrs = append(addrs, fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256))
	}
	p.Profiles[0].Addrs = addrs

	err := p.Validate()
	if !errors.Is(err, ErrFilterTooLarge) {
		t.Fatalf("Validate() = %v, want ErrFilterTooLarge", err)
	}
	// The message has to say how far over it went, or the user cannot act on it.
	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("error should quote the size: %v", err)
	}
}

// winws2 rejects a --wf-raw-filter containing parentheses: the identical
// expression is accepted unparenthesised and refused parenthesised (measured
// 2026-09-04). That rules out OR-ing address ranges, so the filter must stay a
// flat list of equalities.
func TestAddressFilterHasNoParentheses(t *testing.T) {
	p := testPlan()
	p.Profiles = []Profile{
		{Addrs: []string{"1.1.1.1", "2.2.2.2"}},
		{Addrs: []string{"3.3.3.3"}},
	}
	f := p.addressFilter()
	if strings.ContainsAny(f, "()") {
		t.Errorf("filter must not contain parentheses: %q", f)
	}
	for _, want := range []string{"ip.DstAddr==1.1.1.1", "ip.DstAddr==2.2.2.2", "ip.DstAddr==3.3.3.3"} {
		if !strings.Contains(f, want) {
			t.Errorf("filter missing %q: %q", want, f)
		}
	}
	if strings.Count(f, " or ") != 2 {
		t.Errorf("three addresses need two or-joins: %q", f)
	}

	t.Run("addresses are deduplicated across profiles", func(t *testing.T) {
		q := testPlan()
		q.Profiles = []Profile{
			{Addrs: []string{"1.1.1.1"}},
			{Addrs: []string{"1.1.1.1"}},
		}
		if got := strings.Count(q.addressFilter(), "ip.DstAddr=="); got != 1 {
			t.Errorf("expected one address term, got %d: %q", got, q.addressFilter())
		}
	})
}

// A host's IPv6 addresses must land in the same flat filter, each in its own
// namespace. This is what stops a v6-preferring browser from walking around the
// strategy: the kernel filter would match none of its packets, the engine would
// see nothing, and every IPv4 check would still report success.
func TestAddressFilterCoversBothFamilies(t *testing.T) {
	p := testPlan()
	p.Profiles = []Profile{{Addrs: []string{
		"162.159.128.233",
		"2606:4700::6810:85e5",
		"2606:4700::6810:84e5",
	}}}

	f := p.addressFilter()
	for _, want := range []string{
		"ip.DstAddr==162.159.128.233",
		"ipv6.DstAddr==2606:4700::6810:85e5",
		"ipv6.DstAddr==2606:4700::6810:84e5",
	} {
		if !strings.Contains(f, want) {
			t.Errorf("filter missing %q: %q", want, f)
		}
	}
	// Mixing families must not require grouping, because parentheses are
	// refused outright.
	if strings.ContainsAny(f, "()") {
		t.Errorf("filter must not contain parentheses: %q", f)
	}
	// An IPv6 address must never appear under the IPv4 namespace: `ip.DstAddr`
	// is only ever followed by a dotted quad.
	if strings.Contains(f, "ip.DstAddr==2606") {
		t.Errorf("IPv6 address emitted in the IPv4 namespace: %q", f)
	}

	// Rotation needs replies, so each address gains its source form in the
	// matching namespace too.
	t.Run("rotating filter names both directions per family", func(t *testing.T) {
		q := testPlan()
		q.Profiles = []Profile{{
			Stages:    []string{"multisplit:pos=1"},
			Fallbacks: [][]string{{"oob:urp=b"}},
			Addrs:     []string{"1.1.1.1", "2606:4700::1"},
		}}
		f := q.addressFilter()
		for _, want := range []string{
			"ip.DstAddr==1.1.1.1", "ip.SrcAddr==1.1.1.1",
			"ipv6.DstAddr==2606:4700::1", "ipv6.SrcAddr==2606:4700::1",
		} {
			if !strings.Contains(f, want) {
				t.Errorf("rotating filter missing %q: %q", want, f)
			}
		}
	})
}

// The L3 selection must be explicit. Left to the engine's undocumented default,
// an IPv4-only kernel filter would make every IPv6 term in the address filter
// unreachable — and the install would still look correct.
func TestEngineArgsSelectsBothAddressFamilies(t *testing.T) {
	for _, scope := range []Scope{ScopeTargeted, ScopeAll} {
		p := testPlan()
		p.Scope = scope
		found := false
		for _, a := range p.EngineArgs() {
			if a == "--wf-l3=ipv4,ipv6" {
				found = true
			}
		}
		if !found {
			t.Errorf("scope %q: missing --wf-l3=ipv4,ipv6 in %v", scope, p.EngineArgs())
		}
	}
}

// Profiles must stay separated by --new. Without it every stage collapses into
// one profile and each host receives every strategy, which is exactly the
// mistake per-host profiles exist to avoid.
func TestMultipleProfilesAreSeparated(t *testing.T) {
	p := testPlan()
	p.Profiles = []Profile{
		{Stages: []string{"multisplit:pos=1"}, Hosts: []string{"a.example"}, Addrs: []string{"1.1.1.1"}},
		{Stages: []string{"fakedsplit:pos=2:tcp_md5"}, Hosts: []string{"b.example"}, Addrs: []string{"2.2.2.2"}},
	}
	args := p.EngineArgs()

	if n := countArg(args, "--new"); n != 1 {
		t.Errorf("two profiles need exactly one --new separator, got %d", n)
	}
	if n := countPrefix(args, "--hostlist="); n != 2 {
		t.Errorf("each profile needs its own host list, got %d", n)
	}
	if got := desyncStages(args); len(got) != 2 {
		t.Errorf("expected both profiles' stages, got %v", got)
	}

	// Each profile's host list must be a distinct file, or the second would
	// overwrite the first and both profiles would target the same hosts.
	if p.HostlistPath(0) == p.HostlistPath(1) {
		t.Errorf("profiles share a host list path: %q", p.HostlistPath(0))
	}

	t.Run("a single profile needs no separator", func(t *testing.T) {
		if n := countArg(testPlan().EngineArgs(), "--new"); n != 0 {
			t.Errorf("one profile must not emit --new, got %d", n)
		}
	})
}

func TestHostlistPath(t *testing.T) {
	p := testPlan()
	p.Profiles = append(p.Profiles, Profile{Stages: []string{"x"}}) // no hosts

	if p.HostlistPath(0) == "" {
		t.Error("a profile with hosts should have a path")
	}
	if got := p.HostlistPath(1); got != "" {
		t.Errorf("a profile with no hosts must have no path, got %q", got)
	}
	if got := p.HostlistPath(99); got != "" {
		t.Errorf("out-of-range index must be empty, got %q", got)
	}
}

func TestHostlistContent(t *testing.T) {
	// Repeated runs should produce an identical file, so the content is sorted
	// and deduplicated rather than written in argument order.
	got := HostlistContent([]string{"pornhub.com", "discord.com", "discord.com", "  ", "abc.com"})
	want := "abc.com\ndiscord.com\npornhub.com\n"
	if got != want {
		t.Errorf("HostlistContent() = %q, want %q", got, want)
	}
	if got := HostlistContent([]string{"", "   "}); got != "" {
		t.Errorf("expected empty content, got %q", got)
	}
	if got := HostlistContent(nil); got != "" {
		t.Errorf("expected empty content for nil, got %q", got)
	}
}

func TestWriteHostlists(t *testing.T) {
	dir := t.TempDir()
	p := testPlan()
	p.ConfigDir = dir
	p.Profiles = []Profile{
		{Stages: []string{"s1"}, Hosts: []string{"b.example", "a.example"}},
		{Stages: []string{"s2"}, Hosts: []string{"c.example"}},
		{Stages: []string{"s3"}}, // no hosts: no file
	}

	written, err := p.WriteHostlists()
	if err != nil {
		t.Fatalf("WriteHostlists: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("expected two files, got %v", written)
	}
	body, err := os.ReadFile(filepath.Join(dir, "hostlist-1.txt"))
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(body) != "a.example\nb.example\n" {
		t.Errorf("first host list = %q", string(body))
	}
}

func TestAllHostsAndAddrs(t *testing.T) {
	p := Plan{Profiles: []Profile{
		{Hosts: []string{"b.example", "a.example"}, Addrs: []string{"2.2.2.2"}},
		{Hosts: []string{"a.example"}, Addrs: []string{"1.1.1.1", "2.2.2.2"}},
	}}
	if got := strings.Join(p.AllHosts(), ","); got != "a.example,b.example" {
		t.Errorf("AllHosts() = %q", got)
	}
	if got := strings.Join(p.AllAddrs(), ","); got != "1.1.1.1,2.2.2.2" {
		t.Errorf("AllAddrs() = %q", got)
	}
}

// The executable is quoted because an install directory may contain spaces; a
// service whose binPath breaks on "Program Files" fails at boot, long after
// the user stopped watching.
func TestBinPathQuotesTheExecutable(t *testing.T) {
	p := testPlan()
	p.BinaryPath = `C:\Program Files\dpi\winws2.exe`
	got := p.binPathValue()
	if !strings.HasPrefix(got, `"C:\Program Files\dpi\winws2.exe"`) {
		t.Errorf("executable is not quoted: %q", got)
	}
}

// Regression guard for a bug that silently defeated targeted scope. The address
// filter contains spaces ("ip.DstAddr==A or ip.DstAddr==B"); left unquoted in
// the service command line, Windows split it at those spaces and the engine
// received only the first address. The service still installed and ran, so
// every target after the first was quietly outside the capture.
func TestBinPathQuotesSpacedArguments(t *testing.T) {
	p := testPlan()
	p.Profiles = []Profile{{
		Stages: []string{"multisplit:pos=1"},
		Hosts:  []string{"a.example", "b.example"},
		Addrs:  []string{"1.1.1.1", "2.2.2.2"},
	}}

	got := p.binPathValue()
	// The quotes wrap the whole argument, flag name included, which is what
	// makes Windows hand it to the engine as a single value.
	if !strings.Contains(got, `"--wf-raw-filter=ip.DstAddr==1.1.1.1 or ip.DstAddr==2.2.2.2"`) {
		t.Errorf("multi-address filter is not quoted as one argument:\n%s", got)
	}

	// Every space left in the command line must sit either between arguments or
	// inside quotes. Counting quote marks catches an unbalanced wrap.
	if strings.Count(got, `"`)%2 != 0 {
		t.Errorf("unbalanced quoting in %q", got)
	}

	t.Run("arguments without spaces stay bare", func(t *testing.T) {
		if !strings.Contains(got, "--wf-tcp-out=443 ") {
			t.Errorf("space-free argument should not be quoted: %s", got)
		}
	})
}

func TestServiceCommands(t *testing.T) {
	p := testPlan()
	install := p.InstallCommands()
	if len(install) == 0 {
		t.Fatal("no install commands")
	}
	// sc.exe requires the option name and its value as separate arguments.
	first := install[0]
	idx := -1
	for i, a := range first {
		if a == "binPath=" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("binPath= not passed as its own argument: %v", first)
	}
	if idx+1 >= len(first) || !strings.Contains(first[idx+1], "winws2.exe") {
		t.Errorf("binPath value does not follow its key: %v", first)
	}

	remove := p.RemoveCommands()
	if len(remove) != 2 || remove[1][1] != "delete" {
		t.Errorf("remove commands should stop then delete, got %v", remove)
	}
	if !strings.Contains(strings.Join(install[0], " "), DefaultServiceName) {
		t.Errorf("default service name missing from %v", install[0])
	}
}

// sc.exe reports a missing service as an error with code 1060 rather than as a
// state, so absence has to be recognised from the output instead of inferred
// from success. Getting this wrong would make Install refuse to run because it
// believes an absent service is present.
func TestParseState(t *testing.T) {
	cases := []struct {
		name string
		out  string
		err  error
		want State
	}{
		{"missing service reports 1060",
			"[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service.\n",
			errors.New("exit status 1060"), StateAbsent},
		{"running service",
			"SERVICE_NAME: dpi-bypass\n        STATE              : 4  RUNNING\n", nil, StateRunning},
		{"stopped service",
			"SERVICE_NAME: dpi-bypass\n        STATE              : 1  STOPPED\n", nil, StateStopped},
		// Windows keeps a deleted service visible until its process exits.
		// Calling that "unknown" reported a successful removal as a failure.
		{"stopping service is pending, not unknown",
			"SERVICE_NAME: dpi-bypass\n        STATE              : 3  STOP_PENDING\n", nil, StatePending},
		{"starting service is pending",
			"SERVICE_NAME: dpi-bypass\n        STATE              : 2  START_PENDING\n", nil, StatePending},
		{"unrecognised but successful output",
			"SERVICE_NAME: dpi-bypass\n        STATE              : 7  SOMETHING_NEW\n", nil, StateUnknown},
		{"error with no recognisable output is treated as absent",
			"", errors.New("exec failed"), StateAbsent},
	}
	for _, c := range cases {
		if got := parseState(c.out, c.err); got != c.want {
			t.Errorf("%s: parseState() = %q, want %q", c.name, got, c.want)
		}
	}
}

// The WinDivert driver is shared with any other bypass tool on the machine, so
// unloading it must never be folded into removing this service.
func TestDriverRemovalIsSeparate(t *testing.T) {
	for _, cmd := range testPlan().RemoveCommands() {
		if strings.Contains(strings.Join(cmd, " "), "windivert") {
			t.Errorf("service removal must not touch the shared driver: %v", cmd)
		}
	}
	if len(DriverRemoveCommands()) != 2 {
		t.Error("driver removal should stop then delete")
	}
}

// The binPath value must survive being pasted into a shell as ONE argument.
// An earlier version skipped wrapping it because it started with a quote, and
// sc.exe then read the engine's own arguments as arguments to sc: the service
// installed and started, but ran the engine with no strategy.
func TestFormatCommandWrapsBinPathAsOneArgument(t *testing.T) {
	binPath := `"C:\a b\winws2.exe" --wf-tcp-out=443 --lua-desync=multisplit:pos=1`
	got := FormatCommand([]string{"sc.exe", "create", "svc", "binPath=", binPath, "start=", "auto"})

	want := `binPath= "\"C:\a b\winws2.exe\" --wf-tcp-out=443 --lua-desync=multisplit:pos=1" start= auto`
	if !strings.Contains(got, want) {
		t.Errorf("binPath not wrapped as a single escaped argument.\n got: %s\nwant substring: %s", got, want)
	}
}

func TestQuoteArg(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"", `""`},
		{"--flag=value", "--flag=value"},
		{`C:\plain\x.exe`, `C:\plain\x.exe`},
		{`C:\Program Files\x.exe`, `"C:\Program Files\x.exe"`},
		{"has space", `"has space"`},
		{`say "hi"`, `"say \"hi\""`},
	}
	for _, c := range cases {
		if got := quoteArg(c.in); got != c.want {
			t.Errorf("quoteArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func countArg(args []string, want string) int {
	n := 0
	for _, a := range args {
		if a == want {
			n++
		}
	}
	return n
}

func countPrefix(args []string, prefix string) int {
	n := 0
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			n++
		}
	}
	return n
}
