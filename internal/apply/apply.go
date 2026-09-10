// Package apply turns chosen strategies into a configuration that outlives the
// search: host lists, an engine command line, and the service commands that
// install or remove it.
//
// Two deliberate constraints run through this package.
//
// The command line it installs must apply the same desync stages, to the same
// payload, that the measurement used. The engine's own presets add options such
// as --out-range=-d10 to limit work to the first few packets, and that is a
// sound production setting — but it changes engine behaviour, so adopting it
// here would install something that was never measured.
//
// And by default the kernel filter is narrowed to the addresses of the hosts
// being unblocked. A filter of "all TCP 443" makes every connection on the
// machine pass through the WinDivert driver, which anti-cheat systems can and
// do treat as hostile interference. Narrowing it means game traffic never
// reaches the driver at all.
package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"dpi/internal/engine"
)

// DefaultServiceName is the Windows service the plan installs under.
const DefaultServiceName = "desynq-dpi"

// Scope decides how much traffic the kernel-level filter captures.
type Scope string

const (
	// ScopeTargeted captures only traffic to the resolved addresses of the
	// configured hosts. Anything else — games, voice, every other site — never
	// enters the driver. This is the default for that reason.
	ScopeTargeted Scope = "targeted"

	// ScopeAll captures every outbound TLS connection on port 443. It keeps
	// working when a host's addresses change, at the cost of routing all of the
	// machine's traffic through the driver.
	ScopeAll Scope = "all"
)

// Profile is one strategy applied to one set of hosts. Several profiles can
// coexist, which is what allows different names to need different strategies.
type Profile struct {
	// Stages are the winws2 desync stages of the primary strategy, in order.
	Stages []string
	// Fallbacks are alternative strategies, best first, that the engine rotates
	// to when the primary stops working. Empty means no rotation.
	Fallbacks [][]string
	// Hosts are the names this profile applies to. Empty means the profile
	// applies to any name the filter lets through.
	Hosts []string
	// Addrs are the resolved addresses of Hosts, used to build the kernel
	// filter under ScopeTargeted.
	Addrs []string
}

// strategies returns the primary strategy followed by its fallbacks.
func (p Profile) strategies() [][]string {
	out := make([][]string, 0, 1+len(p.Fallbacks))
	if len(p.Stages) > 0 {
		out = append(out, p.Stages)
	}
	out = append(out, p.Fallbacks...)
	return out
}

// rotates reports whether this profile has anything to rotate to.
func (p Profile) rotates() bool { return len(p.Fallbacks) > 0 }

// Plan is everything needed to make a set of strategies permanent.
type Plan struct {
	Profiles    []Profile
	Scope       Scope
	BinaryPath  string
	LuaDir      string
	ConfigDir   string
	ServiceName string
	BlockQUIC   bool
}

func (p Plan) withDefaults() Plan {
	if p.ServiceName == "" {
		p.ServiceName = DefaultServiceName
	}
	if p.Scope == "" {
		p.Scope = ScopeTargeted
	}
	return p
}

// AllHosts returns every host across all profiles, sorted and deduplicated.
func (p Plan) AllHosts() []string {
	return dedupeSorted(func(yield func(string)) {
		for _, prof := range p.Profiles {
			for _, h := range prof.Hosts {
				yield(h)
			}
		}
	})
}

// AllAddrs returns every address across all profiles, sorted and deduplicated.
func (p Plan) AllAddrs() []string {
	return dedupeSorted(func(yield func(string)) {
		for _, prof := range p.Profiles {
			for _, a := range prof.Addrs {
				yield(a)
			}
		}
	})
}

// HostlistPath is the file profile i reads its host names from. Profiles
// without hosts have no file.
func (p Plan) HostlistPath(i int) string {
	if i < 0 || i >= len(p.Profiles) || len(p.Profiles[i].Hosts) == 0 {
		return ""
	}
	return filepath.Join(p.ConfigDir, fmt.Sprintf("hostlist-%d.txt", i+1))
}

// maxFilterBytes is the WinDivert filter size limit winws2 documents. A filter
// beyond it is refused, and the engine then fails to start for a reason the
// user cannot see, so the plan is rejected before installation instead.
const maxFilterBytes = 16 * 1024

// ErrScopeUnbounded means a targeted plan has no addresses to target, which
// would silently widen the capture to every TLS connection on the machine.
var ErrScopeUnbounded = errors.New("apply: targeted scope has no addresses to restrict to")

// ErrFilterTooLarge means the address filter exceeds what WinDivert accepts.
var ErrFilterTooLarge = errors.New("apply: address filter exceeds the WinDivert size limit")

// Validate rejects plans that would not do what they claim.
//
// The unbounded-scope case is the important one. With no addresses the filter
// is omitted, `--wf-tcp-out=443` stands alone, and every connection on the
// machine passes through the kernel driver — the opposite of what a targeted
// scope promises, and exactly the situation anti-cheat software reacts to.
// Failing here is better than installing a service that quietly does the
// broadest possible thing; a caller that genuinely wants everything captured
// says so with ScopeAll.
func (p Plan) Validate() error {
	p = p.withDefaults()
	if len(p.Profiles) == 0 {
		return errors.New("apply: no profiles")
	}
	if p.Scope == ScopeTargeted {
		if len(p.AllAddrs()) == 0 {
			return ErrScopeUnbounded
		}
		if n := len(p.addressFilter()); n > maxFilterBytes {
			return fmt.Errorf("%w: %d bytes for %d addresses", ErrFilterTooLarge, n, len(p.AllAddrs()))
		}
	}
	return nil
}

// addressFilter builds the kernel-level restriction to the plan's addresses.
//
// Exact equalities joined by "or", with no parentheses: winws2 rejects a
// --wf-raw-filter that contains them (measured — the identical expression is
// accepted unparenthesised and refused parenthesised), which also rules out
// OR-ing together address ranges. Exact addresses are the form that works, and
// the 16 KB filter limit leaves room for hundreds of them.
// Rotation needs the replies too: the failure detector counts inbound RSTs and
// HTTP redirects, and on an inbound packet the destination is the local address,
// so a destination-only filter never shows them to the engine. Pairing each
// address with its source form captures both directions while keeping the scope
// to the targets — at the cost of doubling the filter length.
//
// Both address families go into the same flat list. engine.FilterAddressTerm
// picks the namespace per address, and a term of the wrong family is false for
// the packet, so no grouping is needed — which is fortunate, given parentheses
// are refused.
func (p Plan) addressFilter() string {
	addrs := p.AllAddrs()
	if len(addrs) == 0 {
		return ""
	}
	bothDirections := p.rotates()
	parts := make([]string, 0, len(addrs)*2)
	for _, a := range addrs {
		parts = append(parts, engine.FilterAddressTerm("DstAddr", a))
		if bothDirections {
			parts = append(parts, engine.FilterAddressTerm("SrcAddr", a))
		}
	}
	return strings.Join(parts, " or ")
}

// rotates reports whether any profile has fallbacks to rotate to.
func (p Plan) rotates() bool {
	for _, prof := range p.Profiles {
		if prof.rotates() {
			return true
		}
	}
	return false
}

// EngineArgs is the winws2 command line this plan installs.
func (p Plan) EngineArgs() []string {
	p = p.withDefaults()
	// Both families are selected explicitly. Under a targeted scope the address
	// filter still decides what is captured, so this only makes the IPv6 terms
	// in it reachable; under ScopeAll it is what makes "all traffic" true rather
	// than "all IPv4 traffic".
	args := []string{"--wf-tcp-out=443"}
	if p.BlockQUIC {
		args = append(args, "--wf-udp-out=443")
	}
	args = append(args, engine.L3Both)

	if p.Scope == ScopeTargeted {
		if f := p.addressFilter(); f != "" {
			args = append(args, "--wf-raw-filter="+f)
		}
	}

	args = append(args,
		"--lua-init=@"+filepath.Join(p.LuaDir, "zapret-lib.lua"),
		"--lua-init=@"+filepath.Join(p.LuaDir, "zapret-antidpi.lua"),
	)

	// Rotation state lives per host inside the engine, which needs the
	// orchestration library loaded alongside the technique library.
	if p.rotates() {
		args = append(args, "--lua-init=@"+filepath.Join(p.LuaDir, "zapret-auto.lua"))
	}

	for i, prof := range p.Profiles {
		if i > 0 {
			// --new starts the next profile; without it the stages would pile
			// into one profile and every host would get every strategy.
			args = append(args, "--new")
		}
		args = append(args, "--filter-tcp=443", "--filter-l7=tls")
		if p.Scope != ScopeAll {
			if hl := p.HostlistPath(i); hl != "" {
				args = append(args, "--hostlist="+hl)
			}
		}
		args = append(args, "--payload=tls_client_hello")
		args = append(args, profileDesyncArgs(prof)...)
	}

	if p.BlockQUIC {
		args = append(args,
			"--new",
			"--filter-udp=443",
			"--filter-l7=quic",
			"--payload=quic_initial",
			"--lua-desync=drop",
		)
	}
	return args
}

// rotateFails is how many failures a host tolerates before the engine moves to
// the next strategy. The engine's own default is 3; it is spelled out here so
// the installed command line documents its own behaviour.
const rotateFails = 3

// profileDesyncArgs renders one profile's strategies as --lua-desync arguments.
//
// Without fallbacks this is just the stages. With fallbacks it becomes a
// `circular` orchestrator followed by every strategy tagged `strategy=N`:
// numbering starts at 1 and must increment without gaps or the engine errors
// out, and several stages may share one N, which is how a multi-stage strategy
// stays one rotation step.
//
// No stage carries `final`, so the rotation wraps around indefinitely. That is
// deliberate: if every strategy has stopped working, cycling through them again
// is better than settling on one that is known to fail.
func profileDesyncArgs(prof Profile) []string {
	if !prof.rotates() {
		args := make([]string, 0, len(prof.Stages))
		for _, s := range prof.Stages {
			args = append(args, "--lua-desync="+s)
		}
		return args
	}

	strategies := prof.strategies()
	args := make([]string, 0, 1+len(strategies)*2)
	args = append(args, fmt.Sprintf("--lua-desync=circular:fails=%d", rotateFails))
	for n, stages := range strategies {
		for _, s := range stages {
			args = append(args, fmt.Sprintf("--lua-desync=%s:strategy=%d", s, n+1))
		}
	}
	return args
}

// binPathValue is the executable plus arguments that sc.exe stores as the
// service's command line.
//
// Every part that contains a space is quoted, not just the executable path.
// The address filter is the reason: it reads
// "ip.DstAddr==A or ip.DstAddr==B", and an unquoted one is split on those
// spaces when Windows starts the service, so the engine receives only the
// first address and every other target silently falls outside the capture.
// That defeats the whole point of a targeted scope while still looking
// installed and running.
func (p Plan) binPathValue() string {
	// The executable is quoted unconditionally: an install directory can gain a
	// space at any time, and a service whose binPath breaks at boot fails long
	// after anyone is watching.
	parts := []string{`"` + p.BinaryPath + `"`}
	for _, a := range p.EngineArgs() {
		parts = append(parts, quoteIfSpaced(a))
	}
	return strings.Join(parts, " ")
}

// quoteIfSpaced wraps a service command-line component in quotes when it
// contains whitespace, so Windows does not split it into separate arguments.
func quoteIfSpaced(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t") {
		return s
	}
	return `"` + s + `"`
}

// InstallCommands returns the commands that install and start the service, in
// order, as argv slices ready for exec.
//
// sc.exe expects its options as "key=" and value in separate arguments, with
// the trailing space after the key being significant.
func (p Plan) InstallCommands() [][]string {
	p = p.withDefaults()
	return [][]string{
		{"sc.exe", "create", p.ServiceName,
			"binPath=", p.binPathValue(),
			"DisplayName=", "Desynq DPI",
			"start=", "auto"},
		{"sc.exe", "description", p.ServiceName, "Desynq DPI Bypass Service"},
		{"sc.exe", "start", p.ServiceName},
	}
}

// RemoveCommands returns the commands that stop and delete the service. They
// are printed before any install happens, so that the way back is known before
// the way in is taken.
func (p Plan) RemoveCommands() [][]string {
	p = p.withDefaults()
	return [][]string{
		{"sc.exe", "stop", p.ServiceName},
		{"sc.exe", "delete", p.ServiceName},
	}
}

// State is what the service control manager reports about the service.
type State string

const (
	StateAbsent  State = "absent"
	StateRunning State = "running"
	StateStopped State = "stopped"
	StatePending State = "pending"
	StateUnknown State = "unknown"
)

// ErrAlreadyInstalled means a service of this name exists. Overwriting it
// silently could replace a configuration the user still relies on, and a failed
// bypass service takes the network with it.
var ErrAlreadyInstalled = errors.New("apply: service already installed")

// parseState reads `sc query` output. Exit code 1060 means the service does not
// exist, which sc reports as an error rather than as a state.
//
// The *_PENDING states matter: Windows keeps a service visible while it is
// still shutting down, so a query taken straight after a delete sees a dying
// service rather than an absent one.
func parseState(out string, queryErr error) State {
	if strings.Contains(out, "1060") || strings.Contains(strings.ToUpper(out), "DOES NOT EXIST") {
		return StateAbsent
	}
	switch {
	case strings.Contains(out, "STOP_PENDING"), strings.Contains(out, "START_PENDING"):
		return StatePending
	case strings.Contains(out, "RUNNING"):
		return StateRunning
	case strings.Contains(out, "STOPPED"):
		return StateStopped
	}
	if queryErr != nil {
		return StateAbsent
	}
	return StateUnknown
}

// settleTimeout bounds how long a state is allowed to keep changing before it
// is reported as-is.
const settleTimeout = 5 * time.Second

// waitFor polls until the service reaches want, or until settleTimeout.
//
// This exists because `sc delete` does not delete: while any handle to the
// service is open — including the engine process still exiting — Windows only
// marks it for deletion. Reporting the state at that instant tells the user
// "unknown" for a removal that is in fact about to succeed.
func waitFor(ctx context.Context, serviceName string, want State) State {
	deadline := time.Now().Add(settleTimeout)
	for {
		state := Status(ctx, serviceName)
		if state == want {
			return state
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return state
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return state
		}
	}
}

// Status reports the current state of the named service.
func Status(ctx context.Context, serviceName string) State {
	if serviceName == "" {
		serviceName = DefaultServiceName
	}
	out, err := runCombined(ctx, "sc.exe", "query", serviceName)
	return parseState(string(out), err)
}

// Install writes the host lists and registers the service, then reports the
// resulting state. It refuses to overwrite an existing service.
func (p Plan) Install(ctx context.Context) (State, error) {
	p = p.withDefaults()
	if err := p.Validate(); err != nil {
		return StateAbsent, err
	}
	if s := Status(ctx, p.ServiceName); s != StateAbsent {
		return s, fmt.Errorf("%w: %q is %s", ErrAlreadyInstalled, p.ServiceName, s)
	}
	if _, err := p.WriteHostlists(); err != nil {
		return StateAbsent, err
	}
	for _, argv := range p.InstallCommands() {
		out, err := runArgv(ctx, argv)
		if err != nil {
			// Leave nothing half-registered behind: a service that exists but
			// never started is worse than no service, because the next install
			// then refuses to run.
			_, _ = p.Remove(ctx)
			return StateAbsent, fmt.Errorf("apply: %s failed: %w: %s",
				FormatCommand(argv), err, strings.TrimSpace(string(out)))
		}
	}
	return waitFor(ctx, p.ServiceName, StateRunning), nil
}

// Remove stops and deletes the service. A stop failure is ignored because a
// service that is already stopped reports one, and the goal is the end state.
func (p Plan) Remove(ctx context.Context) (State, error) {
	p = p.withDefaults()
	cmds := p.RemoveCommands()
	_, _ = runArgv(ctx, cmds[0])

	del := cmds[1]
	out, err := runArgv(ctx, del)
	state := waitFor(ctx, p.ServiceName, StateAbsent)
	if err != nil && state != StateAbsent {
		return state, fmt.Errorf("apply: %s failed: %w: %s",
			FormatCommand(del), err, strings.TrimSpace(string(out)))
	}
	return state, nil
}

// DriverRemoveCommands returns the commands that unload the WinDivert kernel
// driver. They are separate from Remove because the driver is shared: another
// bypass tool on the same machine may still be using it, and unloading it
// would break that tool rather than this one.
func DriverRemoveCommands() [][]string {
	return [][]string{
		{"sc.exe", "stop", "windivert"},
		{"sc.exe", "delete", "windivert"},
	}
}

// WriteHostlists writes one host list per profile and returns the paths written.
func (p Plan) WriteHostlists() ([]string, error) {
	var written []string
	for i := range p.Profiles {
		path := p.HostlistPath(i)
		if path == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return written, fmt.Errorf("apply: create config dir: %w", err)
		}
		if err := os.WriteFile(path, []byte(HostlistContent(p.Profiles[i].Hosts)), 0o644); err != nil {
			return written, fmt.Errorf("apply: write host list: %w", err)
		}
		written = append(written, path)
	}
	return written, nil
}

// HostlistContent is the file body: one name per line, sorted and deduplicated
// so that repeated runs produce an identical file.
func HostlistContent(hosts []string) string {
	uniq := dedupeSorted(func(yield func(string)) {
		for _, h := range hosts {
			yield(h)
		}
	})
	if len(uniq) == 0 {
		return ""
	}
	return strings.Join(uniq, "\n") + "\n"
}

func dedupeSorted(each func(yield func(string))) []string {
	seen := map[string]struct{}{}
	var out []string
	each(func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	})
	sort.Strings(out)
	return out
}

// FormatCommand renders an argv slice the way a user would type it, so that a
// printed command can be copied into a terminal verbatim.
func FormatCommand(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

// quoteArg wraps an argument for cmd.exe.
//
// The binPath value is the case that matters: it is a single argument that
// itself contains a quoted executable path followed by that executable's own
// arguments. It must be wrapped as a whole with its inner quotes escaped —
// leaving it unwrapped because it merely *starts* with a quote makes sc.exe
// treat the engine's arguments as arguments to sc itself, and the service is
// then installed to run the engine with no strategy at all.
func quoteArg(a string) string {
	if a == "" {
		return `""`
	}
	if !strings.ContainsAny(a, " \t\"") {
		return a
	}
	return `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
}
