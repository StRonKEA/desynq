package apply

import (
	"context"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// InstalledProfile is one strategy paired with the hosts it applies to, as
// recovered from an installed service.
//
// Profiles are what `--new` separates on the engine command line, and each one
// carries its own host list. Reading them back flattened would merge the stages
// of unrelated profiles into a single strategy that was never installed.
type InstalledProfile struct {
	// Strategies are the rotation steps, primary first. A profile that does not
	// rotate has exactly one, holding its stages.
	Strategies [][]string
	// Hostlist is the file this profile reads its names from. Empty means the
	// profile applies to every name the kernel filter lets through.
	Hostlist string
	// Rotating is true when the circular orchestrator drives this profile.
	Rotating bool
}

// Stages are the stages of the strategy currently in force.
func (p InstalledProfile) Stages() []string {
	if len(p.Strategies) == 0 {
		return nil
	}
	return p.Strategies[0]
}

// Fallbacks are the strategies the engine rotates to after the primary.
func (p InstalledProfile) Fallbacks() [][]string {
	if len(p.Strategies) < 2 {
		return nil
	}
	return p.Strategies[1:]
}

// Installed is what an installed service is configured to do, recovered from
// the service control manager.
//
// It is read back from the SCM rather than from our own config files on
// purpose: the config directory may have been edited since, the service may
// predate the current binary, or it may have been installed by hand. The only
// thing that describes what the machine will actually run is the command line
// the SCM holds.
type Installed struct {
	State State
	// BinaryPath is the engine the service runs.
	BinaryPath string
	// LuaDir is where the service loads the zapret2 libraries from. Recovered
	// rather than assumed, so that rebuilding a plan from an installed service
	// keeps pointing at the same files.
	LuaDir string
	// Profiles are the strategy/host pairs, in command-line order.
	Profiles []InstalledProfile
	// Addresses are the destinations the kernel filter is limited to.
	Addresses []string
}

// Scope reports what the installed filter captures. No addresses means the
// filter did not restrict anything, so every TLS connection on the machine
// passes through the driver.
func (i Installed) Scope() Scope {
	if len(i.Addresses) == 0 {
		return ScopeAll
	}
	return ScopeTargeted
}

// Rotating reports whether any profile switches strategy by itself on repeated
// failure.
func (i Installed) Rotating() bool {
	for _, p := range i.Profiles {
		if p.Rotating {
			return true
		}
	}
	return false
}

// Hostlists returns the host list files the profiles read, in order.
func (i Installed) Hostlists() []string {
	var out []string
	for _, p := range i.Profiles {
		if p.Hostlist != "" {
			out = append(out, p.Hostlist)
		}
	}
	return out
}

// inspectBufferSize is passed to `sc qc`, whose default buffer truncates long
// command lines. Ours is long — an address filter alone can run to hundreds of
// bytes, and a rotating one doubles it — and a truncated read would look like
// a service configured with fewer addresses than it really has.
const inspectBufferSize = 8192

// Inspect reads and parses the configuration of an installed service.
func Inspect(ctx context.Context, serviceName string) Installed {
	if serviceName == "" {
		serviceName = DefaultServiceName
	}
	state := Status(ctx, serviceName)
	if state == StateAbsent {
		return Installed{State: state}
	}
	out, err := runCombined(ctx, "sc.exe", "qc", serviceName,
		strconv.Itoa(inspectBufferSize))
	if err != nil {
		// The service exists but its configuration could not be read; report
		// the state without pretending to know the rest.
		return Installed{State: state}
	}
	inst := parseServiceConfig(string(out))
	inst.State = state
	return inst
}

// Filter address terms, one pattern per family. `ip\.` does not match
// "ipv6.DstAddr", so the two cannot capture each other's addresses.
var addrInFilter = []*regexp.Regexp{
	regexp.MustCompile(`ip\.(?:Dst|Src)Addr==(\d{1,3}(?:\.\d{1,3}){3})`),
	// Deliberately permissive: anything that could be an address literal is
	// captured and then validated by net.ParseIP below. A stricter pattern
	// missed a trailing "::" (a real form, e.g. 2606:4700::), and an address
	// this tool had written but could not read back would show up as permanent
	// drift — doctor would report it missing on every run and refresh would
	// reinstall it forever.
	regexp.MustCompile(`ipv6\.(?:Dst|Src)Addr==([0-9A-Fa-f:.]+)`),
}

// filterAddresses extracts the addresses a --wf-raw-filter argument names.
//
// Every address is normalised through net.IP before being reported, so that a
// hand-written or differently-formatted IPv6 literal (uppercase hex, a zero run
// spelled out) compares equal to the same address as this tool would write it.
// Without that, doctor would report drift where none exists.
func filterAddresses(arg string, seen map[string]struct{}) []string {
	var out []string
	for _, re := range addrInFilter {
		for _, m := range re.FindAllStringSubmatch(arg, -1) {
			ip := net.ParseIP(m[1])
			if ip == nil {
				continue
			}
			norm := ip.String()
			if _, dup := seen[norm]; dup {
				continue
			}
			seen[norm] = struct{}{}
			out = append(out, norm)
		}
	}
	return out
}

// profileBuild accumulates one profile's arguments while parsing.
type profileBuild struct {
	hostlist string
	rotating bool
	untagged []string
	byStep   map[int][]string
}

func (b *profileBuild) addStep(n int, stage string) {
	if b.byStep == nil {
		b.byStep = map[int][]string{}
	}
	b.byStep[n] = append(b.byStep[n], stage)
}

func (b *profileBuild) empty() bool {
	return b.hostlist == "" && len(b.untagged) == 0 && len(b.byStep) == 0
}

func (b *profileBuild) build() InstalledProfile {
	p := InstalledProfile{Hostlist: b.hostlist, Rotating: b.rotating}
	if len(b.untagged) > 0 {
		p.Strategies = append(p.Strategies, b.untagged)
	}
	// Rotation numbering is 1..N without gaps, so ascending step order is the
	// order the engine rotates through.
	for i := 1; i <= len(b.byStep); i++ {
		if stages, ok := b.byStep[i]; ok {
			p.Strategies = append(p.Strategies, stages)
		}
	}
	return p
}

// parseServiceConfig extracts the configuration from `sc qc` output.
func parseServiceConfig(out string) Installed {
	var inst Installed

	cmdline := ""
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, "BINARY_PATH_NAME")
		if idx < 0 {
			continue
		}
		rest := line[idx+len("BINARY_PATH_NAME"):]
		if colon := strings.Index(rest, ":"); colon >= 0 {
			cmdline = strings.TrimSpace(rest[colon+1:])
		}
		break
	}
	if cmdline == "" {
		return inst
	}

	args := splitArgs(cmdline)
	if len(args) > 0 {
		inst.BinaryPath = args[0]
	}

	cur := &profileBuild{}
	builds := []*profileBuild{cur}
	seenAddr := map[string]struct{}{}

	for _, a := range args[1:] {
		switch {
		case a == "--new":
			cur = &profileBuild{}
			builds = append(builds, cur)
		case strings.HasPrefix(a, "--wf-raw-filter="):
			inst.Addresses = append(inst.Addresses, filterAddresses(a, seenAddr)...)
		case strings.HasPrefix(a, "--lua-init="):
			if inst.LuaDir == "" {
				inst.LuaDir = filepath.Dir(strings.TrimPrefix(strings.TrimPrefix(a, "--lua-init="), "@"))
			}
		case strings.HasPrefix(a, "--hostlist="):
			cur.hostlist = strings.TrimPrefix(a, "--hostlist=")
		case strings.HasPrefix(a, "--lua-desync="):
			stage := strings.TrimPrefix(a, "--lua-desync=")
			if strings.HasPrefix(stage, "circular") {
				cur.rotating = true
				continue
			}
			if body, n, ok := splitStrategyTag(stage); ok {
				cur.addStep(n, body)
				continue
			}
			cur.untagged = append(cur.untagged, stage)
		}
	}

	for _, b := range builds {
		// A command line with no desync arguments at all leaves one empty
		// build behind; reporting it as a profile would invent a strategy.
		if b.empty() {
			continue
		}
		inst.Profiles = append(inst.Profiles, b.build())
	}
	return inst
}

// splitStrategyTag separates a stage from its trailing ":strategy=N" tag.
func splitStrategyTag(stage string) (body string, n int, ok bool) {
	const tag = ":strategy="
	i := strings.LastIndex(stage, tag)
	if i < 0 {
		return stage, 0, false
	}
	num, err := strconv.Atoi(stage[i+len(tag):])
	if err != nil || num < 1 {
		return stage, 0, false
	}
	return stage[:i], num, true
}

// splitArgs splits a Windows service command line into arguments.
//
// It handles the two forms this tool produces: a quoted executable path, and
// quoted arguments whose value contains spaces (the address filter). Quotes are
// grouping characters, and a backslash-escaped quote is a literal one — the
// same escaping binPathValue writes.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuotes := false
	started := false

	flush := func() {
		if started {
			args = append(args, cur.String())
			cur.Reset()
			started = false
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && s[i+1] == '"':
			cur.WriteByte('"')
			started = true
			i++
		case c == '"':
			inQuotes = !inQuotes
			// An empty quoted run is still an argument.
			started = true
		case (c == ' ' || c == '\t') && !inQuotes:
			flush()
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	flush()
	return args
}
