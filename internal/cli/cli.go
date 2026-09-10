// Package cli provides the command-line engine for Desynq.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"dpi/internal/apply"
	"dpi/internal/engine"
	"dpi/internal/measure"
	"dpi/internal/probe"
	"dpi/internal/search"
	"dpi/internal/windns"
)

// Run dispatches a CLI command from args.
func Run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "probe":
		return cmdProbe(args[1:])
	case "test":
		return cmdTest(args[1:])
	case "search":
		return cmdSearch(args[1:])
	case "auto":
		return cmdAuto(args[1:])
	case "apply":
		return cmdApply(args[1:])
	case "remove":
		return cmdRemove(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "dns":
		return cmdDNS(args[1:])
	case "divert":
		return cmdDivert(args[1:])
	case "refresh":
		return cmdRefresh(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "desynq: unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dpi - automated DPI bypass

usage:
  dpi auto  <domain>...   probe, search and apply in one go
                          (-install makes it permanent)
  dpi probe <domain>...   classify how each domain is being blocked
  dpi test  <domain>...   measure a desync strategy against a baseline
                          (-stage may be repeated; requires Administrator)
  dpi search <domain>...  find and rank every strategy that works
                          (requires Administrator)
  dpi apply               turn a chosen strategy into a permanent config
                          (-install registers the service, -fix-dns fixes DNS)
  dpi dns <domain>...     fix a forged resolver on its own, no service, no driver
                          (-mode=hosts pins only these names, -undo reverts)
  dpi status              show what is installed: strategy, scope and hosts
  dpi doctor              check that the installed bypass still works
                          (exit 1 when it does not, so it can be scheduled)
  dpi refresh             reinstall the same strategy with current addresses
  dpi remove              stop and delete the bypass service
                          (-dns also restores the saved DNS setting)

`)
}

func cmdProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "per-step timeout")
	verbose := fs.Bool("v", false, "print the full error text instead of a truncated one")
	_ = fs.Parse(args)

	domains := uniqueDomains(fs.Args())
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "dpi probe: need at least one domain")
		return 2
	}

	results := probe.Run(context.Background(), probe.Config{Timeout: *timeout}, domains)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "DOMAIN\tDNS\tPATH\tDESYNC\tSYS-IP\tREAL-IP\tTCP\tTLS\tHELLO\tDETAIL")
	for _, r := range results {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Domain, r.DNS, r.Path, yesNo(r.DesyncApplies()),
			firstIP(r.SysIPs), firstIP(r.RealIPs),
			ms(r.TCPTime), ms(r.TLSTime),
			helloSize(r.HelloSize), detail(r.Err, *verbose))
	}
	_ = w.Flush()
	fmt.Println()
	summarise(results, true)
	return 0
}

// stringList collects a repeatable string flag, preserving order.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, " | ") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// uniqueDomains removes repeats and blanks while keeping the given order.
//
// A repeated name is not merely redundant, it breaks the search: two targets
// with the same address make the second engine instance claim a filter the
// first already holds, which surfaces as ErrFilterBusy and aborts the whole
// run. It also lets one name corroborate itself in the shared-block-page
// check. Cleaning the input is cheaper than teaching every layer to tolerate it.
func uniqueDomains(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// expandWithWWW pairs a root domain with its www variant (and vice versa)
// so sites that redirect to or from www are both covered by hosts pins and packet filter.
func expandWithWWW(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts)*2)
	out := make([]string, 0, len(hosts)*2)
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return
		}
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}

	for _, h := range hosts {
		add(h)
		if strings.HasPrefix(h, "www.") {
			add(strings.TrimPrefix(h, "www."))
		} else if strings.Count(h, ".") == 1 {
			add("www." + h)
		}
	}
	return out
}

func cmdTest(args []string) int {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	var stages stringList
	fs.Var(&stages, "stage", "desync stage, repeatable and order-significant (e.g. -stage fake:tcp_md5 -stage multidisorder:pos=midsld)")
	attempts := fs.Int("attempts", 3, "handshake attempts per target")
	timeout := fs.Duration("timeout", 5*time.Second, "per-step timeout")
	binary := fs.String("engine", "", "path to winws2.exe (default tools/zapret-winws/winws2.exe)")
	luaDir := fs.String("lua", "", "path to the zapret2 lua directory (default tools/zapret-winws/lua)")
	_ = fs.Parse(args)

	domains := uniqueDomains(fs.Args())
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "dpi test: need at least one domain")
		return 2
	}
	if len(stages) == 0 {
		fmt.Fprintln(os.Stderr, "dpi test: need at least one -stage")
		return 2
	}

	ctx := context.Background()
	probeCfg := probe.Config{Timeout: *timeout}
	engCfg := engine.Config{BinaryPath: *binary, LuaDir: *luaDir}

	// Addresses come from the encrypted resolver: measuring against a hijacked
	// address would measure the block page instead of the real host.
	fmt.Println("resolving targets through encrypted DNS...")
	found := probe.Run(ctx, probeCfg, domains)
	var targets []measure.Target
	for _, r := range found {
		addr := searchAddr(r)
		if addr == "" {
			fmt.Printf("  %-24s skipped: no address from the encrypted resolver\n", r.Domain)
			continue
		}
		targets = append(targets, measure.Target{Domain: r.Domain, Addr: addr})
		fmt.Printf("  %-24s %s  (baseline path: %s)\n", r.Domain, r.RealIPs[0], r.Path)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "dpi test: no usable targets")
		return 1
	}

	fmt.Println("\nbaseline, no strategy:")
	base := measure.Baseline(ctx, probeCfg, targets, *attempts)
	printScore(base)

	fmt.Printf("\nstrategy %q:\n", stages.String())
	withStrategy, err := measure.Strategy(ctx, engCfg, probeCfg, stages, targets, *attempts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi test: %v\n", err)
		if errors.Is(err, engine.ErrFilterBusy) {
			fmt.Fprintln(os.Stderr, "hint: another bypass tool is already filtering this traffic - stop it first")
		}
		if errors.Is(err, engine.ErrNotReady) {
			fmt.Fprintln(os.Stderr, "hint: winws2 needs Administrator to load the WinDivert driver")
		}
		return 1
	}
	printScore(withStrategy)

	fmt.Println()
	printOutcome(base, withStrategy)
	return 0
}

// cmdAuto is the whole point of the tool: work out what is blocked, find the
// strategy that fixes it, and set that strategy up — without the user needing
// to know what a desync stage is.
//
// It refuses to guess which names matter. A built-in list of "commonly blocked"
// domains would be wrong in every country but the one it was written for, and
// the user already knows what they cannot reach.
func cmdAuto(args []string) int {
	fs := flag.NewFlagSet("auto", flag.ExitOnError)
	screen := fs.Int("screen-attempts", 1, "handshakes per candidate while screening")
	verify := fs.Int("verify-attempts", 10, "handshakes per survivor while verifying")
	timeout := fs.Duration("timeout", 5*time.Second, "per-step timeout")
	binary := fs.String("engine", "", "path to winws2.exe (default tools/zapret-winws/winws2.exe)")
	luaDir := fs.String("lua", "", "path to the zapret2 lua directory (default tools/zapret-winws/lua)")
	allowRisky := fs.Bool("allow-risky", true, "allow the TTL-based tier when safe tiers find nothing")
	install := fs.Bool("install", false, "register and start the service once a strategy is found")
	fixDNS := fs.Bool("fix-dns", false, "also switch to an encrypted resolver when DNS is forged (undo with 'dpi remove -dns')")
	dnsMode := fs.String("dns-mode", "resolver", "how to fix a forged resolver: resolver (switch the machine to encrypted DNS) or hosts (pin only these names, leaving the resolver alone)")
	scopeAll := fs.Bool("all-traffic", false, "capture every TLS connection instead of only the target addresses")
	rotate := fs.Bool("rotate", false, "(does not work: the engine never detects the failure - see -h notes) install runner-up strategies as fallbacks")
	bandwidth := fs.Bool("bandwidth", true, "measure real transfer speed among the tied-fastest and prefer the one that slows the connection least")
	parallel := fs.Int("parallel", 1, "screen this many candidates at once (each in its own source-port lane; ranking stays serial)")
	service := fs.String("service", apply.DefaultServiceName, "windows service name")
	configDir := fs.String("config-dir", "config", "directory for the generated host list")
	quiet := fs.Bool("quiet", true, "hide per-candidate search progress")
	fs.Parse(args) //nolint:errcheck // ExitOnError already handles failures

	domains := uniqueDomains(fs.Args())
	// With no domains named, fall back to what was configured. This is what
	// lets the tool run without someone typing the same command again: a
	// scheduled repair, a service reinstall, or later a window that only
	// edits the file.
	settingsDir, err := filepath.Abs(*configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi auto: %v\n", err)
		return 1
	}
	saved, savedErr := apply.LoadSettings(settingsDir)
	if len(domains) == 0 {
		if savedErr != nil {
			fmt.Fprintln(os.Stderr, "dpi auto: name the domains you cannot reach, e.g. dpi auto discord.com")
			fmt.Fprintf(os.Stderr, "or configure them once in %s\n", apply.SettingsPath(settingsDir))
			return 2
		}
		domains = saved.Hosts
		fmt.Printf("using the hosts configured in %s: %s\n\n", apply.SettingsPath(settingsDir), strings.Join(domains, " "))
		if saved.AllTraffic {
			*scopeAll = true
		}
		if saved.DNSMode != "" {
			*dnsMode = saved.DNSMode
			*fixDNS = true
		}
		if saved.ServiceName != "" {
			*service = saved.ServiceName
		}
	}

	// Rotation is refused rather than silently installed. Measured 2026-09-05
	// against real DPI with the engine's own debug log, and then traced to its
	// cause: the engine receives **no inbound packets at all** on this machine,
	// whatever the filter says — measured against an unblocked host whose
	// replies plainly arrived, seven packets logged, every one outbound. The
	// failure detector counts the inbound RST, so it can never fire, and
	// `circular` reports strategy 1 forever. Installing fallbacks that cannot
	// be reached would be a promise the engine does not keep.
	if *rotate {
		fmt.Println("note: -rotate is ignored. The engine accepts the rotating command line, but")
		fmt.Println("it receives no inbound packets on this machine, so it never sees the reset")
		fmt.Println("that would trigger a switch. Installing the primary strategy alone instead.")
		fmt.Println()
		*rotate = false
	}

	ctx := context.Background()
	probeCfg := probe.Config{Timeout: *timeout}
	engCfg := engine.Config{BinaryPath: *binary, LuaDir: *luaDir}

	fmt.Println("step 1/3  what is happening to these names")
	results := probe.Run(ctx, probeCfg, domains)
	targets, blocked := reportProbe(results)
	summarise(results, !*fixDNS)
	if blocked == 0 {
		// Nothing to search for is a legitimate outcome rather than a failure:
		// a link can censor by DNS alone, and on such a link the desync layer
		// has no part in the problem.
		fmt.Println("\nNo TLS-layer block found, so there is no strategy to look for.")

		// But the DNS layer may still be broken, and stopping here used to
		// leave it that way even when the user had asked for it to be fixed —
		// reporting "nothing to do" about the one thing that was wrong.
		forged := 0
		for _, r := range results {
			if r.NeedsEncryptedDNS() {
				forged++
			}
		}
		// Acted on the request, not on the verdict. A single name can only ever
		// be reported SUSPECT — one observation has nothing to correlate
		// against — and refusing to do what was explicitly asked because the
		// hijack could not be *proven* left the one broken layer broken.
		if *fixDNS {
			return fixDNSNow(ctx, settingsDir, domains, *dnsMode)
		}
		if forged > 0 {
			fmt.Printf("\n%d name(s) are blocked by DNS alone. Fix just that, with no service and no\ndriver:  dpi dns %s\n", forged, strings.Join(domains, " "))
		}
		return 0
	}

	fmt.Printf("\nstep 2/3  searching for a strategy that fixes %d name(s)\n", blocked)
	opts := search.Options{
		ScreenAttempts: *screen,
		VerifyAttempts: *verify,
		MaxTier:        search.TierAggressive,
		Bandwidth:      *bandwidth,
		Concurrency:    *parallel,
	}
	if !*allowRisky {
		opts.MaxTier = search.TierFake
	}
	if !*quiet {
		opts.OnCandidate = func(c search.Candidate, survived bool, err error) {
			if survived {
				fmt.Printf("  [%-10s] %-64s WORKS\n", c.Tier, c)
			}
		}
	}
	start := time.Now()
	report, err := search.Run(ctx, engCfg, probeCfg, targets, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi auto: %v\n", err)
		if errors.Is(err, engine.ErrFilterBusy) {
			fmt.Fprintln(os.Stderr, "hint: another bypass tool is already filtering this traffic - stop it first")
		}
		if errors.Is(err, engine.ErrNotReady) {
			fmt.Fprintln(os.Stderr, "hint: winws2 needs Administrator to load the WinDivert driver")
		}
		return 1
	}
	if len(report.Ranked) == 0 {
		fmt.Printf("  screened %d candidates in %s, none worked\n", report.Screened, time.Since(start).Round(time.Millisecond))
		fmt.Println("\nNo strategy in the space fixed these names. The censor may need techniques")
		fmt.Println("this tool does not implement yet, such as QUIC-level desync.")
		return 1
	}

	best := report.Best()
	pick := preferred(best)
	fmt.Printf("  screened %d candidates in %s, %d worked, %d tied for fastest\n",
		report.Screened, time.Since(start).Round(time.Millisecond), len(report.Ranked), len(best))
	fmt.Printf("  chosen: %s  (%s tier, %s median, %d/%d)\n",
		pick.Candidate, pick.Candidate.Tier, ms(pick.Score.MedianTLS),
		pick.Score.Successes, pick.Score.Attempts)
	if report.BandwidthMeasured > 0 {
		fmt.Printf("  time to first byte measured for %d tied-fastest candidate(s); chosen one at %s\n",
			report.BandwidthMeasured, ms(pick.TTFB))
	}
	if !pick.FullCoverage() {
		fmt.Println("  note: this strategy does not fix every name; see 'dpi search' for the full table")
	}
	recordSearch(settingsDir, report, pick, domains)

	fmt.Println("\nstep 3/3  applying")

	// One strategy rarely fails to cover everything, but when it does, each
	// host gets the strategy that actually works for it rather than the one
	// that works for the majority.
	profiles := buildProfiles(report, results, pick, *rotate)
	if len(profiles) > 1 {
		fmt.Printf("  no single strategy covers every name; using %d per-host profiles\n", len(profiles))
	}
	if *rotate {
		for i, prof := range profiles {
			switch n := len(prof.Fallbacks); n {
			case 0:
				fmt.Printf("  profile %d has no fallback: no other strategy covered the same hosts\n", i+1)
			default:
				fmt.Printf("  profile %d carries %d fallback strategy(ies) for automatic rotation\n", i+1, n)
			}
		}
	}

	resolved := resolveEngine(engCfg)
	binAbs, luaAbs, cfgAbs, err := absPaths(resolved.BinaryPath, resolved.LuaDir, *configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi auto: %v\n", err)
		return 1
	}
	scope := apply.ScopeTargeted
	if *scopeAll {
		scope = apply.ScopeAll
	}

	return runPlan(ctx, apply.Plan{
		Profiles:    profiles,
		Scope:       scope,
		BinaryPath:  binAbs,
		LuaDir:      luaAbs,
		ConfigDir:   cfgAbs,
		ServiceName: *service,
		BlockQUIC:   true,
	}, *install, *fixDNS, *dnsMode, false)
}

// buildProfiles turns the search result into installable profiles.
//
// Hosts that share a strategy share a profile, so the common case — one
// strategy covering everything — produces exactly one profile rather than one
// per host. A host the search could not fully cover falls back to the overall
// pick: partial help beats none, and runPlan's verification will report it as
// still blocked rather than pretending otherwise.
//
// It takes probe results rather than measure targets because a target carries
// only the one address the search dialled, while the kernel filter needs *every*
// address a host resolves to. A CDN rotates between its A records, so a filter
// built from one of them lets the connection through untouched as soon as the
// resolver hands out a different one — the service looks installed and healthy
// while the site stays blocked.
// recordSearch writes down what the search concluded.
//
// The search is the expensive half of this tool and its table used to exist
// only in the terminal, so nothing could answer "why this strategy?" after the
// output scrolled away — and a window has no scrollback at all. The record
// carries its own timestamp and the strategy it picked, so a reader can tell
// whether it still describes what is installed.
//
// A failure to write is reported and never fatal: this is a convenience, and
// the strategy it describes was measured either way.
func recordSearch(configDir string, rep search.Report, pick search.Ranked, hosts []string) {
	rec := apply.SearchReport{
		TakenAt:    time.Now(),
		Hosts:      hosts,
		Chosen:     pick.Candidate.Stages,
		Screened:   rep.Screened,
		Survivors:  rep.Survivors,
		Unverified: rep.Unverified,
		NoiseMS:    msFloat(rep.Noise),
	}
	for _, r := range rep.Ranked {
		rec.Entries = append(rec.Entries, apply.ReportEntry{
			Strategy:  engine.FormatStages(r.Candidate.Stages),
			Group:     r.Group,
			Tier:      r.Candidate.Tier.String(),
			MedianMS:  msFloat(r.Score.MedianTLS),
			SpreadMS:  msFloat(r.Score.SpreadTLS),
			Successes: r.Score.Successes,
			Attempts:  r.Score.Attempts,
			TTFBMS:    msFloat(r.TTFB),
		})
	}
	if err := apply.SaveReport(configDir, rec); err != nil {
		fmt.Fprintf(os.Stderr, "note: could not record the search: %v\n", err)
	}
}

// msFloat keeps sub-millisecond detail, which matters because the whole point
// of the grouping is that differences of a few milliseconds are noise.
func msFloat(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func buildProfiles(report search.Report, results []probe.Result, chosen search.Ranked, rotate bool) []apply.Profile {
	addrsOf := make(map[string][]string, len(results))
	order := make([]string, 0, len(results))
	for _, r := range results {
		// Only names that were actually blocked get a profile; the rest were
		// never interfered with and must stay out of the capture.
		if !r.DesyncApplies() || len(r.AllRealIPs()) == 0 {
			continue
		}
		// Both families, because the filter has to cover whichever one the
		// browser picks — and it picks IPv6 whenever it can.
		addrsOf[r.Domain] = append(addrsOf[r.Domain], r.AllRealIPs()...)
		order = append(order, r.Domain)
	}

	// When the reported strategy already covers every blocked host, install
	// exactly that one. Per-host selection can legitimately land on a different
	// equally-working strategy, and installing something other than what was
	// just reported as chosen would be a lie to the user for no benefit.
	if coversAll(chosen, order) {
		prof := apply.Profile{Stages: chosen.Candidate.Stages}
		for _, host := range order {
			prof.Hosts = append(prof.Hosts, host)
			prof.Addrs = append(prof.Addrs, addrsOf[host]...)
		}
		if rotate && len(order) > 0 {
			// One profile covers every host, so the fallbacks have to work for
			// every host too — an alternative that only fixes one of them would
			// leave the others broken after a rotation.
			prof.Fallbacks = commonFallbacks(report, order, chosen, maxFallbacks)
		}
		return []apply.Profile{prof}
	}

	perHost := report.BestPerHost()

	// Group by strategy while keeping first-seen order, so the output is stable
	// between identical runs.
	byStrategy := make(map[string]*apply.Profile)
	var keys []string
	for _, host := range order {
		forHost, ok := perHost[host]
		if !ok {
			forHost = chosen
		}
		key := engine.FormatStages(forHost.Candidate.Stages)
		prof, seen := byStrategy[key]
		if !seen {
			prof = &apply.Profile{Stages: forHost.Candidate.Stages}
			if rotate {
				prof.Fallbacks = fallbacksFor(report, host, forHost, maxFallbacks)
			}
			byStrategy[key] = prof
			keys = append(keys, key)
		}
		prof.Hosts = append(prof.Hosts, host)
		prof.Addrs = append(prof.Addrs, addrsOf[host]...)
	}

	out := make([]apply.Profile, 0, len(keys))
	for _, k := range keys {
		out = append(out, *byStrategy[k])
	}
	return out
}

// commonFallbacks returns alternatives that work for every host in the list.
//
// A profile shared by several hosts can only rotate to a strategy that covers
// all of them; rotating to one that fixes a single host would leave the rest
// broken with no way back until the next failure threshold.
func commonFallbacks(report search.Report, hosts []string, primary search.Ranked, max int) [][]string {
	primaryKey := engine.FormatStages(primary.Candidate.Stages)
	var out [][]string
	for _, cand := range report.Ranked {
		if len(out) >= max {
			break
		}
		if engine.FormatStages(cand.Candidate.Stages) == primaryKey {
			continue
		}
		if coversAll(cand, hosts) {
			out = append(out, cand.Candidate.Stages)
		}
	}
	return out
}

// maxFallbacks caps how many alternatives a rotating profile carries.
//
// Two is enough to survive a censor update without turning the command line
// into a wall: every extra strategy also lengthens the kernel filter, which is
// bounded, and a rotation that has to try six strategies before working is
// slow enough that the user would rather re-run the search.
const maxFallbacks = 2

// fallbacksFor returns alternative strategies for one host, best first,
// skipping the one already chosen as primary.
//
// Only strategies that worked on *every* attempt for this host qualify: a
// rotation target that fails half the time would trade one broken state for
// another, and the failure detector would rotate straight past it anyway.
func fallbacksFor(report search.Report, host string, primary search.Ranked, max int) [][]string {
	primaryKey := engine.FormatStages(primary.Candidate.Stages)
	var out [][]string
	for _, cand := range report.Ranked {
		if len(out) >= max {
			break
		}
		if engine.FormatStages(cand.Candidate.Stages) == primaryKey {
			continue
		}
		for _, ts := range cand.Score.Targets {
			if ts.Domain == host && ts.Attempts > 0 && ts.Successes == ts.Attempts {
				out = append(out, cand.Candidate.Stages)
				break
			}
		}
	}
	return out
}

// coversAll reports whether one strategy worked on every attempt for every
// host in the list.
func coversAll(r search.Ranked, hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}
	ok := make(map[string]bool, len(r.Score.Targets))
	for _, ts := range r.Score.Targets {
		ok[ts.Domain] = ts.Attempts > 0 && ts.Successes == ts.Attempts
	}
	for _, h := range hosts {
		if !ok[h] {
			return false
		}
	}
	return true
}

// absPaths resolves the engine, library and config locations to absolute paths.
// A service started at boot has no useful working directory, so a relative path
// would resolve somewhere else entirely.
func absPaths(binary, lua, config string) (string, string, string, error) {
	binAbs, err := filepath.Abs(binary)
	if err != nil {
		return "", "", "", err
	}
	luaAbs, err := filepath.Abs(lua)
	if err != nil {
		return "", "", "", err
	}
	cfgAbs, err := filepath.Abs(config)
	if err != nil {
		return "", "", "", err
	}
	if _, err := os.Stat(binAbs); err != nil {
		return "", "", "", fmt.Errorf("engine not found at %s", binAbs)
	}
	return binAbs, luaAbs, cfgAbs, nil
}

func cmdApply(args []string) int {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	var stages stringList
	fs.Var(&stages, "stage", "desync stage, repeatable and order-significant")
	var hosts stringList
	fs.Var(&hosts, "host", "limit the strategy to this name, repeatable (default: every TLS connection)")
	service := fs.String("service", apply.DefaultServiceName, "windows service name")
	configDir := fs.String("config-dir", "config", "directory for the generated host list")
	binary := fs.String("engine", "", "path to winws2.exe (default tools/zapret-winws/winws2.exe)")
	luaDir := fs.String("lua", "", "path to the zapret2 lua directory (default tools/zapret-winws/lua)")
	install := fs.Bool("install", false, "register and start the windows service instead of only printing the commands")
	fixDNS := fs.Bool("fix-dns", false, "also switch the active interface to an encrypted resolver (saved, undo with 'dpi remove -dns')")
	dnsMode := fs.String("dns-mode", "resolver", "how to fix a forged resolver: resolver (switch the machine to encrypted DNS) or hosts (pin only these names, leaving the resolver alone)")
	scopeAll := fs.Bool("all-traffic", false, "capture every TLS connection instead of only the target addresses (see -h notes on anti-cheat)")
	fast := fs.Bool("fast", false, "skip redundant post-install network verification for instant UI startup")
	fs.Parse(args) //nolint:errcheck // ExitOnError already handles failures

	if len(stages) == 0 {
		fmt.Fprintln(os.Stderr, "dpi apply: need at least one -stage")
		fmt.Fprintln(os.Stderr, "run 'dpi search <domain>...' first; it prints the stages to use")
		return 2
	}
	hostList := expandWithWWW(uniqueDomains(hosts))

	resolved := resolveEngine(engine.Config{BinaryPath: *binary, LuaDir: *luaDir})
	binAbs, luaAbs, cfgAbs, err := absPaths(resolved.BinaryPath, resolved.LuaDir, *configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi apply: %v\n", err)
		return 1
	}

	ctx := context.Background()
	scope := apply.ScopeTargeted
	if *scopeAll {
		scope = apply.ScopeAll
	}

	// Addresses come from the encrypted resolver, not the system one: under a
	// DNS hijack the system answer is the block page, and a kernel filter built
	// from it would capture traffic to the censor while letting the real host
	// through untouched.
	var addrs []string
	if len(hostList) > 0 && scope == apply.ScopeTargeted {
		fmt.Println("resolving target addresses through encrypted DNS...")
		for _, r := range probe.Run(ctx, probe.Config{}, hostList) {
			if len(r.AllRealIPs()) == 0 {
				fmt.Printf("  %-24s no address; it cannot be targeted\n", r.Domain)
				continue
			}
			addrs = append(addrs, r.AllRealIPs()...)
			fmt.Printf("  %-24s %s\n", r.Domain, strings.Join(r.AllRealIPs(), " "))
		}
	}

	plan := apply.Plan{
		Profiles:    []apply.Profile{{Stages: stages, Hosts: hostList, Addrs: addrs}},
		Scope:       scope,
		BinaryPath:  binAbs,
		LuaDir:      luaAbs,
		ConfigDir:   cfgAbs,
		ServiceName: *service,
		BlockQUIC:   true,
	}
	return runPlan(ctx, plan, *install, *fixDNS, *dnsMode, *fast)
}

// runPlan prints a plan, optionally installs it, and verifies that the
// installation actually changed anything.
//
// Shared by `apply` and `auto` so that the install path, the verification and
// the honesty about DNS exist once. Duplicating it would let the two commands
// drift, and the one that drifted would be the one reporting a false success.
func runPlan(ctx context.Context, plan apply.Plan, install, fixDNS bool, dnsMode string, fast bool) int {
	// Refuse before printing anything that looks like a working plan. An
	// unbounded targeted scope is the case worth stopping for: it would install
	// a service that captures every connection on the machine while the user
	// believes only one site is affected.
	if err := plan.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "dpi: %v\n", err)
		switch {
		case errors.Is(err, apply.ErrScopeUnbounded):
			fmt.Fprintln(os.Stderr, "targeted scope needs at least one address. Either name the hosts with -host,")
			fmt.Fprintln(os.Stderr, "or ask for the broad capture explicitly with -all-traffic.")
			fmt.Fprintln(os.Stderr, "if you did pass -host, the encrypted resolver returned no address for it.")
		case errors.Is(err, apply.ErrFilterTooLarge):
			fmt.Fprintln(os.Stderr, "too many addresses for one kernel filter; split the hosts across")
			fmt.Fprintln(os.Stderr, "separate services, or use -all-traffic.")
		}
		return 1
	}

	printPlan(plan)

	// The way out is printed before the way in, because a bypass service that
	// misbehaves takes the network with it and the user needs the recovery
	// commands already in front of them.
	fmt.Println("\nto remove it again (keep this):")
	for _, cmd := range plan.RemoveCommands() {
		fmt.Printf("  %s\n", apply.FormatCommand(cmd))
	}
	if !install {
		fmt.Println("\nto install, run as Administrator:")
		for _, cmd := range plan.InstallCommands() {
			fmt.Printf("  %s\n", apply.FormatCommand(cmd))
		}
		fmt.Println("\nNothing was installed. Re-run with -install to register the service,")
		fmt.Println("or paste the commands above yourself.")
		return 0
	}

	fmt.Printf("\ninstalling service %q...\n", plan.ServiceName)
	state, err := plan.Install(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi: %v\n", err)
		if errors.Is(err, apply.ErrAlreadyInstalled) {
			fmt.Fprintf(os.Stderr, "hint: run 'dpi remove -service %s' first\n", plan.ServiceName)
		} else {
			fmt.Fprintln(os.Stderr, "hint: registering a service needs Administrator")
		}
		return 1
	}
	fmt.Printf("service state: %s\n", state)
	if state != apply.StateRunning {
		fmt.Fprintf(os.Stderr, "dpi: service is %s, not running - the strategy is not active\n", state)
		return 1
	}

	hosts := plan.AllHosts()
	// Installing is not the same as working: verify against the very hosts the
	// strategy was scoped to, so a service that starts but does nothing is
	// caught here rather than by the user days later.
	if len(hosts) > 0 && !fast {
		fmt.Println("\nverifying the installed service against its scoped hosts...")
		verified := verifyHosts(ctx, hosts)
		stillBlocked, dnsForged, dnsSuspect := countProblems(hosts, verified)
		if stillBlocked > 0 {
			fmt.Fprintf(os.Stderr, "\ndpi: %d host(s) are still blocked with the service running.\n", stillBlocked)
			fmt.Fprintf(os.Stderr, "the service is installed but not effective - remove it with 'dpi remove -service %s'\n", plan.ServiceName)
			return 1
		}
		fmt.Println("\nthe desync strategy works: the real address completes a TLS handshake.")

		// This verification reaches the real address through an encrypted
		// resolver. A browser does not — it asks the system resolver, which is
		// still being answered with a block page. Saying "working" here without
		// that caveat would be false: nothing the strategy does can help a
		// connection aimed at the wrong address in the first place.
		if dnsForged > 0 && !fixDNS {
			fmt.Printf("\nBUT %d of these names still resolve to a block page through the system resolver.\n", dnsForged)
			fmt.Println("A browser will keep failing until DNS is fixed too - the strategy is only half the problem.")
			printDNSRemedy()
			fmt.Println("\nor let this tool do it: re-run with -fix-dns (it saves the current setting first)")
			return 0
		}

		// A suspect answer is the same hazard with weaker evidence: the system
		// resolver is sending this name somewhere the encrypted one does not,
		// and a browser follows the system resolver. It stays unproven because
		// one observation cannot tell a block page from a CDN edge — probing
		// more names together is what settles it.
		if dnsSuspect > 0 && !fixDNS {
			fmt.Printf("\nNote: %d of these names resolve differently through the system resolver,\n", dnsSuspect)
			fmt.Println("which is unproven but not clean - a browser may still be sent elsewhere.")
			fmt.Println("confirm by probing them together with another blocked name: dpi probe ...")
		}

		// A targeted filter is a fixed address list, so an unanswered AAAA
		// question means it may be missing addresses that do exist. A browser
		// prefers IPv6 wherever it has a route and would then walk around the
		// strategy, with nothing in the service state to show it.
		if plan.Scope == apply.ScopeTargeted {
			unknownV6 := 0
			for _, h := range hosts {
				if verified[h].V6Unknown {
					unknownV6++
				}
			}
			if unknownV6 > 0 {
				fmt.Printf("\nNote: the IPv6 question went unanswered for %d name(s),\n", unknownV6)
				fmt.Println("so the filter may not cover their IPv6 addresses. Re-run to settle it,")
				fmt.Println("or use -all-traffic if the host turns out to prefer IPv6.")
			}
		}
	}

	if fixDNS {
		if code := fixDNSNow(ctx, plan.ConfigDir, hosts, dnsMode); code != 0 {
			return code
		}
	}

	// Recorded only after the install verified itself, so the file always
	// describes something that was seen to work rather than something that was
	// merely attempted.
	savedHosts := hosts
	if len(savedHosts) == 0 {
		if cur, err := apply.LoadSettings(plan.ConfigDir); err == nil && len(cur.Hosts) > 0 {
			savedHosts = cur.Hosts
		}
	}
	if err := apply.SaveSettings(plan.ConfigDir, apply.Settings{
		Hosts:       savedHosts,
		AllTraffic:  plan.Scope == apply.ScopeAll,
		DNSMode:     savedDNSMode(fixDNS, dnsMode),
		ServiceName: plan.ServiceName,
	}); err != nil {
		// Not fatal: the service is installed and working either way.
		fmt.Fprintf(os.Stderr, "note: could not record the settings: %v\n", err)
	} else {
		fmt.Printf("settings recorded in %s - `dpi auto` with no arguments will reuse them\n", apply.SettingsPath(plan.ConfigDir))
	}

	if plan.Scope == apply.ScopeAll && install {
		exePath, err := os.Executable()
		if err == nil {
			toolsDir := filepath.Join(filepath.Dir(exePath), "tools", "zapret-winws")
			_ = exec.Command("sc.exe", "create", "desynq-dns",
				"binPath=", fmt.Sprintf(`"%s" divert -service -tools="%s"`, exePath, toolsDir),
				"DisplayName=", "Desynq DNS Diverter",
				"start=", "auto").Run()
			_ = exec.Command("sc.exe", "description", "desynq-dns", "Desynq Transparent DoH & QUIC Drop Service").Run()
			_ = exec.Command("sc.exe", "start", "desynq-dns").Run()
		}
	}

	fmt.Printf("\ninstalled and running. To undo: dpi remove -service %s\n", plan.ServiceName)
	return 0
}

// verifyAttempts is how many chances a host gets to come back working.
//
// One handshake is too noisy a verdict to act on. The search itself uses ten
// attempts per host for exactly this reason, and an install verified with a
// single probe reported "not effective" for a service that was in fact working
// — sending the user to remove it. Only a host that fails every attempt is
// reported as still blocked.
const verifyAttempts = 3

// verifyHosts probes hosts, retrying only the ones that still look blocked, and
// prints one line per host.
//
// It returns the best result seen for each host rather than a tally, so a caller
// that also needs the resolved addresses — doctor, comparing them against the
// installed filter — does not have to probe the same names a second time.
func verifyHosts(ctx context.Context, hosts []string) map[string]probe.Result {
	final := make(map[string]probe.Result, len(hosts))
	pending := hosts

	for attempt := 1; attempt <= verifyAttempts && len(pending) > 0; attempt++ {
		var retry []string
		for _, r := range probe.Run(ctx, probe.Config{}, pending) {
			// Keep the best result seen: a host that succeeded once is working,
			// and a later dropped packet does not unmake that.
			if prev, seen := final[r.Domain]; !seen || (prev.DesyncApplies() && !r.DesyncApplies()) {
				final[r.Domain] = r
			}
			if r.DesyncApplies() {
				retry = append(retry, r.Domain)
			}
		}
		pending = retry
		if len(pending) > 0 && attempt < verifyAttempts {
			fmt.Printf("  retrying %d host(s) that did not answer on attempt %d\n", len(pending), attempt)
		}
	}

	for _, h := range hosts {
		r := final[h]
		fmt.Printf("  %-24s path %-8s dns %s\n", h, r.Path, r.DNS)
	}
	return final
}

// countProblems tallies a verification: hosts the strategy is not helping, and
// hosts whose system resolver answer is still forged.
//
// A host with no result at all counts as blocked. Its zero value carries an
// empty path status, which DesyncApplies reads as "not a desync case" — so
// treating the map as complete would turn a host that never answered into a
// host that works.
func countProblems(hosts []string, final map[string]probe.Result) (stillBlocked, dnsForged, dnsSuspect int) {
	for _, h := range hosts {
		r, ok := final[h]
		if !ok || r.DesyncApplies() {
			stillBlocked++
		}
		switch {
		case r.NeedsEncryptedDNS():
			dnsForged++
		case r.DNS == probe.DNSSuspect:
			// Not proven forged, and deliberately so: convicting on one
			// observation is what CDN rotation punishes. But it is not clean
			// either, and whether it ever gets convicted depends on how many
			// names happen to be probed together — so it must not pass in
			// silence.
			dnsSuspect++
		}
	}
	return stillBlocked, dnsForged, dnsSuspect
}

// printPlan shows what is about to be installed and writes the host lists.
//
// The scope line is the important one: it is the difference between touching
// one site and putting every connection on the machine through a kernel driver.
func printPlan(plan apply.Plan) {
	fmt.Println("\nplan:")
	fmt.Printf("  service   %s\n", plan.ServiceName)
	fmt.Printf("  engine    %s\n", plan.BinaryPath)
	for i, prof := range plan.Profiles {
		fmt.Printf("  profile %d %s\n", i+1, engine.FormatStages(prof.Stages))
		for n, fb := range prof.Fallbacks {
			fmt.Printf("            fallback %d: %s\n", n+1, engine.FormatStages(fb))
		}
		if len(prof.Hosts) > 0 {
			fmt.Printf("            for %s\n", strings.Join(prof.Hosts, ", "))
		}
	}

	switch {
	case plan.Scope == apply.ScopeAll:
		fmt.Println("  scope     ALL TLS traffic on port 443")
		fmt.Println("            every connection on this machine passes through the driver;")
		fmt.Println("            anti-cheat software may treat that as interference")
	case len(plan.AllAddrs()) == 0:
		fmt.Println("  scope     ALL TLS traffic on port 443 (no target addresses known)")
	default:
		addrs := plan.AllAddrs()
		fmt.Printf("  scope     %d address(es) only: %s\n", len(addrs), strings.Join(addrs, " "))
		fmt.Println("            other traffic never reaches the driver")
		if n := countIPv6(addrs); n > 0 {
			fmt.Printf("            %d of them IPv6, so a v6-preferring browser is covered too\n", n)
		}
	}

	written, err := plan.WriteHostlists()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi apply: %v\n", err)
		return
	}
	for _, path := range written {
		fmt.Printf("  wrote     %s\n", path)
	}
}

// fixDNSNow switches the active interface to an encrypted resolver and checks
// that the names in question stop resolving to a block page.
//
// The previous setting is written to disk before anything changes, so that
// 'dpi remove -dns' restores rather than guesses. Verification matters as much
// as the change: a resolver that is set but not actually answering leaves the
// machine worse off than before.
func fixDNSNow(ctx context.Context, configDir string, hosts []string, mode string) int {
	return pinHosts(ctx, configDir, hosts)
}

// printDNSRemedy gives the concrete steps for the DNS half of the problem.
func printDNSRemedy() {
	fmt.Println("\nDNS resolution for target hosts can be pinned in the hosts file:")
	fmt.Println("  dpi dns <domain>...")
}

func cmdRemove(args []string) int {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	service := fs.String("service", apply.DefaultServiceName, "windows service name")
	driver := fs.Bool("driver", false, "also unload the shared WinDivert kernel driver")
	restoreDNS := fs.Bool("dns", false, "also restore the DNS setting saved by 'apply -fix-dns'")
	configDir := fs.String("config-dir", "config", "directory holding the saved DNS setting")
	fs.Parse(args) //nolint:errcheck // ExitOnError already handles failures

	ctx := context.Background()
	plan := apply.Plan{ServiceName: *service}

	// Terminate any orphaned winws2.exe processes and stop desynq-dns service
	_ = exec.Command("taskkill", "/F", "/IM", "winws2.exe").Run()
	_ = exec.Command("sc.exe", "stop", "desynq-dns").Run()
	_ = exec.Command("sc.exe", "delete", "desynq-dns").Run()

	before := apply.Status(ctx, *service)
	if before == apply.StateAbsent {
		fmt.Printf("service %q is not installed, nothing to remove\n", *service)
	} else {
		state, err := plan.Remove(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dpi remove: %v\n", err)
			fmt.Fprintln(os.Stderr, "hint: removing a service needs Administrator")
			return 1
		}
		fmt.Printf("service %q: %s -> %s\n", *service, before, state)
	}

	if *restoreDNS {
		if code := restoreSavedDNS(ctx, *configDir); code != 0 {
			return code
		}
	}

	if !*driver {
		// The driver is shared, so removing it is opt-in rather than implied.
		fmt.Println("\nthe WinDivert driver is left loaded; it is shared with any other bypass tool.")
		fmt.Println("to unload it too, re-run with -driver, or:")
		for _, cmd := range apply.DriverRemoveCommands() {
			fmt.Printf("  %s\n", apply.FormatCommand(cmd))
		}
		return 0
	}
	fmt.Println("\nunloading the WinDivert driver...")
	for _, cmd := range apply.DriverRemoveCommands() {
		// Stopping the driver can already deregister it, which makes the
		// following delete fail with "service does not exist". Checking first
		// keeps a successful removal from printing an error.
		if apply.Status(ctx, "windivert") == apply.StateAbsent {
			break
		}
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil && apply.Status(ctx, "windivert") != apply.StateAbsent {
			// A driver still in use by another tool refuses to stop; report
			// that rather than pretending the machine is clean.
			fmt.Fprintf(os.Stderr, "  %s: %v: %s\n", apply.FormatCommand(cmd), err, strings.TrimSpace(string(out)))
		}
	}
	fmt.Printf("WinDivert now: %s\n", apply.Status(ctx, "windivert"))
	return 0
}

// restoreSavedDNS puts back the resolver setting recorded by apply -fix-dns.
//
// The backup is only discarded once the restore has succeeded: if it fails, the
// file has to survive so the user can try again or read it themselves.
func restoreSavedDNS(ctx context.Context, configDir string) int {
	abs, err := filepath.Abs(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi remove: %v\n", err)
		return 1
	}

	if pinned, err := apply.ReadManagedHosts(); err == nil && len(pinned) > 0 {
		if err := apply.WriteHosts(abs, nil); err != nil {
			fmt.Fprintf(os.Stderr, "dpi remove: %v\n", err)
			fmt.Fprintln(os.Stderr, "hint: editing the hosts file needs Administrator")
			return 1
		}
		fmt.Printf("\nunpinned %d name(s) from %s\n", len(pinned), apply.HostsPath())
		_ = apply.FlushDNSCache()
	}
	return 0
}

func cmdStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	service := fs.String("service", apply.DefaultServiceName, "windows service name")
	fs.Parse(args) //nolint:errcheck // ExitOnError already handles failures

	ctx := context.Background()
	inst := apply.Inspect(ctx, *service)

	fmt.Printf("service   %-16s %s\n", *service, inst.State)
	fmt.Printf("driver    %-16s %s\n", "windivert", apply.Status(ctx, "windivert"))

	// A stray engine is invisible everywhere else: status and doctor both
	// report the service, so one that outlived its supervisor keeps desyncing
	// traffic with nothing to show for it.
	if n := apply.UnaccountedEngines(len(apply.RunningEngines(ctx, engine.DefaultConfig().BinaryPath)), inst.State); n > 0 {
		fmt.Printf("engines   %d running process(es) this service does not account for\n", n)
	}
	if inst.State == apply.StateAbsent {
		fmt.Println("\nnothing installed. run 'dpi auto <domain>...' to find and apply a strategy.")
		return 0
	}

	// What the service actually runs, read back from the SCM rather than from
	// our config files, so a hand-edited or stale installation shows its real
	// behaviour.
	fmt.Println()
	if len(inst.Profiles) == 0 {
		fmt.Println("strategy  could not be read from the service configuration")
	}
	for i, prof := range inst.Profiles {
		label := "strategy"
		if len(inst.Profiles) > 1 {
			label = fmt.Sprintf("profile %d", i+1)
		}
		if prof.Rotating {
			fmt.Printf("%-9s %s  (active until it fails repeatedly)\n", label, engine.FormatStages(prof.Stages()))
			for n, s := range prof.Fallbacks() {
				fmt.Printf("          fallback %d: %s\n", n+1, engine.FormatStages(s))
			}
		} else {
			fmt.Printf("%-9s %s\n", label, engine.FormatStages(prof.Stages()))
		}
		if prof.Hostlist == "" {
			continue
		}
		if names, err := hostlistNames(prof.Hostlist); err == nil {
			fmt.Printf("          for %s\n", strings.Join(names, " "))
		} else {
			// A missing host list means the service filters on a file that is
			// no longer there, which the engine treats as an empty list.
			fmt.Printf("          for %s (unreadable)\n", prof.Hostlist)
		}
	}

	switch inst.Scope() {
	case apply.ScopeTargeted:
		fmt.Printf("scope     %d address(es): %s\n", len(inst.Addresses), strings.Join(inst.Addresses, " "))
		fmt.Println("          other traffic does not reach the driver")
	default:
		// Worth stating plainly: this is the configuration anti-cheat software
		// reacts to, and it is not visible from the service name alone.
		fmt.Println("scope     ALL TLS traffic on port 443")
		fmt.Println("          every connection on this machine passes through the driver")
	}

	if inst.State != apply.StateRunning {
		fmt.Printf("\nthe service is %s, so no strategy is active right now.\n", inst.State)
	}
	fmt.Println("\nto check that it is still working: dpi doctor")
	return 0
}

// hostlistNames reads the names a profile's host list file contains.
func hostlistNames(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return uniqueDomains(strings.Fields(string(b))), nil
}

// installedHosts collects the names every profile of an installed service
// applies to, plus the host lists that could not be read.
//
// An unreadable list is worth reporting rather than skipping: the engine treats
// a missing file as an empty list, so that profile silently stops matching
// anything while the service still looks healthy.
func installedHosts(inst apply.Installed) (hosts, unreadable []string) {
	var all []string
	for _, prof := range inst.Profiles {
		if prof.Hostlist == "" {
			continue
		}
		names, err := hostlistNames(prof.Hostlist)
		if err != nil {
			unreadable = append(unreadable, prof.Hostlist)
			continue
		}
		all = append(all, names...)
	}
	return uniqueDomains(all), unreadable
}

// countIPv6 reports how many of the addresses are IPv6.
//
// Worth stating on its own: IPv6 coverage is the difference between a filter a
// browser respects and one it silently walks around, and it is not visible from
// an address count alone.
func countIPv6(addrs []string) int {
	n := 0
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
			n++
		}
	}
	return n
}

// currentAddresses is every distinct address the probe found for the given
// hosts, which is what the installed filter has to cover to stay effective.
//
// Deduplicated because CDNs hand the same edge to several names, and a count
// that double-counts them would overstate how much the filter is missing.
func currentAddresses(final map[string]probe.Result) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range final {
		for _, a := range r.AllRealIPs() {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// cmdDoctor answers "is the installed bypass still working" — the question the
// service state cannot answer.
//
// A targeted scope is a fixed address list captured at install time. When a CDN
// moves its hosts, the filter keeps naming addresses nobody uses, the traffic
// passes the driver untouched and the site is blocked again — while the service
// still reports itself as running and `dpi status` still prints a strategy. The
// only way to see that is to compare what is installed against what resolution
// returns now, which is what this does.
func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	service := fs.String("service", apply.DefaultServiceName, "windows service name")
	fs.Parse(args) //nolint:errcheck // ExitOnError already handles failures

	ctx := context.Background()
	inst := apply.Inspect(ctx, *service)

	fmt.Printf("service   %-16s %s\n", *service, inst.State)
	fmt.Printf("driver    %-16s %s\n", "windivert", apply.Status(ctx, "windivert"))
	// Problems are collected rather than printed as they are found, so the
	// diagnosis can be ordered by what to do about it instead of by the order
	// the checks happen to run in.
	var problems []string

	// Checked before the no-service shortcut, because that is exactly when it
	// bites: the case this exists for was a *removed* service whose engine kept
	// running. A stray engine is both a hazard and a liar — it desyncs traffic
	// with no supervisor, and any measurement taken beside it, this check
	// included, sees a host working for a reason nothing here controls.
	strays := apply.UnaccountedEngines(
		len(apply.RunningEngines(ctx, engine.DefaultConfig().BinaryPath)), inst.State)
	if strays > 0 {
		problems = append(problems, fmt.Sprintf(
			"%d engine process(es) are running that this service does not account for; "+
				"they alter traffic unsupervised and make any check here unreliable - "+
				"end them with: taskkill /IM winws2.exe /F", strays))
	}

	// Checked before the shortcut below for the same reason as the stray
	// engines: pins work with no service at all, so a diagnosis that stops at
	// "nothing is installed" would never look at them.
	pinned, pinProblems := checkPins(ctx)
	problems = append(problems, pinProblems...)

	if inst.State == apply.StateAbsent {
		if len(pinned) == 0 {
			fmt.Println("\nno service is installed and no names are pinned.")
			if strays == 0 {
				fmt.Println("run 'dpi auto <domain>...' to find and apply a strategy.")
			}
			return reportDiagnosis(problems, nil, false)
		}
		// Pins are a complete remedy on their own where the block is DNS-only,
		// so this is a healthy shape rather than a missing install.
		return reportDiagnosis(problems, pinned, false)
	}
	if inst.State != apply.StateRunning {
		problems = append(problems, fmt.Sprintf(
			"the service is %s, so no strategy is active - start it with: sc.exe start %s",
			inst.State, *service))
	}
	if len(inst.Profiles) == 0 {
		problems = append(problems,
			"the service configuration names no strategy - reinstall with 'dpi auto'")
	}
	// A service whose engine has been moved or deleted cannot start, and the
	// state alone does not say why — Windows reports it as stopped.
	if inst.BinaryPath != "" {
		if _, err := os.Stat(inst.BinaryPath); err != nil {
			problems = append(problems, fmt.Sprintf(
				"the engine the service runs is gone: %s", inst.BinaryPath))
		}
	}

	hosts, unreadable := installedHosts(inst)
	for _, hl := range unreadable {
		// Not a refresh case: the names that profile covered are only in that
		// file, so nothing can rebuild it — they have to be named again.
		problems = append(problems, fmt.Sprintf(
			"host list %s cannot be read, so that profile matches nothing; reinstall it with 'dpi auto <domain>...'", hl))
	}
	if len(hosts) == 0 {
		fmt.Println("\nthe service names no hosts, so only its state and configuration were checked.")
		return reportDiagnosis(problems, hosts, true)
	}

	fmt.Printf("\nchecking %d host(s) the service is installed for...\n", len(hosts))
	final := verifyHosts(ctx, hosts)
	stillBlocked, dnsForged, dnsSuspect := countProblems(hosts, final)

	// Scope drift is checked before effectiveness because it explains it: a
	// host outside the filter fails exactly as a dead strategy does, and the
	// remedies are opposite.
	drift := apply.CompareAddresses(inst.Addresses, currentAddresses(final))
	fmt.Println()
	switch {
	case inst.Scope() == apply.ScopeAll:
		fmt.Println("scope     ALL TLS traffic on port 443 - address drift cannot apply")
	case len(drift.Current) == 0:
		// Saying "all covered" here would be a lie by omission: nothing was
		// resolved, so the filter was never compared against anything.
		fmt.Println("scope     no address resolved, so the filter could not be checked")
	case drift.Degraded():
		fmt.Printf("scope     %d of %d live address(es) are NOT covered by the filter: %s\n",
			len(drift.Missing), len(drift.Current), strings.Join(drift.Missing, " "))
		fmt.Println("          traffic to those passes the driver untouched")
		problems = append(problems,
			"the kernel filter has gone stale: the hosts moved to addresses it does not name")
	default:
		fmt.Printf("scope     %d address(es), all live addresses covered\n", len(inst.Addresses))
	}
	// Only claim an address is unused when something actually resolved. With
	// no answer at all every installed address looks stale, and calling that
	// harmless would be a finding invented out of missing data.
	if len(drift.Stale) > 0 && !drift.Degraded() && len(drift.Current) > 0 {
		fmt.Printf("          %d installed address(es) are no longer in use (harmless)\n", len(drift.Stale))
	}
	if dnsSuspect > 0 {
		fmt.Printf("          %d name(s) resolve differently through the system resolver (unproven)\n", dnsSuspect)
	}
	if n := countIPv6(inst.Addresses); n > 0 {
		fmt.Printf("          %d of the installed addresses are IPv6\n", n)
	}
	// Stated as a limit rather than a fault: an unanswered AAAA question is a
	// resolver hiccup, not a broken install. But it does mean the drift
	// comparison above could not see IPv6 addresses that exist, so claiming
	// full coverage would overstate what was checked.
	if inst.Scope() == apply.ScopeTargeted {
		unknown := 0
		for _, h := range hosts {
			if final[h].V6Unknown {
				unknown++
			}
		}
		if unknown > 0 {
			fmt.Printf("          IPv6 unverified for %d name(s): the AAAA question went unanswered\n", unknown)
		}
	}

	switch {
	case stillBlocked > 0 && drift.Degraded():
		problems = append(problems, fmt.Sprintf(
			"%d host(s) are still blocked, most likely because of the stale filter", stillBlocked))
	case stillBlocked > 0:
		problems = append(problems, fmt.Sprintf(
			"%d host(s) are still blocked while the filter is current, so the strategy itself has stopped working",
			stillBlocked))
	}
	if dnsForged > 0 {
		problems = append(problems, fmt.Sprintf(
			"%d name(s) still resolve to a block page through the system resolver, so a browser will keep failing",
			dnsForged))
	}

	// A run that verified nothing must not report health. Every check above
	// rests on the encrypted resolver answering: with no answer the filter was
	// never compared against anything and no host was ever dialled, so
	// "healthy" would mean "asked nothing and heard nothing back".
	checked := 0
	for _, h := range hosts {
		if r, ok := final[h]; ok && r.Path != probe.PathSkipped {
			checked++
		}
	}
	if checked == 0 {
		problems = append(problems,
			"nothing was verified: no host resolved through the encrypted resolver, so neither "+
				"the filter nor the strategy was checked - the resolver itself may be blocked on this network")
	}

	return reportDiagnosis(problems, hosts, true)
}

// reportDiagnosis prints the verdict and the commands that fix it, and turns it
// into an exit code so the command can be used in a scheduled check.
//
// The commands are printed with the actual host names in them, so they can be
// pasted rather than reconstructed.
func reportDiagnosis(problems, hosts []string, installed bool) int {
	if len(problems) == 0 {
		fmt.Println("\nhealthy: nothing above needs attention.")
		return 0
	}
	fmt.Println("\ndiagnosis:")
	for _, p := range problems {
		fmt.Printf("  ! %s\n", p)
	}

	// With no service installed there is nothing to refresh or re-search, and
	// naming those commands would send the user at something that answers
	// "not installed". Whatever the problem was, its own line already carries
	// the fix.
	if !installed {
		return 1
	}

	names := "<domain>..."
	if len(hosts) > 0 {
		names = strings.Join(hosts, " ")
	}
	fmt.Println("\nwhat to run:")
	fmt.Println("  dpi refresh               same strategy, current addresses (fixes a stale filter)")
	fmt.Println("  dpi refresh -fix-dns      the same, and fix the resolver too")
	fmt.Printf("  dpi auto %-16s search again, for when the strategy itself is dead\n", names)
	return 1
}

// cmdRefresh reinstalls the strategy that is already installed, with the
// addresses the hosts resolve to now.
//
// It exists because the expensive part of this tool is the search, and a stale
// filter does not invalidate its result: the strategy still works, it is simply
// aimed at addresses the CDN has stopped handing out. Re-running the search for
// that would cost minutes to arrive at the same strategy.
func cmdRefresh(args []string) int {
	fs := flag.NewFlagSet("refresh", flag.ExitOnError)
	service := fs.String("service", apply.DefaultServiceName, "windows service name")
	configDir := fs.String("config-dir", "config", "directory for the generated host list (default: where the installed one lives)")
	force := fs.Bool("force", false, "reinstall even when the filter already covers every live address")
	fixDNS := fs.Bool("fix-dns", false, "also switch the active interface to an encrypted resolver")
	dnsMode := fs.String("dns-mode", "resolver", "how to fix a forged resolver: resolver (switch the machine to encrypted DNS) or hosts (pin only these names, leaving the resolver alone)")
	fs.Parse(args) //nolint:errcheck // ExitOnError already handles failures

	ctx := context.Background()
	inst := apply.Inspect(ctx, *service)
	if inst.State == apply.StateAbsent {
		fmt.Fprintf(os.Stderr, "dpi refresh: service %q is not installed\n", *service)
		fmt.Fprintln(os.Stderr, "there is no strategy to refresh; run 'dpi auto <domain>...' instead")
		return 1
	}
	if len(inst.Profiles) == 0 {
		fmt.Fprintln(os.Stderr, "dpi refresh: the installed service names no strategy to reuse")
		fmt.Fprintln(os.Stderr, "run 'dpi auto <domain>...' to install one")
		return 1
	}

	// An unrestricted capture has no address list to go stale, so there is
	// nothing here to refresh. Checked before the host lists are demanded: such
	// an install may legitimately have none.
	if inst.Scope() == apply.ScopeAll {
		fmt.Println("the installed service captures all TLS traffic, so it has no address list to refresh.")
		if *fixDNS {
			known, _ := installedHosts(inst)
			abs, err := filepath.Abs(*configDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "dpi refresh: %v\n", err)
				return 1
			}
			return fixDNSNow(ctx, abs, known, *dnsMode)
		}
		fmt.Println("nothing to do.")
		return 0
	}

	// Every profile must be rebuilt exactly as installed, and a profile whose
	// host list is gone cannot be: reinstalling it without hosts would widen it
	// from a few names to everything inside the filter. Each list is read once
	// and kept, so the rebuilt plan cannot disagree with what was validated.
	profHosts := make([][]string, len(inst.Profiles))
	var hosts []string
	for i, prof := range inst.Profiles {
		if prof.Hostlist == "" {
			fmt.Fprintf(os.Stderr, "dpi refresh: profile %d names no host list, so its scope cannot be rebuilt\n", i+1)
			return 1
		}
		names, err := hostlistNames(prof.Hostlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dpi refresh: cannot read %s: %v\n", prof.Hostlist, err)
			fmt.Fprintln(os.Stderr, "the hosts of that profile are unknown; reinstall with 'dpi auto <domain>...'")
			return 1
		}
		if len(names) == 0 {
			fmt.Fprintf(os.Stderr, "dpi refresh: host list %s is empty\n", prof.Hostlist)
			return 1
		}
		profHosts[i] = names
		hosts = append(hosts, names...)
	}
	hosts = uniqueDomains(hosts)

	// The config directory of the installed service is where its host lists
	// already live; writing the refreshed ones anywhere else would leave the
	// old files behind as the ones a user goes looking at.
	cfgDir := filepath.Dir(inst.Profiles[0].Hostlist)
	if cfgDir == "" || cfgDir == "." {
		cfgDir = *configDir
	}
	binAbs, luaAbs, cfgAbs, err := absPaths(inst.BinaryPath, refreshLuaDir(inst), cfgDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi refresh: %v\n", err)
		return 1
	}

	// Addresses come from the encrypted resolver for the same reason as in
	// apply: under a hijack the system answer is the block page.
	fmt.Printf("resolving %d host(s) through encrypted DNS...\n", len(hosts))
	addrsOf := make(map[string][]string, len(hosts))
	var current []string
	for _, r := range probe.Run(ctx, probe.Config{}, hosts) {
		if len(r.AllRealIPs()) == 0 {
			fmt.Printf("  %-24s no address; it cannot be targeted\n", r.Domain)
			continue
		}
		addrsOf[r.Domain] = r.AllRealIPs()
		current = append(current, r.AllRealIPs()...)
		fmt.Printf("  %-24s %s\n", r.Domain, strings.Join(r.AllRealIPs(), " "))
	}

	// With no answer at all there is nothing to compare against. Saying
	// "nothing to do" here would read as "all good", when in fact the one
	// thing this command exists to check could not be checked — and a filter
	// rebuilt from an empty answer would carry no addresses at all.
	if len(current) == 0 {
		fmt.Fprintln(os.Stderr, "\ndpi refresh: no host resolved through the encrypted resolver,")
		fmt.Fprintln(os.Stderr, "so the installed filter could not be compared against anything.")
		fmt.Fprintln(os.Stderr, "the existing service was left untouched; the resolver may be blocked here.")
		return 1
	}

	drift := apply.CompareAddresses(inst.Addresses, current)
	if !drift.Degraded() && !*force {
		fmt.Printf("\nthe installed filter already covers every live address (%d installed).\n", len(inst.Addresses))
		if len(drift.Stale) > 0 {
			fmt.Printf("%d of them are no longer in use, which costs nothing.\n", len(drift.Stale))
		}
		// Reinstalling would be pointless, but an explicit -fix-dns is a
		// separate request and must still be honoured; a "nothing to do" that
		// silently skipped it would leave the browser broken.
		if *fixDNS {
			return fixDNSNow(ctx, cfgAbs, hosts, *dnsMode)
		}
		fmt.Println("nothing to do; re-run with -force to reinstall anyway.")
		return 0
	}
	if drift.Degraded() {
		fmt.Printf("\n%d live address(es) were outside the installed filter: %s\n",
			len(drift.Missing), strings.Join(drift.Missing, " "))
	}

	plan := apply.Plan{
		Profiles:    rebuildProfiles(inst, profHosts, addrsOf),
		Scope:       apply.ScopeTargeted,
		BinaryPath:  binAbs,
		LuaDir:      luaAbs,
		ConfigDir:   cfgAbs,
		ServiceName: *service,
		BlockQUIC:   true,
	}

	// Validate before removing anything: a plan that cannot be installed must
	// not be allowed to take the working service down with it.
	if err := plan.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "dpi refresh: %v\n", err)
		fmt.Fprintln(os.Stderr, "the existing service was left untouched")
		return 1
	}

	fmt.Printf("\nreplacing service %q...\n", *service)
	if _, err := plan.Remove(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "dpi refresh: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: replacing a service needs Administrator")
		return 1
	}
	code := runPlan(ctx, plan, true, *fixDNS, *dnsMode, false)
	// Refresh is a replacement, so a failed install leaves the machine with no
	// bypass at all — a state the user must not have to infer.
	if code != 0 && apply.Status(ctx, *service) == apply.StateAbsent {
		fmt.Fprintln(os.Stderr, "\nthe old service was removed and the new one did not install:")
		fmt.Fprintln(os.Stderr, "no bypass is active right now. re-run 'dpi refresh' as Administrator.")
	}
	return code
}

// rebuildProfiles turns an installed configuration back into plan profiles,
// with the addresses its hosts resolve to now.
//
// The pairing is the whole point: profHosts[i] holds the names of the i-th
// installed profile, and each profile keeps its own strategy, its own hosts and
// only their addresses. Mixing them up would install a working strategy against
// the wrong names — which looks healthy and fixes nothing.
//
// Fallbacks are carried only for a profile that was installed rotating. Reusing
// the later strategies of a non-rotating profile would turn a plain install into
// a rotating one, doubling the kernel filter behind the user's back.
func rebuildProfiles(inst apply.Installed, profHosts [][]string, addrsOf map[string][]string) []apply.Profile {
	out := make([]apply.Profile, 0, len(inst.Profiles))
	for i, prof := range inst.Profiles {
		if i >= len(profHosts) {
			break
		}
		rebuilt := apply.Profile{Stages: prof.Stages(), Hosts: profHosts[i]}
		if prof.Rotating {
			rebuilt.Fallbacks = prof.Fallbacks()
		}
		for _, h := range profHosts[i] {
			rebuilt.Addrs = append(rebuilt.Addrs, addrsOf[h]...)
		}
		out = append(out, rebuilt)
	}
	return out
}

// refreshLuaDir prefers the library directory the service was installed with,
// falling back to the built-in default when the command line did not name one.
func refreshLuaDir(inst apply.Installed) string {
	if inst.LuaDir != "" {
		return inst.LuaDir
	}
	return engine.DefaultConfig().LuaDir
}

// resolveEngine fills in the default engine locations without duplicating them
// here, so the default lives in exactly one place.
func resolveEngine(cfg engine.Config) engine.Config {
	def := engine.DefaultConfig()
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = def.BinaryPath
	}
	if cfg.LuaDir == "" {
		cfg.LuaDir = def.LuaDir
	}
	return cfg
}

func cmdSearch(args []string) int {
	fs := flag.NewFlagSet("search", flag.ExitOnError)
	screen := fs.Int("screen-attempts", 1, "handshakes per candidate while screening")
	verify := fs.Int("verify-attempts", 10, "handshakes per survivor while verifying")
	timeout := fs.Duration("timeout", 5*time.Second, "per-step timeout")
	binary := fs.String("engine", "", "path to winws2.exe (default tools/zapret-winws/winws2.exe)")
	luaDir := fs.String("lua", "", "path to the zapret2 lua directory (default tools/zapret-winws/lua)")
	allowRisky := fs.Bool("allow-risky", true, "allow the TTL-based tier when safe tiers find nothing")
	bandwidth := fs.Bool("bandwidth", true, "measure real transfer speed among the tied-fastest")
	parallel := fs.Int("parallel", 1, "screen this many candidates at once (each in its own source-port lane; verification stays serial)")
	quiet := fs.Bool("quiet", false, "do not print per-candidate progress")
	fs.Parse(args) //nolint:errcheck // ExitOnError already handles failures

	domains := uniqueDomains(fs.Args())
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "dpi search: need at least one domain")
		return 2
	}

	ctx := context.Background()
	probeCfg := probe.Config{Timeout: *timeout}
	engCfg := engine.Config{BinaryPath: *binary, LuaDir: *luaDir}

	results := probe.Run(ctx, probeCfg, domains)
	targets, blocked := reportProbe(results)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "dpi search: no usable targets")
		return 1
	}
	if blocked == 0 {
		fmt.Println("\nNothing is blocked at the TLS layer on these names, so there is nothing to search for.")
		return 0
	}

	maxTier := search.TierAggressive
	if !*allowRisky {
		maxTier = search.TierFake
	}

	opts := search.Options{
		ScreenAttempts: *screen,
		VerifyAttempts: *verify,
		MaxTier:        maxTier,
		Bandwidth:      *bandwidth,
		Concurrency:    *parallel,
	}
	if *parallel > 1 {
		// Worth saying out loud: it multiplies the number of live engine
		// instances, and it has not been verified against a real engine yet.
		fmt.Printf("\nscreening %d candidates at once (%d engine instances at a time); ranking stays serial\n",
			*parallel, *parallel*len(targets))
	}
	if !*quiet {
		opts.OnCandidate = func(c search.Candidate, survived bool, err error) {
			switch {
			case err != nil:
				// Show why: a rejected candidate is usually a stage the engine
				// will not parse, which is a bug in the space, not a result.
				fmt.Printf("  [%-10s] %-64s rejected: %s\n", c.Tier, c, detail(err.Error(), false))
			case survived:
				fmt.Printf("  [%-10s] %-64s WORKS\n", c.Tier, c)
			default:
				fmt.Printf("  [%-10s] %-64s no\n", c.Tier, c)
			}
		}
	}

	fmt.Printf("\nscreening the strategy space against %d blocked target(s)...\n", blocked)
	start := time.Now()
	report, err := search.Run(ctx, engCfg, probeCfg, targets, opts)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi search: %v\n", err)
		if errors.Is(err, engine.ErrFilterBusy) {
			fmt.Fprintln(os.Stderr, "hint: another bypass tool is already filtering this traffic - stop it first")
		}
		if errors.Is(err, engine.ErrNotReady) {
			fmt.Fprintln(os.Stderr, "hint: winws2 needs Administrator to load the WinDivert driver")
		}
		return 1
	}

	printSearchReport(report, elapsed)
	if len(report.Ranked) == 0 {
		return 1
	}
	return 0
}

// reportProbe keeps only names that are actually blocked at the TLS layer.
// Searching against a working name would rank every candidate equally and
// prove nothing.
func reportProbe(results []probe.Result) ([]measure.Target, int) {
	fmt.Println("probing targets through encrypted DNS...")
	var targets []measure.Target
	blocked := 0
	for _, r := range results {
		addr := searchAddr(r)
		switch {
		case addr == "":
			fmt.Printf("  %-24s skipped: no address from the encrypted resolver\n", r.Domain)
		case r.DesyncApplies():
			targets = append(targets, measure.Target{Domain: r.Domain, Addr: addr})
			blocked++
			fmt.Printf("  %-24s %-18s %s - will search\n", r.Domain, addr, r.Path)
		default:
			fmt.Printf("  %-24s %-18s %s - not blocked here, skipped\n", r.Domain, addr, r.Path)
		}
	}
	return targets, blocked
}

// searchAddr is the address an engine instance is pinned to while this host is
// searched, or "" when there is none to trust.
//
// IPv4 first, because that is the address the probe classified and every
// measurement in CLAUDE.md was taken against. An IPv6-only name still gets
// searched rather than skipped: the engine pin and the prober both handle it,
// which they did not before the filter learned about IPv6 — and the skip
// message was then simply untrue.
//
// The system resolver's answer is never used, however tempting a fallback it
// looks. Under a hijack it is the block page, and the search would then measure
// strategies against the censor's own server and score them as working.
func searchAddr(r probe.Result) string {
	if len(r.RealIPs) > 0 {
		return r.RealIPs[0]
	}
	if len(r.RealIPs6) > 0 {
		return r.RealIPs6[0]
	}
	return ""
}

func printSearchReport(report search.Report, elapsed time.Duration) {
	tiers := make([]string, 0, len(report.TiersSearched))
	for _, t := range report.TiersSearched {
		tiers = append(tiers, t.String())
	}
	fmt.Printf("\nscreened %d candidates across tier(s) %s in %s, %d survived\n",
		report.Screened, strings.Join(tiers, "+"), elapsed.Round(time.Millisecond), report.Survivors)
	if report.AggressiveSkipped {
		fmt.Println("the TTL-based tier was not needed: a safe strategy already works")
	}
	if report.Unverified > 0 {
		// These screened successfully and then could not be verified, so they
		// are missing from the table below. Saying so beats a silent gap.
		fmt.Printf("%d candidate(s) screened but could not be verified, so they are not ranked\n",
			report.Unverified)
	}

	if len(report.Ranked) == 0 {
		fmt.Println("\nNo strategy worked. The censor may require techniques outside this space,")
		fmt.Println("or the block may not be at the TLS layer at all - re-run 'dpi probe' to check.")
		return
	}

	if report.Noise > 0 {
		fmt.Printf("\nranked results, best first (medians within %s share a group and are not ordered):\n", ms(report.Noise))
	} else {
		fmt.Println("\nranked results, best first (uncalibrated: close medians may be ordered by noise):")
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "  #\tGROUP\tTIER\tOK/ATTEMPTS\tMEDIAN-TLS\tSPREAD\tTTFB\tSTRATEGY")
	for i, r := range report.Ranked {
		_, _ = fmt.Fprintf(w, "  %d\t%s\t%s\t%d/%d\t%s\t%s\t%s\t%s\n",
			i+1, groupLabel(r.Group), r.Candidate.Tier, r.Score.Successes, r.Score.Attempts,
			ms(r.Score.MedianTLS), spread(r.Score.SpreadTLS),
			ms(r.TTFB), r.Candidate)
	}
	_ = w.Flush()
	if report.BandwidthMeasured > 0 {
		fmt.Printf("\ntime to first byte measured for the %d tied-fastest; a gap under %.0f%% counts as equal\n",
			report.BandwidthMeasured, measure.TTFBTolerance*100)
		fmt.Println("(throughput is deliberately not ranked on: it moves ~40% between runs)")
	}

	best := report.Best()
	pick := preferred(best)
	fmt.Println()
	switch {
	case !pick.FullCoverage():
		fmt.Printf("no candidate fixed every target; the best is partial (%d/%d):\n",
			pick.Score.Successes, pick.Score.Attempts)
	case len(best) > 1:
		fmt.Printf("%d strategies are tied for fastest (%s within %s) - the simplest of them:\n",
			len(best), ms(pick.Score.MedianTLS), ms(report.Noise))
	default:
		fmt.Printf("fastest fully working strategy (%s, %s):\n", pick.Candidate.Tier, ms(pick.Score.MedianTLS))
	}
	for _, stage := range pick.Candidate.Stages {
		fmt.Printf("  -stage %s\n", stage)
	}
}

// preferred picks one strategy out of a tied group.
//
// Inside a tie there is no speed argument left, so the choice is made on what
// matters after it: fewer stages age better when the censor updates, and a
// lower tier touches less of the network — a pure split injects nothing at all,
// while a fake tier puts extra packets on the wire. The final comparison on the
// strategy text exists only to make the answer deterministic; without it the
// pick would follow the noise-dependent order inside the group and change
// between identical runs.
func preferred(group []search.Ranked) search.Ranked {
	best := group[0]
	for _, r := range group[1:] {
		if lessInvasive(r, best) {
			best = r
		}
	}
	return best
}

func lessInvasive(a, b search.Ranked) bool {
	if len(a.Candidate.Stages) != len(b.Candidate.Stages) {
		return len(a.Candidate.Stages) < len(b.Candidate.Stages)
	}
	if a.Candidate.Tier != b.Candidate.Tier {
		return a.Candidate.Tier < b.Candidate.Tier
	}
	return a.Candidate.String() < b.Candidate.String()
}

// groupLabel renders group indices as letters, which reads as "these are
// equivalent" far better than a repeated number does.
func groupLabel(n int) string {
	if n < 26 {
		return string(rune('A' + n))
	}
	return fmt.Sprintf("G%d", n)
}

func spread(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return "+/-" + ms(d)
}

func printScore(s measure.Score) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "  DOMAIN\tOK/ATTEMPTS\tRATE\tMEDIAN-TLS\tOUTCOMES")
	for _, t := range s.Targets {
		_, _ = fmt.Fprintf(w, "  %s\t%d/%d\t%.0f%%\t%s\t%s\n",
			t.Domain, t.Successes, t.Attempts, t.SuccessRate()*100,
			ms(t.MedianTLS), outcomes(t.Outcomes))
	}
	_ = w.Flush()
}

// printOutcome states plainly whether the strategy repaired anything, counting
// only targets the baseline showed as broken. A target that was never blocked
// proves nothing about the strategy.
func printOutcome(base, withStrategy measure.Score) {
	byDomain := map[string]measure.TargetScore{}
	for _, t := range base.Targets {
		byDomain[t.Domain] = t
	}

	var wasBlocked, nowWorking, regressed int
	for _, t := range withStrategy.Targets {
		b, ok := byDomain[t.Domain]
		if !ok {
			continue
		}
		switch {
		case b.Successes == 0:
			wasBlocked++
			if t.Successes == t.Attempts {
				nowWorking++
			}
		case t.Successes < b.Successes:
			regressed++
		}
	}

	switch {
	case wasBlocked == 0:
		fmt.Println("verdict: nothing was blocked at baseline, so this run proves nothing about the strategy.")
	case nowWorking == wasBlocked:
		baseline := ms(base.MedianTLS)
		if base.Successes == 0 {
			baseline = "never succeeded"
		}
		fmt.Printf("verdict: the strategy fixed all %d blocked target(s), median handshake %s (baseline: %s).\n",
			wasBlocked, ms(withStrategy.MedianTLS), baseline)
	case nowWorking > 0:
		fmt.Printf("verdict: the strategy fixed %d of %d blocked target(s) - partial, keep searching.\n",
			nowWorking, wasBlocked)
	default:
		fmt.Printf("verdict: the strategy fixed none of the %d blocked target(s).\n", wasBlocked)
	}
	if regressed > 0 {
		fmt.Printf("warning: %d target(s) that worked at baseline got worse under this strategy.\n", regressed)
	}
}

func outcomes(m map[probe.PathStatus]int) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, m[probe.PathStatus(k)]))
	}
	return strings.Join(parts, " ")
}

// summarise turns per-domain results into the one thing the user needs to know:
// which remedy applies. The two layers are reported separately because a domain
// can be hit by both at once and fixing only one leaves it blocked.
//
// showDNSRemedy is off when the caller is about to fix DNS itself; printing
// manual instructions for something the tool is doing anyway reads as a
// contradiction.
func summarise(results []probe.Result, showDNSRemedy bool) {
	var desync, dnsLayer, suspect, ipLayer, certBad int
	for _, r := range results {
		if r.DesyncApplies() {
			desync++
		}
		if r.NeedsEncryptedDNS() {
			dnsLayer++
		}
		if r.DNS == probe.DNSSuspect {
			suspect++
		}
		switch r.Path {
		case probe.PathIPBlock:
			ipLayer++
		case probe.PathCertBad:
			certBad++
		}
	}

	if ip, n := sharedBlockAddress(results); n > 1 {
		fmt.Printf("%s is returned for %d different blocked names - that address is a block page, not a host.\n", ip, n)
	}
	if dnsLayer > 0 {
		fmt.Printf("%d name(s) forged by the system resolver - no desync strategy can fix that layer.\n", dnsLayer)
	}
	if suspect > 0 {
		fmt.Printf("%d name(s) resolve differently than the encrypted resolver, unproven - probe several names together to confirm.\n", suspect)
	}
	if certBad > 0 {
		fmt.Printf("%d name(s) answered with the wrong certificate - the connection is being intercepted.\n", certBad)
	}
	if ipLayer > 0 {
		fmt.Printf("%d name(s) blocked at the IP layer - no desync strategy can reach them.\n", ipLayer)
	}
	if desync > 0 {
		fmt.Printf("%d name(s) killed during the TLS handshake - a desync strategy search applies here.\n", desync)
	}
	// Both layers can hit the same name, and fixing only one leaves it blocked,
	// so the DNS remedy is spelled out whenever it might apply rather than only
	// when nothing else does. An unproven suspicion counts: probing one name
	// alone cannot correlate a shared block page, and withholding the remedy
	// there would hide the fix from the most common single-name use.
	if dnsLayer > 0 || suspect > 0 {
		if showDNSRemedy {
			printDNSRemedy()
		}
		return
	}
	if desync > 0 {
		return
	}
	if suspect == 0 && ipLayer == 0 && certBad == 0 {
		fmt.Println("No interference detected on these names.")
	}
}

// sharedBlockAddress finds an address the system resolver hands out for more
// than one hijacked name. A censor typically points every blocked name at one
// block page, whereas a CDN address shared by unrelated names would still have
// passed the DNS comparison.
func sharedBlockAddress(results []probe.Result) (string, int) {
	counts := map[string]int{}
	for _, r := range results {
		if !r.NeedsEncryptedDNS() || len(r.SysIPs) == 0 {
			continue
		}
		for _, ip := range r.SysIPs {
			counts[ip]++
		}
	}
	// Sort for a deterministic answer when several addresses tie.
	ips := make([]string, 0, len(counts))
	for ip := range counts {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	best, bestN := "", 0
	for _, ip := range ips {
		if counts[ip] > bestN {
			best, bestN = ip, counts[ip]
		}
	}
	return best, bestN
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func firstIP(ips []string) string {
	if len(ips) == 0 {
		return "-"
	}
	s := ips[0]
	if len(ips) > 1 {
		s += fmt.Sprintf("+%d", len(ips)-1)
	}
	return s
}

func ms(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func helloSize(n int) string {
	if n == 0 {
		return "-"
	}
	// A ClientHello beyond a typical 1460-byte MSS spans multiple segments,
	// which changes which desync strategies can work at all.
	if n > 1460 {
		return fmt.Sprintf("%dB!", n)
	}
	return fmt.Sprintf("%dB", n)
}

func detail(s string, full bool) string {
	if s == "" {
		return "-"
	}
	s = strings.ReplaceAll(s, "\n", " ")
	if !full && len(s) > 40 {
		return s[:37] + "..."
	}
	return s
}

// dnsModeHosts pins the names in the hosts file instead of changing the
// machine's resolver.
//
// It is the DNS half of the same principle the kernel filter follows: touch the
// site, not the machine. Switching the system resolver fixes every name on the
// computer and routes all of its DNS elsewhere; pinning fixes exactly the names
// asked for and leaves everything else resolving as it did.
//
// The cost is that a pinned address is a snapshot, and a stale one is worse
// than a stale kernel filter: the filter merely stops helping, while a stale
// pin actively sends the browser to an address that no longer serves the site.
// `dpi doctor` compares the pins against current resolution for that reason.
const dnsModeHosts = "hosts"

// pinHosts writes the managed hosts block and checks the result the way a
// browser would see it.
func pinHosts(ctx context.Context, configDir string, hosts []string) int {
	hosts = expandWithWWW(hosts)
	if len(hosts) == 0 {
		return 0
	}

	// Resolved again here rather than reused from the plan: the plan carries
	// one merged address list per profile, and a hosts entry needs to know
	// which address belongs to which name.
	fmt.Printf("\npinning %d name(s) in the hosts file (the system resolver is left alone)...\n", len(hosts))
	var entries []apply.HostsEntry
	for _, r := range probe.Run(ctx, probe.Config{}, hosts) {
		addrs := r.AllRealIPs()
		if len(addrs) == 0 {
			fmt.Printf("  %-24s no address from the encrypted resolver; not pinned\n", r.Domain)
			continue
		}
		entries = append(entries, apply.HostsEntry{Host: r.Domain, Addrs: addrs})
		fmt.Printf("  %-24s %s\n", r.Domain, strings.Join(addrs, " "))
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "\ndpi: nothing could be resolved, so nothing was pinned.")
		fmt.Fprintln(os.Stderr, "the encrypted resolver may be blocked on this network.")
		return 1
	}

	if err := apply.WriteHosts(configDir, entries); err != nil {
		fmt.Fprintf(os.Stderr, "\ndpi: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: editing the hosts file needs Administrator")
		return 1
	}
	fmt.Printf("  wrote %s\n", apply.HostsPath())
	_ = apply.FlushDNSCache()

	return reportBrowserView(ctx, hosts,
		"pinned. Nothing else on this machine resolves differently than before.")
}

// reportBrowserView connects the way a browser does — through the system
// resolver, verifying the certificate — and reports what it finds.
//
// Everything else in this tool measures the address the *encrypted* resolver
// gave. A browser uses the system one, and that difference is how this tool
// once reported both layers fixed while the user's browser sat on the censor's
// certificate.
func reportBrowserView(ctx context.Context, hosts []string, success string) int {
	fmt.Println("\nnow connecting the way a browser does, through the system resolver...")
	blocked := 0
	for _, h := range hosts {
		status, detail := probe.SystemPath(ctx, probe.Config{Timeout: 5 * time.Second}, h)
		fmt.Printf("  %-24s %s\n", h, status)
		if status == probe.PathOk {
			continue
		}
		blocked++
		if status == probe.PathCertBad {
			fmt.Println("      the certificate is not this site's - you are still being sent")
			fmt.Println("      to the block page")
		} else if detail != "" {
			fmt.Printf("      %s\n", detail)
		}
	}
	if blocked > 0 {
		fmt.Printf("\n%d name(s) still land somewhere a browser will refuse.\n", blocked)
		fmt.Println("A browser keeps its own DNS cache that no external command can clear, so")
		fmt.Println("close every window of it and open it again, then retry.")
		return 0
	}

	// Said plainly rather than as "both layers are in place": a certificate
	// that verifies proves the connection reached the real server, not that the
	// page shows the real content. A censor can serve substitute content — a
	// court notice at the blocked name — and nothing here inspects the page.
	fmt.Printf("\n%s\n", success)
	fmt.Println("Open the site in a browser to confirm the content is the real one:")
	fmt.Println("a valid certificate proves where you connected, not what you were shown.")
	return 0
}

// cmdDNS fixes the DNS layer on its own, with no service and no kernel driver.
//
// It exists because on some links the DNS layer is the whole problem. The
// development line censors only by forging DNS answers — the real address
// completes a TLS handshake untouched — so installing a desync service there
// achieves nothing, and requiring one in order to reach the DNS remedy meant
// loading a kernel driver to solve a problem it has no part in.
func cmdDNS(args []string) int {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	mode := fs.String("mode", dnsModeHosts,
		"hosts (pin only these names, leaving the machine's resolver alone) or resolver (switch the interface to encrypted DNS)")
	undo := fs.Bool("undo", false, "remove whatever this command previously changed")
	configDir := fs.String("config-dir", "config", "directory for the saved originals")
	fs.Parse(args) //nolint:errcheck // ExitOnError already handles failures

	ctx := context.Background()
	abs, err := filepath.Abs(*configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi dns: %v\n", err)
		return 1
	}

	if *undo {
		return restoreSavedDNS(ctx, abs)
	}

	domains := uniqueDomains(fs.Args())
	if len(domains) == 0 && *mode == dnsModeHosts {
		fmt.Fprintln(os.Stderr, "dpi dns: name the domains to pin, e.g. dpi dns discord.com")
		fmt.Fprintln(os.Stderr, "or use -mode=resolver to switch the whole machine to encrypted DNS")
		return 2
	}
	return fixDNSNow(ctx, abs, domains, *mode)
}

func cmdDivert(args []string) int {
	fs := flag.NewFlagSet("divert", flag.ExitOnError)
	asService := fs.Bool("service", false, "run as a Windows Service (desynq-dns)")
	dohURL := fs.String("doh", "", "upstream DoH URL (default Cloudflare)")
	toolsDir := fs.String("tools", filepath.Join("tools", "zapret-winws"), "directory containing WinDivert.dll")
	fs.Parse(args) //nolint:errcheck

	if *asService {
		if err := windns.RunService(*toolsDir, *dohURL); err != nil {
			fmt.Fprintf(os.Stderr, "desynq divert service: %v\n", err)
			return 1
		}
		return 0
	}

	d, err := windns.New(*toolsDir, *dohURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpi divert: %v\n", err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := d.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "dpi divert start: %v\n", err)
		return 1
	}
	defer d.Stop()

	_ = apply.FlushDNSCache()
	fmt.Println("transparent DNS (DoH) & QUIC drop diverter active. Press Ctrl+C to stop.")
	<-ctx.Done()
	_ = apply.FlushDNSCache()
	fmt.Println("\ndiverter stopped.")
	return 0
}

// checkPins reports on the names pinned in the hosts file.
//
// A stale pin is worse than a stale kernel filter and deserves its own check.
// The filter merely stops helping when a host moves; a pin keeps sending the
// browser to an address that no longer serves the site, so the name breaks in a
// way it would not have broken without this tool. It is also the one remedy
// that works with no service at all, so it has to be diagnosed even when
// nothing is installed.
func checkPins(ctx context.Context) (pinned []string, problems []string) {
	entries, err := apply.ReadManagedHosts()
	if err != nil || len(entries) == 0 {
		return nil, nil
	}

	fmt.Printf("\npinned    %d name(s) in %s\n", len(entries), apply.HostsPath())
	for _, e := range entries {
		pinned = append(pinned, e.Host)
	}

	results := probe.Run(ctx, probe.Config{}, pinned)
	current := make(map[string][]string, len(results))
	for _, r := range results {
		current[r.Domain] = r.AllRealIPs()
	}

	for _, e := range entries {
		live := current[e.Host]
		if len(live) == 0 {
			fmt.Printf("  %-24s could not be resolved, so the pin cannot be checked\n", e.Host)
			continue
		}
		drift := apply.CompareAddresses(e.Addrs, live)
		switch {
		case drift.Degraded():
			fmt.Printf("  %-24s STALE - pinned %s, now %s\n",
				e.Host, strings.Join(e.Addrs, " "), strings.Join(live, " "))
			problems = append(problems, fmt.Sprintf(
				"the pin for %s is stale: it sends the browser to an address that no longer "+
					"serves the site, which is worse than not pinning at all - re-pin with: dpi dns %s",
				e.Host, e.Host))
		case len(drift.Stale) > 0:
			fmt.Printf("  %-24s ok (%d pinned address(es) no longer in use, harmless)\n",
				e.Host, len(drift.Stale))
		default:
			fmt.Printf("  %-24s ok\n", e.Host)
		}
	}
	return pinned, problems
}

// savedDNSMode records which DNS remedy was applied, or "" when none was.
//
// Stored rather than inferred, because a later run has no way to tell whether
// the resolver was changed by this tool or by the user.
func savedDNSMode(fixDNS bool, mode string) string {
	if !fixDNS {
		return ""
	}
	if mode == "" {
		return "resolver"
	}
	return mode
}
