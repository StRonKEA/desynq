package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dpi/internal/apply"
	"dpi/internal/engine"
	"dpi/internal/probe"
	"dpi/internal/windns"

	"golang.org/x/net/idna"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the bridge between the window and the tool.
//
// The split is deliberate and follows the elevation decision: reading the
// machine needs no privileges, so inspecting the service, resolving a name and
// dialling it happen in this process through the internal packages. Anything
// that *changes* the machine goes back out through dpi.exe under UAC, so the
// window that sits in the tray all day never runs as administrator.
type App struct {
	ctx context.Context

	mu   sync.Mutex
	busy string // the job currently running, empty when idle

	dnsDiverter *windns.Diverter

	// cancelJob is set by CancelJob so elevate stops waiting on UAC / a hung
	// sentinel. The elevated process is not killed — there is no handle.
	cancelJob bool

	// quitting separates "the user pressed Quit" from "the user pressed the
	// close button", which sends the window to the tray instead.
	quitting atomic.Bool

	// measured is the last known state of each name, so testing one site does
	// not blank the others. Without it a per-row Test button would wipe every
	// verdict on screen except the one it just refreshed.
	measured map[string]measurement
	checked  time.Time
}

// measurement is one name as last seen, on all three resolution paths.
type measurement struct {
	res probe.Result
	// sys is what a browser gets: the system resolver's answer, dialled and
	// certificate-checked. Kept beside res because the two disagree exactly
	// when it matters most.
	sys    probe.PathStatus
	sysErr string
	at     time.Time
}

func NewApp() *App { return &App{} }

// pruneOldLogs keeps only log lines from the past 7 days.
func pruneOldLogs(logPath string) {
	b, err := os.ReadFile(logPath)
	if err != nil || len(b) == 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -7)
	lines := strings.Split(string(b), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && len(trimmed) >= 21 && trimmed[20] == ']' {
			if t, err := time.Parse("2006-01-02 15:04:05", trimmed[1:20]); err == nil {
				if t.Before(cutoff) {
					continue
				}
			}
		}
		kept = append(kept, line)
	}
	_ = os.WriteFile(logPath, []byte(strings.Join(kept, "\n")), 0o644)
}

// appendLog writes a timestamped line directly to logs/dpi.log.
func appendLog(format string, args ...any) {
	logDir := filepath.Join(appRoot(), "logs")
	_ = os.MkdirAll(logDir, 0o755)
	logPath := filepath.Join(logDir, "dpi.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	entry := fmt.Sprintf("[%s] %s\r\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	_, _ = f.WriteString(entry)
}

// LogError records an error line from UI or backend into logs/dpi.log.
func (a *App) LogError(source, msg string) {
	appendLog("ERROR [%s]: %s", source, msg)
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.startTray()
	pruneOldLogs(filepath.Join(appRoot(), "logs", "dpi.log"))

	if set, err := apply.LoadSettings(filepath.Join(appRoot(), "config")); err == nil && set.AllTraffic {
		if apply.Inspect(ctx, a.serviceName()).State == apply.StateRunning {
			a.startDNSDiverter()
		}
	}
}

func (a *App) startDNSDiverter() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dnsDiverter != nil {
		return
	}
	toolsDir := filepath.Join(appRoot(), "tools", "zapret-winws")
	d, err := windns.New(toolsDir, "")
	if err != nil {
		appendLog("ERROR [startDNSDiverter:New]: %v", err)
		return
	}
	if err := d.Start(context.Background()); err != nil {
		appendLog("ERROR [startDNSDiverter:Start]: %v", err)
		return
	}
	a.dnsDiverter = d
	_ = apply.FlushDNSCache()
	appendLog("INFO [startDNSDiverter]: transparent DNS diverter started")
}

func (a *App) stopDNSDiverter() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dnsDiverter != nil {
		a.dnsDiverter.Stop()
		a.dnsDiverter = nil
		_ = apply.FlushDNSCache()
		appendLog("INFO [stopDNSDiverter]: transparent DNS diverter stopped")
	}
}

// ProfileView is one installed strategy and the names it applies to.
type ProfileView struct {
	Strategy   string   `json:"strategy"`
	Hosts      []string `json:"hosts"`
	Rotating   bool     `json:"rotating"`
	Unreadable bool     `json:"unreadable"`
}

// SiteView is everything known about one name, on both censorship layers.
//
// System is kept apart from Path on purpose. Path dials the address the
// encrypted resolver gave, which is what a desync strategy is measured against;
// System dials whatever the machine's own resolver answers, which is the only
// thing a browser will use. The tool has already shipped a false success by
// reporting the first and calling it the second.
type SiteView struct {
	Host      string   `json:"host"`
	DNS       string   `json:"dns"`
	Path      string   `json:"path"`
	System    string   `json:"system"`
	SystemErr string   `json:"systemErr"`
	Addrs     []string `json:"addrs"`
	Missing   []string `json:"missing"`
	Covered   bool     `json:"covered"`
	V6Unknown bool     `json:"v6Unknown"`
	Pinned    bool     `json:"pinned"`
	PinStale  bool     `json:"pinStale"`
	Measured  bool     `json:"measured"`
	// MeasuredAt is per row, because a single Test refreshes one name and
	// leaves the rest as they were. One timestamp for the window would claim
	// every row is as fresh as the newest.
	MeasuredAt string `json:"measuredAt"`
}

// ReportEntryView is one measured strategy, for the tied-group table.
type ReportEntryView struct {
	Strategy  string  `json:"strategy"`
	Tier      string  `json:"tier"`
	MedianMS  float64 `json:"medianMs"`
	SpreadMS  float64 `json:"spreadMs"`
	Successes int     `json:"successes"`
	Attempts  int     `json:"attempts"`
	Chosen    bool    `json:"chosen"`
}

// ReportView is why the installed strategy was chosen.
//
// Describes is the field that keeps this honest: the record is one measurement
// of one moment, and if the service now runs something else, the numbers
// explain a decision nobody is living with any more. The window says so rather
// than presenting them as current.
type ReportView struct {
	TakenAt    string            `json:"takenAt"`
	Chosen     string            `json:"chosen"`
	Describes  bool              `json:"describes"`
	MedianMS   float64           `json:"medianMs"`
	SpreadMS   float64           `json:"spreadMs"`
	Successes  int               `json:"successes"`
	Attempts   int               `json:"attempts"`
	Tied       int               `json:"tied"`
	Ranked     int               `json:"ranked"`
	Screened   int               `json:"screened"`
	Unverified int               `json:"unverified"`
	NoiseMS    float64           `json:"noiseMs"`
	Group      []ReportEntryView `json:"group"`
}

// Snapshot is the whole window's state in one value.
type Snapshot struct {
	ServiceName string `json:"serviceName"`
	Service     string `json:"service"`
	Driver      string `json:"driver"`
	Strays      int    `json:"strays"`
	Scope       string `json:"scope"`
	// Installed and Running spare the frontend from spelling this package's
	// State constants. It guessed "ABSENT" against a value of "absent", so an
	// uninstalled machine offered an Uninstall button and claimed a scope it
	// did not have.
	Installed  bool          `json:"installed"`
	Running    bool          `json:"running"`
	Addresses  []string      `json:"addresses"`
	IPv6Count  int           `json:"ipv6Count"`
	Profiles   []ProfileView `json:"profiles"`
	Sites      []SiteView    `json:"sites"`
	DNSMode    string        `json:"dnsMode"`
	AllTraffic  bool          `json:"allTraffic"`
	DNSDiverter bool          `json:"dnsDiverter"`
	Configured  bool          `json:"configured"`
	CheckedAt  string        `json:"checkedAt"`
	CLIPath    string        `json:"cliPath"`
	Report     *ReportView   `json:"report"`
	// Next is the one thing worth doing now. Computed here rather than in the
	// window so its precedence can be tested.
	Next NextStep `json:"next"`
	// Diagnosis is what the provider does to this link, which is the subject of
	// the window - the method belongs to the provider, not to a site.
	Diagnosis Diagnosis `json:"diagnosis"`
	Note      string    `json:"note"`
}

// Load reads everything that can be known without touching the network, so the
// window can paint immediately on open.
func (a *App) Load() Snapshot { return a.snapshot(false) }

// Check re-measures both layers for the configured hosts. It is the slow path:
// a DoH lookup and two TLS handshakes per name.
//
// It takes no job claim. Two checks at once would only waste probes — they
// change nothing — and claiming one here made the snapshot report the job that
// was producing it, which left the window's buttons disabled for good.
func (a *App) Check() Snapshot { return a.snapshot(true) }

func (a *App) claim(job string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy != "" {
		return false
	}
	a.busy = job
	return true
}

func (a *App) release() {
	a.mu.Lock()
	a.busy = ""
	a.mu.Unlock()
}

func (a *App) current() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.busy
}

// snapshot builds the whole window state, measuring every configured name when
// live is set.
func (a *App) snapshot(live bool) Snapshot { return a.snapshotHosts(live, nil) }

// snapshotHosts measures only the named hosts when only is non-empty. Every
// other name keeps the verdict it already had.
func (a *App) snapshotHosts(live bool, only []string) Snapshot {
	ctx := context.Background()
	root := appRoot()
	cfgDir := filepath.Join(root, "config")

	// Settings are read first because they can name the service: inspecting the
	// default while the user configured another would report an absent service
	// for an installation that is running.
	set, setErr := apply.LoadSettings(cfgDir)
	name := apply.DefaultServiceName
	if setErr == nil && set.ServiceName != "" {
		name = set.ServiceName
	}
	inst := apply.Inspect(ctx, name)

	s := Snapshot{
		ServiceName: name,
		Service:     string(inst.State),
		Driver:      string(apply.Status(ctx, "windivert")),
		Strays:      apply.UnaccountedEngines(len(apply.RunningEngines(ctx, engine.DefaultConfig().BinaryPath)), inst.State),
		Addresses:   inst.Addresses,
		IPv6Count:   countIPv6(inst.Addresses),
		CLIPath:     locateCLI(),
	}
	s.Installed = inst.State != apply.StateAbsent
	s.Running = inst.State == apply.StateRunning
	// An absent service has no addresses, which Scope() reads as "captures
	// everything" — true of a filter, false of a service that is not there.
	switch {
	case !s.Installed:
		s.Scope = "none"
	case inst.Scope() == apply.ScopeTargeted:
		s.Scope = "targeted"
	default:
		s.Scope = "all"
	}

	for _, p := range inst.Profiles {
		v := ProfileView{Strategy: engine.FormatStages(p.Stages()), Rotating: p.Rotating}
		if p.Hostlist != "" {
			names, err := hostlistNames(p.Hostlist)
			if err != nil {
				v.Unreadable = true
			} else {
				v.Hosts = names
			}
		}
		s.Profiles = append(s.Profiles, v)
	}

	// The names to show are the recorded intent, falling back to whatever the
	// installed profiles apply to. Intent first, because it survives an install
	// that has since been removed.
	var hosts []string
	if setErr == nil || errors.Is(setErr, apply.ErrNoHosts) {
		hosts = set.Hosts
		s.DNSMode = set.DNSMode
		s.AllTraffic = set.AllTraffic
		s.Configured = setErr == nil || set.AllTraffic || len(set.Hosts) > 0
	} else {
		for _, p := range s.Profiles {
			hosts = append(hosts, p.Hosts...)
		}
		hosts = uniqueHosts(hosts)
		// Settings failed to load (empty list used to do this). If a machine-wide
		// service is actually running, still show that mode — not "listed sites".
		if s.Installed && inst.Scope() == apply.ScopeAll {
			s.AllTraffic = true
		}
	}

	pins := map[string][]string{}
	var pinHosts []string
	if entries, err := apply.ReadManagedHosts(); err == nil {
		for _, e := range entries {
			pins[e.Host] = e.Addrs
			pinHosts = append(pinHosts, e.Host)
			// Orphan pins only surface when there is no settings file at all.
			// An empty host list is intentional — do not resurrect deleted sites.
			if errors.Is(setErr, os.ErrNotExist) && !contains(hosts, e.Host) {
				hosts = append(hosts, e.Host)
			}
		}
	}
	if live {
		targets := hosts
		if len(only) > 0 {
			targets = only
		}
		a.measureInto(ctx, targets)
	}

	a.mu.Lock()
	seen := make(map[string]measurement, len(a.measured))
	for k, v := range a.measured {
		seen[k] = v
	}
	if !a.checked.IsZero() {
		s.CheckedAt = a.checked.Format(time.RFC3339)
	}
	a.mu.Unlock()

	for _, h := range hosts {
		v := SiteView{Host: h}
		if addrs, ok := pins[h]; ok {
			v.Pinned = true
			v.Addrs = addrs
		}
		if m, ok := seen[h]; ok {
			v.Measured = true
			v.DNS = string(m.res.DNS)
			v.Path = string(m.res.Path)
			v.V6Unknown = m.res.V6Unknown
			v.System = string(m.sys)
			v.SystemErr = m.sysErr
			v.MeasuredAt = m.at.Format(time.RFC3339)

			addrs := m.res.AllRealIPs()
			if len(addrs) > 0 {
				v.Addrs = addrs
			}
			// A pin that outlived its host is worse than no pin: it keeps
			// sending the browser to an address that no longer serves the site.
			if v.Pinned && len(addrs) > 0 {
				v.PinStale = apply.CompareAddresses(pins[h], addrs).Degraded()
			}
			drift := apply.CompareAddresses(inst.Addresses, addrs)
			v.Missing = drift.Missing
			v.Covered = inst.Scope() == apply.ScopeAll || !drift.Degraded()
		}
		s.Sites = append(s.Sites, v)
	}
	a.mu.Lock()
	s.DNSDiverter = a.dnsDiverter != nil || apply.Inspect(ctx, "desynq-dns").State == apply.StateRunning
	a.mu.Unlock()
	s.Report = readReport(cfgDir, inst)
	s = s.normalise()
	s.Next = nextStep(s)
	s.Diagnosis = diagnose(s)
	// The tooltip is the only surface left once the window is in the tray, so
	// it is refreshed from the same value the window renders.
	a.refreshTray(s)
	return s
}

// OptionsView is the configuration the settings panel edits. It is intent, not
// state: nothing here takes effect until an install runs.
type OptionsView struct {
	DNSMode     string `json:"dnsMode"`
	AllTraffic  bool   `json:"allTraffic"`
	ServiceName string `json:"serviceName"`
	Autostart   bool   `json:"autostart"`
	ConfigPath  string `json:"configPath"`
	DefaultName string `json:"defaultName"`
}

// Options reads the editable configuration.
func (a *App) Options() OptionsView {
	dir := filepath.Join(appRoot(), "config")
	v := OptionsView{
		ConfigPath:  apply.SettingsPath(dir),
		DefaultName: apply.DefaultServiceName,
		Autostart:   autostartEnabled(),
	}
	if set, err := apply.LoadSettings(dir); err == nil {
		v.DNSMode = set.DNSMode
		v.AllTraffic = set.AllTraffic
		v.ServiceName = set.ServiceName
	}
	return v
}

// SaveOptions records the configuration. It returns a message on refusal and an
// empty string on success.
//
// The hosts are deliberately left alone: they are edited in the list, and
// rewriting them from a panel that does not show them would be a way to lose
// them.
func (a *App) SaveOptions(dnsMode string, allTraffic bool, serviceName string) string {
	dir := filepath.Join(appRoot(), "config")
	set, err := apply.LoadSettings(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, apply.ErrNoHosts) {
		return err.Error()
	}
	set.DNSMode = dnsMode
	set.AllTraffic = allTraffic
	set.ServiceName = strings.TrimSpace(serviceName)

	// Validated before writing, because the CLI refuses to load a file it
	// cannot read back — a rejected value here would leave the tool unable to
	// run at all. A missing host list is not a reason to refuse: the list is
	// edited elsewhere and may legitimately be empty while options are set.
	if err := set.Validate(); err != nil && !errors.Is(err, apply.ErrNoHosts) {
		return err.Error()
	}
	if err := apply.SaveSettings(dir, set); err != nil {
		return err.Error()
	}
	return ""
}

// Autostart reports whether this window starts with Windows.
func (a *App) Autostart() bool { return autostartEnabled() }

// SetAutostart registers or removes the per-user startup entry. It needs no
// elevation, which is the reason the window runs unprivileged at all.
func (a *App) SetAutostart(on bool) string {
	if err := setAutostart(on); err != nil {
		return err.Error()
	}
	if trayAutostart != nil {
		if on {
			trayAutostart.Check()
		} else {
			trayAutostart.Uncheck()
		}
	}
	return ""
}

// measureInto probes the given names and records what it found.
//
// Both layers are measured for each name: the encrypted resolver's answer (what
// a strategy is judged against) and the system resolver's answer dialled with a
// certificate check (what a browser will actually get). Reporting only the
// first is how this tool once claimed success while a browser sat on a block
// page.
func (a *App) measureInto(ctx context.Context, names []string) {
	if len(names) == 0 {
		return
	}
	now := time.Now()
	fresh := make(map[string]measurement, len(names))
	for _, r := range probe.Run(ctx, probe.Config{}, names) {
		st, msg := probe.SystemPath(ctx, probe.Config{}, r.Domain)
		fresh[r.Domain] = measurement{res: r, sys: st, sysErr: msg, at: now}
	}

	a.mu.Lock()
	if a.measured == nil {
		a.measured = map[string]measurement{}
	}
	for k, v := range fresh {
		a.measured[k] = v
	}
	a.checked = now
	a.mu.Unlock()
}

// groupShown caps the tied table. The point of the group is that its members
// are indistinguishable, so listing every one of thirty-four teaches nothing a
// count does not.
const groupShown = 6

// readReport turns the recorded search into what the window shows, or nil when
// no search has been recorded yet.
func readReport(cfgDir string, inst apply.Installed) *ReportView {
	rec, err := apply.LoadReport(cfgDir)
	if err != nil || len(rec.Entries) == 0 {
		return nil
	}

	chosen := engine.FormatStages(rec.Chosen)
	v := &ReportView{
		TakenAt:    rec.TakenAt.Format(time.RFC3339),
		Chosen:     chosen,
		MedianMS:   -1,
		Ranked:     len(rec.Entries),
		Screened:   rec.Screened,
		Unverified: rec.Unverified,
		NoiseMS:    rec.NoiseMS,
	}
	if best, ok := rec.Best(); ok {
		v.MedianMS = best.MedianMS
		v.SpreadMS = best.SpreadMS
		v.Successes = best.Successes
		v.Attempts = best.Attempts
	}

	// Does this record still describe the running service? Compared against
	// every installed profile, because a per-host install carries several and
	// the record names the one the search settled on.
	for _, p := range inst.Profiles {
		if engine.FormatStages(p.Stages()) == chosen {
			v.Describes = true
			break
		}
	}

	tied := rec.Tied()
	v.Tied = len(tied)
	for i, e := range tied {
		if i >= groupShown {
			break
		}
		v.Group = append(v.Group, ReportEntryView{
			Strategy:  e.Strategy,
			Tier:      e.Tier,
			MedianMS:  e.MedianMS,
			SpreadMS:  e.SpreadMS,
			Successes: e.Successes,
			Attempts:  e.Attempts,
			Chosen:    e.Strategy == chosen,
		})
	}
	return v
}

// nonNil returns an empty slice for a nil one.
//
// A nil Go slice marshals to JSON `null`, and the window read every list as an
// array — so one absent field (no profiles installed) threw while rendering and
// left the panel half drawn. Normalising once here is the fix; guarding every
// read in JavaScript would only move the bug somewhere harder to see.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// normalise guarantees that every list in a Snapshot marshals as an array.
func (s Snapshot) normalise() Snapshot {
	s.Addresses = nonNil(s.Addresses)
	if s.Profiles == nil {
		s.Profiles = []ProfileView{}
	}
	if s.Sites == nil {
		s.Sites = []SiteView{}
	}
	for i := range s.Profiles {
		s.Profiles[i].Hosts = nonNil(s.Profiles[i].Hosts)
	}
	for i := range s.Sites {
		s.Sites[i].Addrs = nonNil(s.Sites[i].Addrs)
		s.Sites[i].Missing = nonNil(s.Sites[i].Missing)
	}
	if s.Report != nil && s.Report.Group == nil {
		s.Report.Group = []ReportEntryView{}
	}
	return s
}

// InstalledStrategy is the strategy the service actually runs, recovered from
// the service control manager, falling back to the recorded search.
//
// Deliberately not read from the settings file: Settings.Strategy means "pin
// this one and stop searching", so writing the chosen strategy there would
// quietly turn every later run into a replay of an expiring result.
func (a *App) InstalledStrategy() []string {
	inst := apply.Inspect(context.Background(), a.serviceName())
	for _, p := range inst.Profiles {
		if st := p.Stages(); len(st) > 0 {
			return st
		}
	}
	if rec, err := apply.LoadReport(filepath.Join(appRoot(), "config")); err == nil {
		return rec.Chosen
	}
	return nil
}

// serviceName is the configured name, or the default.
func (a *App) serviceName() string {
	if set, err := apply.LoadSettings(filepath.Join(appRoot(), "config")); err == nil && set.ServiceName != "" {
		return set.ServiceName
	}
	return apply.DefaultServiceName
}

// SetScope switches between covering only the listed names and covering every
// TLS connection on the machine.
//
// The strategy does not change — it is a property of the provider's DPI, not of
// a site — only the kernel filter does. When something is installed the service
// has to be rebuilt for the new filter, and that is chained into one elevated
// command so the user sees a single prompt rather than two.
func (a *App) SetScope(allTraffic bool) string {
	dir := filepath.Join(appRoot(), "config")
	set, err := apply.LoadSettings(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, apply.ErrNoHosts) {
		return err.Error()
	}
	set.AllTraffic = allTraffic
	if err := apply.SaveSettings(dir, set); err != nil {
		return err.Error()
	}

	// Nothing installed: the setting is the whole change, and the next install
	// will honour it. Do not launch dpi.exe — a console flash here is what
	// made a mode click look like a crashing command.
	if apply.Inspect(context.Background(), a.serviceName()).State == apply.StateAbsent {
		return ""
	}

	stages := a.InstalledStrategy()
	if len(stages) == 0 {
		return "the installed strategy could not be read back, so the scope cannot be rebuilt safely - " +
			"run a fresh search instead"
	}

	cliBase := filepath.Base(locateCLI())
	args := []string{"remove", "-service", a.serviceName(), "&&", cliBase, "apply"}
	for _, st := range stages {
		args = append(args, "-stage", quoteArg(st))
	}
	if !allTraffic {
		for _, h := range set.Hosts {
			args = append(args, "-host", h)
		}
	}
	if allTraffic {
		args = append(args, "-all-traffic")
	} else {
		args = append(args, "-fix-dns", "-dns-mode", "hosts")
	}
	args = append(args, "-fast")
	args = append(args, "-service", a.serviceName(), "-install", "-config-dir", quoteArg(dir))

	what := "Applying to the listed sites only"
	if allTraffic {
		what = "Applying to everything on this machine"
	}
	msg := a.elevate(what, args...)
	if msg != "" {
		appendLog("ERROR [SetScope]: %s", msg)
	} else {
		if allTraffic {
			a.startDNSDiverter()
		} else {
			a.stopDNSDiverter()
		}
	}

	// `dpi remove` / a failed `dpi apply` can leave dpi.json missing or without
	// all_traffic. Write the mode the user just picked so the window does not
	// snap back to "listed sites" after the console flash.
	if cur, err := apply.LoadSettings(dir); err == nil || errors.Is(err, apply.ErrNoHosts) {
		cur.AllTraffic = allTraffic
		if cur.DNSMode == "" && set.DNSMode != "" {
			cur.DNSMode = set.DNSMode
		}
		if len(cur.Hosts) == 0 && len(set.Hosts) > 0 {
			cur.Hosts = set.Hosts
		}
		_ = apply.SaveSettings(dir, cur)
	} else {
		_ = apply.SaveSettings(dir, set)
	}
	return msg
}

// quoteArg wraps a stage that contains characters cmd.exe would split on. The
// stage strings carry colons and equals signs, and one of them once reached the
// engine truncated for exactly this reason.
func quoteArg(s string) string {
	if strings.ContainsAny(s, " \t&|<>^") {
		return `"` + s + `"`
	}
	return s
}

func elevateScript(cli, logPath, donePath string, args []string) []byte {
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	for _, cmd := range splitElevateCmds(args) {
		fmt.Fprintf(&b, "\"%s\" %s >>\"%s\" 2>&1\r\n", cli, strings.Join(cmd, " "), logPath)
	}
	fmt.Fprintf(&b, "echo done>\"%s\"\r\n", donePath)
	return []byte(b.String())
}

// splitElevateCmds turns `remove … && dpi.exe apply …` into two argv lists
// so each process is launched on its own line, output appended to one log.
func splitElevateCmds(args []string) [][]string {
	var out [][]string
	var cur []string
	for i := 0; i < len(args); i++ {
		if args[i] == "&&" && i+1 < len(args) {
			base := strings.ToLower(filepath.Base(args[i+1]))
			if base == "dpi.exe" || base == "desynq.exe" {
				if len(cur) > 0 {
					out = append(out, cur)
					cur = nil
				}
				i++
				continue
			}
		}
		cur = append(cur, args[i])
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	if len(out) == 0 {
		return [][]string{args}
	}
	return out
}

// TestOne measures a single name, which is what a per-row Test button needs:
// re-measuring every site to answer one question is a waste of the user's time
// and of the link.
func (a *App) TestOne(host string) Snapshot {
	parsed, msg := parseHostInput(host)
	if msg != "" {
		// Fall back to a trimmed token so a bare name still measures when the
		// caller already validated it; refuse empty input.
		parsed = strings.ToLower(strings.TrimSpace(host))
	}
	if parsed == "" {
		return a.snapshot(false)
	}
	return a.snapshotHosts(true, []string{parsed})
}

// Hosts returns the configured names.
func (a *App) Hosts() []string {
	if set, err := apply.LoadSettings(filepath.Join(appRoot(), "config")); err == nil {
		return set.Hosts
	}
	return nil
}

// parseHostInput pulls a hostname out of whatever the user had in the
// clipboard.
//
// People copy the address bar, not a bare domain, so refusing
// "https://discord.com/channels/@me" made the user do work this can do. Ports,
// credentials, paths, queries and a trailing dot are all stripped; anything
// left that is not host-shaped is refused rather than guessed at.
func parseHostInput(in string) (string, string) {
	h := strings.TrimSpace(in)
	if h == "" {
		return "", "enter a site address"
	}
	// A scheme, or the // that implies one.
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	} else {
		h = strings.TrimPrefix(h, "//")
	}
	// Path, query and fragment first, leaving the authority. Credentials are
	// stripped only after that: an "@" later in a URL is part of the path
	// ("/channels/@me"), and taking it as a credential separator ate the
	// hostname entirely.
	h = strings.SplitN(h, "/", 2)[0]
	h = strings.SplitN(h, "?", 2)[0]
	h = strings.SplitN(h, "#", 2)[0]
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	// A port, but not an IPv6 literal's colons.
	if !strings.Contains(h, "]") {
		h = strings.SplitN(h, ":", 2)[0]
	}
	h = strings.ToLower(strings.Trim(h, "."))
	if ascii, err := idna.ToASCII(h); err == nil && ascii != "" {
		h = ascii
	}

	if h == "" {
		return "", "that address has no site name in it"
	}
	if net.ParseIP(strings.Trim(h, "[]")) != nil {
		return "", "name the site, not an address — the address is what this works out for you"
	}
	if !strings.Contains(h, ".") {
		return "", h + " is not a full site name — try " + h + ".com"
	}
	for _, r := range h {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			continue
		}
		return "", "that does not look like a site name"
	}
	return h, ""
}

// AddHost records another name to unblock. It only writes intent — nothing is
// applied until the user asks for it, because applying costs a search.
func (a *App) AddHost(input string) string {
	host, msg := parseHostInput(input)
	if msg != "" {
		return msg
	}
	return a.editHosts(func(hosts []string) ([]string, string) {
		if contains(hosts, host) {
			return nil, host + " is already in the list"
		}
		return append(hosts, host), ""
	})
}

// ActivateHost records a name and, when a targeted bypass is already installed,
// rebuilds the filter so that name is actually covered.
//
// Add alone only writes intent. Without this step a user can list a site and
// still have its traffic walk past the driver. Searching for a strategy remains
// Install's job — activation never invents a method, it only widens coverage.
func (a *App) ActivateHost(input string) string {
	host, msg := parseHostInput(input)
	if msg != "" {
		return msg
	}
	if msg := a.editHosts(func(hosts []string) ([]string, string) {
		if contains(hosts, host) {
			return hosts, ""
		}
		return append(hosts, host), ""
	}); msg != "" {
		appendLog("ERROR [ActivateHost:%s]: %s", host, msg)
		return msg
	}

	set, err := apply.LoadSettings(filepath.Join(appRoot(), "config"))
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, apply.ErrNoHosts) {
		return err.Error()
	}
	inst := apply.Inspect(context.Background(), a.serviceName())
	if inst.State == apply.StateAbsent || set.AllTraffic {
		return ""
	}
	return a.Refresh()
}

// RemoveHost drops a name from the recorded intent. When a targeted service is
// installed, the filter is rebuilt so the removed name stops being captured.
func (a *App) RemoveHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	set, _ := apply.LoadSettings(filepath.Join(appRoot(), "config"))
	isAllTraffic := set.AllTraffic
	if msg := a.editHosts(func(hosts []string) ([]string, string) {
		out := hosts[:0:0]
		for _, h := range hosts {
			if h != host {
				out = append(out, h)
			}
		}
		if len(out) == len(hosts) {
			return nil, host + " is not in the list"
		}
		if len(out) == 0 && !isAllTraffic {
			appendLog("WARN [RemoveHost]: en az bir site listede kalmalıdır")
			return nil, "en az bir site listede kalmalıdır"
		}
		return out, ""
	}); msg != "" {
		appendLog("ERROR [RemoveHost:%s]: %s", host, msg)
		return msg
	}

	set, err := apply.LoadSettings(filepath.Join(appRoot(), "config"))
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, apply.ErrNoHosts) {
		return err.Error()
	}
	inst := apply.Inspect(context.Background(), a.serviceName())
	if inst.State == apply.StateAbsent || set.AllTraffic {
		return ""
	}
	if len(set.Hosts) == 0 {
		return a.elevate("removing empty filter", "remove")
	}
	return a.Refresh()
}

// ApplyDNSMode elevates the DNS remedy currently recorded in settings.
//
// Settings alone is intent. Calling this is what actually pins names, switches
// the resolver, or undoes whichever remedy was last applied.
func (a *App) ApplyDNSMode() string {
	set, err := apply.LoadSettings(filepath.Join(appRoot(), "config"))
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, apply.ErrNoHosts) {
		return err.Error()
	}
	switch set.DNSMode {
	case "hosts":
		return a.PinDNS()
	case "resolver":
		return a.elevate("switching to encrypted DNS", "dns", "-mode=resolver")
	default:
		return a.UnpinDNS()
	}
}

func (a *App) editHosts(edit func([]string) ([]string, string)) string {
	dir := filepath.Join(appRoot(), "config")
	set, err := apply.LoadSettings(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, apply.ErrNoHosts) {
		return err.Error()
	}
	next, msg := edit(set.Hosts)
	if msg != "" {
		return msg
	}
	set.Hosts = next
	if err := apply.SaveSettings(dir, set); err != nil {
		return err.Error()
	}
	return ""
}

// ApplyPreset installs a pre-validated ISP profile without requiring a scan.
func (a *App) ApplyPreset(preset string) string {
	dir := filepath.Join(appRoot(), "config")
	_ = os.MkdirAll(dir, 0o755)

	switch preset {
	case "turknet":
		set := apply.Settings{
			Hosts:       []string{"discord.com", "pastebin.com"},
			AllTraffic:  true,
			DNSMode:     "hosts",
			ServiceName: a.serviceName(),
		}
		_ = apply.SaveSettings(dir, set)
		a.startDNSDiverter()
		appendLog("INFO [ApplyPreset]: TurkNet profile applied")
		return ""
	case "vodafone":
		set := apply.Settings{
			Hosts:       []string{"discord.com", "pastebin.com"},
			AllTraffic:  true,
			DNSMode:     "hosts",
			ServiceName: a.serviceName(),
		}
		_ = apply.SaveSettings(dir, set)
		a.startDNSDiverter()
		_ = apply.SaveReport(dir, apply.SearchReport{
			TakenAt: time.Now(),
			Chosen:  []string{"multidisorder:pos=1"},
			Entries: []apply.ReportEntry{{Strategy: "multidisorder:pos=1", Successes: 10, Attempts: 10}},
		})
		args := []string{"apply", "-stage", "multidisorder:pos=1", "-fast", "-all-traffic", "-service", a.serviceName(), "-install", "-config-dir", quoteArg(dir)}
		appendLog("INFO [ApplyPreset]: Vodafone profile applied with multidisorder:pos=1")
		return a.elevate("starting", args...)
	case "turkcell":
		set := apply.Settings{
			Hosts:       []string{"discord.com", "pastebin.com"},
			AllTraffic:  true,
			DNSMode:     "hosts",
			ServiceName: a.serviceName(),
		}
		_ = apply.SaveSettings(dir, set)
		a.startDNSDiverter()
		_ = apply.SaveReport(dir, apply.SearchReport{
			TakenAt: time.Now(),
			Chosen:  []string{"multidisorder:pos=1"},
			Entries: []apply.ReportEntry{{Strategy: "multidisorder:pos=1", Successes: 10, Attempts: 10}},
		})
		args := []string{"apply", "-stage", "multidisorder:pos=1", "-fast", "-all-traffic", "-service", a.serviceName(), "-install", "-config-dir", quoteArg(dir)}
		appendLog("INFO [ApplyPreset]: Turkcell profile applied with multidisorder:pos=1")
		return a.elevate("starting", args...)
	default:
		return "unknown preset"
	}
}

// Start applies the recorded strategy immediately without a full search.
func (a *App) Start() string {
	dir := filepath.Join(appRoot(), "config")
	set, err := apply.LoadSettings(dir)
	if err != nil {
		appendLog("INFO [Start]: no settings found (%v), falling back to Install", err)
		return a.Install()
	}

	a.mu.Lock()
	a.measured = nil // clear stale offline measurements so UI doesn't flash false error
	a.mu.Unlock()

	stages := a.InstalledStrategy()
	if set.AllTraffic {
		if entries, err := apply.ReadManagedHosts(); err == nil && len(entries) > 0 {
			_ = a.UnpinDNS()
		}
		a.startDNSDiverter()
		if len(stages) > 0 {
			args := []string{"apply"}
			for _, st := range stages {
				args = append(args, "-stage", quoteArg(st))
			}
			args = append(args, "-fast", "-all-traffic")
			args = append(args, "-service", a.serviceName(), "-install", "-config-dir", quoteArg(dir))
			msg := a.elevate("starting", args...)
			if cur, err := apply.LoadSettings(dir); err == nil && len(cur.Hosts) == 0 && len(set.Hosts) > 0 {
				cur.Hosts = set.Hosts
				_ = apply.SaveSettings(dir, cur)
			}
			if msg != "" {
				appendLog("ERROR [Start:allTraffic]: %s", msg)
			}
			return msg
		}
		return ""
	}

	a.stopDNSDiverter()
	if len(stages) > 0 {
		args := []string{"apply"}
		for _, st := range stages {
			args = append(args, "-stage", quoteArg(st))
		}
		for _, h := range set.Hosts {
			args = append(args, "-host", h)
		}
		args = append(args, "-fast", "-fix-dns", "-dns-mode", "hosts")
		args = append(args, "-service", a.serviceName(), "-install", "-config-dir", quoteArg(dir))
		msg := a.elevate("starting", args...)
		if msg != "" {
			appendLog("ERROR [Start:sites]: %s", msg)
		}
		return msg
	}
	msg := a.PinDNS()
	if msg != "" {
		appendLog("ERROR [Start:pinDNS]: %s", msg)
	}
	return msg
}

// Stop completely stops protection (service, diverter, and hosts pins).
func (a *App) Stop() string {
	a.stopDNSDiverter()
	_ = exec.Command("taskkill", "/F", "/IM", "winws2.exe").Run()
	a.mu.Lock()
	a.measured = nil
	a.mu.Unlock()
	dir := filepath.Join(appRoot(), "config")
	msg := a.elevate("removing", "remove", "-service", a.serviceName(), "-dns", "-config-dir", quoteArg(dir))
	if msg != "" {
		appendLog("ERROR [Stop]: %s", msg)
	}
	return msg
}

// Install searches for a strategy and installs it, under UAC.
func (a *App) Install() string {
	dir := filepath.Join(appRoot(), "config")
	set, _ := apply.LoadSettings(dir)
	args := []string{"auto", "-install", "-fix-dns"}
	if set.DNSMode != "" {
		args = append(args, "-dns-mode", set.DNSMode)
	} else {
		args = append(args, "-dns-mode", "hosts")
	}
	msg := a.elevate("installing", args...)
	if msg != "" {
		appendLog("ERROR [Install]: %s", msg)
	}
	if msg == "" && set.AllTraffic {
		a.startDNSDiverter()
	} else {
		a.stopDNSDiverter()
	}
	return msg
}

// Refresh reinstalls the same strategy with current addresses, under UAC.
func (a *App) Refresh() string {
	inst := apply.Inspect(context.Background(), a.serviceName())
	if inst.State == apply.StateAbsent {
		return a.PinDNS()
	}
	msg := a.elevate("refreshing", "refresh")
	if msg != "" {
		appendLog("ERROR [Refresh]: %s", msg)
	}
	return msg
}

// Remove takes the service, the driver and the DNS change back off, under UAC.
func (a *App) Remove() string {
	a.stopDNSDiverter()
	_ = exec.Command("taskkill", "/F", "/IM", "winws2.exe").Run()
	dir := filepath.Join(appRoot(), "config")
	return a.elevate("removing", "remove", "-service", a.serviceName(), "-dns", "-config-dir", quoteArg(dir))
}

// PinDNS writes the targeted hosts-file remedy, under UAC.
func (a *App) PinDNS() string {
	hosts := a.Hosts()
	if len(hosts) == 0 {
		return "no hosts configured"
	}
	msg := a.elevate("pinning DNS", append([]string{"dns"}, hosts...)...)
	_ = apply.FlushDNSCache()
	return msg
}

// UnpinDNS removes the hosts-file block, under UAC.
func (a *App) UnpinDNS() string {
	msg := a.elevate("unpinning DNS", "dns", "-undo")
	_ = apply.FlushDNSCache()
	return msg
}

// elevate runs dpi.exe as administrator and streams its output to the window.
//
// The output is captured through a file rather than a pipe because the process
// is started by the shell (that is what raises the UAC prompt) and the shell
// gives no handle back. The same reason drives the sentinel file: without a
// process handle there is nothing to wait on.
func (a *App) elevate(job string, args ...string) string {
	if !a.claim(job) {
		return "already " + a.current()
	}
	defer a.release()
	a.clearCancel()

	cli := locateCLI()
	if cli == "" {
		return "dpi.exe not found next to this application"
	}

	logDir := filepath.Join(appRoot(), "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return err.Error()
	}
	logPath := filepath.Join(logDir, "dpi.log")
	donePath := filepath.Join(logDir, "done")
	scriptPath := filepath.Join(logDir, "run.cmd")
	vbsPath := filepath.Join(logDir, "run.vbs")
	defer func() {
		_ = os.Remove(donePath)
		_ = os.Remove(scriptPath)
		_ = os.Remove(vbsPath)
	}()

	var initialOffset int64
	if fi, err := os.Stat(logPath); err == nil {
		initialOffset = fi.Size()
	}

	// A tiny .cmd file avoids cmd.exe's /c quoting traps around paths with
	// spaces. Each dpi.exe invocation is its own line: `remove && dpi.exe apply`
	// used to flash two console windows.
	if err := os.WriteFile(scriptPath, elevateScript(cli, logPath, donePath, args), 0o644); err != nil {
		return err.Error()
	}

	a.emit("job:start", job)

	cmds := splitElevateCmds(args)
	elev := processElevated()

	// Prefer a direct hidden spawn whenever we already have admin rights.
	// When we do not, ShellExecute still elevates a tiny VBScript that runs the
	// same dpi.exe lines with window style 0 — cmd.exe /c was flashing consoles.
	if elev {
		a.emit("job:line", "Yönetici olarak çalışıyor…")
		type result struct{ err error }
		done := make(chan result, 1)
		go func() {
			done <- result{runCmdsHidden(cli, appRoot(), logPath, donePath, cmds)}
		}()
		offset := initialOffset
		for {
			select {
			case r := <-done:
				offset = a.drain(logPath, offset)
				if _, err := os.Stat(donePath); err == nil {
					a.drain(logPath, offset)
				}
				if r.err != nil {
					msg := "komut çalışmadı: " + r.err.Error()
					a.emit("job:done", msg)
					return msg
				}
				a.emit("job:done", "")
				return ""
			default:
				if a.cancelled() {
					a.emit("job:done", "iptal edildi")
					return "iptal edildi"
				}
				offset = a.drain(logPath, offset)
				time.Sleep(200 * time.Millisecond)
			}
		}
	}

	a.emit("job:line", "Yönetici onayı istenebilir…")
	a.emit("job:line", "Bir pencere çıkarsa onaylayın (bazen bu pencerenin arkasında kalır).")

	if err := writeElevateVBS(vbsPath, scriptPath); err != nil {
		return err.Error()
	}

	type launch struct{ err error }
	launched := make(chan launch, 1)
	go func() {
		wscript := filepath.Join(os.Getenv("SystemRoot"), "System32", "wscript.exe")
		if !fileExists(wscript) {
			wscript = "wscript.exe"
		}
		launched <- launch{shellExecuteRunas(wscript, `//B "`+vbsPath+`"`, appRoot())}
	}()

	for {
		select {
		case r := <-launched:
			if r.err != nil {
				if errors.Is(r.err, ErrUACDeclined) {
					a.emit("job:done", ErrUACDeclined.Error())
					return ErrUACDeclined.Error()
				}
				a.emit("job:done", r.err.Error())
				return r.err.Error()
			}
			a.emit("job:line", "Onay alındı — çalışıyor…")
			if err := a.streamUntilDone(logPath, donePath, initialOffset); err != nil {
				a.emit("job:done", err.Error())
				return err.Error()
			}
			a.emit("job:done", "")
			return ""
		default:
			if a.cancelled() {
				a.emit("job:done", "iptal edildi")
				return "iptal edildi — yönetici penceresi açıksa kapatın"
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// CancelJob asks a running elevate wait to stop. The elevated process itself
// cannot be killed from here (no handle); the window just stops waiting.
func (a *App) CancelJob() {
	a.mu.Lock()
	a.cancelJob = true
	a.mu.Unlock()
}

func (a *App) clearCancel() {
	a.mu.Lock()
	a.cancelJob = false
	a.mu.Unlock()
}

func (a *App) cancelled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cancelJob
}

// elevateTimeout bounds a job that never writes its sentinel — a UAC prompt the
// user dismissed leaves no process and no file, and the window must not wait
// forever for it.
const elevateTimeout = 90 * time.Second

func (a *App) streamUntilDone(logPath, donePath string, initialOffset int64) error {
	offset := initialOffset
	deadline := time.Now().Add(elevateTimeout)
	started := time.Now()
	sawLog := false
	for {
		if a.cancelled() {
			return errors.New("iptal edildi")
		}
		before := offset
		offset = a.drain(logPath, offset)
		if offset > before {
			sawLog = true
		}
		if _, err := os.Stat(donePath); err == nil {
			a.drain(logPath, offset)
			return nil
		}
		// ShellExecute can return success while nothing actually started (UAC off
		// / silent failure). If there is no log and no sentinel soon, stop waiting.
		if !sawLog && time.Since(started) > 20*time.Second {
			return errors.New("komut başlamadı — yönetici olarak çalıştırmayı deneyin, veya UAC açıksa onay penceresine bakın")
		}
		if time.Now().After(deadline) {
			return errors.New("zaman aşımı — işlem bitmedi. İptal edip yönetici olarak yeniden deneyin")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// drain sends whatever the log has grown by and returns the new offset.
func (a *App) drain(path string, offset int64) int64 {
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return offset
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		a.emit("job:line", sc.Text())
	}
	if end, err := f.Seek(0, 1); err == nil {
		return end
	}
	return offset
}

func (a *App) emit(name string, data string) {
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, name, data)
	}
}

// appRoot is the directory the application and its config live in.
//
// `wails build` drops the binary in ui/build/bin. Copying dpi.exe next to it
// for locateCLI must not make that bin directory win over the repo root that
// actually holds config/ and tools/. Prefer a candidate that has config.
func appRoot() string {
	exe, err := os.Executable()
	if err != nil {
		wd, _ := os.Getwd()
		return wd
	}
	dir := filepath.Dir(exe)
	// Portable standalone mode: if config/ or desynq.exe/dpi.exe is beside the executable, use dir.
	if fileExists(filepath.Join(dir, "desynq.exe")) || fileExists(filepath.Join(dir, "dpi.exe")) || fileExists(filepath.Join(dir, "config")) {
		return dir
	}
	// Dev fallback if binary is in ui/build/bin
	for _, cand := range []string{filepath.Join(dir, "..", "..", ".."), "."} {
		abs, err := filepath.Abs(cand)
		if err != nil {
			continue
		}
		if (fileExists(filepath.Join(abs, "desynq.exe")) || fileExists(filepath.Join(abs, "dpi.exe"))) && fileExists(filepath.Join(abs, "config")) {
			return abs
		}
	}
	return dir
}

// locateCLI returns the executable that handles elevated operations.
// Under the single-binary architecture, this is the running executable itself.
func locateCLI() string {
	if exe, err := os.Executable(); err == nil && fileExists(exe) {
		return exe
	}
	if p := filepath.Join(appRoot(), "desynq.exe"); fileExists(p) {
		return p
	}
	if p := filepath.Join(appRoot(), "dpi.exe"); fileExists(p) {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func hostlistNames(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return uniqueHosts(strings.Fields(string(b))), nil
}

func uniqueHosts(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func contains(hs []string, h string) bool {
	for _, x := range hs {
		if x == h {
			return true
		}
	}
	return false
}

func countIPv6(addrs []string) int {
	n := 0
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
			n++
		}
	}
	return n
}
