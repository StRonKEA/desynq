// Package engine runs the zapret2 desync engine (winws2.exe) with one strategy
// applied to one destination address.
//
// Pinning each instance to a single destination address is what makes parallel
// evaluation possible: winws2 refuses to start a second instance carrying an
// identical WinDivert filter, but instances with distinct filters coexist
// happily. Measured on 2026-09-03: four concurrent instances, ~36ms to become
// ready once the driver is loaded, 2-6ms to stop.
package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// readyMarker is the last line winws2 prints before it is actually filtering.
// Anything earlier (profile parsing, filter construction) does not yet mean
// traffic is being touched, so waiting for less would measure unfiltered runs.
const readyMarker = "capture is started"

// busyMarker is winws2 refusing to duplicate an existing filter.
const busyMarker = "already running with the same filter"

// rejectMarker is how the engine reports a stage it cannot resolve —
// `desync function 'dup' does not exist`, and the same wording for an unknown
// fooling or ipfrag function.
//
// It has to be watched for separately because the engine prints it *after*
// readyMarker and then exits: Start would otherwise hand back an instance that
// is already dead, every probe through it would fail, and the candidate would
// be scored as "does not work" rather than "not a real strategy". That is how
// an invented stage name stays invisible — it happened with `dup`.
const rejectMarker = "does not exist"

var (
	// ErrFilterBusy means another instance already owns this exact filter.
	ErrFilterBusy = errors.New("engine: another instance already owns this filter")
	// ErrNotReady means the process started but never began capturing.
	ErrNotReady = errors.New("engine: did not start capturing")
)

// Config locates the engine and its Lua library.
type Config struct {
	BinaryPath   string
	LuaDir       string
	ReadyTimeout time.Duration
}

// DefaultConfig points at the vendored bundle relative to the working directory.
func DefaultConfig() Config {
	root := filepath.Join("tools", "zapret-winws")
	return Config{
		BinaryPath:   filepath.Join(root, "winws2.exe"),
		LuaDir:       filepath.Join(root, "lua"),
		ReadyTimeout: 10 * time.Second,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.BinaryPath == "" {
		c.BinaryPath = d.BinaryPath
	}
	if c.LuaDir == "" {
		c.LuaDir = d.LuaDir
	}
	if c.ReadyTimeout == 0 {
		c.ReadyTimeout = d.ReadyTimeout
	}
	return c
}

// L3Both selects both address families for the WinDivert filter.
//
// It is passed explicitly rather than left to the engine's default, because the
// default is not documented in `winws2 --help` and the consequence of guessing
// wrong is invisible: with IPv6 outside the kernel filter, a browser that
// prefers IPv6 — which Windows does whenever it has a working route — bypasses
// the strategy entirely while every check that dials IPv4 still reports success.
const L3Both = "--wf-l3=ipv4,ipv6"

// FilterAddressTerm renders a WinDivert filter term matching one address, in
// the given direction field ("DstAddr" or "SrcAddr").
//
// WinDivert keeps the families in separate namespaces: `ip.DstAddr` exists only
// for IPv4 packets and `ipv6.DstAddr` only for IPv6 ones, and a term naming the
// other family is simply false for that packet — the engine's own bundled
// filter parts rely on this, writing a bare `ip` to mean "IPv4 only". So a flat
// OR list may mix the two freely, which is what lets one filter cover both
// families without the parentheses that --wf-raw-filter refuses.
func FilterAddressTerm(field, addr string) string {
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return "ipv6." + field + "==" + addr
	}
	return "ip." + field + "==" + addr
}

// Pin restricts one engine instance to a slice of traffic narrow enough that
// other instances can run beside it.
//
// The destination address alone bounds that badly. winws2 refuses a second
// instance carrying an identical WinDivert filter, so with address-only pins the
// number of concurrent instances is capped by the number of distinct target
// addresses — and measuring one candidate already claims every one of them, so
// there is nothing left over to run a second candidate with. Adding a local
// source-port window makes the filters distinct again: several candidates can
// then be screened against the *same* address at once, each instance seeing
// only the connections the prober opens from that instance's own ports.
//
// **Concurrent pins must never overlap.** An address-only pin is a superset of
// every port-windowed pin on the same address, and two desync engines mangling
// one packet produce a strategy neither of them describes — with no error to
// show for it. So either every concurrent instance carries a port window, or
// there is only one instance per address.
type Pin struct {
	// Addr is the destination address. Empty means no address restriction,
	// which captures all of port 443 and precludes any second instance.
	Addr string
	// PortLo and PortHi bound the local source port, inclusive. Zero means no
	// port restriction.
	PortLo, PortHi int
}

// HasPortWindow reports whether this pin is narrowed by source port, which is
// what makes it safe to run beside another pin on the same address.
func (p Pin) HasPortWindow() bool { return p.PortLo > 0 && p.PortHi >= p.PortLo }

// Filter renders the pin as a --wf-raw-filter value.
//
// A flat chain of ANDs with no parentheses: that is the only shape
// --wf-raw-filter accepts (measured), and it is enough here because every term
// narrows. Port range comparisons are known to work in a raw filter — the
// engine's own bundled filter parts use `udp.DstPort>=50000 and
// udp.DstPort<=50099`.
func (p Pin) Filter() string {
	var terms []string
	if p.Addr != "" {
		terms = append(terms, FilterAddressTerm("DstAddr", p.Addr))
	}
	if p.HasPortWindow() {
		terms = append(terms,
			"tcp.SrcPort>="+strconv.Itoa(p.PortLo),
			"tcp.SrcPort<="+strconv.Itoa(p.PortHi))
	}
	return strings.Join(terms, " and ")
}

// Lane port arithmetic for concurrent screening.
//
// Windows' default dynamic port range starts at 49152, so the lanes stay below
// it: drawing from the ephemeral pool would make the prober compete for ports
// with every other program on the machine, and a bind failure in the middle of
// a measurement looks exactly like a censored connection.
const (
	laneBasePort  = 40000
	lanePortCount = 128
	// MaxLanes is how many candidates can be screened against one address at
	// once before the windows would run into the ephemeral range.
	MaxLanes = (49152 - laneBasePort) / lanePortCount
)

// LanePorts returns the inclusive source-port window of concurrent lane n
// (0-based). Windows never overlap, which is what keeps two lanes' filters
// disjoint and their instances out of each other's traffic.
func LanePorts(n int) (lo, hi int) {
	lo = laneBasePort + n*lanePortCount
	return lo, lo + lanePortCount - 1
}

// buildArgs assembles the winws2 command line. The order matters: WinDivert
// filters first, then the Lua libraries, then the profile that consumes them.
//
// Each stage becomes its own --lua-desync, applied in the order given. Real
// strategies are usually multi-stage (a fake packet followed by a split), and
// winws2 expresses that as repeated flags rather than one combined value.
func buildArgs(cfg Config, stages []string, pin Pin) []string {
	args := []string{"--wf-tcp-out=443", L3Both}
	if f := pin.Filter(); f != "" {
		args = append(args, "--wf-raw-filter="+f)
	}
	args = append(args,
		"--lua-init=@"+filepath.Join(cfg.LuaDir, "zapret-lib.lua"),
		"--lua-init=@"+filepath.Join(cfg.LuaDir, "zapret-antidpi.lua"),
		"--filter-tcp=443",
		"--filter-l7=tls",
		"--payload=tls_client_hello",
	)
	for _, s := range stages {
		args = append(args, "--lua-desync="+s)
	}
	return args
}

// Instance is a running engine process.
type Instance struct {
	cmd    *exec.Cmd
	stages []string
	pin    Pin
	// drained is closed once the output consumer has returned, so Stop can
	// avoid calling Wait while the pipe is still being read.
	drained chan struct{}

	mu       sync.Mutex
	log      []string // recent output, kept for diagnostics
	closed   bool
	rejected string // the engine's complaint about an unresolvable stage
}

// Rejected returns the engine's complaint if it refused one of the stages, or
// "" if it did not. Checked after a measurement rather than before, because the
// engine reports it only once the Lua profile is first exercised — by which
// time Start has already returned.
func (i *Instance) Rejected() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.rejected
}

// drainTimeout bounds how long Stop waits for the output consumer.
const drainTimeout = 2 * time.Second

// Strategy returns the desync stages this instance applies, joined for display.
func (i *Instance) Strategy() string { return FormatStages(i.stages) }

// FormatStages renders a multi-stage strategy as a single readable string.
func FormatStages(stages []string) string { return strings.Join(stages, " | ") }

// Log returns the output captured so far.
func (i *Instance) Log() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]string, len(i.log))
	copy(out, i.log)
	return out
}

func (i *Instance) appendLog(line string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	// Cap the buffer: a long-running instance in debug mode would otherwise
	// grow without bound, and only the tail is ever useful.
	const maxLines = 60
	if len(i.log) >= maxLines {
		i.log = i.log[1:]
	}
	i.log = append(i.log, line)
}

// startRetries is how many extra attempts Start makes after a failure that
// looks transient.
//
// Killing an instance returns before the kernel has finished releasing its
// WinDivert handle, so a new instance claiming the same filter moments later
// can be refused or fail to reach the capturing state. Observed during a full
// search: roughly two candidates out of fifty-two failed at random, and the
// same candidates succeeded when run on their own. Retrying costs one short
// delay on the rare failure instead of leaving parts of the space untested.
const startRetries = 2

const retryDelay = 150 * time.Millisecond

// Start launches the engine with stages applied to the traffic pin describes.
// A zero Pin filters all port 443 traffic, which prevents any other instance
// from running concurrently.
func Start(ctx context.Context, cfg Config, stages []string, pin Pin) (*Instance, error) {
	cfg = cfg.withDefaults()
	if len(stages) == 0 {
		return nil, errors.New("engine: no desync stages given")
	}
	for _, s := range stages {
		if strings.TrimSpace(s) == "" {
			return nil, errors.New("engine: empty desync stage")
		}
	}

	var err error
	for attempt := 0; ; attempt++ {
		var inst *Instance
		inst, err = startOnce(ctx, cfg, stages, pin)
		if err == nil {
			return inst, nil
		}
		if attempt >= startRetries || !isTransient(err) {
			return nil, err
		}
		select {
		case <-time.After(retryDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// isTransient reports whether a failure is worth retrying. Both cases stem from
// a previous instance still holding kernel state; a genuinely occupied filter
// or a missing binary fails the same way on every attempt and simply costs the
// retries.
func isTransient(err error) bool {
	return errors.Is(err, ErrFilterBusy) || errors.Is(err, ErrNotReady)
}

func startOnce(ctx context.Context, cfg Config, stages []string, pin Pin) (*Instance, error) {
	cmd := exec.Command(cfg.BinaryPath, buildArgs(cfg, stages, pin)...)
	attr := sysProcAttr()
	if attr != nil {
		cmd.SysProcAttr = attr
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("engine: stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("engine: start %s: %w", cfg.BinaryPath, err)
	}
	inst := &Instance{cmd: cmd, stages: stages, pin: pin, drained: make(chan struct{})}

	ready := make(chan error, 1)
	go func() {
		defer close(inst.drained)
		inst.consume(stdout, ready)
	}()

	select {
	case err := <-ready:
		if err != nil {
			_ = inst.Stop()
			return nil, err
		}
		return inst, nil
	case <-time.After(cfg.ReadyTimeout):
		_ = inst.Stop()
		return nil, fmt.Errorf("%w within %s: %s", ErrNotReady, cfg.ReadyTimeout, lastLine(inst.Log()))
	case <-ctx.Done():
		_ = inst.Stop()
		return nil, ctx.Err()
	}
}

// consume scans engine output for the ready or busy markers, reports the
// outcome once, then keeps draining. Draining is not optional: a full pipe
// would block the engine mid-run.
func (i *Instance) consume(r io.Reader, ready chan<- error) {
	scanner := bufio.NewScanner(r)
	reported := false
	for scanner.Scan() {
		line := scanner.Text()
		i.appendLog(line)
		if strings.Contains(line, rejectMarker) {
			i.mu.Lock()
			if i.rejected == "" {
				i.rejected = line
			}
			i.mu.Unlock()
		}
		if reported {
			continue
		}
		switch {
		case strings.Contains(line, readyMarker):
			ready <- nil
			reported = true
		case strings.Contains(line, busyMarker):
			ready <- ErrFilterBusy
			reported = true
		}
	}
	if !reported {
		// Output ended without either marker: the process died on startup.
		ready <- fmt.Errorf("%w: %s", ErrNotReady, lastLine(i.Log()))
	}
}

// Stop terminates the engine. It is safe to call more than once.
func (i *Instance) Stop() error {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil
	}
	i.closed = true
	i.mu.Unlock()

	if i.cmd.Process == nil {
		return nil
	}
	if err := i.cmd.Process.Kill(); err != nil {
		// Already gone is not a failure worth reporting to the caller.
		//
		// Matched on the sentinel rather than the message. The text used to be
		// compared against "finished", which is the wording of
		// os.ErrProcessDone — a match that says nothing about what actually
		// happened and would break the moment the wording changed. It also
		// reads as the localisation trap this project has already paid for
		// twice, even though this particular string comes from Go.
		if !errors.Is(err, exec.ErrNotFound) && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("engine: kill: %w", err)
		}
	}

	// Wait closes the output pipe, and Go documents reading from it afterwards
	// as incorrect, so the consumer has to finish first. Otherwise the last
	// lines are lost — precisely the lines ErrNotReady quotes as the reason a
	// start failed. The timeout is a safety valve: if the process has not
	// released the pipe, Wait itself will close it and unblock the consumer,
	// which is better than hanging the caller.
	if i.drained != nil {
		select {
		case <-i.drained:
		case <-time.After(drainTimeout):
		}
	}
	_ = i.cmd.Wait()
	return nil
}

func lastLine(lines []string) string {
	for n := len(lines) - 1; n >= 0; n-- {
		if s := strings.TrimSpace(lines[n]); s != "" {
			return s
		}
	}
	return "no output"
}
