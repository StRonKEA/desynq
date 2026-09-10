// Package probe classifies how a hostname is being interfered with, if at all.
//
// Interference is measured on two independent layers, because a censor can act
// on either and the remedies differ:
//
//   - DNS: the system resolver answer is compared against an encrypted (DoH)
//     resolver answer. A forged answer is fixed by using encrypted DNS, never
//     by a desync strategy.
//   - Path: a TLS handshake is attempted against the address the encrypted
//     resolver gave, with the real SNI. Only failures here are candidates for a
//     desync strategy.
//
// Testing the path against the *system* address would be a mistake: a hijacked
// answer points at a block page that completes a perfectly valid handshake, so
// a blocked domain would be reported as open.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sort"
	"sync/atomic"
	"syscall"
	"time"
)

// DNSStatus describes how truthful the system resolver is for one name.
type DNSStatus string

const (
	DNSOk       DNSStatus = "OK"       // system answer agrees with the encrypted resolver
	DNSHijacked DNSStatus = "HIJACKED" // system answer points at a block page
	DNSSuspect  DNSStatus = "SUSPECT"  // answers disagree, but not provably hostile
	DNSAbsent   DNSStatus = "ABSENT"   // system resolver returns nothing, DoH does
	DNSDead     DNSStatus = "DEAD"     // nobody resolves it: the domain is gone
	DNSUnknown  DNSStatus = "UNKNOWN"  // no trustworthy reference available
)

// PathStatus describes what happens to a real TLS handshake to the real address.
type PathStatus string

const (
	PathOk      PathStatus = "OK"
	PathReset   PathStatus = "RESET"    // handshake killed by RST
	PathTimeout PathStatus = "TIMEOUT"  // handshake silently dropped
	PathIPBlock PathStatus = "IP-BLOCK" // TCP never establishes
	PathCertBad PathStatus = "CERT-BAD" // handshake completes with the wrong identity
	PathUnknown PathStatus = "UNKNOWN"  // failed for an unrecognised reason
	PathSkipped PathStatus = "SKIPPED"  // no address to test
	// PathLocalFail means the attempt never left this machine: no local port
	// could be bound. It is kept apart from every other status because a fault
	// on this side must never be read as the censor's work — an exhausted port
	// window would otherwise look exactly like an IP-level block and quietly
	// score a working strategy as broken.
	PathLocalFail PathStatus = "LOCAL-FAIL"
)

type Result struct {
	Domain   string
	SysIPs   []string
	RealIPs  []string
	TestedIP string // the address the path handshake actually used
	// RealIPs6 are the name's IPv6 addresses from the encrypted resolver.
	//
	// They are collected even though the path is measured over IPv4, because
	// they have to reach the kernel filter: Windows and every modern browser
	// prefer IPv6 when a working route exists, so an address the filter does not
	// name is a connection the strategy never touches — and one that no IPv4
	// check can notice.
	RealIPs6 []string
	// V6Unknown means the AAAA question was never answered, so the absence of
	// IPv6 addresses above is unproven rather than established.
	V6Unknown bool
	DNS       DNSStatus
	Path      PathStatus
	TCPTime   time.Duration
	TLSTime   time.Duration
	HelloSize int // bytes in the first TLS write; above the MSS it spans segments
	Err       string
}

// AllRealIPs returns every address of both families, which is what a kernel
// filter has to cover for the strategy to apply to all of the host's traffic.
func (r Result) AllRealIPs() []string {
	out := make([]string, 0, len(r.RealIPs)+len(r.RealIPs6))
	out = append(out, r.RealIPs...)
	return append(out, r.RealIPs6...)
}

// DesyncApplies reports whether a desync strategy search is meaningful. DNS- and
// IP-layer interference is out of reach for packet manipulation.
func (r Result) DesyncApplies() bool {
	return r.Path == PathReset || r.Path == PathTimeout || r.Path == PathUnknown
}

// NeedsEncryptedDNS reports whether the system resolver is lying about this name.
func (r Result) NeedsEncryptedDNS() bool {
	return r.DNS == DNSHijacked || r.DNS == DNSAbsent
}

type Config struct {
	// DoHEndpoints are queried by literal IP to obtain trustworthy addresses.
	// Empty means use the built-in list.
	DoHEndpoints []string
	Timeout      time.Duration
	// LocalPorts, when set, makes the path handshake dial from a local port
	// inside this window.
	//
	// It exists so an engine instance can be pinned to the same window: several
	// instances then coexist on one destination address, each seeing only the
	// connections opened from its own ports. Without it the number of concurrent
	// instances is capped by the number of distinct target addresses.
	LocalPorts PortWindow
}

// PortWindow is an inclusive range of local source ports.
type PortWindow struct{ Lo, Hi int }

// IsZero reports whether no window was set, meaning the operating system picks
// the source port as usual.
func (w PortWindow) IsZero() bool { return w.Lo <= 0 || w.Hi < w.Lo }

// port returns the n-th port of the window, wrapping around.
//
// Attempts step through the window rather than reusing one port, because a
// socket that just closed sits in TIME_WAIT and its port cannot be bound again
// for minutes. Cycling means an attempt only meets its own leftovers after the
// whole window has been used.
func (w PortWindow) port(n int) int {
	span := w.Hi - w.Lo + 1
	return w.Lo + ((n%span)+span)%span
}

func (c Config) withDefaults() Config {
	if len(c.DoHEndpoints) == 0 {
		c.DoHEndpoints = defaultDoH
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	return c
}

// classifyDNS is a pure decision table over resolver observations. A disjoint
// answer yields only DNSSuspect, because a CDN legitimately hands different
// edges to different resolvers; markSharedAddresses promotes it to DNSHijacked
// when the aggregate proves it.
//
// comparable says whether the two sides were asked the same question. They are
// not for a name that publishes only AAAA records: lookupSystem asks the system
// resolver for IPv4 alone, so its silence is this tool's own doing rather than
// the resolver withholding anything.
func classifyDNS(sysIPs, realIPs []string, dohFailed, dohNoRecords, comparable bool) DNSStatus {
	switch {
	case dohNoRecords:
		if len(sysIPs) == 0 {
			return DNSDead
		}
		// The encrypted resolver has nothing while the system one answers.
		// Odd rather than obviously hostile, so do not accuse it.
		return DNSUnknown
	case dohFailed:
		return DNSUnknown
	case !comparable:
		// Never seen in the wild, but it must not read as censorship: an
		// IPv6-only name would otherwise be reported DNSAbsent, which
		// NeedsEncryptedDNS treats as a forged answer, and the install path
		// would tell the user their resolver is lying about a name it was
		// never asked about.
		return DNSUnknown
	case len(sysIPs) == 0:
		return DNSAbsent
	case overlaps(sysIPs, realIPs):
		return DNSOk
	default:
		return DNSSuspect
	}
}

type pathSignals struct {
	tested     bool
	localFail  bool
	tcpOk      bool
	tcpTimeout bool
	tlsOk      bool
	tlsReset   bool
	tlsTimeout bool
	certBad    bool
}

// classifyPath is a pure decision table over handshake observations.
func classifyPath(s pathSignals) PathStatus {
	switch {
	case !s.tested:
		return PathSkipped
	// Checked before anything else: the connection never reached the network,
	// so nothing observed after this point says anything about the censor.
	case s.localFail:
		return PathLocalFail
	case s.tlsOk:
		return PathOk
	case !s.tcpOk:
		return PathIPBlock
	case s.certBad:
		return PathCertBad
	case s.tlsReset:
		return PathReset
	case s.tlsTimeout:
		return PathTimeout
	default:
		return PathUnknown
	}
}

// markSharedAddresses promotes DNSSuspect to DNSHijacked for names whose system
// address is also handed out for at least one other suspect name.
//
// Asking the system address to prove its identity does not work: a censor's DPI
// kills any handshake carrying a blocked SNI, including one aimed at its own
// block page, so no certificate is ever obtained. The aggregate is what gives
// it away — a censor points many unrelated names at one block page, whereas a
// genuinely shared CDN address would have overlapped with the encrypted
// resolver answer and never become suspect in the first place.
//
// A single suspect name stays DNSSuspect: with one observation there is nothing
// to correlate, and claiming certainty would be a guess.
func markSharedAddresses(results []Result) {
	// Count distinct *names* per address, not occurrences. Probing the same
	// name twice would otherwise let it corroborate itself and be convicted as
	// a shared block page on a single observation.
	namesPerAddr := map[string]map[string]struct{}{}
	for _, r := range results {
		if r.DNS != DNSSuspect {
			continue
		}
		for _, ip := range r.SysIPs {
			if namesPerAddr[ip] == nil {
				namesPerAddr[ip] = map[string]struct{}{}
			}
			namesPerAddr[ip][r.Domain] = struct{}{}
		}
	}
	counts := make(map[string]int, len(namesPerAddr))
	for ip, names := range namesPerAddr {
		counts[ip] = len(names)
	}
	for i := range results {
		if results[i].DNS != DNSSuspect {
			continue
		}
		for _, ip := range results[i].SysIPs {
			if counts[ip] > 1 {
				results[i].DNS = DNSHijacked
				break
			}
		}
	}
}

// CheckPath performs one TLS handshake against addr using domain as SNI and
// reports what happened.
//
// The measurement loop uses this instead of Run: it already knows the real
// address, and re-resolving on every attempt would add DoH latency to a
// timing measurement and hammer the resolver.
func CheckPath(ctx context.Context, cfg Config, domain, addr string) (PathStatus, time.Duration, string) {
	cfg = cfg.withDefaults()
	s, t := handshake(ctx, cfg, domain, addr)
	return classifyPath(s), t.tls, t.err
}

// Run probes every domain concurrently and returns results in input order.
func Run(ctx context.Context, cfg Config, domains []string) []Result {
	cfg = cfg.withDefaults()
	out := make([]Result, len(domains))
	done := make(chan struct{}, len(domains))
	for i, d := range domains {
		go func(i int, d string) {
			out[i] = probeOne(ctx, cfg, d)
			done <- struct{}{}
		}(i, d)
	}
	for range domains {
		<-done
	}
	// Order matters. The aggregate check runs first so that a shared block page
	// is convicted before the CDN allowance gets a chance to excuse it.
	markSharedAddresses(out)
	relaxCDNRotation(out)
	return out
}

// relaxCDNRotation clears the suspicion on names whose system and encrypted
// answers land in the same network. A large CDN hands different edges to
// different resolvers, and those edges share a /16 while a censor's block page
// sits in the ISP's own address space entirely.
//
// It runs after markSharedAddresses on purpose: anything already convicted by
// the aggregate stays convicted, so this can only soften an unproven suspicion,
// never overturn evidence.
func relaxCDNRotation(results []Result) {
	for i := range results {
		if results[i].DNS != DNSSuspect {
			continue
		}
		if sameNetwork(results[i].SysIPs, results[i].RealIPs) {
			results[i].DNS = DNSOk
		}
	}
}

// cdnPrefixBits is the network size treated as "the same operator".
//
// /16 rather than something tighter because real rotation spans it: youtube.com
// resolved to 192.178.194.136 through the system resolver and 192.178.24.174
// through DoH, which agree only at /16. A censor's page is far outside any of
// this — 195.175.254.2 against a real 162.159.128.233 — so the wider mask costs
// no accuracy here.
const cdnPrefixBits = 16

func sameNetwork(a, b []string) bool {
	for _, x := range a {
		ipx := net.ParseIP(x)
		if ipx == nil || ipx.To4() == nil {
			continue
		}
		mask := net.CIDRMask(cdnPrefixBits, 32)
		netx := ipx.Mask(mask)
		for _, y := range b {
			ipy := net.ParseIP(y)
			if ipy == nil || ipy.To4() == nil {
				continue
			}
			if netx.Equal(ipy.Mask(mask)) {
				return true
			}
		}
	}
	return false
}

func probeOne(ctx context.Context, cfg Config, domain string) Result {
	r := Result{Domain: domain}

	r.SysIPs = lookupSystem(ctx, cfg, domain)
	rec, dohErr := resolveDoH(ctx, cfg.DoHEndpoints, domain, cfg.Timeout)
	r.RealIPs = rec.v4
	r.RealIPs6 = rec.v6
	r.V6Unknown = rec.v6Unknown

	noRecords := errors.Is(dohErr, errNoRecords)
	// The DNS layer is judged on IPv4 alone. That is where block pages live —
	// a censor forges an A record and usually publishes no AAAA at all — and
	// mixing families into the shared-address aggregate would compare addresses
	// that cannot collide.
	// The system side was asked for IPv4 only, so the two answers can only be
	// compared when the encrypted side has IPv4 to compare against.
	comparable := len(rec.v4) > 0 || len(rec.v6) == 0
	r.DNS = classifyDNS(r.SysIPs, rec.v4, dohErr != nil && !noRecords, noRecords, comparable)

	// Prefer the address the encrypted resolver gave; fall back to the system
	// answer only so that a DoH outage still yields some signal.
	//
	// The path is measured over one address, and IPv4 is the one chosen: it is
	// what the search pins an engine instance to, and a desync strategy acts on
	// the TCP payload, which is identical on both families. An IPv6-only name
	// has nothing else to test, so it is dialled rather than reported SKIPPED.
	addr := ""
	switch {
	case len(rec.v4) > 0:
		addr = rec.v4[0]
	case len(rec.v6) > 0:
		addr = rec.v6[0]
	case len(r.SysIPs) > 0:
		addr = r.SysIPs[0]
	}
	r.TestedIP = addr

	var s pathSignals
	if addr != "" {
		var t timings
		s, t = handshake(ctx, cfg, domain, addr)
		r.TCPTime, r.TLSTime, r.HelloSize, r.Err = t.tcp, t.tls, t.hello, t.err
	}
	r.Path = classifyPath(s)
	return r
}

type timings struct {
	tcp   time.Duration
	tls   time.Duration
	hello int
	err   string
}

// handshake performs one TCP+TLS attempt against addr using domain as SNI.
func handshake(ctx context.Context, cfg Config, domain, addr string) (pathSignals, timings) {
	s := pathSignals{tested: true}
	var t timings

	start := time.Now()
	conn, err := dialPinned(ctx, cfg, addr)
	t.tcp = time.Since(start)
	if err != nil {
		s.localFail = isAddrInUse(err)
		s.tcpTimeout = isTimeout(err)
		t.err = err.Error()
		return s, t
	}
	defer func() { _ = conn.Close() }()
	s.tcpOk = true

	cc := &countingConn{Conn: conn}
	hsCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// Certificate verification stays ON. A middlebox answering in place of the
	// server completes the handshake but cannot present a valid certificate for
	// the name, which is the clearest evidence of interception.
	tc := tls.Client(cc, &tls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS12,
	})
	defer func() { _ = tc.Close() }()

	start = time.Now()
	err = tc.HandshakeContext(hsCtx)
	t.tls = time.Since(start)
	t.hello = cc.firstWrite

	if err != nil {
		s.certBad = isCertError(err)
		s.tlsReset = isReset(err)
		s.tlsTimeout = isTimeout(err)
		t.err = err.Error()
		return s, t
	}
	s.tlsOk = true
	return s, t
}

// portCursor advances across every dial so that concurrent probers inside one
// window do not pick the same local port at the same moment.
var portCursor atomic.Uint64

// bindAttempts is how many ports a dial tries before giving up on the window.
// A handful is plenty: it only has to step past ports left in TIME_WAIT by
// earlier attempts, and a window that is entirely unusable is a real fault
// worth surfacing rather than retrying around forever.
const bindAttempts = 8

// dialPinned opens the TCP connection, from a port inside cfg.LocalPorts when
// one is configured.
//
// A port that cannot be bound is skipped rather than reported. This is the
// whole reason the function exists: a port still in TIME_WAIT from an earlier
// attempt would otherwise surface as a failed connection and be scored as the
// censor's work, which would quietly corrupt every measurement taken inside a
// window. If the whole window is unusable the bind error is returned as-is, and
// classifyPath turns it into PathLocalFail rather than a verdict about the
// network.
func dialPinned(ctx context.Context, cfg Config, addr string) (net.Conn, error) {
	target := net.JoinHostPort(addr, "443")
	if cfg.LocalPorts.IsZero() {
		d := net.Dialer{Timeout: cfg.Timeout}
		return d.DialContext(ctx, "tcp", target)
	}

	var err error
	for i := 0; i < bindAttempts; i++ {
		n := int(portCursor.Add(1))
		d := net.Dialer{
			Timeout:   cfg.Timeout,
			LocalAddr: &net.TCPAddr{Port: cfg.LocalPorts.port(n)},
		}
		var conn net.Conn
		conn, err = d.DialContext(ctx, "tcp", target)
		if err == nil {
			return conn, nil
		}
		if !isAddrInUse(err) {
			return nil, err
		}
	}
	return nil, err
}

// wsaEAddrInUse is WSAEADDRINUSE, the errno Windows really returns when a bind
// hits a port that is taken or still in TIME_WAIT.
//
// It has to be spelled out by number: Go's syscall package defines only four
// WSAE constants on Windows — WSAEACCES, WSAENOPROTOOPT, WSAECONNABORTED and
// WSAECONNRESET (checked in GOROOT/src/syscall/types_windows.go, Go 1.27.1) —
// and referring to a WSAE name that does not exist is a compile error rather
// than a silent miss.
const wsaEAddrInUse = syscall.Errno(10048)

// isAddrInUse detects a local bind failure, as opposed to anything that
// happened on the wire. Matched by errno for the usual reason: Windows returns
// the message in the display language.
func isAddrInUse(err error) bool {
	return errors.Is(err, wsaEAddrInUse) || errors.Is(err, syscall.EADDRINUSE)
}

func lookupSystem(ctx context.Context, cfg Config, domain string) []string {
	lctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	// net.DefaultResolver goes through the OS resolver, which is exactly what
	// ordinary applications see, including any forged answer.
	ips, err := net.DefaultResolver.LookupIP(lctx, "ip4", domain)
	if err != nil {
		return nil
	}
	strs := make([]string, 0, len(ips))
	for _, ip := range ips {
		strs = append(strs, ip.String())
	}
	sort.Strings(strs)
	return strs
}

// overlaps reports whether the two answer sets share any address. CDN-hosted
// domains legitimately return different addresses per resolver, so requiring
// set equality would flag them as tampering. Any overlap means the system
// resolver is pointing at real infrastructure.
func overlaps(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, x := range a {
		seen[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := seen[y]; ok {
			return true
		}
	}
	return false
}

type countingConn struct {
	net.Conn
	firstWrite int
}

func (c *countingConn) Write(b []byte) (int, error) {
	if c.firstWrite == 0 {
		c.firstWrite = len(b)
	}
	return c.Conn.Write(b)
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isReset detects a TCP reset.
//
// Never match on the error text: Windows returns syscall messages in the
// system display language, so an English substring check silently fails on a
// localised install. Match the errno instead. Note that on Windows
// syscall.ECONNRESET is a POSIX-compatibility constant (536870935) that never
// appears in a real socket error — the wire truth is WSAECONNRESET (10054).
func isReset(err error) bool {
	return errors.Is(err, syscall.WSAECONNRESET) ||
		errors.Is(err, syscall.WSAECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET)
}

// isCertError detects an identity mismatch rather than a transport failure.
// Type-based for the same localisation reason as isReset.
func isCertError(err error) bool {
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return true
	}
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var invalidErr x509.CertificateInvalidError
	return errors.As(err, &hostErr) ||
		errors.As(err, &authErr) ||
		errors.As(err, &invalidErr)
}

// SystemPath dials the address the *system* resolver hands out and reports what
// a browser would find there.
//
// Every other check in this package deliberately dials the address the
// encrypted resolver gave, because before a fix the system answer is the block
// page and testing it would report a blocked domain as open. After a fix that
// reasoning inverts: the system answer is the only one a browser will use, and
// checking anything else is how this tool told a user both layers were in place
// while their browser sat on the censor's certificate.
//
// A block page gives itself away here. It terminates TLS with a certificate it
// cannot have for the name, so verification fails with PathCertBad — which is
// exactly what the browser showed: an issuer of "localhost.localdomain".
func SystemPath(ctx context.Context, cfg Config, domain string) (PathStatus, string) {
	cfg = cfg.withDefaults()

	lctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lctx, "ip", domain)
	if err != nil || len(ips) == 0 {
		return PathSkipped, "the system resolver returned no address"
	}

	s, t := handshake(ctx, cfg, domain, ips[0].String())
	return classifyPath(s), t.err
}
