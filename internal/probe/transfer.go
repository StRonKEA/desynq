package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Transfer is how fast data actually moved, as opposed to how quickly the
// connection opened.
//
// A desync strategy alters the first data packet, which is why handshake
// latency is the primary measure. But some strategies keep affecting the
// connection after that: `wssize` shrinks the TCP window on purpose, and a
// high `repeats` count puts extra packets on the wire for every connection.
// Neither shows up in a handshake timing, so it has to be measured separately
// rather than assumed away.
type Transfer struct {
	Status PathStatus
	// TTFB is the time from starting the request to the first response byte.
	TTFB time.Duration
	// Body is how long reading the response body took.
	Body time.Duration
	// Bytes is how much of the body was read.
	Bytes int64
	Err   string
}

// Throughput is body bytes per second. It is zero when nothing was read or the
// read was instantaneous, which keeps a meaningless number out of a ranking.
func (t Transfer) Throughput() float64 {
	if t.Bytes <= 0 || t.Body <= 0 {
		return 0
	}
	return float64(t.Bytes) / t.Body.Seconds()
}

// transferLimit caps how much of a response is read.
//
// Comparisons are only ever made between strategies against the *same* host, so
// the absolute page size does not matter — but it has to be bounded, or a large
// page would dominate the search's runtime.
const transferLimit = 512 << 10 // 512 KiB

// Fetch opens a connection to addr with domain as SNI, requests the site root
// and reads the response body, reporting how long each part took.
//
// It goes through net/http rather than writing the request by hand so that
// ALPN, chunked encoding and HTTP/2 are handled the way a browser would handle
// them — measuring a hand-rolled HTTP/1.0 exchange would measure something no
// real client does.
func Fetch(ctx context.Context, cfg Config, domain, addr string) Transfer {
	cfg = cfg.withDefaults()
	t := Transfer{Status: PathUnknown}

	dialer := &net.Dialer{Timeout: cfg.Timeout}
	transport := &http.Transport{
		// Every connection is pinned to the address the caller resolved, so
		// the system resolver cannot redirect this measurement to a block page.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(addr, "443"))
		},
		TLSClientConfig: &tls.Config{
			ServerName: domain,
			MinVersion: tls.VersionTLS12,
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: cfg.Timeout,
	}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()

	// The body read gets its own budget on top of the handshake, since a
	// throttled connection is slow rather than unresponsive.
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout*3)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		t.Err = err.Error()
		return t
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Err = err.Error()
		t.Status = classifyTransferError(err)
		return t
	}
	defer func() { _ = resp.Body.Close() }()
	t.TTFB = time.Since(start)

	start = time.Now()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, transferLimit))
	t.Body = time.Since(start)
	t.Bytes = n
	if err != nil {
		// Bytes already read still describe the rate up to the failure, but the
		// attempt did not complete and must not be reported as a success.
		t.Err = err.Error()
		t.Status = classifyTransferError(err)
		return t
	}
	t.Status = PathOk
	return t
}

// classifyTransferError reuses the path vocabulary so a failed transfer reads
// the same way as a failed handshake.
func classifyTransferError(err error) PathStatus {
	switch {
	case isCertError(err):
		return PathCertBad
	case isReset(err):
		return PathReset
	case isTimeout(err):
		return PathTimeout
	default:
		return PathUnknown
	}
}

// FormatThroughput renders bytes per second for humans.
func FormatThroughput(bps float64) string {
	switch {
	case bps <= 0:
		return "-"
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", bps/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.0f KB/s", bps/(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}
