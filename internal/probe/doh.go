package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// DoH resolvers are addressed by literal IP on purpose. A hostname would need
// the very DNS we distrust, and connecting to a bare IP sends no SNI, so an
// SNI-filtering middlebox has nothing to match on. Their certificates carry the
// IP in a SAN, so verification still applies.
var defaultDoH = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/resolve",
}

// errNoRecords means the encrypted resolver answered but holds no address of
// either family, which distinguishes a dead domain from an unreachable resolver.
var errNoRecords = errors.New("no address records")

// DNS record types, as they appear in both the query and the JSON answer.
const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

type dohAnswer struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// dohRecords is one name's addresses, kept split by family because the two are
// used differently: the IPv4 address is what the prober dials and what an
// engine instance is pinned to, while IPv6 addresses only have to reach the
// kernel filter.
type dohRecords struct {
	v4 []string
	v6 []string
	// v6Unknown means no endpoint answered the AAAA question at all, so "this
	// name has no IPv6 address" was never established. The distinction matters:
	// a filter built on that assumption is precisely how IPv6 traffic escapes
	// the strategy while every IPv4 check reports success.
	v6Unknown bool
}

// resolveDoH returns the addresses of both families as seen through an
// encrypted resolver, trying each endpoint until one answers.
func resolveDoH(ctx context.Context, endpoints []string, domain string, timeout time.Duration) (dohRecords, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
	}

	rec := dohRecords{v6Unknown: true}
	var transportErr error
	answered := false

	for _, ep := range endpoints {
		v4, err := queryDoH(ctx, client, ep, domain, dnsTypeA)
		if err != nil {
			// An endpoint that cannot answer the A question is not asked the
			// AAAA one either; the next endpoint gets both.
			transportErr = err
			continue
		}
		answered = true
		if rec.v6Unknown {
			if v6, err6 := queryDoH(ctx, client, ep, domain, dnsTypeAAAA); err6 == nil {
				rec.v6Unknown = false
				rec.v6 = v6
			}
		}
		if len(v4) > 0 && rec.v4 == nil {
			rec.v4 = v4
		}
		// Keep asking only while something is still unsettled. An A answer with
		// the AAAA question unanswered is worth one more endpoint, because
		// assuming "no IPv6" is the expensive mistake here.
		if rec.v4 != nil && !rec.v6Unknown {
			return rec, nil
		}
	}

	switch {
	case rec.v4 != nil, len(rec.v6) > 0:
		// An IPv6-only name has no A record and is still perfectly alive.
		return rec, nil
	case answered:
		// Every endpoint replied with an empty answer section, which is a real
		// NXDOMAIN-style result rather than a failure to reach them.
		return rec, errNoRecords
	case transportErr != nil:
		return rec, transportErr
	default:
		return rec, errNoRecords
	}
}

func queryDoH(ctx context.Context, client *http.Client, endpoint, domain string, qtype int) ([]string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("name", domain)
	q.Set("type", strconv.Itoa(qtype))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: http %d", endpoint, resp.StatusCode)
	}

	var ans dohAnswer
	if err := json.NewDecoder(resp.Body).Decode(&ans); err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	var ips []string
	for _, a := range ans.Answer {
		if a.Type != qtype { // CNAME chains also appear in the answer section
			continue
		}
		ip := net.ParseIP(a.Data)
		if ip == nil {
			continue
		}
		// The record type and the literal must agree. A mismatch means the
		// answer is malformed, and letting it through would put an IPv4 address
		// where the caller expects to build an ipv6 filter term.
		if (ip.To4() != nil) != (qtype == dnsTypeA) {
			continue
		}
		ips = append(ips, ip.String())
	}
	sort.Strings(ips)
	return ips, nil
}
