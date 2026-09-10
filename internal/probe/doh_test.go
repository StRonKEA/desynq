package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// dohStub serves canned answers per query type, and records what was asked.
// The record is mutex-guarded because each request is handled on its own
// goroutine.
func dohStub(t *testing.T, byType map[string]string) (endpoint string, asked func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qtype := r.URL.Query().Get("type")
		mu.Lock()
		seen = append(seen, qtype)
		mu.Unlock()
		body, ok := byType[qtype]
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

const (
	answerA = `{"Answer":[
		{"type":5,"data":"cdn.example.net."},
		{"type":1,"data":"162.159.128.233"},
		{"type":1,"data":"162.159.136.232"}]}`
	answerAAAA = `{"Answer":[
		{"type":5,"data":"cdn.example.net."},
		{"type":28,"data":"2606:4700::6810:85E5"}]}`
	answerEmpty = `{"Answer":[]}`
)

func TestResolveDoHReturnsBothFamilies(t *testing.T) {
	ep, asked := dohStub(t, map[string]string{"1": answerA, "28": answerAAAA})

	rec, err := resolveDoH(context.Background(), []string{ep}, "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("resolveDoH: %v", err)
	}
	if strings.Join(rec.v4, ",") != "162.159.128.233,162.159.136.232" {
		t.Errorf("v4 = %v", rec.v4)
	}
	// Normalised to lowercase compressed form, which is what the filter and the
	// drift comparison both expect.
	if strings.Join(rec.v6, ",") != "2606:4700::6810:85e5" {
		t.Errorf("v6 = %v", rec.v6)
	}
	if rec.v6Unknown {
		t.Error("the AAAA question was answered, so it is not unknown")
	}
	if got := asked(); len(got) != 2 {
		t.Errorf("expected both questions to be asked, got %v", got)
	}
}

// The distinction between "no IPv6" and "IPv6 not established" is the whole
// point: a filter built on an unproven absence is exactly how IPv6 traffic
// escapes the strategy while every IPv4 check reports success.
func TestResolveDoHMarksIPv6UnknownWhenAAAAFails(t *testing.T) {
	ep, _ := dohStub(t, map[string]string{"1": answerA}) // AAAA yields 503

	rec, err := resolveDoH(context.Background(), []string{ep}, "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("resolveDoH: %v", err)
	}
	if len(rec.v4) == 0 {
		t.Error("a failed AAAA question must not discard a good A answer")
	}
	if !rec.v6Unknown {
		t.Error("an unanswered AAAA question must be reported as unknown")
	}
}

// An empty AAAA answer is a real result: this name has no IPv6 address, and
// saying so lets the filter be built with confidence.
func TestResolveDoHEmptyAAAAIsKnownAbsence(t *testing.T) {
	ep, _ := dohStub(t, map[string]string{"1": answerA, "28": answerEmpty})

	rec, err := resolveDoH(context.Background(), []string{ep}, "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("resolveDoH: %v", err)
	}
	if rec.v6Unknown || len(rec.v6) != 0 {
		t.Errorf("expected a known absence, got v6=%v unknown=%v", rec.v6, rec.v6Unknown)
	}
}

// A name with AAAA but no A is alive, not dead. Reporting errNoRecords would
// classify it as a vanished domain.
func TestResolveDoHIPv6OnlyNameIsNotNoRecords(t *testing.T) {
	ep, _ := dohStub(t, map[string]string{"1": answerEmpty, "28": answerAAAA})

	rec, err := resolveDoH(context.Background(), []string{ep}, "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("expected success for an IPv6-only name, got %v", err)
	}
	if len(rec.v4) != 0 || len(rec.v6) != 1 {
		t.Errorf("v4=%v v6=%v", rec.v4, rec.v6)
	}
}

func TestResolveDoHNoRecordsWhenBothEmpty(t *testing.T) {
	ep, _ := dohStub(t, map[string]string{"1": answerEmpty, "28": answerEmpty})

	if _, err := resolveDoH(context.Background(), []string{ep}, "gone.example", 2*time.Second); !errors.Is(err, errNoRecords) {
		t.Errorf("err = %v, want errNoRecords", err)
	}
}

// A second endpoint must be able to settle a question the first could not,
// rather than the first endpoint's silence standing as the answer.
func TestResolveDoHFallsThroughToTheNextEndpoint(t *testing.T) {
	dead, _ := dohStub(t, nil) // every question yields 503
	good, _ := dohStub(t, map[string]string{"1": answerA, "28": answerAAAA})

	rec, err := resolveDoH(context.Background(), []string{dead, good}, "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("resolveDoH: %v", err)
	}
	if len(rec.v4) == 0 || len(rec.v6) == 0 || rec.v6Unknown {
		t.Errorf("second endpoint did not settle both questions: %+v", rec)
	}
}

// A record type and its literal must agree. An IPv4 address returned under an
// AAAA answer would otherwise become an `ipv6.DstAddr==1.2.3.4` filter term,
// which matches nothing at all.
func TestQueryDoHRejectsFamilyMismatch(t *testing.T) {
	ep, _ := dohStub(t, map[string]string{
		"28": `{"Answer":[{"type":28,"data":"1.2.3.4"},{"type":28,"data":"2606:4700::1"}]}`,
		"1":  `{"Answer":[{"type":1,"data":"2606:4700::1"},{"type":1,"data":"9.9.9.9"}]}`,
	})

	rec, err := resolveDoH(context.Background(), []string{ep}, "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("resolveDoH: %v", err)
	}
	if strings.Join(rec.v4, ",") != "9.9.9.9" {
		t.Errorf("v4 = %v, want only the dotted quad", rec.v4)
	}
	if strings.Join(rec.v6, ",") != "2606:4700::1" {
		t.Errorf("v6 = %v, want only the IPv6 literal", rec.v6)
	}
}
