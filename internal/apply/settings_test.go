package apply

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := Settings{
		Hosts:       []string{"discord.com", "pornhub.com"},
		Strategy:    []string{"fake:tcp_md5", "multisplit:pos=1"},
		AllTraffic:  true,
		DNSMode:     "hosts",
		ServiceName: "dpi-custom",
	}
	if err := SaveSettings(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Hosts, ",") != "discord.com,pornhub.com" {
		t.Errorf("Hosts = %v", got.Hosts)
	}
	// A multi-stage strategy is one strategy; splitting or reordering it would
	// install something that was never measured.
	if strings.Join(got.Strategy, "|") != "fake:tcp_md5|multisplit:pos=1" {
		t.Errorf("Strategy = %v", got.Strategy)
	}
	if !got.AllTraffic || got.DNSMode != "hosts" || got.ServiceName != "dpi-custom" {
		t.Errorf("settings did not survive the round trip: %+v", got)
	}
}

func TestSettingsRoundTripKeepsAllTrafficFalse(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSettings(dir, Settings{Hosts: []string{}, AllTraffic: false}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(SettingsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"all_traffic": false`) {
		t.Fatalf("all_traffic false was omitted from JSON: %s", raw)
	}
	got, err := LoadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.AllTraffic {
		t.Fatal("AllTraffic false became true on load")
	}
	if got.HasTargets() {
		t.Fatalf("empty listed-sites settings should have no targets: %+v", got)
	}
}

// "Nothing configured yet" is the normal state of a fresh install and must be
// distinguishable from a broken file, or the caller cannot tell whether to
// prompt or to complain.
func TestLoadSettingsReportsAMissingFileAsNotExist(t *testing.T) {
	if _, err := LoadSettings(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist", err)
	}
}

func TestLoadSettingsRejectsBrokenContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(SettingsPath(dir), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(dir); err == nil {
		t.Fatal("expected an error for unreadable JSON")
	} else if errors.Is(err, os.ErrNotExist) {
		t.Errorf("a broken file must not read as a missing one: %v", err)
	}
}

func TestSettingsValidate(t *testing.T) {
	cases := []struct {
		name string
		in   Settings
		ok   bool
	}{
		{"hosts and nothing else", Settings{Hosts: []string{"a.com"}}, true},
		{"resolver mode", Settings{Hosts: []string{"a.com"}, DNSMode: "resolver"}, true},
		{"hosts mode", Settings{Hosts: []string{"a.com"}, DNSMode: "hosts"}, true},
		{"empty list is valid intent", Settings{}, true},
		{"all traffic needs no hosts", Settings{AllTraffic: true}, true},
		{"unknown dns mode", Settings{Hosts: []string{"a.com"}, DNSMode: "magic"}, false},
	}
	for _, c := range cases {
		err := c.in.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: Validate() = %v, want nil", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: Validate() = nil, want an error", c.name)
		}
	}
	if (Settings{}).HasTargets() {
		t.Error("empty settings must not claim to have targets")
	}
	if !(Settings{AllTraffic: true}).HasTargets() {
		t.Error("all-traffic settings must be actionable")
	}
}

func TestLoadSettingsAcceptsAllTrafficWithNoHosts(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSettings(dir, Settings{AllTraffic: true}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings(dir)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if !got.AllTraffic {
		t.Fatal("AllTraffic was dropped on read — the UI would snap back to listed sites")
	}
}

func TestLoadSettingsAcceptsEmptyHostsList(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSettings(dir, Settings{Hosts: nil, DNSMode: "hosts"}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings(dir)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.DNSMode != "hosts" || got.AllTraffic || len(got.Hosts) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestDiscardSettings(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSettings(dir, Settings{Hosts: []string{"a.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := DiscardSettings(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SettingsPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("settings file still present: %v", err)
	}
	// Discarding twice is the normal path of a second `dpi remove`.
	if err := DiscardSettings(dir); err != nil {
		t.Errorf("discarding an absent file must not fail: %v", err)
	}
}
