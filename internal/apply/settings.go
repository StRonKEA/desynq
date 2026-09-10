package apply

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// settingsFile is what turns this from a command into something that runs
// without one.
//
// Everything the tool does is currently spelled out in flags, which means the
// only way to reproduce an install is to remember the command that made it.
// Written down instead, the same intent is available to the service that runs
// at boot, to a future window or tray icon, and a plain `dpi auto` with no
// arguments — all reading one file rather than each holding its own copy of the
// user's mind.
const settingsFile = "dpi.json"

// Settings is the user's intent, as opposed to Plan, which is one particular
// realisation of it.
//
// The distinction matters: a Plan carries resolved addresses and a chosen
// strategy, both of which go stale. Settings carries what was asked for, which
// does not — so it is what a re-run, a repair or a UI should start from.
type Settings struct {
	// Hosts are the names to unblock.
	Hosts []string `json:"hosts"`
	// Strategy pins a specific desync strategy, one stage per entry. Empty
	// means search for one, which is the normal case: a strategy that works
	// today may not work next month, and the search is how that is discovered.
	Strategy []string `json:"strategy,omitempty"`
	// AllTraffic captures every TLS connection instead of only the target
	// addresses. Off by default because a driver that sees every connection is
	// what anti-cheat software reads as interference.
	//
	// Not omitempty: a missing key and "false" must round-trip the same way.
	// omitempty made empty listed-sites settings look broken on reload and the
	// UI flipped between modes.
	AllTraffic bool `json:"all_traffic"`
	// DNSMode is "" (leave the resolver alone), "resolver" or "hosts".
	DNSMode string `json:"dns_mode,omitempty"`
	// ServiceName allows more than one installation to coexist.
	ServiceName string `json:"service_name,omitempty"`
	// Autostart configures whether the Windows service starts automatically at boot.
	Autostart *bool `json:"autostart,omitempty"`
}

// AutostartEnabled reports whether background service autostart is on (defaults to true).
func (s Settings) AutostartEnabled() bool {
	if s.Autostart == nil {
		return true
	}
	return *s.Autostart
}

// SettingsPath is where the settings live for a given config directory.
func SettingsPath(configDir string) string { return filepath.Join(configDir, settingsFile) }

// SaveSettings records the intent behind an installation.
func SaveSettings(configDir string, s Settings) error {
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("apply: create config dir: %w", err)
	}
	if s.Hosts == nil {
		s.Hosts = []string{}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("apply: encode settings: %w", err)
	}
	if err := os.WriteFile(SettingsPath(configDir), append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("apply: write settings: %w", err)
	}
	return nil
}

// LoadSettings reads the recorded intent. A missing file is reported as
// os.ErrNotExist so a caller can tell "nothing configured yet" from "the file
// is broken" — the first is the normal state of a fresh install and must not
// read as an error.
func LoadSettings(configDir string) (Settings, error) {
	b, err := os.ReadFile(SettingsPath(configDir))
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, fmt.Errorf("apply: settings file is not readable JSON: %w", err)
	}
	if s.Hosts == nil {
		s.Hosts = []string{}
	}
	if err := s.Validate(); err != nil {
		return Settings{}, err
	}
	return s, nil
}

// ErrNoHosts means the settings name nothing to act on for an install/apply.
// An empty list is still a valid saved intent for the UI.
var ErrNoHosts = errors.New("apply: settings name no hosts")

// Validate rejects settings that would produce something other than what they
// appear to say.
func (s Settings) Validate() error {
	switch s.DNSMode {
	case "", "resolver", "hosts":
	default:
		return fmt.Errorf("apply: unknown dns_mode %q, want \"resolver\" or \"hosts\"", s.DNSMode)
	}
	return nil
}

// HasTargets reports whether install/apply has anything to cover.
func (s Settings) HasTargets() bool {
	return len(s.Hosts) > 0 || s.AllTraffic
}

// DiscardSettings removes the recorded intent, so that a removal leaves nothing
// claiming to describe an installation that no longer exists.
func DiscardSettings(configDir string) error {
	err := os.Remove(SettingsPath(configDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("apply: remove settings: %w", err)
	}
	return nil
}
