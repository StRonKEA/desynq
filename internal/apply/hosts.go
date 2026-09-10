package apply

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HostsPath is the Windows hosts file.
//
// Read from the environment rather than hardcoded to C:\: Windows can be
// installed elsewhere, and a tool that edits the wrong system file is worse
// than one that refuses.
func HostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

// The managed block is delimited so that removal is exact. Everything outside
// these markers belongs to the user or to other software and is never touched —
// a hosts file can carry entries someone depends on, and rewriting it wholesale
// would be an unrecoverable edit to a system file.
const (
	hostsBegin = "# dpi-bypass begin - managed by dpi, do not edit inside this block"
	hostsEnd   = "# dpi-bypass end"
)

// HostsEntry pins one name to the addresses the encrypted resolver gave.
type HostsEntry struct {
	Host  string
	Addrs []string
}

// RenderHosts returns the contents of the hosts file with the managed block
// replaced by these entries. An empty entry list removes the block entirely.
//
// This is the DNS remedy that touches one site instead of the whole machine.
// Changing the system resolver fixes every name on the computer; pinning here
// fixes exactly the names asked for and leaves everything else resolving the
// way it did. It is the same reasoning as the targeted kernel filter.
//
// The trade-off is the same one too: an address list is a snapshot. When a CDN
// moves the host these entries are stale, and — unlike a stale kernel filter,
// which merely stops helping — a stale hosts entry actively sends the browser
// to an address that no longer serves the site. `dpi doctor` compares them
// against current resolution for exactly that reason.
func RenderHosts(existing string, entries []HostsEntry) string {
	kept := stripManagedBlock(existing)

	usable := make([]HostsEntry, 0, len(entries))
	for _, e := range entries {
		host := strings.TrimSpace(strings.ToLower(e.Host))
		addrs := dedupeSorted(func(yield func(string)) {
			for _, a := range e.Addrs {
				yield(a)
			}
		})
		if host == "" || len(addrs) == 0 {
			continue
		}
		usable = append(usable, HostsEntry{Host: host, Addrs: addrs})
	}
	if len(usable) == 0 {
		return kept
	}
	sort.Slice(usable, func(i, j int) bool { return usable[i].Host < usable[j].Host })

	var b strings.Builder
	b.WriteString(kept)
	if kept != "" && !strings.HasSuffix(kept, "\n") {
		b.WriteString("\r\n")
	}
	b.WriteString(hostsBegin)
	b.WriteString("\r\n")
	for _, e := range usable {
		for _, a := range e.Addrs {
			fmt.Fprintf(&b, "%s %s\r\n", a, e.Host)
		}
	}
	b.WriteString(hostsEnd)
	b.WriteString("\r\n")
	return b.String()
}

// stripManagedBlock removes a previously written block, leaving everything else
// byte for byte.
//
// An unterminated block — someone deleted the end marker by hand — is treated
// as running to the end of the file. Leaving its entries in place would pin
// names nothing could later find or remove.
func stripManagedBlock(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		switch {
		case trimmed == hostsBegin:
			inBlock = true
		case inBlock && trimmed == hostsEnd:
			inBlock = false
		case !inBlock:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// ParseManagedHosts reads back the entries this tool wrote, so they can be
// compared against what the names resolve to now.
func ParseManagedHosts(s string) []HostsEntry {
	byHost := map[string][]string{}
	var order []string

	inBlock := false
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		switch {
		case trimmed == hostsBegin:
			inBlock = true
			continue
		case trimmed == hostsEnd:
			inBlock = false
			continue
		case !inBlock || trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		host := strings.ToLower(fields[1])
		if _, seen := byHost[host]; !seen {
			order = append(order, host)
		}
		byHost[host] = append(byHost[host], fields[0])
	}

	entries := make([]HostsEntry, 0, len(order))
	for _, h := range order {
		entries = append(entries, HostsEntry{Host: h, Addrs: byHost[h]})
	}
	return entries
}

// hostsBackupFile keeps the file as it was before the first managed write.
const hostsBackupFile = "hosts-backup.txt"

// WriteHosts replaces the managed block in the system hosts file.
//
// The original is copied to configDir first. The managed block makes removal
// exact on its own, but a hosts file is a system file that other software also
// edits, and a copy is the only thing that helps if this ever writes something
// unexpected.
func WriteHosts(configDir string, entries []HostsEntry) error {
	path := HostsPath()
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("apply: read hosts: %w", err)
	}

	backup := filepath.Join(configDir, hostsBackupFile)
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			return fmt.Errorf("apply: create config dir: %w", err)
		}
		if err := os.WriteFile(backup, current, 0o644); err != nil {
			return fmt.Errorf("apply: save hosts backup: %w", err)
		}
	}

	next := RenderHosts(string(current), entries)
	if next == string(current) {
		return nil
	}
	if err := os.WriteFile(path, []byte(next), 0o644); err != nil {
		return fmt.Errorf("apply: write hosts (needs Administrator): %w", err)
	}
	return nil
}

// ReadManagedHosts returns the entries currently pinned by this tool.
func ReadManagedHosts() ([]HostsEntry, error) {
	b, err := os.ReadFile(HostsPath())
	if err != nil {
		return nil, fmt.Errorf("apply: read hosts: %w", err)
	}
	return ParseManagedHosts(string(b)), nil
}
