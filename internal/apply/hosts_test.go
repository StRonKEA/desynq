package apply

import (
	"strings"
	"testing"
)

// A real hosts file, with the comment header Windows ships and an entry a user
// might depend on.
const existingHosts = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n" +
	"#\r\n" +
	"#\t127.0.0.1       localhost\r\n" +
	"192.168.1.50 nas.local\r\n"

func TestRenderHostsAddsABlockAndKeepsEverythingElse(t *testing.T) {
	got := RenderHosts(existingHosts, []HostsEntry{
		{Host: "discord.com", Addrs: []string{"162.159.136.232", "162.159.128.233"}},
	})

	// Nothing outside the block may be disturbed: a hosts file carries entries
	// other software and the user depend on, and rewriting it wholesale would
	// be an unrecoverable edit to a system file.
	for _, line := range []string{"127.0.0.1       localhost", "192.168.1.50 nas.local",
		"# Copyright (c) 1993-2009 Microsoft Corp."} {
		if !strings.Contains(got, line) {
			t.Errorf("existing line lost: %q\n---\n%s", line, got)
		}
	}
	if !strings.Contains(got, hostsBegin) || !strings.Contains(got, hostsEnd) {
		t.Errorf("block markers missing:\n%s", got)
	}
	// Sorted, so an unchanged set of addresses produces an unchanged file and a
	// re-run is a no-op rather than a rewrite.
	if !strings.Contains(got, "162.159.128.233 discord.com\r\n162.159.136.232 discord.com") {
		t.Errorf("addresses not written in sorted order:\n%s", got)
	}
}

// Rewriting must replace the previous block, never stack a second one.
func TestRenderHostsReplacesItsOwnBlock(t *testing.T) {
	first := RenderHosts(existingHosts, []HostsEntry{
		{Host: "discord.com", Addrs: []string{"1.1.1.1"}},
	})
	second := RenderHosts(first, []HostsEntry{
		{Host: "discord.com", Addrs: []string{"2.2.2.2"}},
	})

	if strings.Count(second, hostsBegin) != 1 {
		t.Errorf("expected exactly one block, got %d:\n%s", strings.Count(second, hostsBegin), second)
	}
	if strings.Contains(second, "1.1.1.1") {
		t.Errorf("the previous address survived the rewrite:\n%s", second)
	}
	if !strings.Contains(second, "2.2.2.2 discord.com") {
		t.Errorf("the new address is missing:\n%s", second)
	}
	if !strings.Contains(second, "192.168.1.50 nas.local") {
		t.Errorf("a user entry was lost on rewrite:\n%s", second)
	}
}

// Removing must leave the file as it was found. This is the undo path, so it
// has to be exact rather than approximately right.
func TestRenderHostsWithNoEntriesRestoresTheFile(t *testing.T) {
	withBlock := RenderHosts(existingHosts, []HostsEntry{
		{Host: "discord.com", Addrs: []string{"1.1.1.1"}},
	})
	back := RenderHosts(withBlock, nil)

	if strings.Contains(back, hostsBegin) || strings.Contains(back, "1.1.1.1 discord.com") {
		t.Errorf("block not removed:\n%s", back)
	}
	if strings.TrimRight(back, "\r\n") != strings.TrimRight(existingHosts, "\r\n") {
		t.Errorf("file not restored.\ngot:\n%q\nwant:\n%q", back, existingHosts)
	}
}

// A block whose end marker someone deleted by hand must still be removable, or
// its entries would pin names that nothing can later find or undo.
func TestStripHandlesAnUnterminatedBlock(t *testing.T) {
	broken := existingHosts + hostsBegin + "\r\n1.1.1.1 discord.com\r\n"
	got := RenderHosts(broken, nil)
	if strings.Contains(got, "1.1.1.1 discord.com") || strings.Contains(got, hostsBegin) {
		t.Errorf("an unterminated block was left behind:\n%s", got)
	}
	if !strings.Contains(got, "192.168.1.50 nas.local") {
		t.Errorf("a user entry was lost:\n%s", got)
	}
}

func TestRenderHostsSkipsUnusableEntries(t *testing.T) {
	got := RenderHosts("", []HostsEntry{
		{Host: "", Addrs: []string{"1.1.1.1"}},                 // no name
		{Host: "nowhere.example"},                              // no address
		{Host: "  GOOD.example  ", Addrs: []string{"9.9.9.9"}}, // trimmed and lowercased
	})
	if strings.Contains(got, "nowhere.example") {
		t.Errorf("a name with no address must not be pinned:\n%s", got)
	}
	if !strings.Contains(got, "9.9.9.9 good.example") {
		t.Errorf("expected the usable entry, normalised:\n%s", got)
	}
}

// doctor compares what was pinned against what the name resolves to now, so the
// entries have to read back exactly as written.
func TestParseManagedHostsRoundTrip(t *testing.T) {
	entries := []HostsEntry{
		{Host: "discord.com", Addrs: []string{"162.159.128.233", "162.159.136.232"}},
		{Host: "cdn.example", Addrs: []string{"2606:4700::1"}},
	}
	got := ParseManagedHosts(RenderHosts(existingHosts, entries))

	if len(got) != 2 {
		t.Fatalf("read back %d entries, want 2: %+v", len(got), got)
	}
	byHost := map[string][]string{}
	for _, e := range got {
		byHost[e.Host] = e.Addrs
	}
	if strings.Join(byHost["discord.com"], ",") != "162.159.128.233,162.159.136.232" {
		t.Errorf("discord.com = %v", byHost["discord.com"])
	}
	if strings.Join(byHost["cdn.example"], ",") != "2606:4700::1" {
		t.Errorf("cdn.example = %v", byHost["cdn.example"])
	}
}

// Entries outside the managed block belong to someone else and must never be
// reported as ours — doctor would otherwise offer to "refresh" a user's own
// pinning.
func TestParseManagedHostsIgnoresForeignEntries(t *testing.T) {
	content := "10.0.0.1 someone.else\r\n" +
		RenderHosts("", []HostsEntry{{Host: "ours.example", Addrs: []string{"1.1.1.1"}}}) +
		"10.0.0.2 also.theirs\r\n"

	got := ParseManagedHosts(content)
	if len(got) != 1 || got[0].Host != "ours.example" {
		t.Errorf("ParseManagedHosts = %+v, want only the managed entry", got)
	}
}

// The path must follow the actual Windows installation. A tool that edits the
// wrong system file is worse than one that refuses.
func TestHostsPathFollowsSystemRoot(t *testing.T) {
	t.Setenv("SystemRoot", `D:\Windows`)
	if got := HostsPath(); got != `D:\Windows\System32\drivers\etc\hosts` {
		t.Errorf("HostsPath() = %q", got)
	}
	t.Setenv("SystemRoot", "")
	if got := HostsPath(); !strings.HasSuffix(got, `System32\drivers\etc\hosts`) {
		t.Errorf("HostsPath() = %q, want a sane fallback", got)
	}
}
