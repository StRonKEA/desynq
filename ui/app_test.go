package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// A nil Go slice marshals to JSON null, and the window reads every list as an
// array. That mismatch threw mid-render and left the panel half drawn with a
// bare TypeError in the corner, so the contract is worth locking down: no list
// in a Snapshot ever reaches the frontend as null.
func TestSnapshotListsAreNeverNull(t *testing.T) {
	// The zero value is the worst case — nothing installed, nothing configured,
	// which is exactly the state a first run is in.
	b, err := json.Marshal(Snapshot{}.normalise())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"addresses", "profiles", "sites"} {
		if strings.Contains(string(b), `"`+field+`":null`) {
			t.Errorf("%s marshalled as null: %s", field, b)
		}
	}
}

func TestNormaliseReachesNestedLists(t *testing.T) {
	s := Snapshot{
		Profiles: []ProfileView{{Strategy: "multisplit:pos=1"}},
		Sites:    []SiteView{{Host: "discord.com"}},
	}.normalise()

	if s.Profiles[0].Hosts == nil {
		t.Error("ProfileView.Hosts is still nil")
	}
	if s.Sites[0].Addrs == nil || s.Sites[0].Missing == nil {
		t.Error("SiteView lists are still nil")
	}
}

func TestUniqueHostsFoldsCaseAndBlanks(t *testing.T) {
	got := uniqueHosts([]string{"Discord.com", " discord.com ", "", "github.com"})
	if strings.Join(got, ",") != "discord.com,github.com" {
		t.Errorf("uniqueHosts = %v", got)
	}
}

func TestCountIPv6IgnoresGarbage(t *testing.T) {
	if n := countIPv6([]string{"1.2.3.4", "2606:4700::", "not-an-address"}); n != 1 {
		t.Errorf("countIPv6 = %d, want 1", n)
	}
}

func TestSplitElevateCmdsSplitsChainedDpi(t *testing.T) {
	got := splitElevateCmds([]string{
		"remove", "-service", "dpi-bypass", "&&", "dpi.exe", "apply", "-all-traffic", "-install",
	})
	if len(got) != 2 {
		t.Fatalf("got %d commands, want 2: %v", len(got), got)
	}
	if strings.Join(got[0], " ") != "remove -service dpi-bypass" {
		t.Errorf("first = %v", got[0])
	}
	if strings.Join(got[1], " ") != "apply -all-traffic -install" {
		t.Errorf("second = %v", got[1])
	}
}

func TestElevateScriptWritesOneLinePerCommand(t *testing.T) {
	script := string(elevateScript(`C:\app\dpi.exe`, `C:\tmp\out.log`, `C:\tmp\done`, []string{
		"remove", "&&", "dpi.exe", "apply", "-all-traffic",
	}))
	if !strings.Contains(script, `"C:\app\dpi.exe" remove >>"C:\tmp\out.log" 2>&1`) {
		t.Errorf("missing remove line:\n%s", script)
	}
	if !strings.Contains(script, `"C:\app\dpi.exe" apply -all-traffic >>"C:\tmp\out.log" 2>&1`) {
		t.Errorf("missing apply line:\n%s", script)
	}
	if strings.Count(script, "dpi.exe") != 2 {
		t.Errorf("want two dpi.exe lines, got:\n%s", script)
	}
}
