package apply

import (
	"fmt"
	"strings"
	"testing"
)

// Real `tasklist /FI "IMAGENAME eq winws2.exe" /FO CSV /NH` output.
const tasklistTwo = `"winws2.exe","12345","Console","1","9.876 K"
"winws2.exe","12346","Console","1","9.812 K"
`

func TestParseTasklist(t *testing.T) {
	got := parseTasklist(tasklistTwo, "winws2.exe")
	if len(got) != 2 {
		t.Fatalf("got %d processes, want 2: %+v", len(got), got)
	}
	if got[0].PID != 12345 || got[1].PID != 12346 {
		t.Errorf("PIDs = %d, %d", got[0].PID, got[1].PID)
	}
}

// tasklist answers an empty filter with a localised sentence, not with an empty
// document. It must not parse as a process, or every clean machine would report
// a stray engine.
func TestParseTasklistIgnoresLocalisedEmptyAnswer(t *testing.T) {
	cases := []string{
		"INFO: No tasks are running which match the specified criteria.\n",
		"BILGI: Belirtilen olculere uyan calisan gorev yok.\n",
		"",
		"\n\n",
	}
	for _, out := range cases {
		if got := parseTasklist(out, "winws2.exe"); len(got) != 0 {
			t.Errorf("parseTasklist(%q) = %+v, want none", out, got)
		}
	}
}

// The image name is matched again after tasklist has filtered, so a row for
// something else can never be counted as an engine.
func TestParseTasklistMatchesTheImage(t *testing.T) {
	out := `"chrome.exe","999","Console","1","400.000 K"
"WINWS2.EXE","42","Console","1","9.876 K"
`
	got := parseTasklist(out, "winws2.exe")
	if len(got) != 1 || got[0].PID != 42 {
		t.Errorf("parseTasklist = %+v, want only the case-insensitive engine match", got)
	}
}

func TestParseTasklistSkipsMalformedRows(t *testing.T) {
	out := `"winws2.exe"
"winws2.exe","notanumber","Console","1","9 K"
"winws2.exe","-5","Console","1","9 K"
"winws2.exe","7","Console","1","9 K"
`
	got := parseTasklist(out, "winws2.exe")
	if len(got) != 1 || got[0].PID != 7 {
		t.Errorf("parseTasklist = %+v, want only the well-formed row", got)
	}
}

// A running service explains exactly one engine. Anything beyond that is
// altering traffic without a supervisor, and — just as bad — would make a
// search score every candidate as working.
func TestUnaccountedEngines(t *testing.T) {
	cases := []struct {
		running int
		state   State
		want    int
	}{
		{0, StateAbsent, 0},
		{0, StateRunning, 0}, // the service is starting, or its engine just died
		{1, StateRunning, 0}, // the normal healthy shape
		{2, StateRunning, 1}, // one stray beside the service
		{1, StateAbsent, 1},  // the case that was actually hit: service gone, engine left
		{2, StateStopped, 2}, // a stopped service accounts for none
		{3, StatePending, 3}, // mid-transition, still nothing it explains
	}
	for _, c := range cases {
		if got := UnaccountedEngines(c.running, c.state); got != c.want {
			t.Errorf("UnaccountedEngines(%d, %q) = %d, want %d", c.running, c.state, got, c.want)
		}
	}
}

func TestKillCommand(t *testing.T) {
	got := strings.Join(KillCommand(1234), " ")
	if got != "taskkill /PID 1234 /F" {
		t.Errorf("KillCommand = %q", got)
	}
}

func TestSplitCSVLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"a","b","c"`, "a|b|c"},
		{`"winws2.exe","12345","Console","1","9.876 K"`, "winws2.exe|12345|Console|1|9.876 K"},
		// A comma inside a quoted field must not split it: memory figures are
		// comma-grouped in some locales.
		{`"winws2.exe","1","Console","1","9,876 K"`, "winws2.exe|1|Console|1|9,876 K"},
		{"", ""},
	}
	for _, c := range cases {
		got := strings.Join(splitCSVLine(c.in), "|")
		if got != c.want {
			t.Errorf("splitCSVLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func ExampleUnaccountedEngines() {
	// The shape that actually occurred: the service was removed, its engine
	// was not.
	fmt.Println(UnaccountedEngines(2, StateAbsent))
	// Output: 2
}
