package apply

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
)

// EngineProcess is one running engine process.
type EngineProcess struct {
	PID   int
	Image string
}

// RunningEngines lists the engine processes on this machine.
//
// It exists because nothing else in this tool would notice one. `dpi status`
// and `dpi doctor` both report the *service*, so an engine that outlived its
// supervisor — a stop that timed out, a crash, an earlier foreground run —
// keeps desyncing traffic with no sign of it anywhere. That happened: after a
// removal reported the service absent and the driver unloaded, two leftover
// processes were still unblocking a host, and killing them was what brought the
// block back.
//
// It is also a measurement hazard. A search running beside a stray engine
// scores every candidate as working, because the traffic is already being
// fixed by something the search does not know about.
func RunningEngines(ctx context.Context, binaryPath string) []EngineProcess {
	image := filepath.Base(binaryPath)
	if image == "" || image == "." {
		image = "winws2.exe"
	}

	// tasklist rather than a process API: no new dependency, and the CSV form
	// is stable. Its "no tasks" message is localised, but that line simply
	// fails to parse as a row, so nothing depends on reading it.
	out, err := runCombined(ctx, "tasklist",
		"/FI", "IMAGENAME eq "+image, "/FO", "CSV", "/NH")
	if err != nil {
		return nil
	}
	return parseTasklist(string(out), image)
}

// parseTasklist reads `tasklist /FO CSV /NH` output.
func parseTasklist(out, image string) []EngineProcess {
	var procs []EngineProcess
	for _, line := range strings.Split(out, "\n") {
		fields := splitCSVLine(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		// The filter is applied by tasklist, but it is matched again here: a
		// localised "no tasks" line must never be mistaken for a process, and
		// neither must a future column reordering.
		if !strings.EqualFold(fields[0], image) {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(fields[1]))
		if err != nil || pid <= 0 {
			continue
		}
		procs = append(procs, EngineProcess{PID: pid, Image: fields[0]})
	}
	return procs
}

// splitCSVLine splits one quoted CSV row. tasklist quotes every field and the
// values it emits contain no escaped quotes, so this stays deliberately small.
func splitCSVLine(line string) []string {
	if line == "" {
		return nil
	}
	var fields []string
	var cur strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '"':
			inQuotes = !inQuotes
		case c == ',' && !inQuotes:
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

// ExpectedEngines is how many engine processes a service in this state should
// account for.
//
// One per running service: a plan installs a single winws2 carrying every
// profile, so a second process is never this service's doing. A stopped or
// absent service accounts for none.
func ExpectedEngines(state State) int {
	if state == StateRunning {
		return 1
	}
	return 0
}

// UnaccountedEngines is how many running engines the service does not explain.
//
// It deliberately reports a count rather than naming which process is stray:
// the processes are indistinguishable from the outside, and claiming to know
// which one belongs to the service would be a guess presented as a finding.
func UnaccountedEngines(running int, state State) int {
	if n := running - ExpectedEngines(state); n > 0 {
		return n
	}
	return 0
}

// KillCommand returns the command that ends one engine process.
func KillCommand(pid int) []string {
	return []string{"taskkill", "/PID", strconv.Itoa(pid), "/F"}
}
