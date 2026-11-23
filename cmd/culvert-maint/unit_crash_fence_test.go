package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unitServiceSettings returns the [Service] assignments of the shipped unit,
// last assignment winning, as systemd reads them.
func unitServiceSettings(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("..", "..", "packaging", "systemd", "culvert-maint.service")
	f, err := os.Open(path) // #nosec G304 -- fixed repository path
	if err != nil {
		t.Fatalf("open shipped unit: %v", err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && section == "[Service]" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read shipped unit: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("shipped unit has no [Service] settings — the parser or the path is wrong")
	}
	return out
}

// systemdTrue reports whether v is one of systemd's spellings of true.
func systemdTrue(v string) bool {
	switch strings.ToLower(v) {
	case "yes", "true", "1", "on":
		return true
	}
	return false
}

// TestShippedUnit_CrashFence pins the supervisor settings crash recovery
// depends on.
//
// initJournal treats a journal record found at startup as an operation with no
// process behind it, and a later successful operation retires it. Both are
// only sound if a Docker command the dead agent started cannot still be
// running. The runner gives every command its own process group, so the agent
// cannot guarantee that; systemd's control-group kill does, and it also holds
// the next start until the group is empty. KillMode=process or none removes
// the guarantee without any other test in this module noticing — hence this
// one. Drop-ins on an installed host are out of reach of a repository test.
func TestShippedUnit_CrashFence(t *testing.T) {
	svc := unitServiceSettings(t)

	if got := svc["KillMode"]; got != "control-group" {
		t.Errorf("KillMode = %q, want an explicit \"control-group\": process and none let an in-flight "+
			"docker command outlive the agent into the next start", got)
	}
	// SendSIGKILL=no would let a command that ignores SIGTERM stay in the
	// group forever; the unit would then never restart. Not a safety hole,
	// but it turns a crash into a permanent outage of the agent.
	if got, set := svc["SendSIGKILL"]; set && !systemdTrue(got) {
		t.Errorf("SendSIGKILL = %q: leftover commands must be killed after TimeoutStopSec", got)
	}
	// The fence only matters because the agent is restarted automatically.
	if got := svc["Restart"]; got == "" || got == "no" || got == "on-success" {
		t.Errorf("Restart = %q: the unit is expected to restart the agent after a crash", got)
	}
	// ExecStop / ExecStopPost run while leftover commands may still be alive;
	// nothing may be added there that changes Docker.
	for _, k := range []string{"ExecStop", "ExecStopPost"} {
		if v, set := svc[k]; set {
			t.Errorf("%s = %q: a stop hook runs before the control group is empty; review the crash "+
				"fence before adding one", k, v)
		}
	}
}
