package main

// culvert-os-update `docker`: the Docker package holds are the invariant
// (Codex P2 ×2, PR #1528). A failed upgrade AND a failed re-hold must both
// end in the recovery path — holds retried, truthfully reported, stack
// restarted — never in a silent exit with the engine unheld and the stack
// stopped. Driven for real through bash with PATH stubs for every system
// command the branch touches.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runOSUpdateDocker(t *testing.T, env ...string) (out, calls string, code int) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin, stack := filepath.Join(dir, "bin"), filepath.Join(dir, "stack")
	for _, d := range []string{bin, stack} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stack, "docker-compose.yml"), []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "appliance", "os-maintenance", "culvert-os-update"))
	if err != nil {
		t.Fatal(err)
	}
	script := strings.Replace(string(src), "STACK=/srv/culvert", "STACK="+stack, 1)
	script = strings.Replace(script, "LOG=/var/log/culvert-os-update.log", "LOG="+filepath.Join(dir, "log"), 1)
	if script == string(src) {
		t.Fatal("could not relocate STACK/LOG in culvert-os-update")
	}
	scriptPath := filepath.Join(dir, "culvert-os-update")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil { // run as `bash <file>`: no execute bit needed
		t.Fatal(err)
	}
	stubs := map[string]string{
		"id":        `echo 0`,
		"apt-mark":  `echo "apt-mark $*" >> "$CALLS"; [[ "$1" == hold && "${FAIL_HOLD:-0}" == 1 ]] && exit 100; exit 0`,
		"apt-get":   `echo "apt-get $*" >> "$CALLS"; [[ "$*" == *only-upgrade* && "${FAIL_UPGRADE:-0}" == 1 ]] && exit 100; exit 0`,
		"apt-cache": `echo "Candidate: 29.0"; exit 0`,
		"systemctl": `echo "systemctl $*" >> "$CALLS"; exit 0`,
		"docker":    `echo "docker $*" >> "$CALLS"; exit 0`,
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body+"\n"), 0o700); err != nil { //nolint:gosec // PATH stub in a test temp dir: must be executable
			t.Fatal(err)
		}
	}
	callsPath := filepath.Join(dir, "calls")
	cmd := exec.CommandContext(t.Context(), "bash", scriptPath, "docker") //nolint:gosec // test-owned copy of the script in t.TempDir()
	cmd.Env = append([]string{"PATH=" + bin + ":" + os.Getenv("PATH"), "CALLS=" + callsPath}, env...)
	b, _ := cmd.CombinedOutput()
	code = cmd.ProcessState.ExitCode()
	c, _ := os.ReadFile(callsPath)
	return string(b), string(c), code
}

func TestOSUpdateDocker_FailedUpgradeRestoresHoldsAndStack(t *testing.T) {
	out, calls, code := runOSUpdateDocker(t, "FAIL_UPGRADE=1")
	if code == 0 {
		t.Fatalf("a failed upgrade must exit non-zero:\n%s", out)
	}
	if !strings.Contains(out, "package holds restored") || !strings.Contains(calls, "apt-mark hold") || !strings.Contains(calls, "docker compose up -d") {
		t.Fatalf("holds and stack must be restored after a failed upgrade:\nout=%s\ncalls=%s", out, calls)
	}
}

func TestOSUpdateDocker_FailedRehold_IsRecoveredAndReportedTruthfully(t *testing.T) {
	out, calls, code := runOSUpdateDocker(t, "FAIL_HOLD=1")
	if code == 0 {
		t.Fatalf("a failed re-hold must exit non-zero:\n%s", out)
	}
	if strings.Count(calls, "apt-mark hold") < 2 {
		t.Fatalf("the trap must retry the hold after the main re-hold failed:\n%s", calls)
	}
	if !strings.Contains(out, "could NOT be restored") || strings.Contains(out, "package holds restored") {
		t.Fatalf("a failed re-hold must be reported as such, never as restored:\n%s", out)
	}
	if !strings.Contains(calls, "docker compose up -d") {
		t.Fatalf("the stack must be restarted even when the re-hold failed:\n%s", calls)
	}
}

// CONTROL: the happy path re-holds, restarts the engine and the stack, and
// never enters the recovery path.
func TestOSUpdateDocker_SuccessfulUpgradeTakesNoRecoveryPath(t *testing.T) {
	out, calls, code := runOSUpdateDocker(t)
	if code != 0 || strings.Contains(out, "FAILED") {
		t.Fatalf("happy path failed (code %d):\n%s", code, out)
	}
	for _, want := range []string{"apt-mark hold", "systemctl restart docker", "docker compose up -d"} {
		if !strings.Contains(calls, want) {
			t.Fatalf("happy path missing %q:\n%s", want, calls)
		}
	}
}
