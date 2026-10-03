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
	return runOSUpdate(t, "docker", env...)
}

func runOSUpdate(t *testing.T, mode string, env ...string) (out, calls string, code int) {
	t.Helper()
	return runOSUpdateWith(t, []string{mode}, nil, env...)
}

// runOSUpdateWith runs the script with args, after writing one agent
// journal record per name in journal (an operation in flight).
func runOSUpdateWith(t *testing.T, args, journal []string, env ...string) (out, calls string, code int) {
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
	jdir := filepath.Join(dir, "reconcile")
	script = strings.Replace(script, "MAINT_JOURNAL=/var/lib/culvert-maint/reconcile", "MAINT_JOURNAL="+jdir, 1)
	script = strings.Replace(script, "LOCK=/run/culvert-os-update.lock", "LOCK="+filepath.Join(dir, "lock"), 1)
	if !strings.Contains(script, "MAINT_JOURNAL="+jdir) || !strings.Contains(script, "LOCK="+filepath.Join(dir, "lock")) || !strings.Contains(script, "STACK="+stack) {
		t.Fatal("could not relocate STACK/LOG/MAINT_JOURNAL/LOCK in culvert-os-update")
	}
	if err := os.MkdirAll(jdir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, id := range journal {
		if err := os.WriteFile(filepath.Join(jdir, id+".json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scriptPath := filepath.Join(dir, "culvert-os-update")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil { // run as `bash <file>`: no execute bit needed
		t.Fatal(err)
	}
	stubs := map[string]string{
		"id":        `echo 0`,
		"apt-mark":  `echo "apt-mark $*" >> "$CALLS"; [[ "$1" == hold && "${FAIL_HOLD:-0}" == 1 ]] && exit 100; [[ "$1" == unhold && "${FAIL_UNHOLD:-0}" == 1 ]] && exit 100; exit 0`,
		"apt-get":   `echo "apt-get $*" >> "$CALLS"; [[ "$*" == *only-upgrade* && "${FAIL_UPGRADE:-0}" == 1 ]] && exit 100; exit 0`,
		"apt-cache": `echo "Candidate: 29.0"; exit 0`,
		"systemctl": `echo "systemctl $*" >> "$CALLS"; [[ "$1" == restart && "${FAIL_RESTART:-0}" == 1 ]] && exit 1; exit 0`,
		"docker":    `echo "docker $*" >> "$CALLS"; [[ "$1 $2" == "compose stop" && "${FAIL_STOP:-0}" == 1 ]] && exit 1; [[ "$1 $2" == "compose up" && "${FAIL_START:-0}" == 1 ]] && exit 1; exit 0`,
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body+"\n"), 0o700); err != nil { //nolint:gosec // PATH stub in a test temp dir: must be executable
			t.Fatal(err)
		}
	}
	callsPath := filepath.Join(dir, "calls")
	cmd := exec.CommandContext(t.Context(), "bash", append([]string{scriptPath}, args...)...) //nolint:gosec // test-owned copy of the script in t.TempDir(); args are test constants
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

// Owner review (PR #1528, 2026-10-03): recovery must be armed BEFORE the
// first mutation of the docker branch, not after `apt-mark unhold`. A failed
// or partial unhold (dpkg lock, I/O) and a failed stack stop both happen after
// the stack may already be down; a failed engine restart happens after the
// packages moved. Each must end in the same recovery: holds re-applied,
// stack start attempted, non-zero exit with an actionable message.
func TestOSUpdateDocker_EveryMutationFailureIsRecovered(t *testing.T) {
	for _, tc := range []struct{ name, env string }{
		{"unhold-fails", "FAIL_UNHOLD=1"},
		{"stack-stop-fails", "FAIL_STOP=1"},
		{"engine-restart-fails", "FAIL_RESTART=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, code := runOSUpdateDocker(t, tc.env)
			if code == 0 {
				t.Fatalf("a failed step must exit non-zero:\n%s", out)
			}
			if !strings.Contains(out, "Docker upgrade FAILED") {
				t.Fatalf("the failure must reach the recovery path and say so:\n%s", out)
			}
			// The LAST hold-state call must be a hold: whatever moved, the
			// packages end held.
			lastHold, lastUnhold := strings.LastIndex(calls, "apt-mark hold"), strings.LastIndex(calls, "apt-mark unhold")
			if lastHold < 0 || lastHold < lastUnhold {
				t.Fatalf("Docker packages must end HELD (last hold after last unhold):\n%s", calls)
			}
			if !strings.Contains(calls, "docker compose up -d") {
				t.Fatalf("the stack must be restarted after a failed maintenance step:\n%s", calls)
			}
		})
	}
}

// A stack that will not start again is reported, never claimed as done.
func TestOSUpdateDocker_StackStartFailureIsReported(t *testing.T) {
	out, calls, code := runOSUpdateDocker(t, "FAIL_START=1")
	if code == 0 || !strings.Contains(out, "stack did not start") {
		t.Fatalf("a stack that does not come back must fail loudly (code %d):\n%s", code, out)
	}
	if strings.LastIndex(calls, "apt-mark hold") < strings.LastIndex(calls, "apt-mark unhold") {
		t.Fatalf("holds must be re-applied:\n%s", calls)
	}
}

// `os` must move a kernel ABI bump (a new linux-image-<abi> package), which a
// plain `apt-get upgrade` keeps back, while leaving every hold in place and
// never touching the Docker packages (owner review, PR #1528).
func TestOSUpdateOS_InstallsNewKernelPackagesAndKeepsHolds(t *testing.T) {
	out, calls, code := runOSUpdate(t, "os")
	if code != 0 {
		t.Fatalf("os mode failed (%d):\n%s", code, out)
	}
	var upgrade string
	for _, l := range strings.Split(calls, "\n") {
		if strings.HasPrefix(l, "apt-get ") && strings.Contains(l, " upgrade") {
			upgrade = l
		}
	}
	if !strings.Contains(upgrade, "upgrade --with-new-pkgs") {
		t.Fatalf("os mode must run `upgrade --with-new-pkgs` (plain upgrade keeps a kernel ABI bump back); got %q", upgrade)
	}
	for _, forbidden := range []string{"apt-mark unhold", "dist-upgrade", "full-upgrade", "docker-ce"} {
		if strings.Contains(calls, forbidden) {
			t.Fatalf("os mode must leave the Docker holds alone; saw %q in:\n%s", forbidden, calls)
		}
	}
}

// Sequencing with the maintenance agent (owner review, PR #1528): while the
// agent's journal holds a record — an upgrade/rollback/restore in flight, or
// one interrupted and awaiting reconcile — no mutating mode may stop the
// stack, move the engine or reboot under it.
func TestOSUpdate_RefusesWhileTheAgentHasAnOperationInFlight(t *testing.T) {
	for _, mode := range []string{"os", "security", "docker", "reboot"} {
		t.Run(mode, func(t *testing.T) {
			out, calls, code := runOSUpdateWith(t, []string{mode}, []string{"01M40NA2MFQW9CCZN85KRQB6MC"})
			if code != 3 || !strings.Contains(out, "01M40NA2MFQW9CCZN85KRQB6MC") {
				t.Fatalf("%s must refuse (exit 3) naming the in-flight op; code=%d\n%s", mode, code, out)
			}
			if strings.TrimSpace(calls) != "" {
				t.Fatalf("%s mutated something while refusing:\n%s", mode, calls)
			}
		})
	}
}

func TestOSUpdate_ForceOverridesTheJournalGuard(t *testing.T) {
	out, calls, code := runOSUpdateWith(t, []string{"os", "--force"}, []string{"01M40NA2MFQW9CCZN85KRQB6MC"})
	if code != 0 || !strings.Contains(out, "--force: proceeding") || !strings.Contains(calls, "upgrade --with-new-pkgs") {
		t.Fatalf("--force must proceed and say so; code=%d\n%s\n%s", code, out, calls)
	}
}

// CONTROLS: `check` is read-only and never refused, and an empty journal
// refuses nothing.
func TestOSUpdate_GuardIgnoresReadOnlyModeAndEmptyJournal(t *testing.T) {
	if _, _, code := runOSUpdateWith(t, []string{"check"}, []string{"01M40NA2MFQW9CCZN85KRQB6MC"}); code != 0 {
		t.Fatalf("check must not be gated, code=%d", code)
	}
	if _, _, code := runOSUpdate(t, "os"); code != 0 {
		t.Fatalf("an empty journal must not refuse, code=%d", code)
	}
}
