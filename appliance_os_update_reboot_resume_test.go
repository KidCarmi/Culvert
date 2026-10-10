package main

// culvert-os-update `reboot` must bring the stack back (F-OSU-REBOOT-1).
// `docker compose stop` marks the containers manually stopped, so their
// `restart: unless-stopped` policy does NOT start them when the engine comes
// back: in QEMU lab run 37156062516 the guest rebooted onto the new kernel in
// ~11 s and both containers were still Exited 40 minutes later. `reboot` now
// arms a marker BEFORE the stop; culvert-stack-resume.service runs
// `resume-stack` at boot and clears it only once the stack started.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func armShutdownFence(t *testing.T, boot, phase string) {
	t.Helper()
	osUpdateHook = func(state string) {
		if err := os.MkdirAll(state, 0o750); err != nil {
			t.Fatal(err)
		}
		data := "culvert-shutdown-v1 " + boot + " reboot " + phase + "\n"
		if err := os.WriteFile(filepath.Join(state, "host-shutdown.pending"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { osUpdateHook = nil })
}

func TestOSUpdate_PendingShutdownFenceBlocksAfterOwnerExit(t *testing.T) {
	armShutdownFence(t, osUpdateTestBootID, "pending")
	armResumeMarker(t)
	for _, mode := range []string{"reboot", "poweroff", "os", "security", "docker", "resume-stack"} {
		out, calls, code := runOSUpdateWith(t, []string{mode, "--force"}, nil)
		if code != 3 || strings.Contains(calls, "docker ") || strings.Contains(calls, "systemctl ") || !strings.Contains(calls, "final:shutdown-fence-present") {
			t.Fatalf("pending shutdown admitted %s: code=%d calls=%s\n%s", mode, code, calls, out)
		}
	}
}

func TestOSUpdate_AbortedShutdownCanRetryResumeInSameBoot(t *testing.T) {
	armShutdownFence(t, osUpdateTestBootID, "aborted")
	armResumeMarker(t)
	out, calls, code := runOSUpdate(t, "resume-stack")
	if code != 0 || !strings.Contains(calls, "docker compose up -d") || strings.Contains(calls, "final:") {
		t.Fatalf("aborted power did not recover: code=%d calls=%s\n%s", code, calls, out)
	}
	out, calls, code = runOSUpdate(t, "resume-stack", "FAIL_START=1")
	if code == 0 || !strings.Contains(calls, "final:shutdown-fence-present") || !strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("failed retry lost pending recovery: code=%d calls=%s\n%s", code, calls, out)
	}
}

func TestOSUpdate_ResumeRefusesInterruptedJournalEvenAfterNewBoot(t *testing.T) {
	armShutdownFence(t, "00000000-0000-0000-0000-000000000000", "pending")
	armResumeMarker(t)
	out, calls, code := runOSUpdateWith(t, []string{"resume-stack", "--force"}, []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	if code != 3 || strings.Contains(calls, "docker ") || !strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("resume ignored interrupted journal: code=%d calls=%s\n%s", code, calls, out)
	}
	if strings.Contains(calls, "final:shutdown-fence-present") {
		t.Fatal("valid earlier-boot fence was not cleared under lock")
	}
}

func armResumeMarker(t *testing.T) {
	t.Helper()
	osUpdateResumeHook = func(p string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { osUpdateResumeHook = nil })
}

func TestOSUpdateReboot_ArmsResumeBeforeStoppingTheStack(t *testing.T) {
	out, calls, code := runOSUpdate(t, "reboot")
	if code != 0 {
		t.Fatalf("an accepted reboot request must succeed (code %d):\n%s", code, out)
	}
	stop, reboot := strings.Index(calls, "docker compose stop"), strings.Index(calls, "systemctl reboot")
	if stop < 0 || reboot < stop {
		t.Fatalf("want the stack stopped, then the reboot:\n%s", calls)
	}
	if !strings.Contains(calls, "resume-marker:armed") {
		t.Fatalf("the resume marker must be armed BEFORE the stack is stopped (a stop marks the containers manually stopped):\n%s", calls)
	}
	if !strings.Contains(calls, "final:resume-marker-present") || strings.Contains(calls, "docker compose up") {
		t.Fatalf("an accepted reboot must leave the marker for the boot and must not restart the stack:\n%s\n%s", calls, out)
	}
}

// ACCEPTED is not DONE: systemctl returns once the shutdown job is queued and
// this command then exits, releasing both locks. What keeps the agent from
// admitting an upgrade/restore into a host that is going down is the durable
// shutdown fence (#1540), written BEFORE the stack stops and still present
// when the command has exited. (It replaces the interim foreground lock hold
// of cf59cefb; TestOSUpdate_PendingShutdownFenceBlocksAfterOwnerExit proves
// every mode then refuses in the same boot, --force included.)
func TestOSUpdateReboot_AcceptedRequestLeavesTheShutdownFence(t *testing.T) {
	for _, mode := range []string{"reboot", "poweroff"} {
		out, calls, code := runOSUpdate(t, mode)
		if code != 0 {
			t.Fatalf("%s: accepted request must succeed (code %d):\n%s", mode, code, out)
		}
		if !strings.Contains(calls, "shutdown-fence:armed") {
			t.Fatalf("%s: the shutdown fence must exist BEFORE the stack is stopped:\n%s", mode, calls)
		}
		if !strings.Contains(calls, "final:shutdown-fence-present") || !strings.Contains(calls, "final:resume-marker-present") ||
			strings.Contains(calls, "docker compose up") {
			t.Fatalf("%s: an accepted request must leave the fence and the marker and must not restart the stack:\n%s", mode, calls)
		}
	}
}

func TestOSUpdateReboot_FailedStopRestartsTheStackAndDoesNotReboot(t *testing.T) {
	out, calls, code := runOSUpdate(t, "reboot", "FAIL_STOP=1")
	if code == 0 {
		t.Fatalf("a failed stop must exit non-zero:\n%s", out)
	}
	if strings.Contains(calls, "systemctl reboot") {
		t.Fatalf("must not reboot after a failed stop:\n%s", calls)
	}
	if !strings.Contains(calls, "docker compose up -d") || strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("the stack must be started again and the marker cleared:\n%s", calls)
	}
}

func TestOSUpdateResumeStack_StartsTheStackAndClearsTheMarker(t *testing.T) {
	armResumeMarker(t)
	out, calls, code := runOSUpdate(t, "resume-stack")
	if code != 0 {
		t.Fatalf("resume-stack failed (code %d):\n%s", code, out)
	}
	if !strings.Contains(calls, "docker compose up -d") {
		t.Fatalf("resume-stack must start the stack:\n%s", calls)
	}
	if strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("the marker must be cleared once the stack started:\n%s", calls)
	}
}

func TestOSUpdateResumeStack_FailedStartKeepsTheMarkerAndFails(t *testing.T) {
	armResumeMarker(t)
	out, calls, code := runOSUpdate(t, "resume-stack", "FAIL_START=1")
	if code == 0 {
		t.Fatalf("a failed start must fail the unit:\n%s", out)
	}
	if !strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("a failed start must keep the marker (retried at the next boot):\n%s", calls)
	}
}

// A rejected reboot request (systemd refusing, an inhibitor) used to exit
// under set -e with the stack STOPPED and nothing to restart it until some
// later boot (owner review of c49cf14b).
func TestOSUpdateReboot_RejectedRebootRestartsTheStackAndFails(t *testing.T) {
	out, calls, code := runOSUpdate(t, "reboot", "FAIL_REBOOT=1")
	if code == 0 {
		t.Fatalf("a rejected reboot must exit non-zero (the reboot did not happen):\n%s", out)
	}
	stop, reboot, start := strings.Index(calls, "docker compose stop"), strings.Index(calls, "systemctl reboot"), strings.LastIndex(calls, "docker compose up -d")
	if stop < 0 || reboot < stop || start < reboot {
		t.Fatalf("want stop, the rejected reboot, then the stack started again:\n%s", calls)
	}
	if strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("a recovered stack must clear the resume marker:\n%s", calls)
	}
	if !strings.Contains(out, "REJECTED") || !strings.Contains(out, "the reboot did NOT happen") {
		t.Fatalf("the failure must say what happened:\n%s", out)
	}
}

func TestOSUpdateReboot_RejectedRebootAndFailedRestartKeepsRecoveryPending(t *testing.T) {
	out, calls, code := runOSUpdate(t, "reboot", "FAIL_REBOOT=1", "FAIL_START=1")
	if code == 0 {
		t.Fatalf("must exit non-zero:\n%s", out)
	}
	if !strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("a stack that did not restart must keep the resume marker (retried at boot):\n%s", calls)
	}
	if !strings.Contains(out, "did NOT start") || strings.Contains(out, "stack started again") {
		t.Fatalf("a failed restart must be reported as such, never as recovered:\n%s", out)
	}
}

// A resume with the marker present but the stack's compose file missing used
// to report success, delete the marker and log "stack started" without ever
// calling Docker (owner review of c49cf14b).
func TestOSUpdateResumeStack_MissingComposeFailsAndKeepsTheMarker(t *testing.T) {
	osUpdateResumeHook = func(p string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		// The harness lays out <tmp>/state/<marker> beside <tmp>/stack.
		if err := os.Remove(filepath.Join(filepath.Dir(filepath.Dir(p)), "stack", "docker-compose.yml")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { osUpdateResumeHook = nil })
	out, calls, code := runOSUpdate(t, "resume-stack")
	if code == 0 {
		t.Fatalf("missing configuration must fail the recovery:\n%s", out)
	}
	if !strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("the marker must be retained:\n%s", calls)
	}
	if strings.Contains(out, "stack started after the maintenance reboot") {
		t.Fatalf("must never claim the stack started:\n%s", out)
	}
}

// CONTROL: an ordinary boot (no maintenance reboot) must not touch the stack.
func TestOSUpdateResumeStack_WithoutMarkerDoesNothing(t *testing.T) {
	out, calls, code := runOSUpdate(t, "resume-stack")
	if code != 0 || strings.Contains(calls, "docker") {
		t.Fatalf("no marker: want exit 0 and no docker call (code %d):\n%s\n%s", code, out, calls)
	}
}

const stackResumeUnitPath = "appliance/os-maintenance/culvert-stack-resume.service"

func TestStackResumeUnit_IsWiredToTheScriptAndInstalled(t *testing.T) {
	unit, err := os.ReadFile(stackResumeUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("appliance/os-maintenance/culvert-os-update")
	if err != nil {
		t.Fatal(err)
	}
	prep, err := os.ReadFile("appliance/build/prepare-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	u := string(unit)
	for _, want := range []string{
		"ConditionPathExists=/var/lib/culvert-appliance/state/stack-resume-on-boot",
		"ExecStart=/usr/local/sbin/culvert-os-update resume-stack",
		"After=docker.service",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	for _, l := range strings.Split(u, "\n") {
		if strings.HasPrefix(l, "After=") && strings.Contains(l, "cloud-final.service") {
			t.Error("After=cloud-final.service with WantedBy=multi-user.target is an ordering cycle")
		}
	}
	if !strings.Contains(string(script), "STACK_RESUME=/var/lib/culvert-appliance/state/stack-resume-on-boot") {
		t.Error("the script's marker path differs from the unit's ConditionPathExists")
	}
	p := string(prep)
	if !strings.Contains(p, "/etc/systemd/system/culvert-stack-resume.service") ||
		!prepareEnablesUnit(p, "culvert-stack-resume.service") {
		t.Error("prepare-guest.sh must install AND enable culvert-stack-resume.service")
	}
}

func prepareEnablesUnit(src, unit string) bool {
	for _, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "systemctl enable") && strings.Contains(l, unit) {
			return true
		}
	}
	return false
}

func TestStackResumeUnit_NoOrderingCycle(t *testing.T) {
	requireSystemdAnalyze(t)
	fb, err := os.ReadFile(firstbootUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(stackResumeUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	// ConditionPathExists is evaluated at start, not at ordering time; drop it
	// so the stub run does not depend on the host path.
	body := strings.Replace(string(unit), "ConditionPathExists=", "#ConditionPathExists=", 1)
	if rep := orderingCycleReport(t, string(fb), map[string]string{"culvert-stack-resume.service": body}); rep != "" {
		t.Errorf("culvert-stack-resume.service forms an ordering cycle:\n%s", rep)
	}
}

// An interrupted maintenance-agent operation awaiting reconcile (a journal
// record) must stop the boot-time resume exactly as it stops every mutating
// mode: starting the stack under an unreconciled data rollback is the one
// thing the journal exists to prevent (LOCAL-ESXI review of b80968dc).
func TestOSUpdateResumeStack_RefusesWhileTheAgentJournalAwaitsReconcile(t *testing.T) {
	armResumeMarker(t)
	// --force does not override this fence (it does for the other modes).
	out, calls, code := runOSUpdateWith(t, []string{"resume-stack", "--force"}, []string{"op-data-rollback"})
	if code == 0 {
		t.Fatalf("resume must fail while the agent journal holds an interrupted operation:\n%s", out)
	}
	if strings.Contains(calls, "docker compose up") {
		t.Fatalf("the stack must not be started over an unreconciled operation:\n%s", calls)
	}
	if !strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("the marker must be kept (resume after reconcile):\n%s", calls)
	}
	if !strings.Contains(out, "op-data-rollback") {
		t.Fatalf("the refusal must name the operation:\n%s", out)
	}
}
