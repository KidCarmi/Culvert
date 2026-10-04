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
		t.Fatalf("reboot failed (code %d):\n%s", code, out)
	}
	stop, reboot := strings.Index(calls, "docker compose stop"), strings.Index(calls, "systemctl reboot")
	if stop < 0 || reboot < stop {
		t.Fatalf("want the stack stopped, then the reboot:\n%s", calls)
	}
	if !strings.Contains(calls, "resume-marker:armed") {
		t.Fatalf("the resume marker must be armed BEFORE the stack is stopped (a stop marks the containers manually stopped):\n%s", calls)
	}
	if !strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("the marker must survive into the reboot:\n%s", calls)
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
