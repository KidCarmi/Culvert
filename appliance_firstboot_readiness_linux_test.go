//go:build linux

package main

// R10 interruption accounting: a check that is interrupted mid-way (the
// unit is stopped, the host reboots, the unit's start timeout fires) is
// still on record — phase=started is written BEFORE the check runs — and
// the wait leaves a best-effort phase=interrupted marker. Nothing is
// recorded complete.

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFirstBoot_Readiness_InterruptedCheckStaysOnRecord(t *testing.T) {
	h := newFBHarness(t)
	h.setReadiness([]string{"hang"}, nil)
	abs, _ := filepath.Abs(fbScript)
	// #nosec G204 -- program is the literal "bash"; abs is the checked-in script.
	c := exec.CommandContext(t.Context(), "bash", "-c", ". "+abs+"; READY_TIMEOUT_S=60; step_finish")
	c.Env = h.env()
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait until the first check has started (its phase=started record).
	deadline := time.Now().Add(10 * time.Second)
	for h.readinessPhase("started", "application") == 0 {
		if time.Now().After(deadline) {
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			t.Fatal("the first check never started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if err := syscall.Kill(-c.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		t.Fatal("the interrupted wait did not exit")
	}
	if h.exists("appliance/state/complete.done") {
		t.Fatal("an interrupted wait recorded completion")
	}
	if s, e := h.readinessPhase("started", "application"), h.readinessPhase("ended", "application"); s != 1 || e != 0 {
		t.Fatalf("application records: started %d, ended %d; want the interrupted check on record as started-only", s, e)
	}
	if h.readinessPhase("interrupted", "") != 1 {
		b, _ := os.ReadFile(filepath.Join(h.state, "readiness-attempts.jsonl"))
		t.Fatalf("no interruption marker:\n%s", b)
	}
}
