package main

import (
	"strings"
	"testing"
)

func setLogGuardStateForTest(t *testing.T, minimal bool, warning string) {
	t.Helper()
	logGuard.mu.Lock()
	prevWarn := logGuard.warning
	logGuard.warning = warning
	logGuard.mu.Unlock()
	prevMin := logGuard.minimal.Swap(minimal)
	t.Cleanup(func() {
		logGuard.minimal.Store(prevMin)
		logGuard.mu.Lock()
		logGuard.warning = prevWarn
		logGuard.mu.Unlock()
	})
}

func TestCheckLogDiskProtection(t *testing.T) {
	setLogGuardStateForTest(t, false, "")
	if got := checkLogDiskProtection(); got != nil {
		t.Fatalf("idle guard must add no row, got %+v", got)
	}

	setLogGuardStateForTest(t, false, "Disk usage reached 96%.")
	got := checkLogDiskProtection()
	if len(got) != 1 || got[0].Status != diagWarn || got[0].OperatorAction == "" ||
		!strings.Contains(got[0].Message, "before the configured retention") {
		t.Fatalf("pressure cleanup row = %+v", got)
	}

	setLogGuardStateForTest(t, true, "Disk usage 99% — EMERGENCY minimal logging")
	got = checkLogDiskProtection()
	if len(got) != 1 || got[0].Status != diagWarn || got[0].Code != "log_disk_protection" ||
		!strings.Contains(got[0].Message, "NOT being recorded") {
		t.Fatalf("minimal mode row = %+v", got)
	}
}
