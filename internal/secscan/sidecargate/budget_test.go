package sidecargate_test

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
	"github.com/KidCarmi/Culvert/internal/secscan/sidecargate"
)

// QueueWait is chosen against the caller's budget: the sidecar must answer a
// capacity refusal before the caller's own scan deadline fires, or the caller
// counts a saturated sidecar as a slow one. Both sides fail closed; only the
// operator's reading differs. The two constants live in different packages, so
// this is the one place that compares them. Test-only import: the production
// package imports no other Culvert package (boundary_test.go).
func TestQueueWait_IsInsideTheCallersScanBudget(t *testing.T) {
	if sidecargate.QueueWait >= secscan.ScanBodyTimeout {
		t.Fatalf("QueueWait (%s) is not below secscan.ScanBodyTimeout (%s): the caller's deadline would fire first and reclassify capacity as a timeout",
			sidecargate.QueueWait, secscan.ScanBodyTimeout)
	}
}
