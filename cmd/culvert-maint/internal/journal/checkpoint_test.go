package journal

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCheckpoint_BeginCountsAttemptsPerStepAndCarriesTheEpoch(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	rec := Record{OpID: "01JD0000000000000000000001", InterruptedSeen: 2}

	rec.BeginCheckpoint(StepGateTarget, "sha256:t", now)
	if c := rec.Checkpoint; c.Attempts != 1 || c.Epoch != 2 || c.ImageID != "sha256:t" || c.Result != "" || !c.IntentAt.Equal(now) {
		t.Fatalf("first gate:target = %+v", *c)
	}
	rec.BeginCheckpoint(StepGateTarget, "sha256:t", now)
	if rec.Checkpoint.Attempts != 2 {
		t.Errorf("second gate:target attempts = %d, want 2 (only ever raised)", rec.Checkpoint.Attempts)
	}
	rec.InterruptedSeen = 3
	rec.BeginCheckpoint(StepGatePrior, "sha256:p", now)
	if c := rec.Checkpoint; c.Step != StepGatePrior || c.Attempts != 1 || c.Epoch != 3 {
		t.Errorf("gate:prior after gate:target = %+v, want a fresh count at the current epoch", *c)
	}
	// A forged non-positive count restarts at 1, never at 0 or below.
	rec.Checkpoint.Attempts = -5
	rec.BeginCheckpoint(StepGatePrior, "sha256:p", now)
	if rec.Checkpoint.Attempts != 1 {
		t.Errorf("attempts after a forged negative = %d, want 1", rec.Checkpoint.Attempts)
	}
}

func TestCheckpoint_EndOnlyClosesTheOpenRunOfItsStep(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	rec := Record{}
	if rec.EndCheckpoint(StepGateTarget, CheckpointPassed, now) {
		t.Error("EndCheckpoint changed a record with no checkpoint")
	}
	rec.BeginCheckpoint(StepGatePrior, "sha256:p", now)
	if rec.EndCheckpoint(StepGateTarget, "failed:unhealthy", now) {
		t.Error("a gate:target result was written onto a gate:prior checkpoint")
	}
	if !rec.EndCheckpoint(StepGatePrior, "failed:health", now) {
		t.Fatal("the open gate:prior run was not closed")
	}
	if rec.EndCheckpoint(StepGatePrior, CheckpointPassed, now) {
		t.Error("a second result overwrote the first")
	}
	if c := rec.Checkpoint; c.Result != "failed:health" || c.ResultAt == nil || !c.ResultAt.Equal(now) {
		t.Errorf("closed checkpoint = %+v", *c)
	}
}

// TestCheckpoint_AbsentKeyIsByteIdentical: a record that never began a gate
// serialises with no checkpoint key, as every record did before the field.
func TestCheckpoint_AbsentKeyIsByteIdentical(t *testing.T) {
	b, err := json.Marshal(Record{OpID: "01JD0000000000000000000001", Kind: "upgrades.apply", Phase: PhaseAdmitted})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "checkpoint") {
		t.Errorf("record without a gate carries a checkpoint key: %s", b)
	}
}
