package status

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// TestSnapshot_InterruptedRestoreIsListedWithItsStage: GET /v1/status renders
// an interrupted restore from the journal alone, with the restore fields, for
// both restore-class kinds; and a restore this process is running is not an
// interruption.
func TestSnapshot_InterruptedRestoreIsListedWithItsStage(t *testing.T) {
	p, jnl := providerWithJournal(t)
	now := time.Now().UTC()
	const restoreID, dataID = "01HZZZZZZZZZZZZZZZZZZZZZR1", "01HZZZZZZZZZZZZZZZZZZZZZR2"
	for _, rec := range []journal.Record{
		{OpID: restoreID, Kind: ops.KindRestoreCommit, Phase: journal.PhaseAdmitted, RestoreStage: journal.RestoreStageCommitting},
		{OpID: dataID, Kind: ops.KindRollbackCreate, Mode: "data", Phase: journal.PhaseAdmitted, RestoreStage: journal.RestoreStagePreflight},
	} {
		rec.StartedAt, rec.UpdatedAt = now, now
		if err := jnl.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	// This process's own running restore, with its record.
	own, err := p.mgr.Begin(ops.KindRestoreCommit, "uid=0", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := jnl.Write(journal.Record{OpID: own.ID, Kind: ops.KindRestoreCommit, Phase: journal.PhaseAdmitted,
		RestoreStage: journal.RestoreStageStopping, StartedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.InterruptedOperations) != 2 {
		t.Fatalf("interrupted_operations = %+v, want the two orphans and not the running restore", st.InterruptedOperations)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Interrupted []map[string]interface{} `json:"interrupted_operations"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]interface{}{}
	for _, e := range wire.Interrupted {
		byID[e["op_id"].(string)] = e
	}
	for id, want := range map[string]map[string]interface{}{
		restoreID: {"kind": "restore.commit", "restore_stage": "committing", "stack_touched": true, "data_changed": "unknown",
			"previous_state": "recoverable_at_next_proxy_start_or_manual", "docker_state": "data_indeterminate", "docker_reconciled": false},
		dataID: {"kind": "rollbacks.create", "mode": "data", "restore_stage": "preflight", "stack_touched": false, "data_changed": "no",
			"previous_state": "in_place", "docker_state": "data_indeterminate", "docker_reconciled": false},
	} {
		got := byID[id]
		if got == nil {
			t.Fatalf("%s not listed", id)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s: %s = %v, want %v", id, k, got[k], v)
			}
		}
		for _, k := range []string{"restart_safe", "operator_action"} {
			if s, _ := got[k].(string); s == "" {
				t.Errorf("%s: %s is empty", id, k)
			}
		}
		// The fake docker prints nothing: the running image is unknown, and a
		// restore record names no image to compare it with anyway.
		if got["running_image"] != "unknown" {
			t.Errorf("%s: running_image = %v, want unknown", id, got["running_image"])
		}
	}
}
