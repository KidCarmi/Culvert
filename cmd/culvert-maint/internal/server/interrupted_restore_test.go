package server

// interrupted_restore_test.go — the report of an interrupted restore-class
// operation: one row per recorded stage, for both kinds, from the record alone.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

func restoreRec(kind, mode string, stage journal.RestoreStage) *journal.Record {
	return &journal.Record{
		OpID: testOpULID, Kind: kind, Mode: mode, Phase: journal.PhaseAdmitted, Actor: "uid=0,user=cp",
		RestoreStage: stage,
		StartedAt:    time.Unix(1700000000, 0).UTC(), UpdatedAt: time.Unix(1700000060, 0).UTC(),
	}
}

type restoreRow struct {
	stage        journal.RestoreStage
	reported     string
	stackTouched *bool // nil = the key must be absent
	dataChanged  string
	previous     string
	// restartSafe and action are fragments the sentence must contain.
	restartSafe []string
	action      []string
}

func restoreRows() []restoreRow {
	yes, no := boolPtr(true), boolPtr(false)
	const tagCaveat = "`docker compose up -d` starts whatever image the fixed tag is on"
	return []restoreRow{
		{journal.RestoreStageAdmitted, "admitted", no, "no", "in_place",
			[]string{"did not stop the proxy", "did not change the data directory"},
			[]string{"nothing to recover", "submit it again"}},
		{journal.RestoreStagePreflight, "preflight", no, "no", "in_place",
			[]string{"did not stop the proxy", "did not change the data directory"},
			[]string{"nothing to recover", "submit it again"}},
		{journal.RestoreStageStopping, "stopping", yes, "no", "in_place",
			[]string{"data directory was not changed", "Which image starts"},
			[]string{"asked Docker to stop the stack", "data directory was not changed", "compose_stack_up", "pinned_tag.image_id", tagCaveat}},
		{journal.RestoreStageCommitting, "committing", yes, "unknown", "recoverable_at_next_proxy_start_or_manual",
			[]string{"depends on the deployment", "undoes an unfinished in-place restore", "refuses to start", "older proxy image", "8b"},
			[]string{"result was never recorded", "`cli` container", "last-outcome.json", "8b", "pinned_tag.image_id", tagCaveat}},
		{journal.RestoreStageCommitFailed, "commit_failed", yes, "unknown", "recoverable_at_next_proxy_start_or_manual",
			[]string{"depends on the deployment", "undoes an unfinished in-place restore", "refuses to start", "8b"},
			[]string{"returned an error", "cannot vouch", "/logs", "8b", "pinned_tag.image_id", tagCaveat}},
		{journal.RestoreStageCommitted, "committed", yes, "yes", "kept_in_backup_dir",
			[]string{"restore committed", "restored content", "never health-checked"},
			[]string{"restore committed", "previous content is kept", "--list-restore-leftovers", "compose_stack_up", "pinned_tag.image_id", tagCaveat}},
		{journal.RestoreStageStarting, "starting", yes, "yes", "kept_in_backup_dir",
			[]string{"restore committed", "never health-checked"},
			[]string{"restore committed", "previous content is kept", tagCaveat}},
		{journal.RestoreStageStarted, "started", yes, "yes", "kept_in_backup_dir",
			[]string{"restore committed", "never health-checked"},
			[]string{"restore committed", "previous content is kept", tagCaveat}},
		// No stage (a record from before the key, or one an older agent rewrote)
		// and a stage from a newer agent: nothing is claimed.
		{"", "unrecorded", nil, "unknown", "unknown",
			[]string{"Unknown", "does not say how far the restore got", "8b"}, nil},
		{journal.RestoreStageUnknown, "unrecorded", nil, "unknown", "unknown",
			[]string{"Unknown", "does not say how far the restore got", "8b"}, nil},
	}
}

// TestDescribeInterrupted_RestoreStageTable is the stage table, for both kinds.
func TestDescribeInterrupted_RestoreStageTable(t *testing.T) {
	for _, k := range restoreKinds {
		rows := restoreRows()
		for i := range rows {
			row := &rows[i]
			name := k.name + "/" + string(row.stage)
			got := DescribeInterrupted(restoreRec(k.kind, k.mode, row.stage), repo)
			if got.Kind != k.kind || got.Mode != k.mode {
				t.Errorf("%s: kind/mode = %q/%q", name, got.Kind, got.Mode)
			}
			checkRestoreRowFacts(t, name, &got, row)
			checkRestoreRowWording(t, name, &got, row)
		}
	}
}

// checkRestoreRowFacts: the enumerated statements of one row.
func checkRestoreRowFacts(t *testing.T, name string, got *InterruptedOperation, row *restoreRow) {
	t.Helper()
	if got.RestoreStage != row.reported {
		t.Errorf("%s: restore_stage = %q, want %q", name, got.RestoreStage, row.reported)
	}
	switch {
	case row.stackTouched == nil && got.StackTouched != nil:
		t.Errorf("%s: stack_touched = %v, want it absent", name, *got.StackTouched)
	case row.stackTouched != nil && (got.StackTouched == nil || *got.StackTouched != *row.stackTouched):
		t.Errorf("%s: stack_touched = %v, want %v", name, got.StackTouched, *row.stackTouched)
	}
	if got.DataChanged != row.dataChanged || got.PreviousState != row.previous {
		t.Errorf("%s: data_changed/previous_state = %q/%q, want %q/%q", name, got.DataChanged, got.PreviousState, row.dataChanged, row.previous)
	}
	// Never an image-style class, never "reconciled", and the journal phase is
	// the admission phase the record really holds.
	if got.DockerState != DockerStateDataIndeterminate {
		t.Errorf("%s: docker_state = %q, want %q", name, got.DockerState, DockerStateDataIndeterminate)
	}
	if got.DockerReconciled || got.JournalPhase != "admitted" {
		t.Errorf("%s: docker_reconciled=%v journal_phase=%q", name, got.DockerReconciled, got.JournalPhase)
	}
}

// checkRestoreRowWording: the two sentences of one row.
func checkRestoreRowWording(t *testing.T, name string, got *InterruptedOperation, row *restoreRow) {
	t.Helper()
	if got.OperatorAction == "" || got.RestartSafe == "" {
		t.Errorf("%s: empty operator_action or restart_safe", name)
	}
	for _, frag := range row.restartSafe {
		if !strings.Contains(got.RestartSafe, frag) {
			t.Errorf("%s: restart_safe lacks %q:\n%s", name, frag, got.RestartSafe)
		}
	}
	for _, frag := range row.action {
		if !strings.Contains(got.OperatorAction, frag) {
			t.Errorf("%s: operator_action lacks %q:\n%s", name, frag, got.OperatorAction)
		}
	}
	// The advice aimed at an interrupted IMAGE change must not appear.
	for _, wrong := range []string{"mode=image", "submit the upgrade again", "image_ref="} {
		if strings.Contains(got.OperatorAction, wrong) {
			t.Errorf("%s: operator_action carries image-change advice (%q):\n%s", name, wrong, got.OperatorAction)
		}
	}
}

// TestDescribeInterrupted_UnknownOnlyWhereTheJournalCannotVouch: data_changed is
// "no" before the commit command was started, "yes" once it returned success,
// and "unknown" in between and whenever the stage is not recorded. This is the
// one property the table must never lose in an edit.
func TestDescribeInterrupted_UnknownOnlyWhereTheJournalCannotVouch(t *testing.T) {
	want := map[journal.RestoreStage]string{
		journal.RestoreStageAdmitted: DataChangedNo, journal.RestoreStagePreflight: DataChangedNo, journal.RestoreStageStopping: DataChangedNo,
		journal.RestoreStageCommitting: DataChangedUnknown, journal.RestoreStageCommitFailed: DataChangedUnknown,
		journal.RestoreStageCommitted: DataChangedYes, journal.RestoreStageStarting: DataChangedYes, journal.RestoreStageStarted: DataChangedYes,
		"": DataChangedUnknown, journal.RestoreStageUnknown: DataChangedUnknown,
	}
	for stage, w := range want {
		f := restoreFactsFor(stage)
		if f.dataChanged != w {
			t.Errorf("%q: data_changed = %q, want %q", stage, f.dataChanged, w)
		}
		// A stack this operation stopped is never reported untouched.
		if f.dataChanged != DataChangedNo && f.stackTouched != nil && !*f.stackTouched {
			t.Errorf("%q: data may have changed but stack_touched is false", stage)
		}
		// Previous content is called kept only for a recorded commit.
		if (f.previousState == PreviousKeptInBackupDir) != (w == DataChangedYes) {
			t.Errorf("%q: previous_state = %q with data_changed = %q", stage, f.previousState, w)
		}
	}
}

// TestDescribeInterrupted_OldDataRollbackRecordKeepsItsAdvice: a data-rollback
// record written before the stage existed reports what it always did, plus the
// new fields saying nothing is known.
func TestDescribeInterrupted_OldDataRollbackRecordKeepsItsAdvice(t *testing.T) {
	got := DescribeInterrupted(restoreRec(ops.KindRollbackCreate, "data", ""), repo)
	if got.OperatorAction != actionData || got.DockerState != DockerStateDataIndeterminate {
		t.Errorf("old data-rollback record: action=%q docker_state=%q", got.OperatorAction, got.DockerState)
	}
	// restore.commit was never journaled before, so its stage-less record can
	// only have passed through an older agent; it must not be called a "data
	// rollback".
	rc := DescribeInterrupted(restoreRec(ops.KindRestoreCommit, "", ""), repo)
	if strings.Contains(rc.OperatorAction, "data rollback was interrupted") || !strings.Contains(rc.OperatorAction, "does not say how far it got") {
		t.Errorf("stage-less restore.commit record: %q", rc.OperatorAction)
	}
}

// TestDescribeInterrupted_RestoreFieldsAreAdditive: an upgrade, an image
// rollback and an unknown kind carry none of the restore keys, in the report,
// the operation result or the audit parameters; a restore record carries them
// in all three.
func TestDescribeInterrupted_RestoreFieldsAreAdditive(t *testing.T) {
	restoreKeys := []string{"restore_stage", "stack_touched", "data_changed", "previous_state", "restart_safe"}
	keysOf := func(v interface{}) map[string]interface{} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, rec := range []*journal.Record{
		fullRec(journal.PhaseRestarting),
		func() *journal.Record {
			r := fullRec(journal.PhaseAdmitted)
			r.Kind, r.Mode = ops.KindRollbackCreate, "image"
			return r
		}(),
		func() *journal.Record { r := fullRec(journal.PhaseAdmitted); r.Kind = "something.else"; return r }(),
		// A stage on a record that is not restore-class is ignored, not reported.
		func() *journal.Record {
			r := fullRec(journal.PhaseRestarting)
			r.RestoreStage = journal.RestoreStageCommitted
			return r
		}(),
	} {
		d := DescribeInterrupted(rec, repo)
		intr, _ := d.ResultMap()["interrupted"].(map[string]interface{}) //nolint:errcheck // absent → nil map
		for _, k := range restoreKeys {
			if _, ok := keysOf(d)[k]; ok {
				t.Errorf("%s/%s: report carries %q", rec.Kind, rec.Mode, k)
			}
			if _, ok := intr[k]; ok {
				t.Errorf("%s/%s: operation result carries %q", rec.Kind, rec.Mode, k)
			}
			if _, ok := d.AuditParams()[k]; ok {
				t.Errorf("%s/%s: audit params carry %q", rec.Kind, rec.Mode, k)
			}
		}
	}

	d := DescribeInterrupted(restoreRec(ops.KindRestoreCommit, "", journal.RestoreStageCommitting), repo)
	m := keysOf(d)
	intr, _ := d.ResultMap()["interrupted"].(map[string]interface{}) //nolint:errcheck // absent → nil map
	for _, k := range restoreKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("restore report lacks %q", k)
		}
		if _, ok := intr[k]; !ok {
			t.Errorf("restore operation result lacks %q", k)
		}
	}
	if m["stack_touched"] != true || intr["data_changed"] != "unknown" {
		t.Errorf("restore report: stack_touched=%v data_changed=%v", m["stack_touched"], intr["data_changed"])
	}
	ap := d.AuditParams()
	if ap["restore_stage"] != "committing" || ap["data_changed"] != "unknown" || ap["stack_touched"] != true ||
		ap["previous_state"] != PreviousRecoverable {
		t.Errorf("audit params: %+v", ap)
	}
	// stack_touched=false is a statement and must be serialized, not omitted.
	if pre := keysOf(DescribeInterrupted(restoreRec(ops.KindRestoreCommit, "", journal.RestoreStagePreflight), repo)); pre["stack_touched"] != false {
		t.Errorf("stack_touched at preflight = %v, want an explicit false", pre["stack_touched"])
	}
}

// TestDescribeInterrupted_RestoreKindIsReportedByName: restore.commit is a known
// kind now, not "unknown"; the journal's mode field of such a record is not the
// restore mode and an unexpected value is not repeated.
func TestDescribeInterrupted_RestoreKindIsReportedByName(t *testing.T) {
	rec := restoreRec(ops.KindRestoreCommit, "full; rm -rf /", journal.RestoreStageStopping)
	got := DescribeInterrupted(rec, repo)
	if got.Kind != ops.KindRestoreCommit || got.Mode != "unknown" {
		t.Errorf("kind/mode = %q/%q", got.Kind, got.Mode)
	}
	if got.RestoreStage != "stopping" || got.DockerState != DockerStateDataIndeterminate {
		t.Errorf("a restore.commit record with a stray mode lost its report: %+v", got)
	}
	// The running-image class has no meaning for it and must not change its advice.
	before := got.OperatorAction
	got.SetRunningImage(RunningIsOther)
	if got.OperatorAction != before {
		t.Errorf("running_image changed a restore's operator_action")
	}
}
