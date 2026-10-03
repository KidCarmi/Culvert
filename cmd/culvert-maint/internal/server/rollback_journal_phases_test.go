// RISK-022 PR-E P0-F: the shared rollback core advances the journal — and
// carries the FAIL-CLOSED PhaseRestarting barrier — on both the standalone and
// the inline path.
package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// phaseOf reads the live phase of the single record in the rig's journal.
func (r *applyRig) phaseOf(t *testing.T, opID string) journal.Phase {
	t.Helper()
	rec, found, err := r.journal.Read(opID)
	if err != nil || !found {
		t.Fatalf("journal read %s: found=%v err=%v", opID, found, err)
	}
	return rec.Phase
}

// Standalone core, driven stage by stage: captured → pulled → (barrier at the
// tag) → restarted → verified, with prior/target identifiers folded in.
func TestRollbackCore_AdvancesJournalPhases(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	opID := ops.NewID()
	now := time.Now().UTC()
	target := repo + "@sha256:" + digNew
	if err := rig.journal.Write(journal.Record{OpID: opID, Kind: ops.KindRollbackCreate, Mode: "image", Phase: journal.PhaseAdmitted,
		TargetRef: target, TargetDigest: digNew, Actor: "cp", StartedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var atTag journal.Phase
	rig.failFn = func(argv, _ []string) bool { // observer only
		if argvHas(argv, "tag") {
			atTag = rig.phaseOf(t, opID)
		}
		return false
	}
	acc := &rollbackAccumulator{opID: opID, kind: ops.KindRollbackCreate, actor: "cp", mode: "image"}
	stages := rig.srv.buildImageRollbackStages(target, acc)
	want := map[string]journal.Phase{
		"capture_before": journal.PhaseCaptured, "rollback_pull": journal.PhasePulled,
		"rollback_restart": journal.PhaseRestarted, "rollback_verify": journal.PhaseVerified,
	}
	for _, st := range stages {
		if _, _, err := st.Run(context.Background()); err != nil {
			t.Fatalf("stage %s: %v", st.Name, err)
		}
		if w, ok := want[st.Name]; ok {
			if got := rig.phaseOf(t, opID); got != w {
				t.Errorf("after %s: phase %s want %s", st.Name, got, w)
			}
		}
	}
	if atTag != journal.PhaseRestarting {
		t.Errorf("phase observed at `docker tag` must be the restarting barrier, got %q", atTag)
	}
	rec, _, _ := rig.journal.Read(opID)
	if rec.PriorRef != repo+"@sha256:"+digOld || rec.PriorDigest != digOld || rec.PriorImageID != "sha256:"+cfgOld {
		t.Errorf("prior identity not folded: %+v", rec)
	}
	if rec.TargetRef != target || rec.TargetDigest != digNew || rec.TargetImageID != "sha256:"+cfgNew {
		t.Errorf("target identity not folded: %+v", rec)
	}
}

// The barrier is FAIL-CLOSED on the rollback path exactly as on apply: an
// unwritable record refuses the tag advance.
func TestRollbackCore_BarrierFailClosed(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	opID := ops.NewID()
	target := repo + "@sha256:" + digNew
	if err := os.WriteFile(filepath.Join(rig.journal.Dir(), opID+".json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	acc := &rollbackAccumulator{opID: opID, kind: ops.KindRollbackCreate, actor: "cp", mode: "image"}
	var restart ops.FlowStage
	for _, st := range rig.srv.buildImageRollbackStages(target, acc) {
		if st.Name == "rollback_restart" {
			restart = st
		}
	}
	_, _, err := restart.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write-ahead journal barrier failed") {
		t.Fatalf("barrier must refuse: %v", err)
	}
	if rig.sawCommand("tag") || rig.sawCommand("up") {
		t.Error("tag/up must not run when the barrier cannot be written")
	}
}

// A missing record is RE-CREATED by the rollback barrier (kind/mode/actor +
// target), so a crash after the tag advance stays reconcilable.
func TestRollbackCore_BarrierRecreatesMissingRecord(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	opID := ops.NewID()
	target := repo + "@sha256:" + digNew
	acc := &rollbackAccumulator{opID: opID, kind: ops.KindRollbackCreate, actor: "cp", mode: "image"}
	for _, st := range rig.srv.buildImageRollbackStages(target, acc) {
		if st.Name == "rollback_restart" {
			if _, _, err := st.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	rec, found, err := rig.journal.Read(opID)
	if err != nil || !found {
		t.Fatalf("record must exist: found=%v err=%v", found, err)
	}
	if rec.Kind != ops.KindRollbackCreate || rec.Mode != "image" || rec.Actor != "cp" || rec.TargetRef != target || rec.Phase != journal.PhaseRestarted {
		t.Errorf("re-created record: %+v", rec)
	}
}

// Inline auto-rollback: the apply op's record goes restarting (upgrade tag) →
// restarted → restarting again (rollback tag) — the barrier precedes BOTH tag
// advances — and keeps its APPLY identity (target=new, prior=old).
func TestUpgradeApply_InlineRollback_WritesBarrierBeforeRollbackTag(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}

	var seen []journal.Phase
	var lastRec *journal.Record
	rig.failFn = func(argv, _ []string) bool {
		if !argvHas(argv, "tag") && !argvHas(argv, "image") {
			return false
		}
		recs, _, _ := rig.journal.ListQuarantining(time.Now())
		if len(recs) == 1 {
			rec := recs[0]
			lastRec = &rec
			if argvHas(argv, "tag") || (argvHas(argv, "image") && len(seen) > 0) {
				seen = append(seen, rec.Phase)
			}
		}
		return false
	}
	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if res := resultMap(t, op); res["rollback_succeeded"] != true {
		t.Fatalf("inline rollback expected: %+v", res)
	}
	joined := strings.Trim(strings.Join(phaseStrings(seen), ","), ",")
	for _, want := range []string{"restarting", "restarted,", ",restarting"} {
		if !strings.Contains(joined, want) {
			t.Errorf("phase trace %q must contain %q (barrier before each tag, restarted in between)", joined, want)
		}
	}
	if lastRec == nil || lastRec.Kind != ops.KindUpgradeApply || lastRec.TargetDigest != digNew || lastRec.PriorDigest != digOld {
		t.Errorf("inline rollback must keep the apply record identity: %+v", lastRec)
	}
}

func phaseStrings(ps []journal.Phase) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}
