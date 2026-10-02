// Startup reconcile (RISK-022 PR-E E3) — behavioural gates against the fake
// runner. Each scenario seeds a journal record the way a crashed op would have
// left it, sets the fake daemon's truth (running image, pinned-tag target,
// health), runs the same startup sequence main.go runs (MarkAllInterrupted →
// ReconcileOnStartup), and asserts what was auto-resolved vs. surfaced.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

const (
	targetRef = repo + "@sha256:" + digNew
	priorRef  = repo + "@sha256:" + digOld
)

// seedRecord writes an apply record interrupted at phase, with the standard
// target/prior identity (target=digNew/cfgNew, prior=digOld/cfgOld). The
// target image id is recorded only once the flow would have known it
// (restarted or later).
func (r *applyRig) seedRecord(t *testing.T, phase journal.Phase) string {
	t.Helper()
	opID := ops.NewID()
	now := time.Now().UTC()
	rec := journal.Record{OpID: opID, Kind: ops.KindUpgradeApply, Phase: phase, Actor: "cp", StartedAt: now, UpdatedAt: now,
		TargetRef: targetRef, TargetDigest: digNew, PriorRef: priorRef, PriorDigest: digOld, PriorImageID: "sha256:" + cfgOld}
	if phase == journal.PhaseRestarted || phase == journal.PhaseVerified {
		rec.TargetImageID = "sha256:" + cfgNew
	}
	if err := r.journal.Write(rec); err != nil {
		t.Fatal(err)
	}
	return opID
}

// boot mimics main.go's startup sequence for the journal: Phase A mark, then
// the reconcile pass. Returns the attention count.
func (r *applyRig) boot(t *testing.T) int {
	t.Helper()
	recs, _, err := r.journal.ListQuarantining(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	orphans := make([]ops.InterruptedOp, 0, len(recs))
	for i := range recs {
		orphans = append(orphans, ops.InterruptedOp{OpID: recs[i].OpID, Kind: recs[i].Kind, Actor: recs[i].Actor})
	}
	r.mgr.MarkAllInterrupted(orphans)
	return r.srv.ReconcileOnStartup(context.Background())
}

func (r *applyRig) setRunningDigest(d string) {
	r.mu.Lock()
	r.runningDigest = d
	r.mu.Unlock()
}

func (r *applyRig) getJSON(t *testing.T, path string) (code int, out map[string]interface{}) {
	t.Helper()
	cli := udsClient(r.sockPath)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://unix"+path, http.NoBody)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// interrupted returns the status entry for opID, or nil.
func (r *applyRig) interrupted(t *testing.T, opID string) (entry map[string]interface{}, attention bool) {
	t.Helper()
	code, st := r.getJSON(t, "/v1/status")
	if code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	attention, _ = st["attention_required"].(bool)
	list, _ := st["interrupted_operations"].([]interface{})
	for _, e := range list {
		m, _ := e.(map[string]interface{})
		if m["op_id"] == opID {
			return m, attention
		}
	}
	return nil, attention
}

func (r *applyRig) recordExists(opID string) bool {
	_, found, _ := r.journal.Read(opID)
	return found
}

// Interrupted at `pulled` (safe boundary), stack still on prior, tag on prior
// ⇒ noop: record + verdict removed, nothing executed, no attention.
func TestReconcile_SafeBoundary_NoopRemovesRecord(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digOld
	opID := rig.seedRecord(t, journal.PhasePulled)

	if n := rig.boot(t); n != 0 {
		t.Fatalf("attention: got %d want 0", n)
	}
	if rig.recordExists(opID) {
		t.Error("noop must retire the record")
	}
	if rig.sawCommand("tag") || rig.sawCommand("up") || rig.sawCommand("pull") {
		t.Error("a noop must execute nothing")
	}
	if entry, attention := rig.interrupted(t, opID); entry != nil || attention {
		t.Errorf("status must be clean: entry=%v attention=%v", entry, attention)
	}
	op := rig.mgr.Get(opID)
	if op == nil || op.State != ops.StateFailed || op.FailureReason != string(ops.ReasonAgentRestartInterrupted) {
		t.Errorf("the op stays failed(agent_restart_interrupted): %+v", op)
	}
}

// Interrupted at `restarting` with the tag ALREADY advanced to target but the
// container still on prior ⇒ reup is SURFACED (tag hazard), never executed.
func TestReconcile_TagAdvancedContainerStale_SurfacedNotExecuted(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew // tag moved
	opID := rig.seedRecord(t, journal.PhaseRestarting)

	if n := rig.boot(t); n != 1 {
		t.Fatalf("attention: got %d want 1", n)
	}
	if !rig.recordExists(opID) {
		t.Fatal("a surfaced verdict must keep the record")
	}
	if rig.sawCommand("tag") || rig.sawCommand("up") || rig.sawCommand("pull") {
		t.Error("reup must NOT be executed at boot")
	}
	entry, attention := rig.interrupted(t, opID)
	if entry == nil || !attention {
		t.Fatalf("status must surface the op with attention_required: entry=%v attention=%v", entry, attention)
	}
	if entry["verdict"] != "reup" || entry["tag_hazard"] != true || entry["tag_matches_target"] != true || entry["running_matches_target"] != false {
		t.Errorf("entry: %+v", entry)
	}
	if !strings.Contains(entry["recommended_action"].(string), "TAG HAZARD") {
		t.Errorf("recommended_action must call out the pinned-tag hazard: %v", entry["recommended_action"])
	}
	v, err := rig.srv.readVerdict(opID)
	if err != nil || v == nil || v.Verdict != "reup" || !v.TagHazard {
		t.Errorf("durable verdict: %+v err=%v", v, err)
	}
}

// Interrupted at `restarted`, target live and healthy ⇒ adopted: op is
// succeeded(reconciled), record retired.
func TestReconcile_TargetLiveHealthy_Adopted(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.setRunningDigest(digNew)
	opID := rig.seedRecord(t, journal.PhaseRestarted)

	if n := rig.boot(t); n != 0 {
		t.Fatalf("attention: got %d want 0", n)
	}
	if rig.recordExists(opID) {
		t.Error("adopt must retire the record")
	}
	code, op := rig.getJSON(t, "/v1/operations/"+opID)
	if code != http.StatusOK || op["state"] != "succeeded" {
		t.Fatalf("adopted op must read succeeded: code=%d op=%+v", code, op)
	}
	if res, _ := op["result"].(map[string]interface{}); res["reconciled"] != true {
		t.Errorf("result must carry reconciled=true: %+v", op["result"])
	}
	if rig.sawCommand("tag") || rig.sawCommand("up") || rig.sawCommand("pull") {
		t.Error("adopt mutates nothing")
	}
}

// Target live but UNHEALTHY ⇒ surfaced (needs attention), no rollback at boot.
func TestReconcile_TargetLiveUnhealthy_Surfaced(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.setRunningDigest(digNew)
	rig.unhealthyDigests = map[string]bool{digNew: true}
	opID := rig.seedRecord(t, journal.PhaseRestarted)

	if n := rig.boot(t); n != 1 {
		t.Fatalf("attention: got %d want 1", n)
	}
	if !rig.recordExists(opID) {
		t.Fatal("record must be kept")
	}
	if rig.sawCommand("tag") || rig.sawCommand("up") || rig.sawCommand("pull") {
		t.Error("no rollback may run at boot")
	}
	entry, attention := rig.interrupted(t, opID)
	if entry == nil || !attention || entry["verdict"] != "verify_adopt_else_rollback" || entry["running_matches_target"] != true {
		t.Fatalf("entry: %+v attention=%v", entry, attention)
	}
	if lh, _ := entry["last_health"].(string); !strings.Contains(lh, "ready=false") {
		t.Errorf("last_health must record the failed probe: %q", lh)
	}
	if op := rig.mgr.Get(opID); op.State != ops.StateFailed {
		t.Errorf("op must stay interrupted: %+v", op)
	}
}

// A corrupt record is quarantined; the agent serves; status says so.
func TestReconcile_CorruptRecord_QuarantinedAgentServes(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	bad := ops.NewID()
	if err := os.WriteFile(filepath.Join(rig.journal.Dir(), bad+".json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.pinnedDigest = digOld
	good := rig.seedRecord(t, journal.PhasePulled)

	if n := rig.boot(t); n != 1 {
		t.Fatalf("attention (the quarantined file): got %d want 1", n)
	}
	if rig.recordExists(good) {
		t.Error("the readable record must still be reconciled (noop) alongside the quarantined one")
	}
	code, _ := rig.getJSON(t, "/v1/health")
	if code != http.StatusOK {
		t.Fatalf("agent must serve: %d", code)
	}
	_, st := rig.getJSON(t, "/v1/status")
	q, _ := st["quarantined_journal_records"].([]interface{})
	if len(q) != 1 || !strings.HasPrefix(q[0].(string), bad+".json.corrupt.") || st["attention_required"] != true {
		t.Errorf("status must surface the quarantined record: %+v", st)
	}
	code, body := rig.getJSON(t, "/v1/reconcile/"+bad)
	_ = body
	if code == http.StatusOK {
		t.Error("a quarantined record is never actionable")
	}
}

// Docker not reachable at boot ⇒ inputs_unavailable, surfaced, nothing acted
// on; the record is not misread as "stack down → rollback".
func TestReconcile_DockerDown_InputsUnavailable(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.dockerDown.Store(true)
	opID := rig.seedRecord(t, journal.PhaseRestarting)

	if n := rig.boot(t); n != 1 {
		t.Fatalf("attention: got %d want 1", n)
	}
	entry, attention := rig.interrupted(t, opID)
	if entry == nil || !attention || entry["verdict"] != verdictInputsUnavailable || entry["reason"] != "docker_unavailable" {
		t.Fatalf("entry: %+v attention=%v", entry, attention)
	}
}

// mode=data records never enter the image table: data_manual, surfaced.
func TestReconcile_DataRollback_Manual(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	opID := ops.NewID()
	now := time.Now().UTC()
	if err := rig.journal.Write(journal.Record{OpID: opID, Kind: ops.KindRollbackCreate, Mode: "data", Phase: journal.PhaseRestarting, Actor: "cp", StartedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if n := rig.boot(t); n != 1 {
		t.Fatalf("attention: got %d want 1", n)
	}
	entry, _ := rig.interrupted(t, opID)
	if entry == nil || entry["verdict"] != "data_manual" {
		t.Fatalf("entry: %+v", entry)
	}
	if rig.sawCommand("ps") {
		t.Error("a data-window record must not even consult docker")
	}
}

// reconcile_on_startup=false (ReconcileOnStartup never called) ⇒ records are
// listed unclassified with attention_required, nothing touched.
func TestReconcile_MarkOnly_ListsUnclassified(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	opID := rig.seedRecord(t, journal.PhaseRestarting)
	entry, attention := rig.interrupted(t, opID)
	if entry == nil || !attention || entry["verdict"] != verdictUnclassified {
		t.Fatalf("entry: %+v attention=%v", entry, attention)
	}
	if len(rig.snapshot()) != 0 {
		t.Error("status must not run docker for the reconcile overlay")
	}
}

// A record that belongs to a RUNNING op is not an interrupted one.
func TestReconcile_LiveOpRecordNotListed(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.blockUp = make(chan struct{})
	status, rb := rig.post(t, map[string]interface{}{"image_ref": targetRef})
	if status != http.StatusAccepted {
		t.Fatalf("apply: %d %s", status, rb)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(rb, &ack)
	opID := ack["op_id"].(string)
	deadline := time.Now().Add(3 * time.Second)
	for !rig.sawCommand("up") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	entry, attention := rig.interrupted(t, opID)
	if entry != nil || attention {
		t.Errorf("a live op must not be surfaced as interrupted: %v %v", entry, attention)
	}
	close(rig.blockUp)
	rig.waitOp(t, opID)
}
