// POST /v1/reconcile/{op_id} — explicit resolve / dismiss semantics.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

func (r *applyRig) postReconcile(t *testing.T, opID string, body interface{}) (code int, out map[string]interface{}) {
	t.Helper()
	cli := udsClient(r.sockPath)
	bb, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://unix/v1/reconcile/"+opID, strings.NewReader(string(bb)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/reconcile: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// resolve on a tag-hazard (reup) verdict executes tag+up under the health
// gate as a journaled rollbacks.create op; success retires the original.
func TestReconcileResolve_ExecutesReup(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.localImages = map[string]bool{digNew: true, digOld: true}
	opID := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t)

	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusAccepted {
		t.Fatalf("resolve: %d %+v", code, body)
	}
	resolveID := body["op_id"].(string)
	if resolveID == opID {
		t.Fatal("the resolve must be a NEW op")
	}
	op := rig.waitOp(t, resolveID)
	if op["state"] != "succeeded" || op["kind"] != ops.KindRollbackCreate {
		t.Fatalf("resolve op: %+v", op)
	}
	params, _ := op["params"].(map[string]interface{})
	if params["reconcile_of"] != opID || params["reconcile_action"] != "reup" || params["image_ref"] != targetRef {
		t.Errorf("resolve op params: %+v", params)
	}
	res := resultMap(t, op)
	if res["rollback_pull_skipped_local"] != true {
		t.Errorf("reup must be local-first: %+v", res)
	}
	if !rig.pinnedFor("tag", digNew) || !rig.sawCommand("up") || rig.sawCommand("pull") {
		t.Error("reup must tag+up the target without a pull")
	}
	// Original record retired only after success; resolve op's own record retired too.
	deadline := time.Now().Add(2 * time.Second)
	for rig.recordExists(opID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rig.recordExists(opID) || rig.recordExists(resolveID) {
		t.Error("both records must be retired after a successful resolve")
	}
	if entry, attention := rig.interrupted(t, opID); entry != nil || attention {
		t.Errorf("status must be clean: %v %v", entry, attention)
	}
	// Duplicate resolve after completion ⇒ 404, never a second mutation.
	code, body = rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusNotFound || body["error"] != "record_not_found" {
		t.Errorf("post-resolve duplicate: %d %+v", code, body)
	}
}

// resolve on an unhealthy live target rolls back to prior (local-first).
func TestReconcileResolve_UnhealthyTarget_RollsBackToPrior(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.setRunningDigest(digNew)
	rig.unhealthyDigests = map[string]bool{digNew: true}
	rig.localImages = map[string]bool{digOld: true}
	rig.failFor = []string{"pull"} // registry dead
	opID := rig.seedRecord(t, journal.PhaseRestarted)
	rig.boot(t)

	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusAccepted {
		t.Fatalf("resolve: %d %+v", code, body)
	}
	op := rig.waitOp(t, body["op_id"].(string))
	if op["state"] != "succeeded" {
		t.Fatalf("rollback op: %+v", op)
	}
	params, _ := op["params"].(map[string]interface{})
	if params["reconcile_action"] != "rollback_to_prior" || params["image_ref"] != priorRef {
		t.Errorf("params: %+v", params)
	}
	if !rig.pinnedFor("tag", digOld) {
		t.Error("must retag the prior")
	}
	time.Sleep(50 * time.Millisecond)
	if rig.recordExists(opID) {
		t.Error("original record must be retired after the rollback succeeded")
	}
}

// A failed resolve keeps the original record visible with the outcome.
func TestReconcileResolve_FailureKeepsRecord(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.localImages = map[string]bool{}
	rig.failFor = []string{"pull"} // target not local, registry dead ⇒ reup fails at pull
	opID := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t)

	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusAccepted {
		t.Fatalf("resolve: %d %+v", code, body)
	}
	op := rig.waitOp(t, body["op_id"].(string))
	if op["state"] != "failed" {
		t.Fatalf("resolve op: %+v", op)
	}
	time.Sleep(50 * time.Millisecond)
	if !rig.recordExists(opID) {
		t.Fatal("a failed resolve must keep the original record")
	}
	entry, attention := rig.interrupted(t, opID)
	if entry == nil || !attention || entry["last_resolve_op_id"] != body["op_id"] || !strings.HasPrefix(entry["last_resolve_outcome"].(string), "failed") {
		t.Errorf("entry: %+v", entry)
	}
	if entry["attempts"] != float64(1) {
		t.Errorf("attempts must be charged: %v", entry["attempts"])
	}
}

// Dismiss semantics: a tag hazard needs acknowledge_tag_hazard; an
// unclassified / non-noop verdict needs acknowledge_unresolved; a second
// dismiss is 404.
func TestReconcileDismiss_Semantics(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	hazard := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t)

	code, body := rig.postReconcile(t, hazard, map[string]interface{}{"action": "dismiss"})
	if code != http.StatusConflict || body["error"] != "tag_hazard_unacknowledged" {
		t.Fatalf("unacknowledged hazard: %d %+v", code, body)
	}
	code, body = rig.postReconcile(t, hazard, map[string]interface{}{"action": "dismiss", "acknowledge_unresolved": true})
	if code != http.StatusConflict {
		t.Fatalf("acknowledge_unresolved must not satisfy a TAG hazard: %d %+v", code, body)
	}
	code, body = rig.postReconcile(t, hazard, map[string]interface{}{"action": "dismiss", "acknowledge_tag_hazard": true})
	if code != http.StatusOK || body["dismissed"] != true {
		t.Fatalf("acknowledged dismiss: %d %+v", code, body)
	}
	if rig.recordExists(hazard) {
		t.Error("dismiss must retire the record")
	}
	if rig.sawCommand("tag") || rig.sawCommand("up") {
		t.Error("dismiss must not touch docker")
	}
	code, body = rig.postReconcile(t, hazard, map[string]interface{}{"action": "dismiss", "acknowledge_tag_hazard": true})
	if code != http.StatusNotFound {
		t.Errorf("second dismiss: %d %+v", code, body)
	}

	// Unclassified (mark-only): needs acknowledge_unresolved.
	unc := rig.seedRecord(t, journal.PhaseRestarting)
	code, body = rig.postReconcile(t, unc, map[string]interface{}{"action": "dismiss"})
	if code != http.StatusConflict || body["error"] != "verdict_unresolved" {
		t.Fatalf("unclassified dismiss: %d %+v", code, body)
	}
	code, _ = rig.postReconcile(t, unc, map[string]interface{}{"action": "dismiss", "acknowledge_unresolved": true})
	if code != http.StatusOK {
		t.Fatalf("acknowledged unclassified dismiss: %d", code)
	}
	if _, attention := rig.interrupted(t, unc); attention {
		t.Error("status must be clean after dismiss")
	}
	// Bad inputs.
	if code, _ = rig.postReconcile(t, "not-an-id", map[string]interface{}{"action": "dismiss"}); code != http.StatusBadRequest {
		t.Errorf("invalid op_id: %d", code)
	}
	if code, _ = rig.postReconcile(t, ops.NewID(), map[string]interface{}{"action": "bogus"}); code != http.StatusNotFound {
		t.Errorf("unknown record wins over bad action: %d", code)
	}
}

// A duplicate resolve while one is in flight is refused (409), never admitted
// as a second mutation; the maintenance lock is held by the first.
func TestReconcileResolve_DuplicateWhileInFlight(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.localImages = map[string]bool{digNew: true}
	rig.blockUp = make(chan struct{})
	opID := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t)

	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusAccepted {
		t.Fatalf("first resolve: %d %+v", code, body)
	}
	first := body["op_id"].(string)
	code, body = rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusConflict || body["error"] != "resolve_in_flight" || body["resolve_op_id"] != first {
		t.Fatalf("duplicate: %d %+v", code, body)
	}
	if entry, _ := rig.interrupted(t, opID); entry == nil || entry["resolve_op_id"] != first {
		t.Errorf("status must show the in-flight resolve: %+v", entry)
	}
	code, body = rig.postReconcile(t, opID, map[string]interface{}{"action": "dismiss", "acknowledge_tag_hazard": true})
	if code != http.StatusConflict {
		t.Errorf("dismiss during an in-flight resolve: %d %+v", code, body)
	}
	close(rig.blockUp)
	if op := rig.waitOp(t, first); op["state"] != "succeeded" {
		t.Fatalf("resolve op: %+v", op)
	}
	if n := rig.countCommand("tag"); n != 1 {
		t.Errorf("exactly one tag advance, got %d", n)
	}
}

// resolve recomputes: a verdict that changed since boot is refused once
// (verdict_changed), then acted on; loud_stop/data_manual are manual_required;
// docker-down is inputs_unavailable.
func TestReconcileResolve_RefusalLadder(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	opID := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t) // reup

	rig.dockerDown.Store(true)
	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusConflict || body["error"] != verdictInputsUnavailable {
		t.Fatalf("docker down: %d %+v", code, body)
	}
	rig.dockerDown.Store(false)

	// Someone converged the container by hand: the live verdict is now adopt.
	rig.setRunningDigest(digNew)
	code, body = rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusConflict || body["error"] != "verdict_changed" || body["previous_verdict"] != "reup" || body["current_verdict"] != "verify_adopt_else_rollback" {
		t.Fatalf("verdict_changed: %d %+v", code, body)
	}
	code, body = rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusOK || body["resolved"] != "adopted" {
		t.Fatalf("adopt: %d %+v", code, body)
	}
	if rig.recordExists(opID) || rig.mgr.Get(opID).State != ops.StateSucceeded {
		t.Error("adopt must retire the record and mark the op succeeded")
	}

	// data_manual ⇒ manual_required.
	data := ops.NewID()
	now := time.Now().UTC()
	_ = rig.journal.Write(journal.Record{OpID: data, Kind: ops.KindRollbackCreate, Mode: "data", Phase: journal.PhaseRestarting, Actor: "cp", StartedAt: now, UpdatedAt: now})
	code, body = rig.postReconcile(t, data, map[string]interface{}{"action": "resolve"})
	if code != http.StatusConflict || body["error"] != "manual_required" {
		t.Fatalf("data_manual: %d %+v", code, body)
	}
	// invalid ref ⇒ loud_stop ⇒ manual_required, and docker never pulls it.
	bad := ops.NewID()
	_ = rig.journal.Write(journal.Record{OpID: bad, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting, Actor: "cp", StartedAt: now, UpdatedAt: now,
		TargetRef: "evil.io/x@sha256:" + digNew, TargetDigest: digNew})
	code, body = rig.postReconcile(t, bad, map[string]interface{}{"action": "resolve"})
	if code != http.StatusConflict || body["error"] != "manual_required" || body["reason"] != "invalid_record_ref" {
		t.Fatalf("invalid ref: %d %+v", code, body)
	}
}

// A noop recomputed at resolve time simply retires the record.
func TestReconcileResolve_NoopRetires(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digOld
	opID := rig.seedRecord(t, journal.PhasePulled) // mark-only: no boot
	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusOK || body["resolved"] != "noop" {
		t.Fatalf("noop resolve: %d %+v", code, body)
	}
	if rig.recordExists(opID) {
		t.Error("record must be retired")
	}
}

// The attempt bound: after reconcileMaxAttempts resolves the op is loud_stop.
func TestReconcileResolve_AttemptBound(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.localImages = map[string]bool{}
	rig.failFor = []string{"pull"}
	opID := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t)
	for i := 0; i < reconcileMaxAttempts; i++ {
		code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
		if code != http.StatusAccepted {
			t.Fatalf("attempt %d: %d %+v", i, code, body)
		}
		rig.waitOp(t, body["op_id"].(string))
		deadline := time.Now().Add(2 * time.Second)
		for rig.resolveInFlightForTest(opID) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusConflict || body["error"] != "verdict_changed" {
		t.Fatalf("exhaustion first shows as a changed verdict: %d %+v", code, body)
	}
	code, body = rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusConflict || body["error"] != "manual_required" || body["reason"] != "reconcile_exhausted" {
		t.Fatalf("exhausted: %d %+v", code, body)
	}
}

func (r *applyRig) resolveInFlightForTest(opID string) bool { return r.srv.resolveInFlight(opID) != "" }

// A resolve REFUSED at admission (another op holds the maintenance lock) ran
// nothing and must not consume the attempt bound: pre-fix the attempt was
// charged and persisted BEFORE startAsyncOp, so a CP retrying against a busy
// agent drove the record to loud_stop(reconcile_exhausted) without one action
// (adversarial review, PR #1528). Verified failing against the pre-fix
// launchResolveOp.
func TestReconcileResolve_RefusedLaunchDoesNotChargeAnAttempt(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.localImages = map[string]bool{digNew: true}
	rig.blockUp = make(chan struct{})
	opA := rig.seedRecord(t, journal.PhaseRestarting)
	opB := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t)

	code, body := rig.postReconcile(t, opA, map[string]interface{}{"action": "resolve"})
	if code != http.StatusAccepted {
		t.Fatalf("resolve A: %d %+v", code, body)
	}
	first := body["op_id"].(string)
	// The first refusal is the lock conflict; A's pull/tag may already have
	// moved the fake daemon's live view, so later ones may re-classify B
	// (verdict_changed) — either way nothing ran, so nothing may be charged.
	code, body = rig.postReconcile(t, opB, map[string]interface{}{"action": "resolve"})
	if code != http.StatusConflict || body["error"] != "concurrency_conflict" {
		t.Fatalf("resolve B while A holds the lock: %d %+v", code, body)
	}
	if v, _ := rig.srv.readVerdict(opB); v == nil || v.Attempts != 0 {
		t.Fatalf("B attempts = %+v, want 0 (nothing ran)", v)
	}
	if rig.srv.resolveInFlight(opA) != first {
		t.Fatal("B's refusal must not clear A's in-flight marker")
	}
	close(rig.blockUp)
	rig.waitOp(t, first)
	// B is still resolvable once the lock is free: the bound was not spent.
	code, body = rig.postReconcile(t, opB, map[string]interface{}{"action": "resolve"})
	if body["error"] == "manual_required" || body["reason"] == "reconcile_exhausted" {
		t.Fatalf("refused launches consumed the attempt bound: %d %+v", code, body)
	}
	if code == http.StatusAccepted {
		rig.waitOp(t, body["op_id"].(string))
	}
}

// A deduplicated replay (same idempotency_key as an earlier, failed resolve)
// returns the prior op and runs nothing, so it must not consume the attempt
// bound: three harmless retries used to exhaust the record (Codex P1,
// PR #1528).
func TestReconcileResolve_DedupedReplayDoesNotChargeAnAttempt(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.localImages = map[string]bool{}
	rig.failFor = []string{"pull"}
	opID := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t)

	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve", "idempotency_key": "replay-me"})
	if code != http.StatusAccepted {
		t.Fatalf("first resolve: %d %+v", code, body)
	}
	first := body["op_id"].(string)
	rig.waitOp(t, first)
	deadline := time.Now().Add(2 * time.Second)
	for rig.resolveInFlightForTest(opID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if v, _ := rig.srv.readVerdict(opID); v == nil || v.Attempts != 1 {
		t.Fatalf("after one real attempt: %+v, want Attempts=1", v)
	}
	for i := 0; i < reconcileMaxAttempts+1; i++ {
		code, body = rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve", "idempotency_key": "replay-me"})
		if code != http.StatusOK || body["deduped"] != true || body["op_id"] != first {
			t.Fatalf("replay %d must dedupe to the first op: %d %+v", i, code, body)
		}
		if v, _ := rig.srv.readVerdict(opID); v == nil || v.Attempts != 1 {
			t.Fatalf("replay %d charged an attempt: %+v", i, v)
		}
	}
	// A genuinely new resolve still works: the bound was not spent by replays.
	code, body = rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve", "idempotency_key": "fresh"})
	if code != http.StatusAccepted {
		t.Fatalf("a fresh resolve after replays must be admitted: %d %+v", code, body)
	}
	rig.waitOp(t, body["op_id"].(string))
}

// A dismiss and a resolve for the same record must never both act: the
// in-flight marker used to be installed only after classification and
// admission, so a dismiss arriving in that window retired the record while
// the resolve went on to re-up or roll back (Codex P2, PR #1528). While one
// request holds the claim, every other request for that record is refused
// before it reads anything.
func TestReconcile_ClaimRefusesAConcurrentRequestForTheSameRecord(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.pinnedDigest = digNew
	rig.localImages = map[string]bool{digNew: true, digOld: true}
	opID := rig.seedRecord(t, journal.PhaseRestarting)
	rig.boot(t)

	if ok, _, _ := rig.srv.claimReconcile(opID); !ok {
		t.Fatal("first claim must succeed")
	}
	for _, action := range []string{"dismiss", "resolve"} {
		code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": action, "acknowledge_tag_hazard": true, "acknowledge_unresolved": true})
		if code != http.StatusConflict || body["error"] != "reconcile_in_progress" {
			t.Fatalf("%s during another request's claim: %d %+v", action, code, body)
		}
	}
	if !rig.recordExists(opID) || rig.sawCommand("up") {
		t.Fatal("a refused request must neither retire the record nor touch Docker")
	}
	// CONTROL: once released, the record is actionable again.
	rig.srv.releaseReconcile(opID)
	code, body := rig.postReconcile(t, opID, map[string]interface{}{"action": "resolve"})
	if code != http.StatusAccepted {
		t.Fatalf("after release the resolve must be admitted: %d %+v", code, body)
	}
	// The admitted resolve runs asynchronously and writes the journal; wait
	// for it so the temp dir is not removed underneath it.
	rig.waitOp(t, body["op_id"].(string))
}
