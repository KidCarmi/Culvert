// Integration + unit tests for inline auto-rollback (#375). Reuses the
// applyRig harness, whose fake stack tracks the pinned running image and
// fails health per-digest — so "new image unhealthy, prior healthy" and
// "rollback flips the running image back" are both expressible.
package server

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"culvert-maint/internal/ops"
)

// rollbackAuditOutcomes returns the outcomes of every
// upgrades.apply:rollback audit entry, in order.
func (r *applyRig) rollbackAuditOutcomes(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(r.auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev map[string]interface{}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		if ev["kind"] == auditKindRollback {
			if o, ok := ev["outcome"].(string); ok {
				out = append(out, o)
			}
		}
	}
	return out
}

// pinnedFor reports whether any captured command whose argv contains token
// also carries the digest in its argv. P1.4: the image is selected by the
// `docker pull <repo@sha256:…>` / `docker tag <repo@sha256:…> …` argv, so the
// digest appears for "pull" and "tag" but NEVER for a plain "up".
//
//nolint:unparam // generic test helper; current callers happen to pass digOld
func (r *applyRig) pinnedFor(token, digest string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, argv := range r.captured {
		if argvHas(argv, token) && envContains(argv, digest) {
			return true
		}
	}
	return false
}

func argvHas(argv []string, tok string) bool {
	for _, a := range argv {
		if a == tok {
			return true
		}
	}
	return false
}

func envContains(env []string, sub string) bool {
	for _, e := range env {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func resultMap(t *testing.T, op map[string]interface{}) map[string]interface{} {
	t.Helper()
	res, _ := op["result"].(map[string]interface{})
	if res == nil {
		t.Fatalf("op.result missing/!map: %+v", op)
	}
	return res
}

// health fail + rollback SUCCESS: op failed/health_failed, service restored
// to the prior digest, audit started+succeeded.
func TestUpgradeApply_InlineRollback_Success(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true} // new image broken, prior (digOld) fine

	ref := repo + "@sha256:" + digNew
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": ref})

	if op["state"] != "failed" || op["failure_reason"] != "health_failed" {
		t.Fatalf("want failed/health_failed; got state=%v reason=%v", op["state"], op["failure_reason"])
	}
	res := resultMap(t, op)
	checks := map[string]interface{}{
		"upgrade_succeeded":       false,
		"rollback_attempted":      true,
		"rollback_succeeded":      true,
		"rollback_skipped_reason": "",
		"upgrade_digest":          "sha256:" + digNew,
		"rollback_digest":         "sha256:" + digOld,
		"final_running_digest":    "sha256:" + digOld,
	}
	for k, want := range checks {
		if res[k] != want {
			t.Errorf("result[%s]: got %v want %v", k, res[k], want)
		}
	}
	if rig.countCommand("pull") != 2 {
		t.Errorf("expected an upgrade pull + a rollback pull; got %d", rig.countCommand("pull"))
	}
	if !rig.pinnedFor("pull", digOld) || !rig.pinnedFor("tag", digOld) {
		t.Error("rollback pull+tag must carry the prior digest (P1.4: the retag re-pins culvert/proxy:pinned)")
	}
	if got := rig.rollbackAuditOutcomes(t); len(got) != 2 || got[0] != "started" || got[1] != "succeeded" {
		t.Errorf("rollback audit: got %v want [started succeeded]", got)
	}
	logStr := rig.opLog(t, opID)
	for _, want := range []string{"recovery: running after earlier failure at stage=health_gate", "rollback_verify", "rollback attempted=true succeeded=true"} {
		if !strings.Contains(logStr, want) {
			t.Errorf("op-log missing %q:\n%s", want, logStr)
		}
	}
}

// health fail + rollback PULL fail → rollback_failed; restart never runs.
func TestUpgradeApply_InlineRollback_PullFails(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	// Fail only the rollback pull (the one pinning the prior digest).
	rig.failFn = func(argv, _ []string) bool { return argvHas(argv, "pull") && envContains(argv, digOld) }

	ref := repo + "@sha256:" + digNew
	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": ref})

	if op["state"] != "failed" || op["failure_reason"] != "rollback_failed" {
		t.Fatalf("want failed/rollback_failed; got state=%v reason=%v", op["state"], op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_attempted"] != true || res["rollback_succeeded"] != false {
		t.Errorf("want attempted=true succeeded=false; got %v", res)
	}
	if rig.pinnedFor("tag", digOld) {
		t.Error("a failed rollback pull must NOT proceed to retag/restart")
	}
	if got := rig.rollbackAuditOutcomes(t); len(got) != 2 || got[0] != "started" || got[1] != "failed" {
		t.Errorf("rollback audit: got %v want [started failed]", got)
	}
}

// health fail + rollback RESTART fail → rollback_failed.
func TestUpgradeApply_InlineRollback_RestartFails(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	// P1.4: `up` no longer carries the digest, so target the rollback
	// restart by the running view it brings up (set by the preceding pull).
	rig.failFn = func(argv, _ []string) bool { return argvHas(argv, "up") && rig.currentRunning() == digOld }

	ref := repo + "@sha256:" + digNew
	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": ref})

	if op["state"] != "failed" || op["failure_reason"] != "rollback_failed" {
		t.Fatalf("want failed/rollback_failed; got state=%v reason=%v", op["state"], op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_succeeded"] != false {
		t.Errorf("rollback_succeeded must be false; got %v", res["rollback_succeeded"])
	}
	if !rig.pinnedFor("pull", digOld) {
		t.Error("rollback should have pulled the prior digest before the failing restart")
	}
}

// health fail + rollback HEALTH fail → rollback_failed (final-reason
// override fired: the FIRST reason was health_failed, the failed recovery
// stage promoted it to rollback_failed).
func TestUpgradeApply_InlineRollback_HealthFails_OverridesReason(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true, digOld: true} // both unhealthy

	ref := repo + "@sha256:" + digNew
	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": ref})

	if op["state"] != "failed" {
		t.Fatalf("state: got %v want failed", op["state"])
	}
	if op["failure_reason"] != "rollback_failed" {
		t.Errorf("final-reason override must promote to rollback_failed (NOT health_failed); got %v", op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_attempted"] != true || res["rollback_succeeded"] != false {
		t.Errorf("want attempted=true succeeded=false; got %v", res)
	}
}

// upgrade RESTART failure is indeterminate (the new image may already be
// running) → inline rollback MUST fire and can restore service. The op
// keeps the upgrade's own failure_reason (command_error) while the result
// shows rollback_succeeded=true (service restored).
func TestUpgradeApply_InlineRollback_UpgradeRestartFails_TriggersRollback(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	// Fail only the UPGRADE restart (the one bringing up the new digest);
	// the rollback restart brings up the prior digest and is left to succeed.
	rig.failFn = func(argv, _ []string) bool { return argvHas(argv, "up") && rig.currentRunning() == digNew }

	ref := repo + "@sha256:" + digNew
	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": ref})

	if op["state"] != "failed" {
		t.Fatalf("state: got %v want failed", op["state"])
	}
	if op["failure_reason"] != "command_error" {
		t.Errorf("failure_reason: got %v want command_error (the upgrade's restart failure)", op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_attempted"] != true || res["rollback_succeeded"] != true {
		t.Errorf("a restart failure must trigger rollback and restore service; got %v", res)
	}
	if !rig.pinnedFor("tag", digOld) {
		t.Error("rollback must retag the prior digest before restart")
	}
	if got := rig.rollbackAuditOutcomes(t); len(got) != 2 || got[1] != "succeeded" {
		t.Errorf("rollback audit: got %v want [started succeeded]", got)
	}
}

// missing prior digest → no rollback attempted; reason stays health_failed.
func TestUpgradeApply_InlineRollback_MissingPriorDigest(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	rig.noPriorDigest = true // capture_before yields no usable rollback target

	ref := repo + "@sha256:" + digNew
	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": ref})

	if op["state"] != "failed" || op["failure_reason"] != "health_failed" {
		t.Fatalf("want failed/health_failed; got state=%v reason=%v", op["state"], op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_attempted"] != false || res["rollback_skipped_reason"] != "no_prior_digest" {
		t.Errorf("want attempted=false skipped=no_prior_digest; got %v", res)
	}
	if rig.countCommand("pull") != 1 {
		t.Errorf("missing prior target → only the upgrade pull; got %d", rig.countCommand("pull"))
	}
	if got := rig.rollbackAuditOutcomes(t); len(got) != 0 {
		t.Errorf("a skipped rollback must emit no :rollback audit; got %v", got)
	}
}

// Idempotent replay: a second apply with the same key returns the original
// op_id with no new work (200, not 202).
func TestUpgradeApply_InlineRollback_IdempotentReplay(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()

	ref := repo + "@sha256:" + digNew
	body := map[string]interface{}{"image_ref": ref, "idempotency_key": "inline-rb-idem-1"}
	_, opID := rig.acceptAndWait(t, body)

	status, rb := rig.post(t, body)
	if status != 200 {
		t.Fatalf("replay status: got %d want 200 (deduped)", status)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(rb, &ack)
	if ack["op_id"] != opID {
		t.Errorf("replay op_id: got %v want %s", ack["op_id"], opID)
	}
}

// Stage-parity drift guard: the inline recovery stages and the standalone
// rollback stages are both produced by the SHARED imageRollbackStages
// builder (same core names + order), and the inline copies are decorated
// (ContinueOnError + rollback_failed promotion).
func TestInlineRollback_StageParity(t *testing.T) {
	srv := &Server{} // building stages does not invoke Run, so no deps needed
	wantCore := []string{"rollback_pull", "rollback_restart", "rollback_health", "rollback_verify"}

	core := srv.imageRollbackStages(func() string { return repo + "@sha256:" + digOld }, &rollbackAccumulator{})
	if len(core) != len(wantCore) {
		t.Fatalf("shared core: got %d stages want %d", len(core), len(wantCore))
	}
	for i, w := range wantCore {
		if core[i].Name != w {
			t.Errorf("shared core[%d]: got %q want %q", i, core[i].Name, w)
		}
	}

	// Standalone: capture_before + core + report.
	stand := names(srv.buildImageRollbackStages(repo + "@sha256:" + digNew))
	if !containsSubsequence(stand, wantCore) {
		t.Errorf("standalone stages %v must contain the shared core %v in order", stand, wantCore)
	}

	// Inline: the apply flow appends the same core as decorated recovery
	// stages — same names+order, ContinueOnError + PromoteReasonOnFailure.
	inline := srv.buildUpgradeApplyStages(&upgradeApplyAccumulator{}, &rollbackAccumulator{}, repo+"@sha256:"+digNew, false, "", true)
	if !containsSubsequence(names(inline), wantCore) {
		t.Errorf("inline stages %v must contain the shared core %v in order", names(inline), wantCore)
	}
	core2 := map[string]bool{"rollback_pull": true, "rollback_restart": true, "rollback_health": true, "rollback_verify": true}
	for _, st := range inline {
		if !core2[st.Name] {
			continue
		}
		if !st.ContinueOnError || !st.PromoteReasonOnFailure || st.FailureReason != "rollback_failed" {
			t.Errorf("inline core stage %q must be ContinueOnError+PromoteReasonOnFailure+rollback_failed; got cont=%v promote=%v reason=%v",
				st.Name, st.ContinueOnError, st.PromoteReasonOnFailure, st.FailureReason)
		}
	}
}

func names(stages []ops.FlowStage) []string {
	out := make([]string, len(stages))
	for i := range stages {
		out[i] = stages[i].Name
	}
	return out
}

func containsSubsequence(haystack, needle []string) bool {
	j := 0
	for _, h := range haystack {
		if j < len(needle) && h == needle[j] {
			j++
		}
	}
	return j == len(needle)
}
