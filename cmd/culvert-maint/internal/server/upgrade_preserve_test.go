package server

import (
	"strings"
	"testing"
)

// The upgrade success contract (owner review, PR #1528): a 2xx /ready is
// not enough. Whatever the running stack reported as healthy BEFORE the
// restart — admin setup, session signing, the inspection CA, policy and
// enforcement — must read "ok" again, or the upgrade fails health_gate
// and inline rollback restores the prior image.

const (
	readyAllOK          = `{"checks":{"setup_complete":{"status":"ok"},"session_secret":{"status":"ok"},"ca":{"status":"ok"},"policy_loaded":{"status":"ok"},"policy_posture":{"status":"ok"},"clamav":{"status":"ok"}}}`
	readyAdminLost      = `{"checks":{"setup_complete":{"status":"fail"},"session_secret":{"status":"ok"},"ca":{"status":"ok"},"policy_loaded":{"status":"ok"},"policy_posture":{"status":"ok"}}}`
	readyExternalDegrad = `{"checks":{"setup_complete":{"status":"ok"},"session_secret":{"status":"ok"},"ca":{"status":"ok"},"policy_loaded":{"status":"ok"},"policy_posture":{"status":"ok"},"clamav":{"status":"fail"}}}`
)

func TestUpgradeApply_RegressedPreservedRowRollsBack(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.readyBodies = map[string]string{digOld: readyAllOK, digNew: readyAdminLost}

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "health_failed" {
		t.Fatalf("an upgrade that loses the admin setup must fail health_gate: state=%v reason=%v", op["state"], op["failure_reason"])
	}
	res, _ := op["result"].(map[string]interface{})
	if res == nil || res["rollback_succeeded"] != true {
		t.Fatalf("inline rollback must restore the prior image: %v", res)
	}
	log := rig.opLog(t, opID)
	for _, want := range []string{
		"preserved=[setup_complete,session_secret,ca,policy_loaded,policy_posture]", // baseline, from the running stack
		"preserved_check_regressed: setup_complete",
		"not_restored=[]", // rollback health: prior image back to the baseline
	} {
		if !strings.Contains(log, want) {
			t.Errorf("op-log missing %q:\n%s", want, log)
		}
	}
}

// CONTROL: an external-dependency row (clamav) degrading across the
// upgrade must NOT roll it back — it is outside the preserved set.
func TestUpgradeApply_ExternalRowDegradingDoesNotRollBack(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.readyBodies = map[string]string{digOld: readyAllOK, digNew: readyExternalDegrad}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("an external-dependency row must not fail the upgrade: %+v", op)
	}
}

// CONTROL: rows that were NOT ok before (fresh, unclaimed appliance) are
// not required after — an upgrade before setup works as it always did.
func TestUpgradeApply_RowsNotOKBeforeAreNotRequired(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.readyBodies = map[string]string{digOld: readyAdminLost, digNew: readyAdminLost}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("a row that was already failing must not be required: %+v", op)
	}
}

// A ClamAV sidecar that was already down gates /ready (503) before AND
// after the restart. The upgrade did not cause it and a rollback would not
// fix it, so it must succeed — not fail health_gate and then fail the
// rollback's health check the same way.
func TestUpgradeApply_PreexistingGatingFailureDoesNotRollBack(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.readyBodies = map[string]string{digOld: readyExternalDegrad, digNew: readyExternalDegrad}
	rig.readyStatuses = map[string]int{digOld: 503, digNew: 503}

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("a failure that predates the upgrade must be tolerated: %+v\n%s", op, rig.opLog(t, opID))
	}
	if log := rig.opLog(t, opID); !strings.Contains(log, "tolerated: failing [clamav]") {
		t.Errorf("op-log must say what was tolerated:\n%s", log)
	}
}

// The defect direction: the same 503 that appears only AFTER the restart
// is something the upgrade broke.
func TestUpgradeApply_NewGatingFailureRollsBack(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.readyBodies = map[string]string{digOld: readyAllOK, digNew: readyExternalDegrad}
	rig.readyStatuses = map[string]int{digNew: 503}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "health_failed" {
		t.Fatalf("a gating row that newly fails must fail the upgrade: %+v", op)
	}
}

// The standalone image rollback takes the same baseline, so a host whose
// /ready was already 503 (ClamAV down) can still be rolled back.
func TestImageRollback_PreexistingGatingFailureIsTolerated(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.readyBodies = map[string]string{digOld: readyExternalDegrad, digNew: readyExternalDegrad}
	rig.readyStatuses = map[string]int{digOld: 503, digNew: 503}

	op, opID := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("a rollback on a host already at 503 must be tolerated: %+v\n%s", op, rig.opLog(t, opID))
	}
	// CONTROL: from a 2xx host, a rollback target that answers 503 fails.
	rig2 := startApplyRig(t)
	defer rig2.stop()
	rig2.readyStatuses = map[string]int{digNew: 503}
	if op2, _ := rig2.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digNew}); op2["state"] != "failed" {
		t.Fatalf("a rollback that turns a 2xx host into 503 must fail: %+v", op2)
	}
}
