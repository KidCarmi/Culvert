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
