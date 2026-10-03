//go:build linux

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// While culvert-os-update holds the shared host maintenance lock, no
// state-changing agent op may be admitted (Codex P1, PR #1528).
func TestHostLock_RefusesAdmissionWhileOSMaintenanceHoldsIt(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	release, busy, err := acquireHostMaintenanceLock(rig.stateDir) // stands in for culvert-os-update
	if err != nil || busy {
		t.Fatalf("test could not take the lock: busy=%v err=%v", busy, err)
	}
	status, body := rig.post(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	var out map[string]interface{}
	_ = json.Unmarshal(body, &out)
	if status != http.StatusConflict || out["error"] != "host_maintenance_in_progress" {
		t.Fatalf("admission during OS maintenance: %d %s", status, body)
	}
	if rig.sawCommand("pull") || rig.sawCommand("up") {
		t.Fatal("a refused op must not touch Docker")
	}
	release()
	// CONTROL: once OS maintenance is done the same request is admitted.
	if op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew}); op["state"] != "succeeded" {
		t.Fatalf("after release the upgrade must run: %+v", op)
	}
}

// The other direction: while an agent op runs, the lock is held, so
// culvert-os-update's flock -n fails; it is released when the op ends.
func TestHostLock_HeldForTheWholeOperation(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.blockUp = make(chan struct{})
	status, body := rig.post(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if status != http.StatusAccepted {
		t.Fatalf("apply: %d %s", status, body)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(body, &ack)
	deadline := time.Now().Add(5 * time.Second)
	for !rig.sawCommand("up") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, busy, _ := acquireHostMaintenanceLock(rig.stateDir); !busy {
		t.Fatal("the lock must be held while the op is running (os-update would not see it)")
	}
	close(rig.blockUp)
	rig.waitOp(t, ack["op_id"].(string))
	var release func()
	for i := 0; i < 100; i++ { // the goroutine releases just after the flow returns
		var busy bool
		if release, busy, _ = acquireHostMaintenanceLock(rig.stateDir); !busy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if release == nil {
		t.Fatal("the lock must be released when the op ends")
	}
	release()
}
