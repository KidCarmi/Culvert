// Integration tests for POST /v1/rollbacks (mode=image). Reuses the
// applyRig harness (faked exec + fake health): image rollback exercises
// the same capture/pull/restart/health/verify primitives as apply.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func (r *applyRig) postRollback(t *testing.T, body interface{}) (status int, respBody []byte) {
	t.Helper()
	cli := udsClient(r.sockPath)
	bodyBytes, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://unix/v1/rollbacks", strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/rollbacks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

func (r *applyRig) rollbackAndWait(t *testing.T, body interface{}) (op map[string]interface{}, opID string) {
	t.Helper()
	status, rb := r.postRollback(t, body)
	if status != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", status, rb)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(rb, &ack)
	opID, _ = ack["op_id"].(string)
	if opID == "" {
		t.Fatalf("ack missing op_id: %s", rb)
	}
	return r.waitOp(t, opID), opID
}

// Success: rolling back to a prior pinned digest pulls + restarts pinned
// to it and verifies the running image matches.
func TestRollback_Image_Success(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	// The running image is digOld; we roll "back" to a pinned digest.
	// After the pull, the rig reports digAfter as the running image.
	rig.digBefore = digOld
	rig.digAfter = digNew

	target := repo + "@sha256:" + digNew
	op, opID := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": target})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded; op=%+v", op["state"], op)
	}
	if !rig.sawCommand("pull") || !rig.sawCommand("up") {
		t.Error("rollback must pull and restart")
	}
	// pull + up must be pinned to the target digest, never a tag.
	for _, cmd := range []string{"pull", "up"} {
		if !envHas(rig.envFor(cmd), "CULVERT_PROXY_IMAGE="+target) {
			t.Errorf("%s must pin CULVERT_PROXY_IMAGE=%s; env=%v", cmd, target, rig.envFor(cmd))
		}
	}
	logStr := rig.opLog(t, opID)
	for _, want := range []string{"rollback mode=image", `target_ref="` + target + `"`, "verify: running_digests="} {
		if !strings.Contains(logStr, want) {
			t.Errorf("op-log missing %q:\n%s", want, logStr)
		}
	}
}

// Invalid / missing targets are rejected at the handler before any exec.
func TestRollback_RejectsInvalidTarget(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	cases := []map[string]interface{}{
		{"mode": "data"},  // data mode requires a filename → 400 (missing filename)
		{"mode": "image"}, // missing image_ref
		{"mode": "image", "image_ref": repo + ":v1.2.4"},                        // tag, not a digest
		{"mode": "image", "image_ref": "ghcr.io/evil/culvert@sha256:" + digNew}, // not allowlisted
		{"mode": "image", "image_ref": "-rf"},                                   // malformed
		{"image_ref": repo + "@sha256:" + digNew},                               // missing mode
	}
	for _, body := range cases {
		status, rb := rig.postRollback(t, body)
		if status != http.StatusBadRequest {
			t.Errorf("body %v: got %d want 400; resp=%s", body, status, rb)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if cmds := rig.snapshot(); len(cmds) != 0 {
		t.Errorf("a rejected rollback must NOT reach the runner; cmds=%v", cmds)
	}
}

// A pull failure fails the op (no restart).
func TestRollback_PullFailure_FailsOp(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.failFor = []string{"pull"}

	target := repo + "@sha256:" + digNew
	op, _ := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": target})
	if op["state"] != "failed" {
		t.Fatalf("state: got %v want failed", op["state"])
	}
	if op["failure_reason"] != "command_error" {
		t.Errorf("failure_reason: got %v want command_error", op["failure_reason"])
	}
	if rig.sawCommand("up") {
		t.Error("a failed pull must abort before restart")
	}
}

// A health-gate failure fails the op.
func TestRollback_HealthFailure_FailsOp(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.healthFail.Store(true)

	target := repo + "@sha256:" + digNew
	op, _ := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": target})
	if op["state"] != "failed" {
		t.Fatalf("state: got %v want failed", op["state"])
	}
	if op["failure_reason"] != "health_failed" {
		t.Errorf("failure_reason: got %v want health_failed", op["failure_reason"])
	}
}
