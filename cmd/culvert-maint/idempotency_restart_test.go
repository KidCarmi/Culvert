package main

// idempotency_restart_test.go — durable idempotency across a real agent
// restart (internal/idem, ops/idempotency.go).
//
// Same rig as startup_crash_recovery_test.go: the real binary on the real Unix
// socket, SIGKILL as the crash, a new process on the same state_dir as the
// restart, and the Docker model's calls.log as the record of what was actually
// executed. backup.create is the op under test because it is state-changing
// but NOT journaled — before the durable record a restarted agent knew nothing
// about it, so a same-key retry ran the backup container a second time.

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type idemAck struct {
	OpID          string `json:"op_id"`
	Kind          string `json:"kind"`
	State         string `json:"state"`
	Deduped       bool   `json:"deduped"`
	FailureReason string `json:"failure_reason"`
	Outcome       string `json:"outcome"`
	Error         string `json:"error"`
}

// backupRuns counts the backup CLI container invocations the model saw.
func (r *crashRig) backupRuns() int {
	n := 0
	for _, line := range strings.Split(r.read("calls.log"), "\n") {
		if strings.Contains(line, " run ") && strings.Contains(line, "--backup") {
			n++
		}
	}
	return n
}

// callLog is the model's raw docker call log, for byte-for-byte comparison.
func (r *crashRig) callLog() string { return r.read("calls.log") }

func (r *crashRig) waitBlocked() {
	r.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(r.model, "blocked")); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatalf("the op never reached its stop point; agent output:\n%s\ncalls:\n%s", r.logs.String(), r.callLog())
}

// TestIdempotencyRestart_KilledMidBackupIsUnknownAndNotRerun: SIGKILL while
// the backup container is running. After the restart the same key returns the
// original op as failed(agent_restart_interrupted), outcome unknown, and the
// agent issues no docker command at all — neither at startup nor for the
// retry. A new key then runs the backup.
func TestIdempotencyRestart_KilledMidBackupIsUnknownAndNotRerun(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	req := map[string]interface{}{"filename": "nightly.tar.gz", "idempotency_key": "backup-2026-11-24"}

	r.put("block_on", "cli_run:1")
	var first idemAck
	if code := r.post("/v1/backups", req, &first); code != http.StatusAccepted {
		t.Fatalf("first submission: HTTP %d; agent output:\n%s", code, r.logs.String())
	}
	r.waitBlocked()
	// The write-ahead record is on disk while the container is still running.
	recs, err := filepath.Glob(filepath.Join(r.state, "idempotency", "*.json"))
	if err != nil || len(recs) != 1 {
		t.Fatalf("want exactly one durable admission record mid-op, got %v (err=%v)", recs, err)
	}
	r.kill() // the crash
	if n := r.backupRuns(); n != 1 {
		t.Fatalf("the model saw %d backup runs before the restart, want 1:\n%s", n, r.callLog())
	}
	callsBefore := r.callLog()

	r.start() // the restart
	var retry idemAck
	if code := r.post("/v1/backups", req, &retry); code != http.StatusOK {
		t.Fatalf("same-key retry: HTTP %d, want 200; agent output:\n%s", code, r.logs.String())
	}
	if retry.OpID != first.OpID || !retry.Deduped {
		t.Fatalf("retry was not answered with the original op: %+v (original %s)", retry, first.OpID)
	}
	if retry.State != "failed" || retry.FailureReason != "agent_restart_interrupted" || retry.Outcome != "unknown" {
		t.Fatalf("retry must say failed(agent_restart_interrupted), outcome unknown; got %+v", retry)
	}
	var op opView
	if code := r.get("/v1/operations/"+first.OpID, &op); code != http.StatusOK {
		t.Fatalf("GET /v1/operations/%s after restart: HTTP %d, want 200", first.OpID, code)
	}
	if op.State != "failed" || op.FailureReason != "agent_restart_interrupted" || op.Result["outcome"] != "unknown" {
		t.Fatalf("operation record after restart: %+v", op)
	}
	// A second retry gives the same answer (the verdict is stable).
	var again idemAck
	if code := r.post("/v1/backups", req, &again); code != http.StatusOK || again.OpID != first.OpID || again.State != "failed" {
		t.Fatalf("second retry: HTTP %d %+v", code, again)
	}
	if got := r.callLog(); got != callsBefore {
		t.Fatalf("the restarted agent issued docker commands for a replay.\nbefore:\n%s\nafter:\n%s", callsBefore, got)
	}

	// A deliberate re-run under a new key executes.
	var fresh idemAck
	req2 := map[string]interface{}{"filename": "nightly.tar.gz", "idempotency_key": "backup-2026-11-24-retry"}
	if code := r.post("/v1/backups", req2, &fresh); code != http.StatusAccepted {
		t.Fatalf("new key: HTTP %d; agent output:\n%s", code, r.logs.String())
	}
	if fresh.OpID == first.OpID {
		t.Fatal("new key returned the interrupted op")
	}
	if done := r.waitOp(fresh.OpID); done.State != "succeeded" {
		t.Fatalf("new-key backup: %+v", done)
	}
	if n := r.backupRuns(); n != 2 {
		t.Fatalf("backup runs after the new-key request: %d, want 2", n)
	}
}

// TestIdempotencyRestart_CompletedBackupIsReplayed: the backup finished, then
// the agent was killed. The restarted agent answers the same key with the same
// op and the same result, and issues no docker command. A different payload
// under that key is refused.
func TestIdempotencyRestart_CompletedBackupIsReplayed(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	req := map[string]interface{}{"filename": "nightly.tar.gz", "idempotency_key": "backup-done"}

	var first idemAck
	if code := r.post("/v1/backups", req, &first); code != http.StatusAccepted {
		t.Fatalf("first submission: HTTP %d; agent output:\n%s", code, r.logs.String())
	}
	before := r.waitOp(first.OpID)
	if before.State != "succeeded" {
		t.Fatalf("first run: %+v; agent output:\n%s", before, r.logs.String())
	}
	if n := r.backupRuns(); n != 1 {
		t.Fatalf("backup runs: %d, want 1", n)
	}
	r.kill()
	callsBefore := r.callLog()

	r.start()
	var retry idemAck
	if code := r.post("/v1/backups", req, &retry); code != http.StatusOK {
		t.Fatalf("same-key retry: HTTP %d, want 200; agent output:\n%s", code, r.logs.String())
	}
	if retry.OpID != first.OpID || !retry.Deduped || retry.State != "succeeded" || retry.FailureReason != "" {
		t.Fatalf("retry: %+v (original %s)", retry, first.OpID)
	}
	var after opView
	if code := r.get("/v1/operations/"+first.OpID, &after); code != http.StatusOK {
		t.Fatalf("GET after restart: HTTP %d, want 200", code)
	}
	if after.State != before.State || after.Kind != before.Kind || !after.StartedAt.Equal(before.StartedAt) || after.FailureReason != "" {
		t.Fatalf("operation record changed across the restart:\nbefore %+v\nafter  %+v", before, after)
	}

	var refused idemAck
	other := map[string]interface{}{"filename": "something-else.tar.gz", "idempotency_key": "backup-done"}
	if code := r.post("/v1/backups", other, &refused); code != http.StatusUnprocessableEntity {
		t.Fatalf("different payload under a used key: HTTP %d, want 422", code)
	}
	if refused.Error != "idempotency_key_reused" || refused.OpID != first.OpID {
		t.Fatalf("refusal body: %+v", refused)
	}
	if got := r.callLog(); got != callsBefore {
		t.Fatalf("the restarted agent issued docker commands for a replay or a refusal.\nbefore:\n%s\nafter:\n%s", callsBefore, got)
	}
}
