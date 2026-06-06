// Integration tests for POST /v1/rollbacks mode=data — the wrap of
// restore.commit. Reuses the d16b restore rig (faked exec + fake health).
// Backups are NOT host-statted (allowed_backup_dir is the cli-container
// path), so tests don't create on-disk backup files.
package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// dataRollbackRig builds the standard d16b rig. The backup need not exist
// on the agent host: allowed_backup_dir is the CONTAINER path (the
// `culvert-backups` volume is mounted only in `cli`), so existence is
// validated by the CLI at restore time, exactly as restore.commit does —
// the agent must NOT host-stat it.
func dataRollbackRig(t *testing.T) *d16bTestRig {
	t.Helper()
	return startD16bRig(t)
}

func (r *d16bTestRig) postRollback(t *testing.T, body interface{}) (status int, respBody []byte) {
	t.Helper()
	return r.post(t, "/v1/rollbacks", body)
}

func (r *d16bTestRig) rollbackOpID(t *testing.T, body interface{}) string {
	t.Helper()
	status, rb := r.postRollback(t, body)
	if status != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", status, rb)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(rb, &ack)
	id, _ := ack["op_id"].(string)
	if id == "" {
		t.Fatalf("ack missing op_id: %s", rb)
	}
	return id
}

// rollbackAuditOutcomesD16b returns outcomes of rollbacks.create audit
// entries (data rollback must NOT emit restore.commit entries).
func (r *d16bTestRig) auditOutcomes(t *testing.T, kind string) []string {
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
		if ev["kind"] == kind {
			if o, ok := ev["outcome"].(string); ok {
				out = append(out, o)
			}
		}
	}
	return out
}

func argvWith(cmds []capturedExecD16b, tok string) (capturedExecD16b, bool) {
	for _, c := range cmds {
		for _, a := range c.Argv {
			if a == tok {
				return c, true
			}
		}
	}
	return capturedExecD16b{}, false
}

func envHasD16b(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

// Success: mode=data wraps restore.commit — stop→restore(--confirm)→up→
// health, op succeeded, kind rollbacks.create, result + audit correct.
func TestDataRollback_Success_WrapsRestoreCommit(t *testing.T) {
	fn := "pre-upgrade-20260101T000000Z.tar.gz.enc"
	rig := dataRollbackRig(t)
	defer rig.stop()

	opID := rig.rollbackOpID(t, map[string]interface{}{
		"mode": "data", "filename": fn, "restore_mode": "full",
	})
	op := rig.waitForOpFinished(t, opID)
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded; op=%+v", op["state"], op)
	}
	if op["kind"] != "rollbacks.create" {
		t.Errorf("kind: got %v want rollbacks.create", op["kind"])
	}
	// Wrap evidence: the restore.commit command sequence ran.
	cmds := rig.captured.snapshot()
	if _, ok := argvWith(cmds, "down"); !ok {
		t.Error("data rollback must stop the stack (down)")
	}
	restoreCmd, ok := argvWith(cmds, "--restore")
	if !ok {
		t.Fatal("data rollback must run cli --restore")
	}
	hasConfirm := false
	for _, a := range restoreCmd.Argv {
		if a == "--confirm" {
			hasConfirm = true
		}
	}
	if !hasConfirm {
		t.Error("data rollback must commit with --confirm")
	}
	// Result payload.
	res, _ := op["result"].(map[string]interface{})
	if res == nil {
		t.Fatalf("missing result: %+v", op)
	}
	for k, want := range map[string]interface{}{
		"mode": "data", "filename": fn, "restore_mode": "full",
		"restore_committed": true, "succeeded": true,
	} {
		if res[k] != want {
			t.Errorf("result[%s]: got %v want %v", k, res[k], want)
		}
	}
	// Audit: rollbacks.create started+succeeded; no restore.commit kind.
	if got := rig.auditOutcomes(t, "rollbacks.create"); len(got) < 2 || got[0] != "started" || got[len(got)-1] != "succeeded" {
		t.Errorf("rollbacks.create audit: got %v want started…succeeded", got)
	}
	if got := rig.auditOutcomes(t, "restore.commit"); len(got) != 0 {
		t.Errorf("data rollback must NOT emit restore.commit audit; got %v", got)
	}
}

// Missing/malformed inputs are rejected BEFORE the runner (no docker).
// Backup EXISTENCE is NOT checked on the host — allowed_backup_dir is the
// cli-container path, so existence is validated by the CLI at restore time
// (parity with restore.commit), not pre-flight.
func TestDataRollback_RejectsInvalidInput(t *testing.T) {
	rig := dataRollbackRig(t)
	defer rig.stop()

	cases := []map[string]interface{}{
		{"mode": "data"}, // missing filename
		{"mode": "data", "filename": "../etc/passwd"},                          // traversal/separator → ValidateBackupFilename
		{"mode": "data", "filename": "has/slash.enc"},                          // separator → ValidateBackupFilename
		{"mode": "data", "filename": "ok.tar.gz.enc", "restore_mode": "bogus"}, // bad restore_mode
		{"mode": "data", "filename": "ok.tar.gz.enc", "passphrase_ref": "bad"}, // bad passphrase_ref shape
	}
	for _, body := range cases {
		status, rb := rig.postRollback(t, body)
		if status != http.StatusBadRequest {
			t.Errorf("body %v: got %d want 400; resp=%s", body, status, rb)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if cmds := rig.captured.snapshot(); len(cmds) != 0 {
		t.Errorf("an input rejected at validation must NOT reach the runner; cmds=%v", cmds)
	}
}

// passphrase_ref: a valid ref is forwarded to the cli restore command env;
// a malformed ref is rejected at 400.
func TestDataRollback_PassphraseRefForwardedAndValidated(t *testing.T) {
	fn := "pre-upgrade-enc.tar.gz.enc"
	rig := dataRollbackRig(t)
	defer rig.stop()

	// Malformed ref → 400 before runner.
	status, _ := rig.postRollback(t, map[string]interface{}{
		"mode": "data", "filename": fn, "passphrase_ref": "not-an-env-ref",
	})
	if status != http.StatusBadRequest {
		t.Errorf("malformed passphrase_ref: got %d want 400", status)
	}

	// Valid ref → value forwarded to the cli --restore command env.
	t.Setenv("CULVERT_BACKUP_PASSPHRASE", "s3cret")
	opID := rig.rollbackOpID(t, map[string]interface{}{
		"mode": "data", "filename": fn, "passphrase_ref": "env:CULVERT_BACKUP_PASSPHRASE",
	})
	rig.waitForOpFinished(t, opID)
	restoreCmd, ok := argvWith(rig.captured.snapshot(), "--restore")
	if !ok {
		t.Fatal("expected a --restore command")
	}
	if !envHasD16b(restoreCmd.Env, "CULVERT_BACKUP_PASSPHRASE=s3cret") {
		t.Errorf("passphrase value must be forwarded to the cli restore env; env=%v", restoreCmd.Env)
	}
}

// DP-reenrollment + counter-rollback safety flags are forwarded exactly as
// restore.commit forwards them, and a CLI refusal (the WouldBlock guard)
// fails the op closed.
func TestDataRollback_SafetyFlagsForwardedAndFailClosed(t *testing.T) {
	fn := "pre-upgrade-flags.tar.gz.enc"

	// Default (no acks): neither flag is in the restore argv.
	rig := dataRollbackRig(t)
	defer rig.stop()
	rig.waitForOpFinished(t, rig.rollbackOpID(t, map[string]interface{}{"mode": "data", "filename": fn}))
	restoreCmd, _ := argvWith(rig.captured.snapshot(), "--restore")
	for _, banned := range []string{"--accept-dp-reenrollment", "--allow-counter-rollback"} {
		for _, a := range restoreCmd.Argv {
			if a == banned {
				t.Errorf("default data rollback must NOT forward %s", banned)
			}
		}
	}

	// With both acks: both flags forwarded.
	rig2 := dataRollbackRig(t)
	defer rig2.stop()
	rig2.waitForOpFinished(t, rig2.rollbackOpID(t, map[string]interface{}{
		"mode": "data", "filename": fn,
		"accept_dp_reenrollment": true, "allow_counter_rollback": true,
	}))
	rc2, _ := argvWith(rig2.captured.snapshot(), "--restore")
	for _, want := range []string{"--accept-dp-reenrollment", "--allow-counter-rollback"} {
		found := false
		for _, a := range rc2.Argv {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("ack must forward %s to the cli restore argv", want)
		}
	}

	// CLI refusal (models the WouldBlock fail-closed guard): the op fails
	// cli_error.
	rig3 := dataRollbackRig(t)
	defer rig3.stop()
	rig3.addFailMatch("--restore")
	op := rig3.waitForOpFinished(t, rig3.rollbackOpID(t, map[string]interface{}{"mode": "data", "filename": fn}))
	if op["state"] != "failed" || op["failure_reason"] != "cli_error" {
		t.Errorf("a CLI refusal must fail the op cli_error; got state=%v reason=%v", op["state"], op["failure_reason"])
	}
}

// Idempotent replay: same key → same op_id, 200, no second restore.
func TestDataRollback_IdempotentReplay(t *testing.T) {
	fn := "pre-upgrade-idem.tar.gz.enc"
	rig := dataRollbackRig(t)
	defer rig.stop()

	body := map[string]interface{}{"mode": "data", "filename": fn, "idempotency_key": "data-rb-1"}
	opID := rig.rollbackOpID(t, body)
	rig.waitForOpFinished(t, opID)

	status, rb := rig.postRollback(t, body)
	if status != http.StatusOK {
		t.Fatalf("replay status: got %d want 200 (deduped); body=%s", status, rb)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(rb, &ack)
	if ack["op_id"] != opID {
		t.Errorf("replay op_id: got %v want %s", ack["op_id"], opID)
	}
}

// Wrap-not-fork + no-new-surface: data rollback's stages are exactly the
// restore.commit stages plus a report; it introduces no new stage names.
func TestDataRollback_WrapsRestoreStages_NoNewSurface(t *testing.T) {
	srv := &Server{}
	restoreNames := map[string]bool{}
	for _, st := range srv.buildRestoreStages(true, "x.enc", "full", false, false, "") {
		restoreNames[st.Name] = true
	}
	data := srv.buildDataRollbackStages("x.enc", "full", false, false, "", &dataRollbackAccumulator{})
	for _, st := range data {
		if st.Name == "report" {
			continue // the only addition
		}
		if !restoreNames[st.Name] {
			t.Errorf("data rollback stage %q is not a restore.commit stage — that would be a fork/new surface", st.Name)
		}
	}
}

// No auto data rollback: the apply inline-rollback path is image-only and
// must never produce a restore (down / cli --restore) stage.
func TestDataRollback_NoAutoPathFromApply(t *testing.T) {
	srv := &Server{}
	stages := srv.buildUpgradeApplyStages(
		&upgradeApplyAccumulator{}, &rollbackAccumulator{},
		repo+"@sha256:"+digNew, false, "", true, // inline rollback enabled
	)
	for _, st := range stages {
		if st.Name == "stop_stack" || st.Name == "run_cli_restore_commit" || strings.Contains(st.Name, "restore") {
			t.Errorf("apply must NEVER auto-trigger a data restore; found stage %q", st.Name)
		}
	}
}
