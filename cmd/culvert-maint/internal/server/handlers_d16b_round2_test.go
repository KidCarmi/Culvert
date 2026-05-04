package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// ─── Item #1+#12: admission-time failures expose op_id + audit ────

// When buildStages fails (late validation, e.g. missing env on a
// non-deduped op), the response MUST carry the op_id + state="failed"
// so the operator can fetch /v1/operations/{id} for diagnostics.
func TestBackupCreate_BuildStagesFailureSurfacesOpID(t *testing.T) {
	rig := startD16bRig(t)
	defer rig.stop()

	// New idempotency_key — guarantees BeginIdempotent admits a
	// fresh op (so buildStages will run). With no env var set,
	// readPassphraseFromEnv inside buildStages returns an error.
	if err := os.Unsetenv(runner.EnvCulvertBackupPassphrase); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}
	status, body := rig.post(t, "/v1/backups", map[string]interface{}{
		"filename":        "x.enc",
		"encrypt":         true,
		"passphrase_ref":  "env:CULVERT_BACKUP_PASSPHRASE",
		"idempotency_key": "fresh-key-buildfail",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status: got %d body=%s", status, body)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["op_id"].(string)
	if opID == "" {
		t.Fatalf("admission-failure response MUST carry op_id; got %s", body)
	}
	if resp["state"] != "failed" {
		t.Errorf("response should include state=failed; got %v", resp["state"])
	}
	// op MUST be retrievable via /v1/operations/{id}.
	statusGet, opBody := rig.get(t, "/v1/operations/"+opID)
	if statusGet != http.StatusOK {
		t.Fatalf("GET /v1/operations/%s: got %d body=%s", opID, statusGet, opBody)
	}
	var op map[string]interface{}
	_ = json.Unmarshal(opBody, &op)
	if op["state"] != "failed" {
		t.Errorf("op record state: got %v want failed", op["state"])
	}
	if op["failure_reason"] != "validation" {
		t.Errorf("op record failure_reason: got %v want validation", op["failure_reason"])
	}
	// Audit jsonl MUST contain the started+failed pair for this op.
	auditBody, _ := os.ReadFile(rig.auditPath) //nolint:gosec // test path
	if !strings.Contains(string(auditBody), `"op_id":"`+opID+`"`) {
		t.Errorf("audit must contain events for op_id %s; got\n%s", opID, auditBody)
	}
	if !strings.Contains(string(auditBody), `"outcome":"started"`) {
		t.Errorf("audit must contain started event; got\n%s", auditBody)
	}
	if !strings.Contains(string(auditBody), `"outcome":"failed"`) {
		t.Errorf("audit must contain failed event; got\n%s", auditBody)
	}
}

// ─── Item #5: GET /v1/backups validates entry shape ──────────────

// d16bRigWithListJSON returns a rig whose fake exec injects the given
// JSON bytes for any --list-backups invocation.
func d16bRigWithListJSON(t *testing.T, listJSON string) *d16bTestRig {
	t.Helper()
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "agent.sock")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	al, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	pol, _ := auth.NewPolicy([]string{strconv.Itoa(os.Geteuid())})
	cfg := &config.Config{
		ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml",
		SocketPath: sockPath, StateDir: tmp,
		PrivilegeMode:    config.PrivilegeSudoers,
		AllowedBackupDir: "/backup",
		StageTimeout:     5 * time.Second,
		OperationTimeout: 30 * time.Second,
	}
	r, _ := runner.New(runner.Options{
		ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml",
		StageTimeout: 5 * time.Second,
		EnvAllow:     []string{runner.EnvCulvertBackupPassphrase},
		DockerBinary: "/usr/bin/docker",
	})
	r.SetExecHooksForTest(
		func(cmd *exec.Cmd) error {
			if isListBackupsArgv(cmd.Args) {
				_, _ = cmd.Stdout.Write([]byte(listJSON))
			}
			return nil
		},
		func(_ *exec.Cmd) error { return nil },
	)
	mgr := ops.NewManager(nil)
	srv, _ := New(Options{
		Cfg: cfg, Auth: pol, Audit: al, Ops: mgr, Status: &fakeStatus{},
		StateDir: tmp, AuditPath: auditPath, Runner: r,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	rig := &d16bTestRig{
		sockPath:  sockPath,
		stateDir:  tmp,
		auditPath: auditPath,
		captured:  &captured{},
	}
	rig.stop = func() {
		cancel()
		_ = srv.Close()
		_ = al.Close()
	}
	return rig
}

func TestBackupList_RejectsEmptyFilename(t *testing.T) {
	rig := d16bRigWithListJSON(t, `[{"filename":"","path":"/backup/x","size_bytes":1,"modified_at":"2026-05-04T00:00:00Z","encrypted":false}]`)
	defer rig.stop()
	status, body := rig.get(t, "/v1/backups")
	if status != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500; body=%s", status, body)
	}
	if !strings.Contains(string(body), "list_backups_invalid_entry") {
		t.Errorf("body must contain list_backups_invalid_entry: %s", body)
	}
}

func TestBackupList_RejectsPathOutsideBackupDir(t *testing.T) {
	rig := d16bRigWithListJSON(t, `[{"filename":"a.tar","path":"/etc/passwd","size_bytes":1,"modified_at":"2026-05-04T00:00:00Z","encrypted":false}]`)
	defer rig.stop()
	status, body := rig.get(t, "/v1/backups")
	if status != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500; body=%s", status, body)
	}
	if !strings.Contains(string(body), "list_backups_invalid_entry") {
		t.Errorf("body must contain list_backups_invalid_entry: %s", body)
	}
}

func TestBackupList_RejectsPathBasenameMismatch(t *testing.T) {
	// filename and path's basename disagree — a misbehaving cli
	// could hide the real path under a misleading filename.
	rig := d16bRigWithListJSON(t, `[{"filename":"a.tar","path":"/backup/b.tar","size_bytes":1,"modified_at":"2026-05-04T00:00:00Z","encrypted":false}]`)
	defer rig.stop()
	status, _ := rig.get(t, "/v1/backups")
	if status != http.StatusInternalServerError {
		t.Errorf("filename/path mismatch must produce 500; got %d", status)
	}
}

func TestBackupList_RejectsNegativeSize(t *testing.T) {
	rig := d16bRigWithListJSON(t, `[{"filename":"a.tar","path":"/backup/a.tar","size_bytes":-1,"modified_at":"2026-05-04T00:00:00Z","encrypted":false}]`)
	defer rig.stop()
	status, body := rig.get(t, "/v1/backups")
	if status != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500; body=%s", status, body)
	}
}

// Sanity: a fully valid JSON list passes through.
func TestBackupList_AcceptsValidEntries(t *testing.T) {
	rig := d16bRigWithListJSON(t, `[{"filename":"a.tar","path":"/backup/a.tar","size_bytes":123,"modified_at":"2026-05-04T00:00:00Z","encrypted":false}]`)
	defer rig.stop()
	status, body := rig.get(t, "/v1/backups")
	if status != http.StatusOK {
		t.Fatalf("got %d, want 200; body=%s", status, body)
	}
	var entries []map[string]interface{}
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 1 || entries[0]["filename"] != "a.tar" {
		t.Errorf("unexpected entries: %v", entries)
	}
}
