// Integration tests for POST /v1/upgrades/check. Each test boots a real
// *server.Server on a temp UDS with a real *runner.Runner whose exec
// layer is faked: the fake captures argv/env and can emit canned stdout
// per command so the digest-compare path is exercised without docker.
//
// This file uses its own rig (not the backup/restore rig) so the
// upgrade-check wiring — image_allowlist policy, argv-safety shape, the
// two inspect templates, and the read-only op flow — is covered in
// isolation.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// upgradeRig is a wired test server whose fake runner emits per-command
// stdout and can be told to fail a command by argv substring.
type upgradeRig struct {
	sockPath  string
	stateDir  string
	auditPath string

	mu       sync.Mutex
	captured [][]string
	// stdoutFor maps an argv substring → canned stdout for any command
	// whose argv contains that substring.
	stdoutFor map[string][]byte
	// failFor is the set of argv substrings whose command should exit
	// non-zero.
	failFor []string

	stop func()
}

func (r *upgradeRig) snapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.captured))
	copy(out, r.captured)
	return out
}

func (r *upgradeRig) shouldFail(argv []string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sub := range r.failFor {
		for _, a := range argv {
			if strings.Contains(a, sub) {
				return true
			}
		}
	}
	return false
}

func (r *upgradeRig) cannedStdout(argv []string) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	for sub, out := range r.stdoutFor {
		for _, a := range argv {
			if strings.Contains(a, sub) {
				return out
			}
		}
	}
	return nil
}

//nolint:funlen // test rig setup; splitting hides the wiring sequence
func startUpgradeRig(t *testing.T) *upgradeRig {
	t.Helper()
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "agent.sock")
	auditPath := filepath.Join(tmp, "audit.jsonl")

	al, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	pol, err := auth.NewPolicy([]string{strconv.Itoa(os.Geteuid())})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	cfg := &config.Config{
		ComposeProjectDir: tmp,
		ComposeFile:       "docker-compose.yml",
		SocketPath:        sockPath,
		StateDir:          tmp,
		PrivilegeMode:     config.PrivilegeSudoers,
		AllowedBackupDir:  "/backup",
		StageTimeout:      5 * time.Second,
		OperationTimeout:  30 * time.Second,
		ImageAllowlist:    regexp.MustCompile(`^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`),
	}

	r, err := runner.New(runner.Options{
		ComposeProjectDir: tmp,
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      5 * time.Second,
		EnvAllow:          []string{runner.EnvCulvertBackupPassphrase},
		DockerBinary:      "/usr/bin/docker",
	})
	if err != nil {
		t.Fatalf("runner: %v", err)
	}

	rig := &upgradeRig{
		sockPath:  sockPath,
		stateDir:  tmp,
		auditPath: auditPath,
		stdoutFor: map[string][]byte{},
	}

	r.SetExecHooksForTest(
		func(cmd *exec.Cmd) error {
			rig.mu.Lock()
			rig.captured = append(rig.captured, append([]string(nil), cmd.Args...))
			rig.mu.Unlock()
			if out := rig.cannedStdout(cmd.Args); out != nil {
				_, _ = cmd.Stdout.Write(out)
			}
			return nil
		},
		func(cmd *exec.Cmd) error {
			if rig.shouldFail(cmd.Args) {
				return errors.New("simulated non-zero exit")
			}
			return nil
		},
	)

	mgr := ops.NewManager(nil)
	srv, err := New(Options{
		Cfg:       cfg,
		Auth:      pol,
		Audit:     al,
		Ops:       mgr,
		Status:    &fakeStatus{},
		StateDir:  tmp,
		AuditPath: auditPath,
		Runner:    r,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	for i := 0; i < 50; i++ {
		if _, statErr := os.Stat(sockPath); statErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	rig.stop = func() {
		cancel()
		_ = srv.Close()
		_ = al.Close()
	}
	return rig
}

func (r *upgradeRig) post(t *testing.T, body interface{}) (status int, respBody []byte) {
	t.Helper()
	cli := udsClient(r.sockPath)
	bodyBytes, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://unix/v1/upgrades/check", strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/upgrades/check: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// waitOp polls /v1/operations/{id} until terminal. Reuses pollOpOnce
// (defined alongside the backup/restore rig in the same package).
func (r *upgradeRig) waitOp(t *testing.T, opID string) map[string]interface{} {
	t.Helper()
	cli := udsClient(r.sockPath)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if op := pollOpOnce(cli, opID); op != nil {
			return op
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("op %s did not finish within 5s", opID)
	return nil
}

func (r *upgradeRig) opLog(t *testing.T, opID string) string {
	t.Helper()
	body, _ := os.ReadFile(filepath.Join(r.stateDir, "operations", opID+".log")) //nolint:gosec // test path
	return string(body)
}

// ─── tests ──────────────────────────────────────────────────────────

func TestUpgradeCheck_HappyPath_UpToDate(t *testing.T) {
	rig := startUpgradeRig(t)
	defer rig.stop()

	const ref = "ghcr.io/kidcarmi/culvert:v1.2.3"
	// Both the registry manifest and the local image report digestA →
	// the digest sets intersect → up_to_date.
	rig.stdoutFor["manifest"] = []byte(`{"Descriptor":{"digest":"` + digestA + `"}}`)
	rig.stdoutFor["image"] = []byte(`[{"Id":"` + digestA + `","RepoDigests":["ghcr.io/kidcarmi/culvert@` + digestA + `"]}]`)

	status, body := rig.post(t, map[string]interface{}{"image_ref": ref})
	if status != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", status, body)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(body, &ack)
	if ack["kind"] != ops.KindUpgradeCheck {
		t.Errorf("kind: got %v want %q", ack["kind"], ops.KindUpgradeCheck)
	}
	opID, _ := ack["op_id"].(string)
	op := rig.waitOp(t, opID)
	if op["state"] != "succeeded" {
		t.Errorf("op state: got %v want succeeded; op=%+v", op["state"], op)
	}

	logStr := rig.opLog(t, opID)
	if !strings.Contains(logStr, "up_to_date=true") {
		t.Errorf("op-log must report up_to_date=true:\n%s", logStr)
	}

	// The image_ref must reach exec as a single argv token, with no
	// shell wrapper anywhere.
	cmds := rig.snapshot()
	refToken, sawSh := false, false
	for _, argv := range cmds {
		for _, a := range argv {
			if a == ref {
				refToken = true
			}
			if a == "sh" || a == "bash" || a == "-c" {
				sawSh = true
			}
		}
	}
	if !refToken {
		t.Errorf("image_ref must appear as a single argv token; cmds=%v", cmds)
	}
	if sawSh {
		t.Errorf("no command may be wrapped in a shell; cmds=%v", cmds)
	}
}

func TestUpgradeCheck_UpgradeAvailable(t *testing.T) {
	rig := startUpgradeRig(t)
	defer rig.stop()

	// Remote reports digestB, local has digestA → disjoint → not up to date.
	rig.stdoutFor["manifest"] = []byte(`{"Descriptor":{"digest":"` + digestB + `"}}`)
	rig.stdoutFor["image"] = []byte(`[{"RepoDigests":["ghcr.io/kidcarmi/culvert@` + digestA + `"]}]`)

	status, body := rig.post(t, map[string]interface{}{"image_ref": "ghcr.io/kidcarmi/culvert:v2"})
	if status != http.StatusAccepted {
		t.Fatalf("status: got %d body=%s", status, body)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(body, &ack)
	op := rig.waitOp(t, ack["op_id"].(string))
	if op["state"] != "succeeded" {
		t.Errorf("op state: got %v want succeeded", op["state"])
	}
	logStr := rig.opLog(t, ack["op_id"].(string))
	if !strings.Contains(logStr, "up_to_date=false") {
		t.Errorf("op-log must report up_to_date=false:\n%s", logStr)
	}
}

// A locally-absent image (image inspect exits non-zero) is a normal
// check outcome, not an op failure.
func TestUpgradeCheck_LocalImageAbsent_StillSucceeds(t *testing.T) {
	rig := startUpgradeRig(t)
	defer rig.stop()

	rig.stdoutFor["manifest"] = []byte(`{"Descriptor":{"digest":"` + digestA + `"}}`)
	rig.failFor = []string{"image"} // only `docker image inspect` carries the bare "image" token

	status, body := rig.post(t, map[string]interface{}{"image_ref": "ghcr.io/kidcarmi/culvert:v1"})
	if status != http.StatusAccepted {
		t.Fatalf("status: got %d body=%s", status, body)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(body, &ack)
	op := rig.waitOp(t, ack["op_id"].(string))
	if op["state"] != "succeeded" {
		t.Errorf("absent-local must NOT fail the op; got state=%v", op["state"])
	}
	logStr := rig.opLog(t, ack["op_id"].(string))
	if !strings.Contains(logStr, "local_present=false") {
		t.Errorf("op-log must report local_present=false:\n%s", logStr)
	}
}

// A registry lookup failure DOES fail the op — the operator's question
// could not be answered.
func TestUpgradeCheck_RemoteInspectFailure_FailsOp(t *testing.T) {
	rig := startUpgradeRig(t)
	defer rig.stop()
	rig.failFor = []string{"manifest"}

	status, body := rig.post(t, map[string]interface{}{"image_ref": "ghcr.io/kidcarmi/culvert:v1"})
	if status != http.StatusAccepted {
		t.Fatalf("status: got %d body=%s", status, body)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(body, &ack)
	op := rig.waitOp(t, ack["op_id"].(string))
	if op["state"] != "failed" {
		t.Errorf("op state: got %v want failed", op["state"])
	}
	if op["failure_reason"] != "command_error" {
		t.Errorf("failure_reason: got %v want command_error", op["failure_reason"])
	}
}

// Malformed image refs are rejected at the handler before any exec.
func TestUpgradeCheck_RejectsMalformedImageRef(t *testing.T) {
	rig := startUpgradeRig(t)
	defer rig.stop()
	for _, ref := range []string{"", "-rf", "ghcr.io/x;rm -rf /", "ghcr.io/x $(id)", "ghcr.io/x\nculvert"} {
		status, body := rig.post(t, map[string]interface{}{"image_ref": ref})
		if status != http.StatusBadRequest {
			t.Errorf("ref %q: got %d want 400; body=%s", ref, status, body)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if cmds := rig.snapshot(); len(cmds) != 0 {
		t.Errorf("a rejected ref must NOT reach the runner; cmds=%v", cmds)
	}
}

// A well-formed ref outside image_allowlist is rejected (policy gate).
func TestUpgradeCheck_RejectsRefOutsideAllowlist(t *testing.T) {
	rig := startUpgradeRig(t)
	defer rig.stop()
	for _, ref := range []string{"docker.io/library/alpine:latest", "ghcr.io/evil/culvert:v1", "registry.example.com/team/app:1.0"} {
		status, body := rig.post(t, map[string]interface{}{"image_ref": ref})
		if status != http.StatusBadRequest {
			t.Errorf("ref %q: got %d want 400; body=%s", ref, status, body)
		}
		if !strings.Contains(string(body), "image_allowlist") {
			t.Errorf("ref %q: 400 body should mention image_allowlist; got %s", ref, body)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if cmds := rig.snapshot(); len(cmds) != 0 {
		t.Errorf("a non-allowlisted ref must NOT reach the runner; cmds=%v", cmds)
	}
}

func TestUpgradeCheck_IdempotencyDedup(t *testing.T) {
	rig := startUpgradeRig(t)
	defer rig.stop()
	rig.stdoutFor["manifest"] = []byte(`{"Descriptor":{"digest":"` + digestA + `"}}`)

	body := map[string]interface{}{
		"image_ref":       "ghcr.io/kidcarmi/culvert:v1",
		"idempotency_key": "check-key-1",
	}
	s1, b1 := rig.post(t, body)
	s2, b2 := rig.post(t, body)
	if s1 != http.StatusAccepted {
		t.Fatalf("first: %d %s", s1, b1)
	}
	if s2 != http.StatusOK {
		t.Errorf("second (deduped) should be 200; got %d body=%s", s2, b2)
	}
	var a1, a2 map[string]interface{}
	_ = json.Unmarshal(b1, &a1)
	_ = json.Unmarshal(b2, &a2)
	if a1["op_id"] != a2["op_id"] {
		t.Errorf("dedup must return same op_id; got %v vs %v", a1["op_id"], a2["op_id"])
	}
	if a2["deduped"] != true {
		t.Errorf("second response must be deduped=true: %s", b2)
	}
}

func TestUpgradeCheck_AuditEmitted(t *testing.T) {
	rig := startUpgradeRig(t)
	defer rig.stop()
	rig.stdoutFor["manifest"] = []byte(`{"Descriptor":{"digest":"` + digestA + `"}}`)

	status, body := rig.post(t, map[string]interface{}{"image_ref": "ghcr.io/kidcarmi/culvert:v9"})
	if status != http.StatusAccepted {
		t.Fatalf("status: got %d body=%s", status, body)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(body, &ack)
	rig.waitOp(t, ack["op_id"].(string))

	auditBody, _ := os.ReadFile(rig.auditPath) //nolint:gosec // test path
	auditStr := string(auditBody)
	for _, want := range []string{`"kind":"upgrades.check"`, `"image_ref":"ghcr.io/kidcarmi/culvert:v9"`, `"outcome":"started"`, `"outcome":"succeeded"`} {
		if !strings.Contains(auditStr, want) {
			t.Errorf("audit jsonl missing %q:\n%s", want, auditStr)
		}
	}
}
