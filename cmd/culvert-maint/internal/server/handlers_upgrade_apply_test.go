// Integration tests for POST /v1/upgrades/apply. Boots a real Server on a
// temp UDS with a real *runner.Runner whose exec layer is faked: canned
// stdout per docker command drives the capture/resolve/pull/restart/health
// flow without docker. A fake health client (200/503) drives the gate.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/health"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

const (
	digOld = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digNew = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cfgOld = "1111111111111111111111111111111111111111111111111111111111111111"
	cfgNew = "2222222222222222222222222222222222222222222222222222222222222222"
	repo   = "ghcr.io/kidcarmi/culvert"
)

// applyRig is a wired test server whose fake runner emits canned stdout
// per docker command and flips its "running image" view once a pull runs.
type applyRig struct {
	sockPath  string
	stateDir  string
	auditPath string
	journal   *journal.Journal // crash-recovery journal wired into the server (RISK-022)

	mu       sync.Mutex
	captured [][]string

	// targetDigest is what manifest inspect reports (the upgrade target).
	targetDigest string
	// before pull: capture reports digBefore; after pull: digAfter.
	digBefore string
	digAfter  string

	// runningDigest models the ACTUAL running image. It starts at
	// digBefore and is updated to the digest pinned via CULVERT_PROXY_IMAGE
	// on every `pull` — so a rollback that re-pins the prior digest flips
	// the running view back. Guarded by mu. (image inspect / health read it.)
	runningDigest string
	// unhealthyDigests: a running image whose bare digest is in this set
	// makes the fake health probe fail. Models "the new image is broken,
	// the prior one is fine." nil/empty → all healthy (unless healthFail).
	unhealthyDigests map[string]bool
	// noPriorDigest makes capture_before (before any pull) report an empty
	// RepoDigests list → no valid rollback target.
	noPriorDigest bool

	// localImages models the LOCAL image store for the local-first probe
	// (`docker image inspect <repo@sha256:…>`): nil ⇒ legacy behaviour (the
	// inspect answers from the running view, as the capture path expects);
	// non-nil ⇒ present iff the bare digest is in the set, absent ⇒ non-zero
	// exit. Keyed by bare digest.
	localImages map[string]bool
	// pinnedDigest is what `docker image inspect culvert/proxy:pinned`
	// resolves to (bare digest); "" ⇒ the tag is absent (inspect fails).
	pinnedDigest string
	// dockerDown makes EVERY docker command fail (daemon not up).
	dockerDown atomic.Bool
	// stackDown makes `compose ps` report no containers at all.
	stackDown atomic.Bool
	// blockUp, when non-nil, makes `compose up` block until it is closed.
	blockUp chan struct{}

	srv *Server
	mgr *ops.Manager

	pulled     atomic.Bool
	healthFail atomic.Bool
	failFor    []string
	// failFn, when set, fails any command for which it returns true,
	// given (argv, env). Lets a test fail ONLY the rollback pull/restart
	// (discriminated by the pinned digest in env).
	failFn func(argv, env []string) bool

	stop func()
}

func (r *applyRig) snapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.captured))
	copy(out, r.captured)
	return out
}

func (r *applyRig) sawCommand(token string) bool {
	for _, argv := range r.snapshot() {
		for _, a := range argv {
			if a == token {
				return true
			}
		}
	}
	return false
}

func (r *applyRig) shouldFail(argv []string) bool {
	for _, sub := range r.failFor {
		for _, a := range argv {
			if strings.Contains(a, sub) {
				return true
			}
		}
	}
	return false
}

// canned routes stdout by the docker command shape.
func (r *applyRig) canned(argv []string) []byte {
	has := func(tok string) bool {
		for _, a := range argv {
			if a == tok {
				return true
			}
		}
		return false
	}
	contains := func(sub string) bool {
		for _, a := range argv {
			if strings.Contains(a, sub) {
				return true
			}
		}
		return false
	}
	running := r.currentRunning()
	cfg := cfgOld
	if running != r.digBefore {
		cfg = cfgNew
	}
	switch {
	case has("ps"):
		if r.stackDown.Load() {
			return []byte(`[]`)
		}
		return []byte(`{"Service":"proxy","State":"running","ID":"abcdef012345"}`)
	case contains("{{json .Image}}"):
		return []byte(`"sha256:` + cfg + `"`)
	case has("manifest"):
		return []byte(`{"Descriptor":{"digest":"sha256:` + r.targetDigest + `"}}`)
	case has("image") && has("inspect"):
		ref := argv[len(argv)-1]
		if ref == runner.PinnedProxyTag {
			if r.pinnedDigest == "" {
				return nil
			}
			return []byte(`[{"Id":"sha256:` + r.cfgFor(r.pinnedDigest) + `","RepoDigests":["` + repo + `@sha256:` + r.pinnedDigest + `"]}]`)
		}
		if d := digestRE.FindString(ref); strings.Contains(ref, "@sha256:") && r.localImages != nil {
			bare := strings.TrimPrefix(d, "sha256:")
			if !r.localImages[bare] {
				return nil
			}
			return []byte(`[{"Id":"sha256:` + r.cfgFor(bare) + `","RepoDigests":["` + ref + `"]}]`)
		}
		if r.noPriorDigest && !r.pulled.Load() {
			return []byte(`[{"RepoDigests":[]}]`) // no rollback target available
		}
		return []byte(`[{"Id":"sha256:` + cfg + `","RepoDigests":["` + repo + `@sha256:` + running + `"]}]`)
	}
	return nil
}

// cfgFor maps a bare digest to the config digest the fake daemon reports for
// it (the "before" image is cfgOld, anything else cfgNew).
func (r *applyRig) cfgFor(digest string) string {
	if digest == r.digBefore {
		return cfgOld
	}
	return cfgNew
}

// inspectAbsent reports whether an image-inspect argv targets an image the
// fake store does not hold (the pinned tag when unset; a digest ref outside
// localImages when the local store is modelled).
func (r *applyRig) inspectAbsent(argv []string) bool {
	if len(argv) < 3 || !argvHas(argv, "image") || !argvHas(argv, "inspect") {
		return false
	}
	ref := argv[len(argv)-1]
	if ref == runner.PinnedProxyTag {
		return r.pinnedDigest == ""
	}
	if strings.Contains(ref, "@sha256:") && r.localImages != nil {
		return !r.localImages[strings.TrimPrefix(digestRE.FindString(ref), "sha256:")]
	}
	return false
}

// currentRunning returns the digest the fake stack is currently running.
func (r *applyRig) currentRunning() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.runningDigest == "" {
		return r.digBefore
	}
	return r.runningDigest
}

// setRunning records the digest carried in a `docker pull <repo@sha256:…>`
// argv as the new running image (called on each `pull`). P1.4: the pin is in
// the argv (the pulled ref), not an env var.
func (r *applyRig) setRunning(argv []string) {
	for _, a := range argv {
		if d := digestRE.FindString(a); d != "" {
			r.mu.Lock()
			r.runningDigest = strings.TrimPrefix(d, "sha256:")
			r.mu.Unlock()
			return
		}
	}
}

// countCommand counts captured commands whose argv contains token.
//
//nolint:unparam // generic test helper; current callers happen to pass "pull"
func (r *applyRig) countCommand(token string) int {
	n := 0
	for _, argv := range r.snapshot() {
		for _, a := range argv {
			if a == token {
				n++
				break
			}
		}
	}
	return n
}

func startApplyRig(t *testing.T) *applyRig {
	t.Helper()
	return startApplyRigAt(t, t.TempDir())
}

// startApplyRigAt boots the rig on an explicit state dir so a test can stop
// an agent and start a fresh one over the SAME on-disk state (journal,
// idempotency index), modelling an agent restart.
//
//nolint:funlen // test rig setup; splitting hides the wiring sequence
func startApplyRigAt(t *testing.T, tmp string) *applyRig {
	t.Helper()
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
		ProxyRepo:         repo, // config.Load always sets it; the reconcile trust gate is repo-bound
	}

	rig := &applyRig{
		sockPath:     sockPath,
		stateDir:     tmp,
		auditPath:    auditPath,
		targetDigest: digNew,
		digBefore:    digOld,
		digAfter:     digNew,
	}

	rn, err := runner.New(runner.Options{
		ComposeProjectDir: tmp,
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      5 * time.Second,
		ProxyRepo:         repo, // ghcr.io/kidcarmi/culvert (matches test refs)
		EnvAllow:          []string{runner.EnvCulvertBackupPassphrase},
		EnvOverlayOnly:    []string{runner.EnvCulvertBackupPassphrase},
		DockerBinary:      "/usr/bin/docker",
	})
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	rn.SetExecHooksForTest(rig.execStart, rig.execWait)

	mgr := ops.NewManager(nil)
	mgr.EnableIdempotencyPersistence(filepath.Join(tmp, "idempotency.json"))
	if _, lerr := mgr.LoadIdempotencyIndex(); lerr != nil {
		t.Fatalf("idempotency index: %v", lerr)
	}
	jnl, err := journal.New(tmp)
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	rig.journal = jnl
	rig.mgr = mgr
	srv, err := New(Options{
		Cfg:       cfg,
		Auth:      pol,
		Audit:     al,
		Ops:       mgr,
		Status:    &fakeStatus{},
		StateDir:  tmp,
		AuditPath: auditPath,
		Runner:    rn,
		Journal:   jnl,
		HealthProbeFactory: func() health.Probe {
			baseURL, _ := url.Parse("http://127.0.0.1:8080")
			return health.Probe{
				BaseURL:        baseURL,
				HealthPath:     "/health",
				ReadyPath:      "/ready",
				Budget:         200 * time.Millisecond,
				PollInterval:   40 * time.Millisecond,
				RequestTimeout: 100 * time.Millisecond,
				Client:         applyHealthClient(rig),
			}
		},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	rig.srv = srv
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

// execStart is the fake exec START hook: records argv, emits the canned
// stdout, and honours blockUp.
func (r *applyRig) execStart(cmd *exec.Cmd) error {
	r.mu.Lock()
	r.captured = append(r.captured, append([]string(nil), cmd.Args...))
	r.mu.Unlock()
	if out := r.canned(cmd.Args); out != nil {
		_, _ = cmd.Stdout.Write(out)
	}
	if r.blockUp != nil && argvHas(cmd.Args, "up") {
		<-r.blockUp
	}
	return nil
}

// execWait is the fake exec WAIT hook: decides the exit status and, on
// success, moves the fake "running image" view.
func (r *applyRig) execWait(cmd *exec.Cmd) error {
	if r.dockerDown.Load() {
		return errors.New("simulated daemon down")
	}
	if r.inspectAbsent(cmd.Args) {
		return errors.New("simulated: no such image")
	}
	if r.failFn != nil && r.failFn(cmd.Args, cmd.Env) {
		return errors.New("simulated non-zero exit (failFn)")
	}
	if r.shouldFail(cmd.Args) {
		return errors.New("simulated non-zero exit")
	}
	// A SUCCESSFUL `docker pull <repo@sha256:…>` (or the `docker tag`
	// of a locally-present digest, which the local-first path reaches
	// with NO pull) re-pins the "running image" view from the ref in
	// argv (P1.4: the digest is in the argv, not an env var), so a
	// rollback that re-pins the prior digest flips the running view
	// back for later captures. A FAILED pull leaves it unchanged.
	for _, a := range cmd.Args {
		if a == "pull" {
			r.pulled.Store(true)
			r.setRunning(cmd.Args)
		}
		if a == "tag" {
			r.setRunning(cmd.Args)
		}
	}
	return nil
}

func applyHealthClient(rig *applyRig) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			status := 200
			if rig.healthFail.Load() || rig.unhealthyDigests[rig.currentRunning()] {
				status = 503
			}
			return &http.Response{
				StatusCode: status,
				Status:     strconv.Itoa(status) + " test",
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
		Timeout: time.Second,
	}
}

func (r *applyRig) post(t *testing.T, body interface{}) (status int, respBody []byte) {
	t.Helper()
	cli := udsClient(r.sockPath)
	bodyBytes, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://unix/v1/upgrades/apply", strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/upgrades/apply: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, rb
}

func (r *applyRig) waitOp(t *testing.T, opID string) map[string]interface{} {
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

func (r *applyRig) opLog(t *testing.T, opID string) string {
	t.Helper()
	body, _ := os.ReadFile(filepath.Join(r.stateDir, "operations", opID+".log")) //nolint:gosec // test path
	return string(body)
}

func (r *applyRig) acceptAndWait(t *testing.T, body interface{}) (op map[string]interface{}, opID string) {
	t.Helper()
	status, rb := r.post(t, body)
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

// ─── tests ──────────────────────────────────────────────────────────

func TestUpgradeApply_Success_DigestRef(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()

	ref := repo + "@sha256:" + digNew
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": ref})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded; op=%+v", op["state"], op)
	}
	if !rig.sawCommand("pull") {
		t.Error("a real upgrade must run a pull")
	}
	if !rig.sawCommand("up") {
		t.Error("a real upgrade must restart the stack")
	}
	logStr := rig.opLog(t, opID)
	for _, want := range []string{"already_current=false", "running_digests=", "verify: running_image_id", digNew} {
		if !strings.Contains(logStr, want) {
			t.Errorf("op-log missing %q:\n%s", want, logStr)
		}
	}
}

// Regression: a TAG request must be resolved to a digest and the PIN
// (repo@sha256:<resolved>) — not the raw tag — must be what pull/up
// forward via CULVERT_PROXY_IMAGE.
func TestUpgradeApply_TagResolvedToDigest_PinsDigest(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()

	tag := repo + ":v1.2.4"
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": tag})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded; op=%+v", op["state"], op)
	}
	pinned := repo + "@sha256:" + digNew // manifest resolved the tag to digNew
	// P1.4: the resolved digest (not the raw tag) is what pull + tag carry
	// in their argv; `up` is plain (no digest, resolves culvert/proxy:pinned).
	if !rig.pinnedFor("pull", digNew) || !rig.pinnedFor("tag", digNew) {
		t.Errorf("pull + tag must carry the resolved digest %s in argv", digNew)
	}
	// The raw tag may appear ONLY in the read-only `manifest inspect`
	// (resolve step) — never in the state-changing pull/tag image ops.
	for _, argv := range rig.snapshot() {
		if (argvHas(argv, "pull") || argvHas(argv, "tag")) && envContains(argv, tag) {
			t.Errorf("pull/tag must carry the resolved digest, never the raw tag %q; argv=%v", tag, argv)
		}
	}
	if rig.pinnedFor("up", digNew) {
		t.Errorf("up must be plain compose up -d (no digest in argv)")
	}
	logStr := rig.opLog(t, opID)
	if !strings.Contains(logStr, `pinned_ref="`+pinned+`"`) {
		t.Errorf("op-log must record the resolved pinned_ref %q:\n%s", pinned, logStr)
	}
	if !strings.Contains(logStr, `requested_ref="`+tag+`"`) {
		t.Errorf("op-log must preserve the original requested_ref %q:\n%s", tag, logStr)
	}
}

// Running digest already equals the target → no-op success; no pull/up.
func TestUpgradeApply_AlreadyCurrent_NoOp(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.digBefore = digNew // already on the target

	ref := repo + "@sha256:" + digNew
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": ref})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded", op["state"])
	}
	if rig.sawCommand("pull") {
		t.Error("already-current must NOT pull")
	}
	if rig.sawCommand("up") {
		t.Error("already-current must NOT restart")
	}
	logStr := rig.opLog(t, opID)
	if !strings.Contains(logStr, "already_current=true") {
		t.Errorf("op-log must report already_current=true:\n%s", logStr)
	}
}

func TestUpgradeApply_RejectsInvalidRef(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	for _, ref := range []string{"", "-rf", "docker.io/library/alpine:latest", "ghcr.io/evil/culvert:v1"} {
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

// A pre_backup failure ABORTS before any pull/restart.
func TestUpgradeApply_PreBackupFailure_Aborts(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	t.Setenv(runner.EnvCulvertBackupPassphrase, "test-pass")
	rig.failFor = []string{"--encrypt"} // fail the encrypted backup

	ref := repo + "@sha256:" + digNew
	op, _ := rig.acceptAndWait(t, map[string]interface{}{
		"image_ref":      ref,
		"pre_backup":     true,
		"passphrase_ref": "env:" + runner.EnvCulvertBackupPassphrase,
	})
	if op["state"] != "failed" {
		t.Fatalf("state: got %v want failed", op["state"])
	}
	if op["failure_reason"] != "cli_error" {
		t.Errorf("failure_reason: got %v want cli_error", op["failure_reason"])
	}
	if rig.sawCommand("pull") {
		t.Error("a failed pre_backup must abort BEFORE pull")
	}
}

// rollback_on_failure=false: a health-gate failure fails the op with NO
// rollback attempted, even though a valid prior target exists.
func TestUpgradeApply_HealthFail_RollbackDisabled(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.healthFail.Store(true)

	ref := repo + "@sha256:" + digNew
	op, opID := rig.acceptAndWait(t, map[string]interface{}{
		"image_ref":           ref,
		"rollback_on_failure": false,
	})
	if op["state"] != "failed" {
		t.Fatalf("state: got %v want failed", op["state"])
	}
	if op["failure_reason"] != "health_failed" {
		t.Errorf("failure_reason: got %v want health_failed", op["failure_reason"])
	}
	res, _ := op["result"].(map[string]interface{})
	if res == nil || res["rollback_attempted"] != false || res["rollback_skipped_reason"] != "disabled" {
		t.Errorf("disabled rollback must record rollback_attempted=false skipped_reason=disabled; result=%v", res)
	}
	// Only the upgrade pulled; no second (rollback) pull.
	if n := rig.countCommand("pull"); n != 1 {
		t.Errorf("disabled rollback must not pull again; pull count=%d", n)
	}
	logStr := rig.opLog(t, opID)
	if !strings.Contains(logStr, "rollback_pull: skipped (disabled)") {
		t.Errorf("op-log should record the disabled-rollback skip:\n%s", logStr)
	}
}

func TestUpgradeApply_PreBackupRequiresPassphrase(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	status, body := rig.post(t, map[string]interface{}{
		"image_ref":  repo + "@sha256:" + digNew,
		"pre_backup": true,
	})
	if status != http.StatusBadRequest {
		t.Errorf("pre_backup without passphrase_ref: got %d want 400; body=%s", status, body)
	}
}
