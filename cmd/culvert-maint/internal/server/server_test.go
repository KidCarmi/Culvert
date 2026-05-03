package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/ops"
)

// fakeStatus is a StatusProvider that returns a fixed Status; used so
// the server tests don't depend on the runner / docker-compose layer.
type fakeStatus struct {
	st  Status
	err error
}

func (f *fakeStatus) Snapshot(_ context.Context) (Status, error) {
	return f.st, f.err
}

// startTestServer boots the agent server on a temp UDS, allowing only
// the current process UID. Returns the socket path and a cleanup fn.
func startTestServer(t *testing.T, status StatusProvider, mgr *ops.Manager, auditPath string) (sockPath string, stop func()) {
	t.Helper()
	tmp := t.TempDir()
	sockPath = filepath.Join(tmp, "agent.sock")

	if auditPath == "" {
		auditPath = filepath.Join(tmp, "audit.jsonl")
	}
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
	}
	if mgr == nil {
		mgr = ops.NewManager(nil)
	}

	srv, err := New(Options{
		Cfg:       cfg,
		Auth:      pol,
		Audit:     al,
		Ops:       mgr,
		Status:    status,
		StateDir:  tmp,
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()

	// Wait for the socket to appear.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	stop = func() {
		cancel()
		_ = srv.Close()
		_ = al.Close()
	}
	return sockPath, stop
}

// udsClient returns an http.Client that dials the given UDS path.
func udsClient(sock string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
}

func TestSocketCreatedWithMode0660(t *testing.T) {
	sock, stop := startTestServer(t, &fakeStatus{}, nil, "")
	defer stop()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat sock: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o660 {
		t.Errorf("socket mode: got %o want 0660", mode)
	}
}

func TestListen_RefusesSymlinkAtSocketPath(t *testing.T) {
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "agent.sock")
	target := filepath.Join(tmp, "elsewhere")
	if err := os.WriteFile(target, []byte(""), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(target, sockPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := listen(sockPath); err == nil {
		t.Fatal("expected listen() to refuse a symlink at socket path")
	}
	// Symlink must remain — listen() must NOT remove it.
	if fi, err := os.Lstat(sockPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink unexpectedly modified or removed: fi=%v err=%v", fi, err)
	}
}

func TestListen_RefusesNonSocketRegularFileAtSocketPath(t *testing.T) {
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "agent.sock")
	if err := os.WriteFile(sockPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("seed regular file: %v", err)
	}
	if _, err := listen(sockPath); err == nil {
		t.Fatal("expected listen() to refuse non-socket file at socket path")
	}
	// Regular file must remain.
	if fi, err := os.Lstat(sockPath); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("regular file at socket path unexpectedly modified: fi=%v err=%v", fi, err)
	}
}

func TestHealthEndpoint(t *testing.T) {
	sock, stop := startTestServer(t, &fakeStatus{}, nil, "")
	defer stop()

	resp := mustGet(t, udsClient(sock), "http://unix/v1/health")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["status"] != "ok" {
		t.Errorf("body: %v", body)
	}
}

func TestStatusEndpoint_PassesThroughProvider(t *testing.T) {
	stub := &fakeStatus{
		st: Status{
			PrivilegeMode:  "sudoers",
			ComposeStackUp: true,
			ComposeServices: []ServiceStatus{
				{Name: "proxy", State: "running", Image: "ghcr.io/kidcarmi/culvert:latest"},
			},
		},
	}
	sock, stop := startTestServer(t, stub, nil, "")
	defer stop()

	resp := mustGet(t, udsClient(sock), "http://unix/v1/status")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["privilege_mode"] != "sudoers" {
		t.Errorf("privilege_mode: %v", body)
	}
	if body["compose_stack_up"] != true {
		t.Errorf("compose_stack_up: %v", body)
	}
	if body["agent_version"] == "" {
		t.Errorf("agent_version should be populated")
	}
}

func TestStatusEndpoint_DockerGroupLabSurfacesWarning(t *testing.T) {
	stub := &fakeStatus{
		st: Status{
			PrivilegeMode:    "docker_group_lab",
			PrivilegeWarning: "docker_group_lab is dev/lab only and effectively root-equivalent; not for production",
		},
	}
	sock, stop := startTestServer(t, stub, nil, "")
	defer stop()

	resp := mustGet(t, udsClient(sock), "http://unix/v1/status")
	defer func() { _ = resp.Body.Close() }()
	body := decodeJSON(t, resp.Body)
	pw, _ := body["privilege_warning"].(string)
	if !strings.Contains(pw, "root-equivalent") {
		t.Errorf("privilege_warning missing or weak: %q", pw)
	}
}

func TestAuditEndpoint_ReturnsRecentEvents(t *testing.T) {
	tmp := t.TempDir()
	ap := filepath.Join(tmp, "audit.jsonl")
	al, err := audit.New(ap)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for i := 0; i < 3; i++ {
		_ = al.Write(audit.Event{
			Actor:   "uid=0,user=test",
			OpID:    "01J0X3F00000000000000000" + strconv.Itoa(i)[:1],
			Kind:    "test.kind",
			Outcome: audit.OutcomeStarted,
		})
	}
	_ = al.Close()

	sock, stop := startTestServer(t, &fakeStatus{}, nil, ap)
	defer stop()

	resp := mustGet(t, udsClient(sock), "http://unix/v1/audit?limit=2")
	defer func() { _ = resp.Body.Close() }()
	body := decodeJSON(t, resp.Body)
	count, _ := body["count"].(float64)
	if int(count) != 2 {
		t.Errorf("count: got %v want 2", count)
	}
}

func TestOperationsEndpoint_GetUnknownReturns404(t *testing.T) {
	sock, stop := startTestServer(t, &fakeStatus{}, nil, "")
	defer stop()

	// Use a syntactically valid ULID (26 alnum chars) that doesn't exist.
	resp := mustGet(t, udsClient(sock), "http://unix/v1/operations/01ABCDEFGHJKMNPQRSTVWXYZ12")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 404 {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

func TestOperationsEndpoint_RejectsInvalidOpID(t *testing.T) {
	sock, stop := startTestServer(t, &fakeStatus{}, nil, "")
	defer stop()

	// Path-injection attempt + obviously-invalid ID.
	resp := mustGet(t, udsClient(sock), "http://unix/v1/operations/..%2Fetc")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for bad op_id, got %d", resp.StatusCode)
	}
}

func TestOperationsEndpoint_GetReturnsKnownOp(t *testing.T) {
	mgr := ops.NewManager(nil)
	op, err := mgr.Begin("backup.create", "test-actor", "", nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	sock, stop := startTestServer(t, &fakeStatus{}, mgr, "")
	defer stop()

	resp := mustGet(t, udsClient(sock), "http://unix/v1/operations/"+op.ID)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["op_id"] != op.ID {
		t.Errorf("op_id: got %v want %s", body["op_id"], op.ID)
	}
}

func TestOperationsLogsEndpoint_404WhenMissing(t *testing.T) {
	sock, stop := startTestServer(t, &fakeStatus{}, nil, "")
	defer stop()

	resp := mustGet(t, udsClient(sock), "http://unix/v1/operations/01ABCDEFGHJKMNPQRSTVWXYZ12/logs")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 404 {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

// TestFutureEndpointsReturn404 — every D1.6b/c path must 404 in D1.6a.
func TestFutureEndpointsReturn404(t *testing.T) {
	sock, stop := startTestServer(t, &fakeStatus{}, nil, "")
	defer stop()

	cli := udsClient(sock)
	for _, path := range []string{
		"/v1/backups",
		"/v1/restores/dryrun",
		"/v1/restores/commit",
		"/v1/cleanups",
		"/v1/upgrades/check",
		"/v1/upgrades/apply",
		"/v1/rollbacks",
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://unix"+path, strings.NewReader(`{}`))
		resp, err := cli.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("POST %s: got %d want 404", path, resp.StatusCode)
		}
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	sock, stop := startTestServer(t, &fakeStatus{}, nil, "")
	defer stop()

	resp := mustGet(t, udsClient(sock), "http://unix/v1/whatever")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 404 {
		t.Errorf("status: got %d want 404", resp.StatusCode)
	}
}

func TestAuthGate_RejectsForeignPeer(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "agent.sock")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	al, _ := audit.New(auditPath)
	defer func() { _ = al.Close() }()

	// Allowlist a UID that is NOT us.
	foreignUID := os.Geteuid() + 1
	pol, err := auth.NewPolicy([]string{strconv.Itoa(foreignUID)})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	cfg := &config.Config{
		ComposeProjectDir: tmp,
		ComposeFile:       "docker-compose.yml",
		SocketPath:        sock,
		StateDir:          tmp,
		PrivilegeMode:     config.PrivilegeSudoers,
	}
	mgr := ops.NewManager(nil)
	srv, err := New(Options{
		Cfg:       cfg,
		Auth:      pol,
		Audit:     al,
		Ops:       mgr,
		Status:    &fakeStatus{},
		StateDir:  tmp,
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	defer func() { _ = srv.Close() }()

	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	resp, err := udsClient(sock).Get("http://unix/v1/health") //nolint:noctx // test-controlled call
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 403 {
		t.Errorf("status: got %d want 403 (ours=%d, allowlist=%d)", resp.StatusCode, os.Geteuid(), foreignUID)
	}
}

func TestNew_FailsClosedOnMissingDeps(t *testing.T) {
	cases := []Options{
		{},
		{Cfg: &config.Config{}},
		{Cfg: &config.Config{}, Auth: &auth.Policy{}},
	}
	for i, c := range cases {
		_, err := New(c)
		if err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────

func mustGet(t *testing.T, cli *http.Client, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Get %s: %v", url, err)
	}
	return resp
}

func decodeJSON(t *testing.T, r io.Reader) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.NewDecoder(r).Decode(&out); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("decode JSON: %v", err)
	}
	return out
}
