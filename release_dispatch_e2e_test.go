package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type e2eCatalogProvider struct{ cat *Catalog }

func (p e2eCatalogProvider) GetCatalog() *Catalog { return p.cat }

type e2eMaintAgent struct {
	mu            sync.Mutex
	srv           *httptest.Server
	running       []string
	opID          string
	opState       string
	statusCode    int
	successDigest bool
	applyRefs     []string
	paths         []string
	holdOp        chan struct{}
}

func newE2EMaintAgent(t *testing.T, running []string) *e2eMaintAgent {
	t.Helper()
	a := &e2eMaintAgent{
		running:       append([]string(nil), running...),
		opID:          "op-catalog-e2e",
		opState:       agentStateSucceeded,
		successDigest: true,
	}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serveHTTP))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *e2eMaintAgent) serveHTTP(w http.ResponseWriter, r *http.Request) {
	a.recordPath(r)

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
		a.serveStatus(w)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/upgrades/apply":
		a.serveApply(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/operations/"+a.opID:
		a.serveOperation(w, r)
	default:
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
	}
}

func (a *e2eMaintAgent) recordPath(r *http.Request) {
	a.mu.Lock()
	a.paths = append(a.paths, r.Method+" "+r.URL.Path)
	a.mu.Unlock()
}

func (a *e2eMaintAgent) serveStatus(w http.ResponseWriter) {
	a.mu.Lock()
	code := a.statusCode
	running := append([]string(nil), a.running...)
	a.mu.Unlock()
	if code != 0 {
		http.Error(w, `{"error":"status_failed"}`, code)
		return
	}
	e2eWriteJSON(w, http.StatusOK, map[string]any{
		"running_image": map[string]any{"repo_digests": running},
	})
}

func (a *e2eMaintAgent) serveApply(w http.ResponseWriter, r *http.Request) {
	var req UpgradeApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ImageRef == "" {
		http.Error(w, `{"error":"bad_apply_request"}`, http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	a.applyRefs = append(a.applyRefs, req.ImageRef)
	a.mu.Unlock()
	e2eWriteJSON(w, http.StatusAccepted, map[string]string{"op_id": a.opID})
}

func (a *e2eMaintAgent) serveOperation(w http.ResponseWriter, r *http.Request) {
	if !a.waitOperationHold(r) {
		return
	}

	a.mu.Lock()
	state := a.opState
	if state == agentStateSucceeded && a.successDigest && len(a.applyRefs) > 0 {
		a.running = []string{a.applyRefs[len(a.applyRefs)-1]}
	}
	a.mu.Unlock()
	e2eWriteJSON(w, http.StatusOK, map[string]string{"state": state})
}

func (a *e2eMaintAgent) waitOperationHold(r *http.Request) bool {
	a.mu.Lock()
	hold := a.holdOp
	a.mu.Unlock()
	if hold == nil {
		return true
	}
	select {
	case <-hold:
		return true
	case <-r.Context().Done():
		return false
	}
}

func (a *e2eMaintAgent) endpoint() AgentEndpoint {
	return AgentEndpoint{Key: localAgentKey, BaseURL: a.srv.URL, Client: a.srv.Client()}
}

func (a *e2eMaintAgent) appliedRefs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.applyRefs...)
}

func (a *e2eMaintAgent) runningDigests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.running...)
}

func (a *e2eMaintAgent) pathLog() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.paths, "\n")
}

func (a *e2eMaintAgent) setSuccessDigest(ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.successDigest = ok
}

func (a *e2eMaintAgent) setStatusCode(code int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.statusCode = code
}

func (a *e2eMaintAgent) holdOperations() chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.holdOp = make(chan struct{})
	return a.holdOp
}

func installE2EReleaseManager(t *testing.T, cat *Catalog, agent *e2eMaintAgent) *releaseManager {
	return installE2EReleaseManagerWithProxy(t, cat, agent, repo)
}

func installE2EReleaseManagerWithProxy(t *testing.T, cat *Catalog, agent *e2eMaintAgent, proxyRepo string) *releaseManager {
	t.Helper()
	svc, err := NewDispatchService(e2eCatalogProvider{cat: cat}, DispatchConfig{ProxyRepo: proxyRepo})
	if err != nil {
		t.Fatalf("NewDispatchService: %v", err)
	}
	svc.newClient = func(ep AgentEndpoint) (AgentClient, error) {
		c, err := NewHTTPAgentClient(ep.BaseURL, ep.Client)
		if err != nil {
			return nil, err
		}
		c.pollInterval = time.Millisecond
		return c, nil
	}
	svc.newOpID = func() string { return "E2E01" }
	resolve := func(key string) (AgentEndpoint, bool) {
		if agent != nil && key == localAgentKey {
			return agent.endpoint(), true
		}
		return AgentEndpoint{}, false
	}
	rm := newReleaseManager(svc, resolve)
	rm.newID = func() string { return "01K00000000000000000000000" }
	setReleaseManager(rm)
	t.Cleanup(func() { setReleaseManager(nil) })
	return rm
}

func e2eReleaseRequest(method, path string, body any, role UIRole) *http.Request {
	var rdr io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rdr)
	r.RemoteAddr = "192.0.2.44:1234"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
}

func e2eServeRelease(t *testing.T, mux *http.ServeMux, method, path string, body any, role UIRole) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, e2eReleaseRequest(method, path, body, role))
	return rec
}

func e2eDecodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d %q: %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

func e2eWaitTerminal(t *testing.T, rm *releaseManager) dispatchRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rec, ok := rm.store.get(localAgentKey)
		if ok && rec.Phase == phaseTerminal {
			return rec
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for terminal dispatch status for %s", localAgentKey)
	return dispatchRecord{}
}

func e2eWriteJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func TestE2E_ReleaseCatalogDispatchReplacesLegacyUpdater_WithPinnedDigest(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := newE2EMaintAgent(t, []string{repo + "@" + digB})
	rm := installE2EReleaseManager(t, cat, agent)
	mux := newE2EReleaseMux()

	assertE2EReleasesAvailable(t, mux)
	assertE2ECurrentRelease(t, mux, "rel_b")
	assertE2EDispatchAccepted(t, mux, "rel_a")
	assertE2ETerminalSucceeded(t, rm)
	assertE2EStatusSucceeded(t, mux)
	assertE2EAgentAppliedDigest(t, agent, repo+"@"+digA)
	assertE2ELegacyUpdaterNotUsed(t, agent)
}

func assertE2EReleasesAvailable(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	list := e2eServeRelease(t, mux, http.MethodGet, "/api/releases", nil, RoleViewer)
	if list.Code != http.StatusOK {
		t.Fatalf("GET /api/releases = %d: %s", list.Code, list.Body.String())
	}
	if got := e2eDecodeMap(t, list)["available"]; got != true {
		t.Fatalf("/api/releases available = %v; want true", got)
	}
}

func assertE2ECurrentRelease(t *testing.T, mux *http.ServeMux, wantRelease string) {
	t.Helper()
	cur := e2eServeRelease(t, mux, http.MethodGet, "/api/releases/current?agent=local", nil, RoleViewer)
	if cur.Code != http.StatusOK {
		t.Fatalf("GET /api/releases/current = %d: %s", cur.Code, cur.Body.String())
	}
	curDoc := e2eDecodeMap(t, cur)
	if curDoc["known"] != true || curDoc["release_id"] != wantRelease {
		t.Fatalf("current = %+v; want known %s", curDoc, wantRelease)
	}
}

func assertE2EDispatchAccepted(t *testing.T, mux *http.ServeMux, releaseID string) {
	t.Helper()
	dispatch := e2eServeRelease(t, mux, http.MethodPost, "/api/releases/dispatch", dispatchRequest{
		Agent:     localAgentKey,
		ReleaseID: releaseID,
	}, RoleAdmin)
	if dispatch.Code != http.StatusAccepted {
		t.Fatalf("POST /api/releases/dispatch = %d: %s", dispatch.Code, dispatch.Body.String())
	}
}

func assertE2ETerminalSucceeded(t *testing.T, rm *releaseManager) {
	t.Helper()
	terminal := e2eWaitTerminal(t, rm)
	if terminal.Terminal != TerminalSucceeded || !terminal.Verified {
		t.Fatalf("terminal = %+v; want succeeded and verified", terminal)
	}
}

func assertE2EStatusSucceeded(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	status := e2eServeRelease(t, mux, http.MethodGet, "/api/releases/dispatch/status?agent=local", nil, RoleViewer)
	if status.Code != http.StatusOK {
		t.Fatalf("GET /api/releases/dispatch/status = %d: %s", status.Code, status.Body.String())
	}
	statusDoc := e2eDecodeMap(t, status)
	if statusDoc["terminal"] != string(TerminalSucceeded) || statusDoc["verified"] != true {
		t.Fatalf("status = %+v; want terminal succeeded and verified", statusDoc)
	}
}

func assertE2EAgentAppliedDigest(t *testing.T, agent *e2eMaintAgent, wantDigest string) {
	t.Helper()
	applied := agent.appliedRefs()
	if len(applied) != 1 || applied[0] != wantDigest {
		t.Fatalf("agent applied refs = %v; want exactly catalog pinned digest", applied)
	}
	if strings.Contains(applied[0], ":latest") || !strings.Contains(applied[0], "@sha256:") {
		t.Fatalf("dispatch used a tag instead of repo@sha256 digest: %q", applied[0])
	}
	running := agent.runningDigests()
	if len(running) != 1 || running[0] != wantDigest {
		t.Fatalf("running_image.repo_digests = %v; want catalog pinned digest %s", running, wantDigest)
	}
}

func assertE2ELegacyUpdaterNotUsed(t *testing.T, agent *e2eMaintAgent) {
	t.Helper()
	paths := agent.pathLog()
	for _, want := range []string{"GET /v1/status", "POST /v1/upgrades/apply", "GET /v1/operations/" + agent.opID} {
		if !strings.Contains(paths, want) {
			t.Fatalf("maintenance-agent path log missing %q; paths:\n%s", want, paths)
		}
	}
	for _, forbidden := range []string{"/api/update/apply", "/api/update/preview", "/api/update/rollback", "/api/self-update", "docker.sock"} {
		if strings.Contains(paths, forbidden) {
			t.Fatalf("release catalog dispatch used legacy updater path %q; paths:\n%s", forbidden, paths)
		}
	}
}

func TestReleaseCatalogDispatch_E2ENegativeCases(t *testing.T) {
	t.Run("no catalog available false", testE2ENegativeNoCatalog)
	t.Run("unknown agent 404", testE2ENegativeUnknownAgent)
	t.Run("repo mismatch refused", testE2ENegativeRepoMismatch)
	t.Run("malformed pinned ref refused", testE2ENegativeMalformedPinnedRef)
	t.Run("agent unreachable 503", testE2ENegativeAgentUnreachable)
	t.Run("agent success digest mismatch failed needs attention", testE2ENegativeDigestMismatch)
	t.Run("concurrent dispatch rejected single flight", testE2ENegativeConcurrentDispatch)
	t.Run("control plane restart resume path", testE2ENegativeRestartResume)
}

func testE2ENegativeNoCatalog(t *testing.T) {
	t.Helper()
	installE2EReleaseManager(t, nil, newE2EMaintAgent(t, nil))
	mux := newE2EReleaseMux()
	rec := e2eServeRelease(t, mux, http.MethodGet, "/api/releases", nil, RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/releases = %d: %s", rec.Code, rec.Body.String())
	}
	if got := e2eDecodeMap(t, rec)["available"]; got != false {
		t.Fatalf("available = %v; want false", got)
	}
}

func testE2ENegativeUnknownAgent(t *testing.T) {
	t.Helper()
	installE2EReleaseManager(t, mustLoad(t, validSource()), newE2EMaintAgent(t, nil))
	mux := newE2EReleaseMux()
	rec := e2eServeRelease(t, mux, http.MethodGet, "/api/releases/current?agent=missing", nil, RoleViewer)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404 body=%s", rec.Code, rec.Body.String())
	}
}

func testE2ENegativeRepoMismatch(t *testing.T) {
	t.Helper()
	agent := newE2EMaintAgent(t, []string{repo + "@" + digB})
	installE2EReleaseManagerWithProxy(t, mustLoad(t, validSource()), agent, "ghcr.io/other/culvert")
	rec := e2eDispatchRelease(t, "rel_a")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 body=%s", rec.Code, rec.Body.String())
	}
}

func testE2ENegativeMalformedPinnedRef(t *testing.T) {
	t.Helper()
	cat := mustLoad(t, validSource())
	rel := cat.byReleaseID["rel_a"]
	rel.PinnedRef = repo + ":latest"
	cat.byReleaseID["rel_bad"] = rel
	installE2EReleaseManager(t, cat, newE2EMaintAgent(t, []string{repo + "@" + digB}))
	rec := e2eDispatchRelease(t, "rel_bad")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 body=%s", rec.Code, rec.Body.String())
	}
}

func testE2ENegativeAgentUnreachable(t *testing.T) {
	t.Helper()
	agent := newE2EMaintAgent(t, []string{repo + "@" + digB})
	agent.setStatusCode(http.StatusServiceUnavailable)
	installE2EReleaseManager(t, mustLoad(t, validSource()), agent)
	rec := e2eDispatchRelease(t, "rel_a")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503 body=%s", rec.Code, rec.Body.String())
	}
}

func testE2ENegativeDigestMismatch(t *testing.T) {
	t.Helper()
	agent := newE2EMaintAgent(t, []string{repo + "@" + digB})
	agent.setSuccessDigest(false)
	rm := installE2EReleaseManager(t, mustLoad(t, validSource()), agent)
	rec := e2eDispatchRelease(t, "rel_a")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("dispatch = %d: %s", rec.Code, rec.Body.String())
	}
	terminal := e2eWaitTerminal(t, rm)
	if terminal.Terminal != TerminalFailedNeedsAttn || terminal.Detail != "verify_mismatch" {
		t.Fatalf("terminal = %+v; want failed_needs_attn/verify_mismatch", terminal)
	}
}

func testE2ENegativeConcurrentDispatch(t *testing.T) {
	t.Helper()
	agent := newE2EMaintAgent(t, []string{repo + "@" + digB})
	hold := agent.holdOperations()
	installE2EReleaseManager(t, mustLoad(t, validSource()), agent)
	first := e2eDispatchRelease(t, "rel_a")
	if first.Code != http.StatusAccepted {
		t.Fatalf("first = %d: %s", first.Code, first.Body.String())
	}
	second := e2eDispatchRelease(t, "rel_a")
	close(hold)
	if second.Code != http.StatusConflict {
		t.Fatalf("second = %d; want 409 body=%s", second.Code, second.Body.String())
	}
}

func testE2ENegativeRestartResume(t *testing.T) {
	t.Helper()
	target := repo + "@" + digA
	agent := newE2EMaintAgent(t, []string{target})
	rm := installE2EReleaseManager(t, mustLoad(t, validSource()), agent)
	mux := newE2EReleaseMux()
	rc := DispatchResumeContext{
		AgentID:         localAgentKey,
		OpID:            agent.opID,
		ReleaseID:       "rel_a",
		VersionID:       "1.10.0",
		Severity:        SeverityCritical,
		TargetPinnedRef: target,
		ImageRef:        target,
		IdempotencyKey:  "rel-rel_a-E2E01",
	}
	resume := e2eServeRelease(t, mux, http.MethodPost, "/api/releases/dispatch/resume", resumeRequest{
		Agent: localAgentKey, ResumeContext: &rc,
	}, RoleAdmin)
	if resume.Code != http.StatusAccepted {
		t.Fatalf("resume = %d: %s", resume.Code, resume.Body.String())
	}
	terminal := e2eWaitTerminal(t, rm)
	if terminal.Terminal != TerminalSucceeded || !terminal.Verified {
		t.Fatalf("resumed terminal = %+v; want succeeded/verified", terminal)
	}
	if got := len(agent.appliedRefs()); got != 0 {
		t.Fatalf("resume must not apply; apply count = %d", got)
	}
}

func newE2EReleaseMux() *http.ServeMux {
	mux := http.NewServeMux()
	registerReleaseRoutes(mux)
	return mux
}

func e2eDispatchRelease(t *testing.T, releaseID string) *httptest.ResponseRecorder {
	t.Helper()
	return e2eServeRelease(t, newE2EReleaseMux(), http.MethodPost, "/api/releases/dispatch", dispatchRequest{
		Agent: localAgentKey, ReleaseID: releaseID,
	}, RoleAdmin)
}

func TestReleaseCatalogDispatch_CIGate_LegacyUpdaterNotRequiredOrCalled(t *testing.T) {
	for _, file := range []string{"release_api.go", "release_dispatch_exec.go", "release_dispatch_service.go", "release_wiring.go"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(b)
		for _, forbidden := range []string{
			"updaterRequest",
			"defaultUpdaterURL",
			"/api/update/apply",
			"/api/update/preview",
			"/api/update/rollback",
			"/api/self-update",
			"culvert-updater",
			"docker.sock",
			":7123",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s references legacy updater path %q", file, forbidden)
			}
		}
		if strings.Contains(text, `":latest"`) {
			t.Fatalf("%s must not dispatch tag refs; use catalog repo@sha256 pins only", file)
		}
	}
	execText, err := os.ReadFile(filepath.Join(pkgSourceDir(), "release_dispatch_exec.go"))
	if err != nil {
		t.Fatalf("read release_dispatch_exec.go: %v", err)
	}
	for _, required := range []string{`"/v1/status"`, `"/v1/upgrades/apply"`, `path.Join("/v1/operations", opID)`} {
		if !strings.Contains(string(execText), required) {
			t.Fatalf("release dispatch must use maintenance-agent endpoint %s", required)
		}
	}
	if _, err := os.Stat(filepath.Join(pkgSourceDir(), "release_dispatch_api.go")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale parallel release_dispatch_api.go should not exist; err=%v", err)
	}
}
