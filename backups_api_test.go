package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
	"time"
)

// generatedBackupFilenameRE matches apiBackupsCreate's server-generated
// filename shape (culvert-backup-YYYYMMDD-HHMMSS-<microseconds>.tar.gz).
var generatedBackupFilenameRE = regexp.MustCompile(`^culvert-backup-\d{8}-\d{6}-\d{6}\.tar\.gz$`)

// resetBackupsCache isolates the process-global listing cache per test.
func resetBackupsCache(t *testing.T) {
	t.Helper()
	backupsCache.mu.Lock()
	prevAt, prevPayload := backupsCache.at, backupsCache.payload
	backupsCache.at, backupsCache.payload = time.Time{}, nil
	backupsCache.mu.Unlock()
	t.Cleanup(func() {
		backupsCache.mu.Lock()
		backupsCache.at, backupsCache.payload = prevAt, prevPayload
		backupsCache.mu.Unlock()
	})
}

func callAPIBackups(t *testing.T) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/backups", http.NoBody)
	apiBackups(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON (%d): %s", w.Code, w.Body.String())
	}
	return w.Code, body
}

// TestAPIBackups_ListingIsSingleFlightedAndCached pins the review P1: every
// agent listing spawns a `docker compose run` container on the host and
// securityMiddleware rate-limits only mutating methods, so back-to-back
// viewer GETs must be served from the short cache — one agent round trip,
// not one container per refresh.
func TestAPIBackups_ListingIsSingleFlightedAndCached(t *testing.T) {
	resetBackupsCache(t)
	var hits atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`[{"name":"backup-1.tar.gz","size_bytes":42,"modified_at":"2026-08-20T01:00:00Z"}]`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	for i := 0; i < 3; i++ {
		code, body := callAPIBackups(t)
		if code != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200", i, code)
		}
		if body["available"] != true {
			t.Fatalf("call %d: available = %v, want true (body %v)", i, body["available"], body)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("agent hit %d times for 3 GETs inside the TTL, want exactly 1 (cache/single-flight lost)", got)
	}
}

// TestAPIBackups_AgentDownIsHTTP200Unavailable pins the review P2: the
// OpenAPI contract declares 200/403 only and the GUI's api() helper throws on
// any non-2xx (blanking the panel exactly while the operator diagnoses the
// agent), so agent-down must answer 200 {available:false} like the
// not-configured branch always did — never 503.
func TestAPIBackups_AgentDownIsHTTP200Unavailable(t *testing.T) {
	resetBackupsCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	agent.Close() // connection refused from here on
	t.Setenv(envMaintAgentURL, agent.URL)

	code, body := callAPIBackups(t)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with available:false", code)
	}
	if body["available"] != false {
		t.Fatalf("available = %v, want false (body %v)", body["available"], body)
	}
	if body["reason"] == "" || body["reason"] == nil {
		t.Fatal("reason missing — the operator needs the cause on the panel")
	}
}

// postAPIBackups drives POST /api/backups with the given role and JSON body
// (nil for no body).
func postAPIBackups(t *testing.T, role UIRole, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	ctx := context.WithValue(context.Background(), uiRoleKey{}, role)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/backups", reqBody)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	apiBackups(w, r)
	var parsed map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &parsed) // error bodies are plain text, not JSON
	return w, parsed
}

// TestAPIBackupsCreate_RequiresAdmin pins that triggering a backup — unlike
// listing them — is admin-only: a viewer POST must be refused with no call to
// the agent at all.
func TestAPIBackupsCreate_RequiresAdmin(t *testing.T) {
	resetBackupsCache(t)
	var hits atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w, _ := postAPIBackups(t, RoleViewer, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer POST: status = %d, want 403", w.Code)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("agent called %d times for a refused viewer POST, want 0", got)
	}
}

// TestAPIBackupsCreate_EncryptRequiresPassphraseEnvVar and its sibling below
// pin the request-shape validation that keeps the wire contract self-
// describing: encrypt and passphraseEnvVar must agree, rejected BEFORE any
// call reaches the agent (which would otherwise 400 for the same reason,
// after already spawning nothing — but the CP should say so first).
func TestAPIBackupsCreate_EncryptRequiresPassphraseEnvVar(t *testing.T) {
	resetBackupsCache(t)
	var hits atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w, _ := postAPIBackups(t, RoleAdmin, map[string]any{"encrypt": true})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("encrypt without passphraseEnvVar: status = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("agent called %d times for a rejected request, want 0", got)
	}
}

func TestAPIBackupsCreate_PassphraseEnvVarWithoutEncryptRejected(t *testing.T) {
	resetBackupsCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w, _ := postAPIBackups(t, RoleAdmin, map[string]any{"encrypt": false, "passphraseEnvVar": "CULVERT_BACKUP_PASSPHRASE"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("passphraseEnvVar without encrypt: status = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
}

// TestAPIBackupsCreate_NotConfigured pins that a missing agent answers a
// clear, non-2xx error for this deliberate button-click action — unlike the
// listing GET, which stays 200 so an auto-refreshing panel isn't blanked.
func TestAPIBackupsCreate_NotConfigured(t *testing.T) {
	resetBackupsCache(t)
	// A blank env var falls back to the default agent socket path, which
	// localAgentEndpoint still resolves (just unreachable in a test sandbox —
	// see TestAPIBackups_AgentDownIsHTTP200Unavailable's sibling case). To
	// exercise "not configured" (resolveLocalMaintAgentEndpoint's ok=false
	// branch) the value must fail localAgentEndpoint's own shape check.
	t.Setenv(envMaintAgentURL, "not-a-valid-endpoint")

	w, _ := postAPIBackups(t, RoleAdmin, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", w.Code, w.Body.String())
	}
}

// TestAPIBackupsCreate_Success drives the full happy path: the agent sees a
// generated, validator-shaped filename and no passphrase_ref for an
// unencrypted request; the handler reports triggered:true with the op fields;
// and a "backup.trigger" audit entry is recorded (content-matched per the
// audit-ring-saturation note in CLAUDE.md, not a length delta).
func TestAPIBackupsCreate_Success(t *testing.T) {
	resetBackupsCache(t)
	// Prime the listing cache so we can assert it gets invalidated by a
	// successful trigger (the next GET should re-hit the agent, not serve a
	// stale pre-trigger snapshot).
	backupsCache.mu.Lock()
	backupsCache.payload, backupsCache.at = map[string]any{"available": true, "count": 0}, time.Now()
	backupsCache.mu.Unlock()

	var gotReq backupCreateAgentRequest
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/backups" {
			t.Errorf("unexpected agent call: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"op_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","kind":"backup.create","state":"pending","deduped":false}`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	baselineTS := time.Now().UnixMilli()
	req := httptest.NewRequest(http.MethodPost, "/api/backups", bytes.NewReader(nil))
	req.RemoteAddr = "198.51.100.60:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiBackups(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v (body=%s)", err, w.Body.String())
	}
	if body["triggered"] != true {
		t.Fatalf("triggered = %v, want true", body["triggered"])
	}
	if body["opId"] != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("opId = %v, want the agent's op_id", body["opId"])
	}
	filename, _ := body["filename"].(string)
	if !generatedBackupFilenameRE.MatchString(filename) {
		t.Fatalf("filename %q does not look server-generated", filename)
	}
	if gotReq.Filename != filename {
		t.Fatalf("agent saw filename %q, response said %q", gotReq.Filename, filename)
	}
	if gotReq.Encrypt {
		t.Fatalf("agent request Encrypt = true for an unencrypted trigger")
	}
	if gotReq.PassphraseRef != "" {
		t.Fatalf("agent request PassphraseRef = %q, want empty for an unencrypted trigger", gotReq.PassphraseRef)
	}
	if !hasMatchingAuditEntry(auditGet(), "198.51.100.60", "backup.trigger", filename, baselineTS) {
		t.Fatalf("no audit entry recorded with Actor=198.51.100.60 Action=backup.trigger Object=%q", filename)
	}
	backupsCache.mu.Lock()
	stillCached := backupsCache.payload != nil
	backupsCache.mu.Unlock()
	if stillCached {
		t.Fatal("listing cache was not invalidated by a successful trigger")
	}
}

// TestAPIBackupsCreate_EncryptSendsEnvPrefixedRef pins the "env:" prefix the
// agent's validatePassphraseRefShape requires — the GUI only ever sends a
// bare env var NAME, so the CP must build the wire shape itself rather than
// relying on every caller to know that convention (see the passphrase_ref
// note in backups_api.go).
func TestAPIBackupsCreate_EncryptSendsEnvPrefixedRef(t *testing.T) {
	resetBackupsCache(t)
	var gotReq backupCreateAgentRequest
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"op_id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","state":"pending"}`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w, _ := postAPIBackups(t, RoleAdmin, map[string]any{"encrypt": true, "passphraseEnvVar": "CULVERT_BACKUP_PASSPHRASE"})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if !gotReq.Encrypt {
		t.Fatal("agent request Encrypt = false, want true")
	}
	if gotReq.PassphraseRef != "env:CULVERT_BACKUP_PASSPHRASE" {
		t.Fatalf("agent request PassphraseRef = %q, want %q", gotReq.PassphraseRef, "env:CULVERT_BACKUP_PASSPHRASE")
	}
}

// TestAPIBackupsCreate_AgentRejectionIsPassedThrough pins that a deterministic
// agent-side rejection (e.g. an env var outside its EnvAllow) reaches the
// admin as a readable error rather than a generic failure.
func TestAPIBackupsCreate_AgentRejectionIsPassedThrough(t *testing.T) {
	resetBackupsCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"passphrase_ref: env name \"EVIL\" is not in the runner's EnvAllow"}`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w, _ := postAPIBackups(t, RoleAdmin, map[string]any{"encrypt": true, "passphraseEnvVar": "EVIL"})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body=%s)", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !bytes.Contains([]byte(got), []byte("EnvAllow")) {
		t.Fatalf("body = %q, want the agent's rejection reason surfaced", got)
	}
}

// getAPIBackupOperationStatus drives GET /api/backups/operations/{id}.
func getAPIBackupOperationStatus(t *testing.T, role UIRole, id string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, role)
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/backups/operations/"+id, http.NoBody)
	w := httptest.NewRecorder()
	apiBackupOperationStatus(w, r)
	return w
}

func TestAPIBackupOperationStatus_RequiresViewer(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w := getAPIBackupOperationStatus(t, RolePublic, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestAPIBackupOperationStatus_InvalidID(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("agent should not be called for a rejected id")
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w := getAPIBackupOperationStatus(t, RoleViewer, "..%2Fetc%2Fpasswd")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
}

func TestAPIBackupOperationStatus_NotConfigured(t *testing.T) {
	t.Setenv(envMaintAgentURL, "not-a-valid-endpoint")
	w := getAPIBackupOperationStatus(t, RoleViewer, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", w.Code, w.Body.String())
	}
}

func TestAPIBackupOperationStatus_NotFound(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"op_not_found"}`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w := getAPIBackupOperationStatus(t, RoleViewer, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%s)", w.Code, w.Body.String())
	}
}

// TestAPIBackupOperationStatus_PassesThroughAgentRecord pins that the CP does
// not reshape the agent's op record — the GUI's poller reads `state` and
// `failure_reason` straight off it.
func TestAPIBackupOperationStatus_PassesThroughAgentRecord(t *testing.T) {
	const opJSON = `{"op_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","kind":"backup.create","state":"succeeded","progress":[]}`
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/operations/01ARZ3NDEKTSV4RRFFQ69G5FAV" {
			t.Errorf("unexpected agent path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(opJSON))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	w := getAPIBackupOperationStatus(t, RoleViewer, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var got, want map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	_ = json.Unmarshal([]byte(opJSON), &want)
	if got["state"] != want["state"] || got["op_id"] != want["op_id"] {
		t.Fatalf("body = %s, want a verbatim pass-through of %s", w.Body.String(), opJSON)
	}
}
