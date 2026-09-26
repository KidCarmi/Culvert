// Backup archive visibility (Enterprise Product Experience finding): a
// read-only admin surface for GET /v1/backups on the CP-local maintenance
// agent (see list_backups.go for the on-disk scan the agent shells out to,
// and cmd/culvert-maint/internal/server/handlers_d16b.go for the agent-side
// handler that already exists and is already validated/sanitized there).
//
// Today an admin can only learn "did last night's backup job actually
// produce a file, how big, how stale" by running
// `docker compose --profile cli run --rm cli --list-backups --backup-dir
// /backup` by hand, or by curling the agent's unix socket directly — both
// require SSH access to the host. This file adds no new agent capability
// (the endpoint already exists and is read-only); it only gives the CP admin
// GUI/API a way to reach it, matching the read pattern release_dispatch_exec.go
// / release_api.go already use to talk to the same maintenance agent.
//
// This file also gives the admin GUI a way to TRIGGER an on-demand backup
// (POST /api/backups) and poll it to completion (GET
// /api/backups/operations/{id}). D1.5 (roadmap/D1.5-docker-compose-operator-
// contract.md) documents backup creation as "runtime-OK" — safe to run at
// any time, no downtime required — yet the only way to run one today is the
// same `docker compose --profile cli run --rm cli --backup ...` SSH
// invocation used for listing. The maintenance agent already implements
// POST /v1/backups end to end (handleBackupCreate, handlers_d16b.go: input
// validation, idempotency, exclusive maintenance-lock serialization against
// a concurrent backup/restore/upgrade) and already reports operation
// progress via GET /v1/operations/{id}; both handlers below are thin,
// pass-through wrappers over that existing surface — no new agent
// capability, no change to what the agent is allowed to do.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// resolveLocalMaintAgentEndpoint reuses the SAME env var and default socket
// path Release Management resolves for its own agent client (envMaintAgentURL
// / defaultMaintAgentSocket / localAgentEndpoint, release_wiring.go) but is
// deliberately NOT gated on Release Management being configured — backup
// visibility must keep working even when catalog trust/verification is
// disabled, unconfigured, or in break-glass mode.
func resolveLocalMaintAgentEndpoint() (AgentEndpoint, bool) {
	raw := os.Getenv(envMaintAgentURL)
	if raw == "" {
		raw = defaultMaintAgentSocket
	}
	return localAgentEndpoint(raw)
}

// backupsAgentReadBound bounds the agent response read; a backup directory
// listing is small JSON (one entry per archive file).
const backupsAgentReadBound = 1 << 20 // 1 MiB

// fetchAgentBackups performs a GET /v1/backups against the maintenance agent
// and parses the response into the wire shape (backupListEntry,
// list_backups.go) the agent's --list-backups CLI already emits and the
// agent itself already shape-validates before returning it.
func fetchAgentBackups(ctx context.Context, ep AgentEndpoint) ([]backupListEntry, error) {
	u, err := url.Parse(ep.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse agent base URL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/backups"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	client := ep.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maintenance agent unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, backupsAgentReadBound))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maintenance agent returned HTTP %d", resp.StatusCode)
	}
	var entries []backupListEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse agent response: %w", err)
	}
	return entries, nil
}

func registerBackupsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/backups", apiBackups)
	mux.HandleFunc("/api/backups/operations/", apiBackupOperationStatus)
}

// backupsCache single-flights and briefly caches the agent listing. Every
// call below makes the maintenance agent spawn a `docker compose run --rm
// cli` container, and securityMiddleware rate-limits only mutating methods —
// so without this, any authenticated viewer holding refresh could spawn
// unbounded containers on the host (review P1). One fetch at a time (the
// mutex is held across the fetch: concurrent callers wait, then read the
// fresh result), and results — including failures, which would otherwise
// hammer a down agent — are served from cache inside the TTL.
var backupsCache struct {
	mu      sync.Mutex
	at      time.Time
	payload map[string]any
}

const backupsCacheTTL = 15 * time.Second

// apiBackups serves GET (viewer — list, unchanged) and POST (admin —
// trigger a new backup). The requireRole call for each verb stays directly
// in this switch, not in a delegated helper, so the C1.5 metadata/handler
// parity scanner can attribute MinRole per method with confidence instead
// of falling back to the MethodAny/"unknown" shape apiIdPRouter uses.
func apiBackups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		apiBackupsList(w, r)
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiBackupsCreate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiBackupsList answers "is my backup job actually working" from the GUI
// instead of SSHing in to run the CLI by hand. Newest-first so the question
// an admin actually has ("did the most recent backup happen") is the first
// row, not buried in a filename-sorted list. Caller has already checked
// RoleViewer.
func apiBackupsList(w http.ResponseWriter, r *http.Request) {
	backupsCache.mu.Lock()
	defer backupsCache.mu.Unlock()
	if backupsCache.payload != nil && time.Since(backupsCache.at) < backupsCacheTTL {
		jsonOK(w, backupsCache.payload)
		return
	}
	out := buildBackupsPayload(r.Context())
	backupsCache.payload, backupsCache.at = out, time.Now()
	jsonOK(w, out)
}

// buildBackupsPayload performs one agent listing and shapes the response.
// Agent-down and not-configured both answer 200 {available:false, reason} —
// the OpenAPI contract declares 200/403 only, and the GUI's api() helper
// throws on any non-2xx, which would blank the panel exactly while the
// operator is diagnosing the agent (review P2; mirrors the not-configured
// branch that already behaved this way).
func buildBackupsPayload(ctx context.Context) map[string]any {
	ep, ok := resolveLocalMaintAgentEndpoint()
	if !ok {
		return map[string]any{
			"available": false,
			"reason":    "maintenance agent not configured",
		}
	}
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	entries, err := fetchAgentBackups(fctx, ep)
	if err != nil {
		return map[string]any{
			"available": false,
			"reason":    err.Error(),
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ModifiedAt.After(entries[j].ModifiedAt) })
	out := map[string]any{
		"available": true,
		"count":     len(entries),
		"backups":   entries,
	}
	if len(entries) > 0 {
		out["newest_at"] = entries[0].ModifiedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// ─── POST /api/backups (backup.create trigger) ────────────────────────────

// backupCreateAgentRequest is the wire shape the agent's POST /v1/backups
// expects (handlers_d16b.go backupCreateRequest). PassphraseRef must be
// "env:NAME" — the agent resolves NAME from its own restricted environment
// (EnvAllow) at execution time; the secret value itself never crosses this
// API.
type backupCreateAgentRequest struct {
	Filename      string `json:"filename"`
	Encrypt       bool   `json:"encrypt"`
	PassphraseRef string `json:"passphrase_ref,omitempty"`
}

// backupCreateUIRequest is what the admin GUI sends: a bare env var NAME
// (matching the hint already shown on the Release Dispatch pre-backup
// field), never a secret value. apiBackupsCreate builds the "env:" prefix
// the agent requires so the GUI caller doesn't need to know that wire detail.
type backupCreateUIRequest struct {
	Encrypt          bool   `json:"encrypt"`
	PassphraseEnvVar string `json:"passphraseEnvVar,omitempty"`
}

// backupTriggerReadBound bounds the agent's create-op response (op_id / kind
// / state / deduped — a few hundred bytes of JSON).
const backupTriggerReadBound = 1 << 16

// backupCreateEnvVar validates that encrypt and passphraseEnvVar agree and
// returns the trimmed env var name, or a non-empty 400 message.
func backupCreateEnvVar(body backupCreateUIRequest) (envVar, errMsg string) {
	envVar = strings.TrimSpace(body.PassphraseEnvVar)
	switch {
	case body.Encrypt && envVar == "":
		return "", "encrypt requires passphraseEnvVar (the name of an env var the maintenance agent is allowed to read)"
	case !body.Encrypt && envVar != "":
		return "", "passphraseEnvVar must be omitted unless encrypt is true"
	}
	return envVar, ""
}

// backupArchiveName generates the on-demand archive filename. An encrypted
// archive is an AES-GCM blob, not gzip, so it carries the repository's
// *.tar.gz.enc convention (the agent's own pre-upgrade backups use it too) —
// tooling that selects by suffix must not mistake it for gzip.
func backupArchiveName(now time.Time, encrypt bool) string {
	suffix := ".tar.gz"
	if encrypt {
		suffix = ".tar.gz.enc"
	}
	return fmt.Sprintf("culvert-backup-%s-%06d%s", now.Format("20060102-150405"), now.Nanosecond()/1000, suffix)
}

// apiBackupsCreate triggers a new backup via the maintenance agent's
// existing POST /v1/backups and returns its op_id for polling. Caller has
// already checked RoleAdmin. Failure to reach or use the agent is reported
// as a non-2xx error (unlike apiBackupsList's 200-with-available:false
// shape) — this is a deliberate user action from a button click, not an
// auto-refreshing panel, so the GUI's normal fetch-error handling
// (try/catch → toast) is the right response.
func apiBackupsCreate(w http.ResponseWriter, r *http.Request) {
	var body backupCreateUIRequest
	if err := decodeJSON(r, &body); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	envVar, verr := backupCreateEnvVar(body)
	if verr != "" {
		http.Error(w, verr, http.StatusBadRequest)
		return
	}
	ep, ok := resolveLocalMaintAgentEndpoint()
	if !ok {
		http.Error(w, "maintenance agent not configured", http.StatusServiceUnavailable)
		return
	}
	filename := backupArchiveName(time.Now().UTC(), body.Encrypt)
	agentReq := backupCreateAgentRequest{Filename: filename, Encrypt: body.Encrypt}
	if envVar != "" {
		agentReq.PassphraseRef = "env:" + envVar
	}
	payload, err := json.Marshal(agentReq)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	fctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	status, data, err := callMaintAgent(fctx, ep, http.MethodPost, "/v1/backups", payload, backupTriggerReadBound)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	var opResp map[string]any
	_ = json.Unmarshal(data, &opResp)
	if status != http.StatusOK && status != http.StatusAccepted {
		reason := fmt.Sprintf("maintenance agent returned HTTP %d", status)
		if msg, ok := opResp["error"].(string); ok && msg != "" {
			reason = msg
		}
		http.Error(w, reason, http.StatusBadGateway)
		return
	}
	auditEvent(r, "backup.trigger", filename, fmt.Sprintf("encrypt=%v op_id=%v", body.Encrypt, opResp["op_id"]))
	// The listing is cached for backupsCacheTTL — drop it so the next GET
	// (e.g. right after this op reaches a terminal state) shows the new
	// archive instead of a stale pre-trigger snapshot.
	backupsCache.mu.Lock()
	backupsCache.payload = nil
	backupsCache.mu.Unlock()
	jsonOK(w, map[string]any{
		"triggered": true,
		"filename":  filename,
		"opId":      opResp["op_id"],
		"state":     opResp["state"],
		"deduped":   opResp["deduped"],
	})
}

// ─── GET /api/backups/operations/{id} (poll a triggered backup) ──────────

// backupOpIDRE accepts exactly the shape the agent's validOpID accepts — a
// canonical 26-character Crockford-base32 ULID (ulid.ParseStrict: no I/L/O/U,
// first character 0-7 so the 128-bit value cannot overflow). Matching the
// agent's contract here, rather than a looser alphanumeric bound, means a
// malformed id is answered 400 by the CP instead of reaching the agent,
// being rejected there, and surfacing as a misleading 502 upstream failure.
var backupOpIDRE = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}$`)

// backupOpKind is the agent's op kind for a backup this API can trigger
// (cmd/culvert-maint/internal/ops KindBackupCreate).
const backupOpKind = "backup.create"

// backupOpRecord is the subset of the agent's op record (ops.Op) this API
// inspects before passing the record through.
type backupOpRecord struct {
	Kind     string     `json:"kind"`
	State    string     `json:"state"`
	Finished *time.Time `json:"finished_at,omitempty"`
}

// terminal reports whether the op has reached a terminal state. Kept in step
// with cmd/culvert-maint/internal/ops State*.
func (op backupOpRecord) terminal() bool {
	switch op.State {
	case "succeeded", "failed", "cancelled":
		return true
	}
	return false
}

// apiBackupOperationStatus lets the GUI poll a triggered backup (or any
// other op_id the agent knows about) to a terminal state via the agent's
// existing GET /v1/operations/{id} — viewer role, matching apiBackupsList.
func apiBackupOperationStatus(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/backups/operations/")
	if !backupOpIDRE.MatchString(id) {
		http.Error(w, "invalid operation id", http.StatusBadRequest)
		return
	}
	ep, ok := resolveLocalMaintAgentEndpoint()
	if !ok {
		http.Error(w, "maintenance agent not configured", http.StatusServiceUnavailable)
		return
	}
	fctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	status, data, err := callMaintAgent(fctx, ep, http.MethodGet, "/v1/operations/"+url.PathEscape(id), nil, backupsAgentReadBound)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if status == http.StatusNotFound {
		http.Error(w, "operation not found", http.StatusNotFound)
		return
	}
	if status != http.StatusOK {
		http.Error(w, fmt.Sprintf("maintenance agent returned HTTP %d", status), http.StatusBadGateway)
		return
	}
	// The agent's operation endpoint is GLOBAL — it also answers upgrade and
	// restore ops, whose params/progress/result this viewer-role backup route
	// must not disclose. Anything that is not a backup op (or cannot be
	// decoded as one) is answered exactly like an unknown id.
	var op backupOpRecord
	if json.Unmarshal(data, &op) != nil || op.Kind != backupOpKind {
		http.Error(w, "operation not found", http.StatusNotFound)
		return
	}
	// A terminal op means the archive set may have changed since the listing
	// was cached — possibly re-cached by a Refresh WHILE the backup was still
	// running, which the trigger-time invalidation cannot cover. Drop it so
	// the GUI's completion refresh shows the new archive.
	//
	// Only a listing captured BEFORE the op finished is stale. Invalidating on
	// every terminal poll would let any viewer holding a completed op id
	// alternate status/listing GETs and defeat the 15 s cache that bounds how
	// often the agent spawns a listing container. The agent is node-local, so
	// its finished_at and this process's cache stamp share one clock; a
	// terminal record without finished_at invalidates nothing (the TTL still
	// bounds staleness).
	if op.terminal() && op.Finished != nil {
		backupsCache.mu.Lock()
		if backupsCache.payload != nil && backupsCache.at.Before(*op.Finished) {
			backupsCache.payload = nil
		}
		backupsCache.mu.Unlock()
	}
	// Pass the agent's op record through verbatim (op_id/kind/state/actor/
	// started_at/finished_at/failure_reason/params/progress, ops.Op) — params
	// only ever carries filename/encrypt/passphrase_ref (an env var NAME,
	// never a secret value), and the agent already shape-validated this JSON
	// before answering it on its own GET /v1/operations/{id}.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// callMaintAgent performs one request against the maintenance agent's local
// endpoint and returns the raw status + body, bounded by readBound. Shared
// by every backups_api.go handler that talks to the agent (fetchAgentBackups
// predates this helper and is left as-is to keep this change scoped).
func callMaintAgent(ctx context.Context, ep AgentEndpoint, method, path string, body []byte, readBound int64) (status int, data []byte, err error) {
	u, err := url.Parse(ep.BaseURL)
	if err != nil {
		return 0, nil, fmt.Errorf("parse agent base URL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := ep.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("maintenance agent unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err = io.ReadAll(io.LimitReader(resp.Body, readBound))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, data, nil
}
