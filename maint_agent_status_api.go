// Maintenance-agent health visibility (Enterprise Product Experience
// finding): a read-only admin surface for GET /v1/status on the CP-local
// maintenance agent (see cmd/culvert-maint/internal/server/server.go for the
// agent-side Status struct this reads from).
//
// The agent already reports its own version, privilege posture, and whether
// the proxy compose stack is actually up — release_dispatch_exec.go's
// RunningDigests fetches this same document today but keeps only
// running_image.repo_digests and discards the rest. Today an admin can only
// learn "is the agent healthy, what version, is the compose stack really up"
// by SSHing into the host and running `systemctl status culvert-maint` (the
// exact fallback docs/operator/release-management-agent.md documents for a
// "Maintenance agent unreachable" banner). This file adds no new agent
// capability (the endpoint already exists and is read-only); it only gives
// the CP admin GUI/API a way to reach the fields already in the response,
// matching the read pattern backups_api.go already uses for the same agent.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maintAgentStatusReadBound bounds the agent response read; /v1/status is a
// small, fixed-shape JSON document.
const maintAgentStatusReadBound = 1 << 20 // 1 MiB

// agentStatusDoc is the subset of the agent's GET /v1/status response
// (server.Status) worth surfacing to an admin — version, privilege posture,
// and compose-stack health. Deliberately excludes LockHeldBy/ComposeServices
// detail: those are dispatch-operation internals, not steady-state health.
type agentStatusDoc struct {
	AgentVersion       string `json:"agent_version"`
	PrivilegeMode      string `json:"privilege_mode"`
	PrivilegeWarning   string `json:"privilege_warning,omitempty"`
	ComposeStackUp     bool   `json:"compose_stack_up"`
	ComposeError       string `json:"compose_error,omitempty"`
	LastOperationKind  string `json:"last_operation_kind,omitempty"`
	LastOperationState string `json:"last_operation_state,omitempty"`
}

// fetchMaintAgentStatus performs a GET /v1/status against the maintenance
// agent and parses the response into agentStatusDoc.
func fetchMaintAgentStatus(ctx context.Context, ep AgentEndpoint) (agentStatusDoc, error) {
	u, err := url.Parse(ep.BaseURL)
	if err != nil {
		return agentStatusDoc{}, fmt.Errorf("parse agent base URL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return agentStatusDoc{}, err
	}
	client := ep.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return agentStatusDoc{}, fmt.Errorf("maintenance agent unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maintAgentStatusReadBound))
	if err != nil {
		return agentStatusDoc{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return agentStatusDoc{}, fmt.Errorf("maintenance agent returned HTTP %d", resp.StatusCode)
	}
	var doc agentStatusDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return agentStatusDoc{}, fmt.Errorf("parse agent response: %w", err)
	}
	return doc, nil
}

func registerMaintAgentStatusRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/maintenance-agent", apiMaintAgentStatus)
}

// maintAgentStatusCache single-flights and briefly caches the agent status
// read, mirroring backupsCache: a viewer refreshing the panel must not spawn
// a `docker compose ps` on the host per click.
var maintAgentStatusCache struct {
	mu      sync.Mutex
	at      time.Time
	payload map[string]any
}

const maintAgentStatusCacheTTL = 15 * time.Second

// apiMaintAgentStatus is a read-only, viewer-role GET surfacing the CP-local
// maintenance agent's own health — version, privilege posture, compose-stack
// state — so an admin can answer "is my host-root agent healthy" from the
// GUI instead of SSHing in to check `systemctl status culvert-maint`.
func apiMaintAgentStatus(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Encode OUTSIDE the cache lock (a viewer that stops reading must not pin
	// it — the backups listing's rule).
	jsonOK(w, maintAgentStatusPayload(r.Context()))
}

// agentReadFailureTTL is how long an UNAVAILABLE agent read is reused. It is
// short, so a recovered agent is reported within seconds rather than after
// the full TTL, while single-flight still bounds the host to one read at a
// time (a down agent is re-asked at most every few seconds).
const agentReadFailureTTL = 3 * time.Second

// agentReadTTL picks the reuse window for a cached agent payload.
func agentReadTTL(payload map[string]any, ok time.Duration) time.Duration {
	if avail, _ := payload["available"].(bool); !avail {
		return agentReadFailureTTL
	}
	return ok
}

// maintAgentStatusPayload returns the cached status inside its TTL, else
// performs ONE agent read under the cache lock (single-flight). The read runs
// on a context DETACHED from the requester (still bounded by the read's own
// 10 s timeout): the result is shared by every viewer, so one viewer closing
// its connection must not turn it into a cached "unavailable" for all of them
// (ASTRA review of f37a2a39 — reproduced against b579).
func maintAgentStatusPayload(ctx context.Context) map[string]any {
	c := &maintAgentStatusCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.payload != nil && time.Since(c.at) < agentReadTTL(c.payload, maintAgentStatusCacheTTL) {
		return c.payload
	}
	out := buildMaintAgentStatusPayload(context.WithoutCancel(ctx))
	c.payload, c.at = out, time.Now()
	return out
}

// buildMaintAgentStatusPayload performs one agent status read and shapes the
// response. Agent-down and not-configured both answer 200 {available:false,
// reason} — matching apiBackups' contract (200/403 only; the GUI's api()
// helper throws on any non-2xx, which would blank the panel exactly while an
// operator is diagnosing the agent).
func buildMaintAgentStatusPayload(ctx context.Context) map[string]any {
	ep, ok := resolveLocalMaintAgentEndpoint()
	if !ok {
		return map[string]any{
			"available": false,
			"reason":    "maintenance agent not configured",
		}
	}
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	doc, err := fetchMaintAgentStatus(fctx, ep)
	if err != nil {
		return map[string]any{
			"available": false,
			"reason":    err.Error(),
		}
	}
	out := map[string]any{
		"available":        true,
		"agent_version":    doc.AgentVersion,
		"privilege_mode":   doc.PrivilegeMode,
		"compose_stack_up": doc.ComposeStackUp,
	}
	if doc.PrivilegeWarning != "" {
		out["privilege_warning"] = doc.PrivilegeWarning
	}
	if doc.ComposeError != "" {
		out["compose_error"] = doc.ComposeError
	}
	if doc.LastOperationKind != "" {
		out["last_operation_kind"] = doc.LastOperationKind
	}
	if doc.LastOperationState != "" {
		out["last_operation_state"] = doc.LastOperationState
	}
	return out
}
