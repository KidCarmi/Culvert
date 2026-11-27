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
	// RuntimeHealth is the agent's runtime health observer evidence (ADR-0062
	// slice 5). Absent when the agent's runtime_health_interval is off or the
	// agent predates it.
	RuntimeHealth *agentRuntimeHealth `json:"runtime_health,omitempty"`
}

// agentRuntimeHealth is the part of the agent's runtime_health surfaced to an
// admin: what the observer last saw and the last-known-good image. The agent
// reports image ids and digests only, never a container id.
type agentRuntimeHealth struct {
	State           string             `json:"state"`
	Reason          string             `json:"reason,omitempty"`
	ObservedAt      *time.Time         `json:"observed_at,omitempty"`
	ImageID         string             `json:"image_id,omitempty"`
	IntervalSeconds int64              `json:"interval_seconds"`
	Error           string             `json:"error,omitempty"`
	LastGood        *agentLastGoodInfo `json:"last_good,omitempty"`
	LastGoodError   string             `json:"last_good_error,omitempty"`
}

type agentLastGoodInfo struct {
	ImageID  string    `json:"image_id"`
	Ref      string    `json:"ref"`
	Digest   string    `json:"digest"`
	PassedAt time.Time `json:"passed_at"`
}

// agentRuntimeStates is the closed set the agent reports. Anything else (a
// newer agent's state, or garbage) is surfaced as unknown rather than passed
// through as if this build understood it.
var agentRuntimeStates = map[string]bool{"gated": true, "ungated": true, "unhealthy": true, "unknown": true, "stale": true}

// maintAgentFieldBound bounds each agent-supplied string surfaced to an admin.
const maintAgentFieldBound = 256

func boundAgentField(s string) string {
	if len(s) > maintAgentFieldBound {
		return s[:maintAgentFieldBound]
	}
	return s
}

// runtimeHealthPayload shapes runtime_health for the admin API.
func runtimeHealthPayload(rh *agentRuntimeHealth) map[string]any {
	state := rh.State
	if !agentRuntimeStates[state] {
		state = "unknown"
	}
	out := map[string]any{"state": state, "interval_seconds": rh.IntervalSeconds}
	for k, v := range map[string]string{"reason": rh.Reason, "image_id": rh.ImageID, "error": rh.Error, "last_good_error": rh.LastGoodError} {
		if v != "" {
			out[k] = boundAgentField(v)
		}
	}
	if rh.ObservedAt != nil {
		out["observed_at"] = rh.ObservedAt.UTC()
	}
	if lg := rh.LastGood; lg != nil {
		out["last_good"] = map[string]any{
			"image_id":  boundAgentField(lg.ImageID),
			"ref":       boundAgentField(lg.Ref),
			"digest":    boundAgentField(lg.Digest),
			"passed_at": lg.PassedAt.UTC(),
		}
	}
	return out
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
	maintAgentStatusCache.mu.Lock()
	defer maintAgentStatusCache.mu.Unlock()
	if maintAgentStatusCache.payload != nil && time.Since(maintAgentStatusCache.at) < maintAgentStatusCacheTTL {
		jsonOK(w, maintAgentStatusCache.payload)
		return
	}
	out := buildMaintAgentStatusPayload(r.Context())
	maintAgentStatusCache.payload, maintAgentStatusCache.at = out, time.Now()
	jsonOK(w, out)
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
	if doc.RuntimeHealth != nil {
		out["runtime_health"] = runtimeHealthPayload(doc.RuntimeHealth)
	}
	return out
}
