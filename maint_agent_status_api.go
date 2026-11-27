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
// and compose-stack health — plus the crash-recovery state an operator must
// act on (interrupted operations, startup-reconcile verdict, pinned-tag drift).
// Deliberately excludes LockHeldBy/ComposeServices detail: those are
// dispatch-operation internals, not steady-state health.
type agentStatusDoc struct {
	AgentVersion       string `json:"agent_version"`
	PrivilegeMode      string `json:"privilege_mode"`
	PrivilegeWarning   string `json:"privilege_warning,omitempty"`
	ComposeStackUp     bool   `json:"compose_stack_up"`
	ComposeError       string `json:"compose_error,omitempty"`
	LastOperationKind  string `json:"last_operation_kind,omitempty"`
	LastOperationState string `json:"last_operation_state,omitempty"`

	// Recovery state (cmd/culvert-maint/internal/server Status). Before this
	// relay the GUI dropped it, so an upgrade/rollback/restore the agent died
	// in — which the agent journals and reports until it is resolved — was
	// visible only by SSHing to the host and curling the agent socket. The
	// GUI's "Last operation" row is in-memory on the agent and vanishes on the
	// very restart that produced the interrupted record.
	InterruptedOperations      []agentInterruptedOp `json:"interrupted_operations,omitempty"`
	InterruptedOperationsError string               `json:"interrupted_operations_error,omitempty"`
	RecoveryRequired           *bool                `json:"recovery_required,omitempty"`
	PinnedTag                  *struct {
		MatchesRunning *bool `json:"matches_running,omitempty"`
	} `json:"pinned_tag,omitempty"`
}

// agentInterruptedOp is the viewer-safe subset of the agent's
// InterruptedOperation: what stopped, what Docker looks like now and the
// agent's own operator_action sentence. Actor (an identity) and the raw
// image ids are not relayed; prior_ref is the reference a rollback takes.
type agentInterruptedOp struct {
	OpID             string `json:"op_id"`
	Kind             string `json:"kind"`
	JournalPhase     string `json:"journal_phase,omitempty"`
	DockerState      string `json:"docker_state,omitempty"`
	RunningImage     string `json:"running_image,omitempty"`
	DiedInCommand    string `json:"died_in_command,omitempty"`
	TerminalOutcome  string `json:"terminal_outcome,omitempty"`
	ReconcileOutcome string `json:"reconcile_outcome,omitempty"`
	DockerReconciled bool   `json:"docker_reconciled"`
	PriorRef         string `json:"prior_ref,omitempty"`
	RestartSafe      string `json:"restart_safe,omitempty"`
	OperatorAction   string `json:"operator_action,omitempty"`
	StartedAt        string `json:"started_at,omitempty"`
}

// maintAgentInterruptedRelayMax bounds the relayed list; the agent keeps one
// record per unresolved operation, so more than this is itself the finding.
const maintAgentInterruptedRelayMax = 20

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
	addMaintAgentRecoveryFields(out, &doc)
	return out
}

// addMaintAgentRecoveryFields relays the agent's crash-recovery state. Keys are
// absent when the agent reports nothing (or is an older version), so the
// healthy payload is unchanged.
func addMaintAgentRecoveryFields(out map[string]any, doc *agentStatusDoc) {
	if n := len(doc.InterruptedOperations); n > 0 {
		ops := doc.InterruptedOperations
		if n > maintAgentInterruptedRelayMax {
			ops = ops[:maintAgentInterruptedRelayMax]
			out["interrupted_operations_truncated"] = n
		}
		out["interrupted_operations"] = ops
	}
	if doc.InterruptedOperationsError != "" {
		out["interrupted_operations_error"] = doc.InterruptedOperationsError
	}
	if doc.RecoveryRequired != nil {
		out["recovery_required"] = *doc.RecoveryRequired
	}
	if pt := doc.PinnedTag; pt != nil && pt.MatchesRunning != nil {
		out["pinned_tag_matches_running"] = *pt.MatchesRunning
	}
}
