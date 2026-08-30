package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// PR-11 rollout admin surface. All mutation handlers are disabled-by-default:
// mode transitions, scope widening, and rollback rehearsal require the signed
// PR-10 publication path (four-eyes + PR-8 durable commit + sign + distribute +
// DP-ack), which is NOT wired in this node's disabled-by-default posture — so they
// report the request truthfully as not-configured rather than fabricating a
// pending/success result. Emergency disable is node-local and narrowing-only, so
// it engages the local kill switch immediately.

func mcpRolloutCapability(r *http.Request) rollout.Capability {
	if mcpCapability(r) == "management" {
		return rollout.CapabilityManagement
	}
	return rollout.CapabilityGateway
}

// apiMCPRollout returns the comprehensive, safe rollout status: desired / local /
// fleet-effective mode, scope + revision, per-capability metrics, Shadow/Canary/
// hard-failure summaries, DP acknowledgement counts, and the qualification lock.
func apiMCPRollout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	st := getMCPRollout().status()
	// Fleet-effective mode + DP ack counts come from the signed-distribution status;
	// in disabled-default there is no fleet, so local == desired == effective.
	st["distribution"] = mcpDistributionStatus()
	// Controlled Shadow activation: the non-executing evaluator composition state, the
	// two readiness tiers (shadow vs live), the §14 activation preflight, and the bounded
	// shadow evaluation metrics. Read-only; distinguishes gateway / shadow / live-exec.
	st["shadow"] = mcpShadowStatus()
	// Canary architecture (ADR-0035): read-only machine-verifiable readiness contract. Always
	// defined, never armed in this build — node_ready is false and unmet names every missing
	// prerequisite. Surfacing it here (viewer-gated) makes the activation contract observable
	// without any ability to activate.
	st["canary"] = mcpCanaryStatus()
	jsonOK(w, st)
}

// apiMCPRolloutTransition requests a one-stage promotion or a demotion. A
// promotion/widening requires the signed publication path (not wired in the
// disabled-default posture); it is recorded and reported not-configured. Production
// is always rejected without an externally-verified qualification receipt.
func apiMCPRolloutTransition(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		Capability string `json:"capability"`
		ToMode     string `json:"to_mode"`
		BaseRev    uint64 `json:"base_revision"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	to, err := rollout.ParseMode(req.ToMode)
	if err != nil {
		http.Error(w, "rollout_mode_invalid", http.StatusBadRequest)
		return
	}
	if to == rollout.ModeProduction {
		// Production is unreachable without an externally-verified qualification
		// receipt; this build ships no issuer. Never enable it from the admin surface.
		auditEvent(r, "mcp.rollout.transition.rejected", req.Capability+":production", "")
		http.Error(w, "rollout_production_locked", http.StatusForbidden)
		return
	}
	auditEvent(r, "mcp.rollout.transition.request", req.Capability+":"+req.ToMode, "")
	// Execution-dependency precondition (Shadow execution safety gate): a transition
	// to an executing mode (Shadow/Canary) cannot be honored while the guarded-
	// execution plane is not composed. Surface that fail-closed reason truthfully
	// rather than the generic distribution message, so the operator sees the real
	// blocker. Production was already rejected above.
	if to.RequiresExecutionPlane() {
		capbManagement := mcpRolloutCapability(r) == rollout.CapabilityManagement
		if req.Capability != "" {
			if parsed, perr := rollout.ParseCapability(req.Capability); perr == nil {
				capbManagement = parsed == rollout.CapabilityManagement
			}
		}
		// The readiness TIER the target mode requires must be composed: Shadow needs
		// only the non-executing shadow plane; Canary needs the live-execution plane
		// (never composed in this build). modeExecReady owns the shadow-vs-live split.
		if !modeExecReady(to, capbManagement) {
			http.Error(w, "shadow_execution_dependencies_not_configured", http.StatusConflict)
			return
		}
	}
	// A CP-side accepted transition is not fleet-effective until it is published +
	// acknowledged; that signed path is not wired in the disabled-default posture.
	http.Error(w, "distribution_not_configured", http.StatusConflict)
}

// apiMCPRolloutScope returns (GET, viewer) or updates (PUT, admin) the rollout
// scope. A scope update is a widening-capable mutation and rides the signed
// publication path; reported not-configured in the disabled-default posture.
func apiMCPRolloutScope(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		capab := mcpRolloutCapability(r)
		st := getMCPRollout().stateFor(capab)
		cfg := st.CurrentConfig()
		// PR-UX-5: enrich the scope view with the full safe summary (kind /
		// enumerable / percentage / high-risk / per-dimension selector + exclusion
		// counts / the exact serializable spec) so the UI can present the exact
		// configured scope, not just a hash. Backward-compatible: the original five
		// fields are retained.
		spec := cfg.Scope
		spec.Capability = capab
		// Compile at the config's real ScopeRevision so the summary hash matches
		// st.ScopeHash() (both fold the revision into the content hash).
		out := mcpScopeSummary(spec, cfg.ScopeRevision, rollout.DefaultLimits())
		out["capability"] = capab.String()
		out["mode"] = st.CurrentMode().String()
		out["scope_hash"] = st.ScopeHash()
		out["scope_revision"] = cfg.ScopeRevision
		out["connector_mode"] = cfg.ConnectorMode
		jsonOK(w, out)
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		auditEvent(r, "mcp.rollout.scope.update", mcpRolloutCapability(r).String(), "")
		http.Error(w, "distribution_not_configured", http.StatusConflict)
	default:
		mcpMethodNotAllowed(w)
	}
}

// apiMCPRolloutEvidence returns the measured Production Qualification evidence read
// model (shadow >=14d, canary >=7d, soak >=24h windows, zero open critical/high
// defects, rollback rehearsal) with per-requirement typed states, server-computed
// elapsed durations, and the synthetic/production origin label. PR-UX-6 enriches the
// original response additively (every original key is retained) with start
// timestamps, elapsed seconds, typed requirement states, a bounded summary, and the
// broader unsupported categories. It is a pure reporting surface: it performs NO
// mutation (Evidence() returns a copy, no window is stamped on read) and never
// asserts Production qualification, which remains locked behind the separate gate.
func apiMCPRolloutEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	capab := mcpRolloutCapability(r)
	st := getMCPRollout().stateFor(capab)
	ev := st.Evidence()
	now := time.Now()
	jsonOK(w, buildMCPEvidenceDTO(capab.String(), st.CurrentMode().String(), ev, now, now.UnixNano()))
}

// apiMCPRolloutEmergency engages the capability-local kill switch (immediate
// admission stop) or clears it. Emergency actions NARROW only; they can never
// promote, widen scope, or enable execution. Node-local — no CP round trip.
func apiMCPRolloutEmergency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		Capability string `json:"capability"`
		Action     string `json:"action"` // "disable" | "clear"
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Honor the capability from the JSON body (the documented API + UI contract). A
	// present-but-invalid value fails closed; an omitted value falls back to the
	// query-string capability for backward compatibility.
	capab := mcpRolloutCapability(r)
	if req.Capability != "" {
		parsed, err := rollout.ParseCapability(req.Capability)
		if err != nil {
			http.Error(w, "rollout_capability_invalid", http.StatusBadRequest)
			return
		}
		capab = parsed
	}
	var perr error
	switch req.Action {
	case "clear":
		perr = getMCPRollout().clearEmergency(capab)
		auditEvent(r, "mcp.rollout.emergency.clear", capab.String(), "")
	default:
		perr = getMCPRollout().emergencyDisable(capab, r.RemoteAddr)
		auditEvent(r, "mcp.rollout.emergency.disable", capab.String(), "")
	}
	killed := getMCPRollout().stateFor(capab).Killed()
	if perr != nil {
		// The in-memory action took effect (kill switch is engaged/cleared) but could
		// not be made restart-durable. Report it truthfully so the operator does not
		// trust a durable success: a restart may not preserve this action. 500 with the
		// current in-memory state and persisted:false.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"capability": capab.String(), "killed": killed, "persisted": false, "error": "rollout_persist_failed"})
		return
	}
	jsonOK(w, map[string]any{"capability": capab.String(), "killed": killed, "persisted": true})
}

// apiMCPRolloutRehearse records a rollback rehearsal (evidence). The live signed
// rollback runs through the PR-10 coordinator (not wired in the disabled-default
// posture); the rehearsal marker is a local evidence update only.
//
// Capability is bound from the JSON body (present-but-invalid fails closed; an
// omitted value falls back to the query-string capability) - identical to
// apiMCPRolloutEmergency so a rehearsal recorded for one capability can never land
// on the other (capability isolation). Nothing else about the action changes: it
// still records evidence only and never rolls back traffic or unlocks Production.
func apiMCPRolloutRehearse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		Capability string `json:"capability"`
	}
	// The body is OPTIONAL. An absent/empty body decodes to io.EOF — treat that as
	// "no body" and fall back to the query-string capability (back-compat). Do NOT
	// gate on Content-Length: a bodyless chunked POST sets it to -1, which must not
	// be misread as a malformed body. Only a genuinely malformed body is a 400.
	if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	capab := mcpRolloutCapability(r)
	if req.Capability != "" {
		parsed, err := rollout.ParseCapability(req.Capability)
		if err != nil {
			http.Error(w, "rollout_capability_invalid", http.StatusBadRequest)
			return
		}
		capab = parsed
	}
	// A rollback rehearsal is durable, build-bound evidence that ValidateRehearsal re-checks against the
	// current runtime identity on read; a placeholder/non-unique build stamp ("dev" on a local/untagged
	// build) makes currentRuntimeIdentity().Valid() false, so the record can never satisfy that check.
	// Refuse to run or persist the drill here rather than report rollback_rehearsed:true/persisted:true
	// for a record the activation gate will immediately reject as rollback_path_unhealthy (Codex P2).
	// Analogous to the Shadow Exit review POST's uniquely-versioned-build guard.
	if !currentRuntimeIdentity().Valid() {
		http.Error(w, "rollback_rehearsal_requires_a_uniquely_versioned_build", http.StatusConflict)
		return
	}
	// Rehearsal is durable evidence; record + persist under the durable-mutation lock
	// so a restart preserves it. A persist failure is surfaced truthfully.
	if err := getMCPRollout().recordRehearsal(capab); err != nil {
		auditEvent(r, "mcp.rollout.rehearse-rollback", capab.String(), "")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		// A persist failure means recordRehearsal removed/invalidated the record and reverted the
		// evidence marker, so the status model and the activation gate treat the rehearsal as ABSENT.
		// Report rollback_rehearsed:false so clients/operators are not told a rehearsal occurred when
		// both the durable record and the gate say it did not (Codex round-21 P2).
		_ = json.NewEncoder(w).Encode(map[string]any{"capability": capab.String(), "rollback_rehearsed": false, "persisted": false, "error": "rollout_persist_failed"})
		return
	}
	auditEvent(r, "mcp.rollout.rehearse-rollback", capab.String(), "")
	jsonOK(w, map[string]any{"capability": capab.String(), "rollback_rehearsed": true, "persisted": true})
}

// apiMCPRolloutRehearseAuthoritative runs the AUTHORITATIVE rollback rehearsal: it drives the
// Canary→Shadow→Observe demotion ladder through the REAL rollout coordinator core
// (commitRolloutTransitionCore — the same body every production transition runs) on a scratch state,
// so it fails for every security reason a real rollback would fail (Shadow preflight, emergency kill,
// config validity, durability). On full success it records durable, build-bound evidence that closes
// the CANARY-ROLLBACK-COORDINATOR-REHEARSAL prerequisite (readiness reason
// rollback_coordinator_rehearsal_pending, row 20). It is DISTINCT from the mechanics rehearsal above
// (rollback_path_healthy, row 19): the two facts never merge. It NEVER mutates live rollout state,
// arms live execution, or activates Canary — it is evidence-only, like the mechanics rehearsal.
//
// Capability isolation and the uniquely-versioned-build guard are identical to apiMCPRolloutRehearse.
func apiMCPRolloutRehearseAuthoritative(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		Capability string `json:"capability"`
	}
	if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	capab := mcpRolloutCapability(r)
	if req.Capability != "" {
		parsed, err := rollout.ParseCapability(req.Capability)
		if err != nil {
			http.Error(w, "rollout_capability_invalid", http.StatusBadRequest)
			return
		}
		capab = parsed
	}
	// The evidence is build-bound; a placeholder/non-unique build stamp can never satisfy the read-time
	// check, so refuse rather than record a record the gate will immediately reject.
	if !currentRuntimeIdentity().Valid() {
		http.Error(w, "rollback_rehearsal_requires_a_uniquely_versioned_build", http.StatusConflict)
		return
	}
	if err := getMCPRollout().recordCoordinatorRehearsal(capab); err != nil {
		auditEvent(r, "mcp.rollout.rehearse-rollback-authoritative", capab.String(), "")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		// A failure means no valid evidence was recorded (the drill failed a real coordinator gate, or the
		// evidence write was not crash-durable and was invalidated), so the gate treats it as ABSENT.
		_ = json.NewEncoder(w).Encode(map[string]any{"capability": capab.String(), "authoritative_rollback_rehearsed": false, "error": "rollout_persist_failed"})
		return
	}
	auditEvent(r, "mcp.rollout.rehearse-rollback-authoritative", capab.String(), "")
	jsonOK(w, map[string]any{"capability": capab.String(), "authoritative_rollback_rehearsed": true})
}

// apiMCPExecutions returns the bounded, safe execution history (counts only — no
// tenant/subject/argument/URL/token content).
func apiMCPExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	m := &getMCPRollout().metrics
	jsonOK(w, map[string]any{
		"executed":        m.executed.Load(),
		"upstream_ok":     m.upstreamOK.Load(),
		"upstream_err":    m.upstreamErr.Load(),
		"dlp_blocks":      m.dlpBlocks.Load(),
		"hard_blocks":     m.hardBlocks.Load(),
		"shadow_override": m.shadowOverride.Load(),
		"commit_fail":     m.commitFail.Load(),
	})
}

// apiMCPUpstreamHealth returns bounded upstream-leg health (counts only).
func apiMCPUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	m := &getMCPRollout().metrics
	jsonOK(w, map[string]any{
		"upstream_ok":  m.upstreamOK.Load(),
		"upstream_err": m.upstreamErr.Load(),
		"enabled":      false, // disabled-by-default: no upstream pool bound
	})
}
