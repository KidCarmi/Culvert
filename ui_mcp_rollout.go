package main

import (
	"errors"
	"io"
	"net/http"

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
		st := getMCPRollout().stateFor(mcpRolloutCapability(r))
		cfg := st.CurrentConfig()
		jsonOK(w, map[string]any{
			"capability":     mcpRolloutCapability(r).String(),
			"scope_hash":     st.ScopeHash(),
			"scope_revision": cfg.ScopeRevision,
			"connector_mode": cfg.ConnectorMode,
			"high_risk":      cfg.Scope.HighRisk,
		})
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

// apiMCPRolloutEvidence returns the measured evidence-window progress (shadow ≥14d,
// canary ≥7d, soak ≥24h) with the synthetic/production origin label. It is a
// reporting surface; it never asserts Production qualification.
func apiMCPRolloutEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	st := getMCPRollout().stateFor(mcpRolloutCapability(r))
	ev := st.Evidence()
	jsonOK(w, map[string]any{
		"capability":              mcpRolloutCapability(r).String(),
		"origin":                  ev.Origin.String(),
		"open_critical_high":      ev.OpenCriticalHighDefects,
		"rollback_rehearsed":      ev.RollbackRehearsed,
		"false_positive_reviews":  ev.FalsePositiveReviews,
		"shadow_window_target_h":  int(rollout.ShadowWindowTarget.Hours()),
		"canary_window_target_h":  int(rollout.CanaryWindowTarget.Hours()),
		"soak_target_h":           int(rollout.SoakTarget.Hours()),
		"production_locked":       true,
		"production_lock_message": "Production locked — qualification required",
	})
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
	switch req.Action {
	case "clear":
		getMCPRollout().clearEmergency(capab)
		auditEvent(r, "mcp.rollout.emergency.clear", capab.String(), "")
	default:
		getMCPRollout().emergencyDisable(capab, r.RemoteAddr)
		auditEvent(r, "mcp.rollout.emergency.disable", capab.String(), "")
	}
	jsonOK(w, map[string]any{"capability": capab.String(), "killed": getMCPRollout().stateFor(capab).Killed()})
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
	getMCPRollout().stateFor(capab).UpdateEvidence(func(e *rollout.EvidenceSummary) { e.RollbackRehearsed = true })
	auditEvent(r, "mcp.rollout.rehearse-rollback", capab.String(), "")
	jsonOK(w, map[string]any{"capability": capab.String(), "rollback_rehearsed": true})
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
