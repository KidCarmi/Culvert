package main

// saas_feed_status_api.go — F3b-4: the truthful signed-feed runtime STATUS + manual
// refresh admin API. Replaces the F3a-2 configuration-only placeholder.
//
//	GET  /api/saas-feed/status   — viewer: the full runtime status snapshot (F0 §14 fields)
//	POST /api/saas-feed/refresh  — admin: manual refresh (singleflight; deterministic
//	                               accepted / in_progress / no-op / error)
//
// The status is READ-ONLY and never fabricates success: it reflects the live status
// holder, which the lifecycle/scheduler update only AFTER durable activation + cutover.
// It exposes no raw error bodies, filesystem paths, bundles, tokens, or high-cardinality
// values — every field is a bounded enum, a count, a timestamp, or an official URL.

import (
	"net/http"
	"time"
)

// saasFeedStatusJSON renders an immutable status snapshot as the API/GUI read model, with
// F0 §14 null semantics (never render "0 new hosts" / a fake zero timestamp).
func saasFeedStatusJSON(snap saasFeedStatusSnapshot) map[string]any {
	m := map[string]any{
		"state":            snap.State.String(),
		"configured":       snap.Configured,
		"enabled":          snap.Enabled,
		"managed":          snap.Managed,
		"authority":        snap.Authority,
		"protocol":         snap.Protocol,
		"url":              snap.URL,
		"active_source":    snap.ActiveSource,
		"provenance":       snap.Provenance,
		"signature_status": snap.SignatureStatus,
		"compiled_trusted": snap.CompiledTrusted,
		"stale":            snap.Stale,
		"host_count":       snap.HostCount,
		"category_count":   snap.CategoryCount,
		"override_count":   snap.OverrideCount,
		"not_modified":     snap.Last304,

		"failures_since_start": snap.FailuresSinceStart,
		"consecutive_failures": snap.ConsecutiveFailures,
		"never_succeeded":      snap.NeverSucceeded,

		"syncing":               snap.Syncing,
		"waiting_for_authority": snap.WaitingForAuthority,
		"recovering":            snap.Recovering,
		"critical":              snap.Critical,

		// Nullable fields (F0 §14): absent/zero renders as JSON null, never a fake value.
		"active_feed_version":        nullableInt64(snap.ActiveFeedVersion),
		"config_revision":            nullIfEmpty(snap.ConfigRevision),
		"override_revision":          nullIfEmpty(snap.OverrideRevision),
		"generated_at":               rfc3339OrNull(snap.GeneratedAt),
		"manifest_expires_at":        rfc3339OrNull(snap.ExpiresAt),
		"expires_in_days":            nullableIntPtr(snap.ExpiresInDays),
		"last_attempt":               rfc3339OrNull(snap.LastAttempt),
		"last_successful_check":      rfc3339OrNull(snap.LastSuccessfulCheck),
		"last_successful_activation": rfc3339OrNull(snap.LastSuccessfulActivation),
		"next_attempt":               rfc3339OrNull(snap.NextAttempt),
		"last_outcome":               nullIfEmpty(snap.LastOutcome),
		"last_error_class":           nullIfEmpty(snap.LastErrorClass),
		"last_http_status":           nullableInt(snap.LastHTTPStatus),
		"last_activation_delta":      snap.LastActivationDelta, // *struct ⇒ null in never_succeeded
	}
	if snap.CriticalReason != "" {
		m["critical_reason"] = snap.CriticalReason
	}
	if snap.Detail != "" {
		m["detail"] = snap.Detail
	}
	return m
}

// apiSaaSFeedStatus serves the read-only signed-feed runtime status (viewer).
func apiSaaSFeedStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, saasFeedStatusJSON(globalSaaSFeedStatus.Snapshot()))
}

// apiSaaSFeedRefresh triggers a manual refresh (admin). It shares the runtime's serialized
// refresh path (singleflight): if a refresh is already in flight it returns 202 in_progress
// without starting a second. A manual refresh is an OPERATIONAL action (it mutates no
// config), so it is permitted on a managed DP — the runtime's readiness gate still makes
// it a deterministic no-op when the feed is disabled or the DP lacks authority.
func apiSaaSFeedRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	rt := globalSaaSFeedRuntime
	if rt == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"refreshed": false, "status": "unavailable"})
		return
	}
	outcome, ran := rt.manualRefresh(r.Context())
	if !ran {
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"refreshed": false, "status": "in_progress"})
		return
	}
	auditEvent(r, "saasfeed.refresh", "feed", "result="+outcome.String())
	snap := globalSaaSFeedStatus.Snapshot()
	jsonOK(w, map[string]any{
		"refreshed": outcome == refreshActivated,
		"status":    outcome.String(),
		"state":     snap.State.String(),
	})
}

// ─── nullable JSON helpers (F0 §14: absent ⇒ null, never a fabricated zero) ─────────

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableIntPtr(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func rfc3339OrNull(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}
