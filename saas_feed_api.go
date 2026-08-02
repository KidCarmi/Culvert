package main

// saas_feed_api.go — F3a-2 admin API for the SaaS signed category-feed
// CONFIGURATION and admin category OVERRIDES (roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md
// §A.6). Two handlers on the existing settings pattern:
//
//   GET/PUT /api/saas-feed/settings   — url / protocol / managed / enabled / refresh
//   GET/PUT /api/saas-feed/overrides  — added / recategorized / tombstones (full-set)
//
// SCOPE (F3a-2): configuration plumbing ONLY. Nothing here downloads, verifies,
// activates, schedules, or publishes a feed, and nothing touches the live category
// store or the legacy syncer. A PUT resolves + validates through the single F3a-1
// boundary, persists via the durable holder / override store, audits, snapshots a
// config version, and republishes the cluster snapshot so the fleet converges. The
// read path clearly separates CONFIGURED state from runtime activation state, and
// never fabricates last_success / active version / freshness — those arrive with
// the F3b signed-feed client. On a managed Data Plane node every mutation is denied
// (409): feed policy is control-plane-authoritative.

import (
	"fmt"
	"net/http"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// ─── shared helpers (also used by config import, ui_config.go) ──────────────────

// backupCarriesSaaSFeed reports whether an import payload carries any SaaS
// feed-config or override field — the trigger for the managed-DP import denial.
func backupCarriesSaaSFeed(b *configBackup) bool {
	if b.SaaSFeedProtocol != "" || b.SaaSFeedURL != "" || b.SaaSFeedManaged ||
		b.SaaSFeedEnabled || b.SaaSFeedRefreshSeconds != 0 {
		return true
	}
	return b.CategoryOverrides != nil && !categoryOverridesEmpty(*b.CategoryOverrides)
}

// categoryOverridesEmpty reports whether an override set has no entries at all.
func categoryOverridesEmpty(o CategoryOverrides) bool {
	return len(o.Added) == 0 && len(o.Recategorized) == 0 && len(o.Tombstones) == 0
}

// categoryOverridesCount totals the host entries in an override set (adds +
// recategorizations + tombstones) — used by the import preview to report the
// incoming/current override footprint.
func categoryOverridesCount(o CategoryOverrides) int {
	return len(o.Added) + len(o.Recategorized) + len(o.Tombstones)
}

// validateSaaSFeedImport strict-validates the feed-config + override fields of an
// import payload through the SAME F3a-1 boundary the write path uses — no weaker
// duplicate. A legacy/unsupported protocol or URL, a malformed refresh interval,
// or an invalid override set rejects the whole import.
func validateSaaSFeedImport(b *configBackup) error {
	if b.SaaSFeedProtocol != "" {
		if _, err := resolveFeedProtocol(b.SaaSFeedProtocol); err != nil {
			return err
		}
	}
	if b.SaaSFeedURL != "" {
		if _, err := resolveFeedURL(b.SaaSFeedURL); err != nil {
			return err
		}
	}
	if _, err := resolveFeedRefresh(b.SaaSFeedRefreshSeconds); err != nil {
		return err
	}
	if b.CategoryOverrides != nil {
		if _, err := catoverride.Normalize(*b.CategoryOverrides); err != nil {
			return err
		}
	}
	return nil
}

// importCategoryOverrides applies the override set from an import payload.
// Never-wipe: an absent (nil) or empty set skips in both modes (an explicit clear
// is a rollback-only capability). Replace mode wholesale-replaces; merge mode
// upserts the incoming added/recategorized entries and unions the tombstones onto
// the live set. Pre-validated by validateSaaSFeedImport; ReplaceAll re-validates
// the merged result and skips (with a log) on conflict, never rejecting the import.
func importCategoryOverrides(b *configBackup, replaceMode bool) {
	if b.CategoryOverrides == nil || categoryOverridesEmpty(*b.CategoryOverrides) {
		return
	}
	incoming := *b.CategoryOverrides
	var target CategoryOverrides
	if replaceMode {
		target = incoming
	} else {
		target = mergeCategoryOverrides(globalCategoryOverrides.Get(), incoming)
	}
	if err := globalCategoryOverrides.ReplaceAll(target); err != nil {
		logger.Printf("ConfigImport: category overrides rejected: %q", sanitizeLog(err.Error()))
		return
	}
	if err := globalCategoryOverrides.Save(); err != nil {
		logger.Printf("ConfigImport: category overrides save: %v", err)
	}
	// F3b-4 finding #5: recompose the policy view for the imported overrides (local, no network).
	recomposeSignedFeedOverrides()
}

// mergeCategoryOverrides unions incoming onto base (incoming wins on key
// collisions), for merge-mode import. The result is re-validated by ReplaceAll.
func mergeCategoryOverrides(base, incoming CategoryOverrides) CategoryOverrides {
	out := CategoryOverrides{
		Added:         map[string]string{},
		Recategorized: map[string]string{},
	}
	for k, v := range base.Added {
		out.Added[k] = v
	}
	for k, v := range incoming.Added {
		out.Added[k] = v
	}
	for k, v := range base.Recategorized {
		out.Recategorized[k] = v
	}
	for k, v := range incoming.Recategorized {
		out.Recategorized[k] = v
	}
	seen := map[string]bool{}
	for _, t := range append(append([]string{}, base.Tombstones...), incoming.Tombstones...) {
		if !seen[t] {
			seen[t] = true
			out.Tombstones = append(out.Tombstones, t)
		}
	}
	return out
}

// importSaaSFeedConfig applies the feed-config scalars from an import payload.
// Never-wipe: applied only when the backup carries the config (SaaSFeedProtocol
// set). Publishes to the durable holder only — persisted by the caller's
// adminSettingsSave; no downloader/legacy-syncer call.
func importSaaSFeedConfig(b *configBackup) {
	if b.SaaSFeedProtocol == "" {
		return
	}
	d := getSaaSFeedDurable()
	d.Managed = b.SaaSFeedManaged
	d.Enabled = b.SaaSFeedEnabled
	d.URL = b.SaaSFeedURL
	d.Protocol = b.SaaSFeedProtocol
	d.RefreshSeconds = b.SaaSFeedRefreshSeconds
	setSaaSFeedDurable(d)
}

// ─── GET/PUT /api/saas-feed/settings ────────────────────────────────────────────

// saasFeedSettingsBody is the PUT request body. All fields optional: managed /
// enabled are *bool presence toggles (absent ⇒ managed defaults true — a PUT is
// explicit management — enabled defaults true); url/protocol/refresh are resolved
// (empty ⇒ the built-in official envelope / signed_manifest_v1 / 24h default).
type saasFeedSettingsBody struct {
	Managed  *bool  `json:"managed,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty"`
	URL      string `json:"url,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Refresh  string `json:"refresh,omitempty"` // Go duration string
}

// apiSaaSFeedSettings serves the SaaS feed-config surface. GET is viewer
// (read-only, distinguishes configured vs runtime state); PUT is admin.
func apiSaaSFeedSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, saasFeedSettingsView())

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		putSaaSFeedSettings(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// putSaaSFeedSettings handles the admin PUT: managed-DP denial, validate through
// the F3a-1 boundary, apply-then-persist with rollback, audit, version, republish.
// Split out of apiSaaSFeedSettings to keep each function under the cyclop bound.
func putSaaSFeedSettings(w http.ResponseWriter, r *http.Request) {
	if isManagedDataPlane() {
		http.Error(w, "saas feed config is control-plane managed on this data-plane node", http.StatusConflict)
		return
	}
	var body saasFeedSettingsBody
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	next, err := resolveSaaSFeedSettingsUpdate(body)
	if err != nil {
		http.Error(w, sanitizeLog(err.Error()), http.StatusBadRequest)
		return
	}
	// Apply-then-persist with runtime rollback on durable-write failure.
	old := getSaaSFeedDurable()
	setSaaSFeedDurable(next)
	if err := SaveAdminSettings(); err != nil {
		setSaaSFeedDurable(old) // ROLLBACK runtime; no config-snapshot change committed
		logger.Printf("SaaSFeedSettings: persist failed, runtime reverted: %v", err)
		http.Error(w, "failed to persist saas feed settings", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "saasfeed.settings", boolState(next.Enabled), "saas feed configuration updated")
	saveConfigVersion(sessionAdmin(r), "saasfeed.settings")
	// F3b-4: a config change (esp. disabled→enabled or an interval change) requires the
	// scheduler to re-evaluate now rather than at the next tick.
	wakeSignedFeedScheduler()
	// Republish so the fleet converges (CP-authoritative).
	pubErr := publishCurrentConfigSnapshot()
	resp := saasFeedSettingsView()
	if pubErr != nil {
		resp["cluster_publish_rejected"] = pubErr.Error()
	}
	jsonOK(w, resp)
}

// resolveSaaSFeedSettingsUpdate validates the request body through the F3a-1
// boundary and returns the target durable state (preserving the schema marker). A
// PUT is explicit management, so managed/enabled default to true when omitted.
func resolveSaaSFeedSettingsUpdate(body saasFeedSettingsBody) (saasFeedDurable, error) {
	url, err := resolveFeedURL(body.URL)
	if err != nil {
		return saasFeedDurable{}, fmt.Errorf("invalid url: %w", err)
	}
	protocol, err := resolveFeedProtocol(body.Protocol)
	if err != nil {
		return saasFeedDurable{}, fmt.Errorf("invalid protocol: %w", err)
	}
	refreshSecs, err := parseRefreshInterval(body.Refresh)
	if err != nil {
		return saasFeedDurable{}, fmt.Errorf("invalid refresh: %w", err)
	}
	next := getSaaSFeedDurable()
	next.Managed = body.Managed == nil || *body.Managed
	next.Enabled = body.Enabled == nil || *body.Enabled
	next.URL = url
	next.Protocol = protocol
	next.RefreshSeconds = refreshSecs
	return next, nil
}

// saasFeedSettingsView is the read model. It separates the CONFIGURED fields from
// the RESOLVED effective values, and states honestly that runtime activation is
// unavailable until the F3b signed-feed client lands — it NEVER fabricates
// last_success, active version, freshness, or provenance.
func saasFeedSettingsView() map[string]any {
	d := getSaaSFeedDurable()
	resolved, resolveErr := resolvedSaaSFeedConfig()
	view := map[string]any{
		"managed":         d.Managed,
		"enabled":         d.Enabled,
		"url":             d.URL,
		"protocol":        d.Protocol,
		"refresh_seconds": d.RefreshSeconds,
		// The official built-in endpoint the empty/unset URL resolves to, and the
		// exact host the GUI constrains input to (no generic mirror).
		"official_url": builtinSaaSFeedURL,
		"editable":     !isManagedDataPlane(),
		// F3b-4: the signed-feed runtime (download/verify/activate/serve) is now wired.
		// This endpoint stays CONFIG-only; the live runtime state (state/provenance/
		// version/freshness/counts/activity) is on GET /api/saas-feed/status.
		"runtime_activation_available": true,
		"note":                         "configuration surface — the live runtime status is on /api/saas-feed/status",
	}
	if resolveErr == nil {
		view["resolved"] = map[string]any{
			"url":             resolved.URL,
			"protocol":        resolved.Protocol,
			"enabled":         resolved.Enabled,
			"refresh_seconds": int64(resolved.Refresh / 1e9),
		}
	} else {
		view["resolve_error"] = resolveErr.Error()
	}
	return view
}

// boolState renders a bool as an audit-friendly enabled/disabled token.
func boolState(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// ─── GET/PUT /api/saas-feed/overrides ───────────────────────────────────────────

// apiSaaSFeedOverrides serves the admin category-override surface. GET is viewer
// (returns the current full set); PUT is admin (full-set replacement — an empty
// body clears every override).
func apiSaaSFeedOverrides(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		ov := globalCategoryOverrides.Get()
		jsonOK(w, map[string]any{
			"overrides": ov,
			"editable":  !isManagedDataPlane(),
		})

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		putSaaSFeedOverrides(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// putSaaSFeedOverrides handles the admin full-set override replacement (an empty
// body clears every override). Split out to keep apiSaaSFeedOverrides under the
// cyclop bound.
func putSaaSFeedOverrides(w http.ResponseWriter, r *http.Request) {
	if isManagedDataPlane() {
		http.Error(w, "category overrides are control-plane managed on this data-plane node", http.StatusConflict)
		return
	}
	// Full-set replacement. The GUI transmits the complete desired set; an empty
	// {} is a deliberate clear (explicit empty replacement, delete-propagating).
	var incoming CategoryOverrides
	if err := decodeJSON(r, &incoming); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	old := globalCategoryOverrides.Get()
	if err := globalCategoryOverrides.ReplaceAll(incoming); err != nil {
		http.Error(w, "invalid overrides: "+sanitizeLog(err.Error()), http.StatusBadRequest)
		return
	}
	if err := globalCategoryOverrides.Save(); err != nil {
		_ = globalCategoryOverrides.ReplaceAll(old) // ROLLBACK runtime
		logger.Printf("SaaSFeedOverrides: persist failed, runtime reverted: %v", err)
		http.Error(w, "failed to persist overrides", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "saasfeed.overrides", "replace", "category overrides updated")
	saveConfigVersion(sessionAdmin(r), "saasfeed.overrides")
	// F3b-4 finding #5: apply the new overrides to the policy hot path NOW (local recompose,
	// no network) so an add/change/delete-all takes effect immediately.
	recomposeSignedFeedOverrides()
	pubErr := publishCurrentConfigSnapshot()
	resp := map[string]any{"ok": true, "overrides": globalCategoryOverrides.Get()}
	if pubErr != nil {
		resp["cluster_publish_rejected"] = pubErr.Error()
	}
	jsonOK(w, resp)
}
