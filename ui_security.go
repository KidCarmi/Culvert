package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/geoip"
)

// pendingCARotation holds a confirmation token for the two-step CA rotation flow.
// An admin must first request rotation (receives a token), then confirm with that token.
var pendingCARotation struct {
	sync.Mutex
	token   string
	expires time.Time
}

// ── Alert Webhooks ─────────────────────────────────────────────────────────

// GET  /api/alerts/webhooks      → list webhooks (secrets redacted)
// POST /api/alerts/webhooks      → create webhook
// PUT  /api/alerts/webhooks?id=X → update webhook
// DELETE /api/alerts/webhooks?id=X → delete webhook
func apiAlertsWebhooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{"webhooks": globalAlertStore.List()})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var h AlertWebhook
		if err := decodeJSON(r, &h); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if h.URL == "" {
			http.Error(w, "url required", http.StatusBadRequest)
			return
		}
		if err := validateWebhookURL(h.URL); err != nil {
			http.Error(w, "invalid webhook URL: "+err.Error(), http.StatusBadRequest)
			return
		}
		h.Enabled = true
		created := globalAlertStore.Add(h)
		auditEvent(r, "alert.webhook.create", created.ID, h.URL)
		jsonOK(w, created)

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		var h AlertWebhook
		if err := decodeJSON(r, &h); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if h.URL != "" {
			if err := validateWebhookURL(h.URL); err != nil {
				http.Error(w, "invalid webhook URL: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if !globalAlertStore.Update(id, h) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		auditEvent(r, "alert.webhook.update", id, "")
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if !globalAlertStore.Delete(id) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		auditEvent(r, "alert.webhook.delete", id, "")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/alerts/webhooks/test?id=X → fire a test payload to the webhook
func apiAlertsWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	h, ok := globalAlertStore.GetByID(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// Finding 8.2: deliver synchronously so the UI gets actual result feedback.
	payload := AlertPayload{
		Event:     "test",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     "culvert",
		Host:      "test",
		Detail:    "This is a test alert from Culvert",
		Source:    "test",
	}
	ok2 := globalAlertStore.Deliver(h, payload)
	jsonOK(w, map[string]any{"ok": ok2, "delivered": ok2})
}

// GET /api/alerts/webhooks/history — delivery history (Finding 8.1), plus
// retry-queue health so an admin can see alerting degradation (queued
// retries, permanently exhausted/dropped deliveries) without grepping logs.
func apiAlertsDeliveryHist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{
		"deliveries":            globalAlertStore.DeliveryHistory(),
		"retry_queue_depth":     alerts.RetryQueueDepth(),
		"retry_exhausted_total": alerts.RetryExhaustedTotal(),
		"retry_dropped_total":   alerts.RetryDroppedTotal(),
		// CHAOS-27: dedup-window health. Evictions mean the alert key space is
		// being flooded with unique details, so duplicate suppression is
		// degraded (more deliveries, never fewer) — the operator-visible
		// signature of a scanning wave reaching the alert plane.
		"dedup_tracked":         globalAlertStore.DedupTracked(),
		"dedup_evictions_total": alerts.DedupEvictionsTotal(),
	})
}

func apiSecurity(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"ipFilterMode":    ipf.Mode(),
			"ipList":          ipf.List(),
			"rateLimitRPM":    rl.Limit(),
			"rateLimitOn":     rl.Enabled(),
			"rateLimitExempt": rl.ListExemptions(),
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			IPFilterMode       string   `json:"ipFilterMode"` // "allow"|"block"|""
			IPAdd              string   `json:"ipAdd"`
			IPRemove           string   `json:"ipRemove"`
			RateLimitRPM       int      `json:"rateLimitRPM"`       // 0 = disable
			IPList             []string `json:"ipList"`             // full replace
			RateLimitExemptAdd string   `json:"rateLimitExemptAdd"` // IP or CIDR to exempt
			RateLimitExemptDel string   `json:"rateLimitExemptDel"` // IP or CIDR to un-exempt
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.IPFilterMode != "" {
			if body.IPFilterMode != "allow" && body.IPFilterMode != "block" {
				http.Error(w, `ipFilterMode must be "allow" or "block"`, http.StatusBadRequest)
				return
			}
			ipf.SetMode(body.IPFilterMode)
		}
		if body.IPAdd != "" {
			if err := ipf.Add(body.IPAdd); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if body.IPRemove != "" {
			ipf.Remove(body.IPRemove)
		}
		if body.RateLimitRPM >= 0 {
			rl.Configure(body.RateLimitRPM, time.Minute)
		}
		if body.RateLimitExemptAdd != "" {
			if err := rl.AddExemption(body.RateLimitExemptAdd); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if body.RateLimitExemptDel != "" {
			rl.RemoveExemption(body.RateLimitExemptDel)
		}
		logMode := strings.ReplaceAll(strings.ReplaceAll(ipf.Mode(), "\n", "_"), "\r", "_")
		logRPM := strings.ReplaceAll(fmt.Sprintf("%d", rl.Limit()), "\n", "_")
		logger.Printf("UI: security config updated (ipMode=%q rateRPM=%s)", logMode, logRPM)
		auditEvent(r, "security.update", "ip_filter+rate_limit",
			fmt.Sprintf("mode=%s rpm=%d", ipf.Mode(), rl.Limit()))
		adminSettingsSave()
		saveConfigVersion(sessionAdmin(r), "security.update")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/settings
func apiCACert(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		if certMgr.CACertPEM() == nil {
			http.Error(w, "CA not initialised", http.StatusServiceUnavailable)
			return
		}
		// Return JSON metadata or raw PEM depending on Accept header.
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			jsonOK(w, certMgr.CACertInfo())
			return
		}
		writeCACertPEM(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// writeCACertPEM serves the Root CA certificate as a downloadable PEM file.
// Shared by /api/ca-cert (Certificates panel) and /api/ca/download (CA
// Management panel) — both routes exist for GUI back-compat, but must never
// re-diverge into two independently-maintained copies of this response.
func writeCACertPEM(w http.ResponseWriter) {
	pem := certMgr.CACertPEM()
	if pem == nil {
		http.Error(w, "CA not initialised", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="culvert-ca.pem"`)
	w.Write(pem) //nolint:errcheck // HTTP response write
}

// POST /api/certs/upload — upload a custom TLS certificate+key for the UI or MITM engine.
// Body: multipart/form-data with fields: "cert" (PEM), "key" (PEM), "target" ("ui"|"mitm")
//
// Intentionally OUT of the config-version rollback surface — this is a
// forward-only trust mutation; rolling back would silently restore
// superseded MITM/UI certs. Do NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (D-sec).
func apiCertsUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)        // enforce 1 MB limit before parsing
	if err := r.ParseMultipartForm(1 << 20); err != nil { // #nosec G120 -- body already bounded by MaxBytesReader(1 MiB) on the line above
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}
	target := r.FormValue("target")
	if target != "ui" && target != "mitm" {
		http.Error(w, `target must be "ui" or "mitm"`, http.StatusBadRequest)
		return
	}
	certPEM := []byte(r.FormValue("cert"))
	keyPEM := []byte(r.FormValue("key"))
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		http.Error(w, "cert and key are required", http.StatusBadRequest)
		return
	}
	if target == "mitm" {
		// CHAOS-50: PERSIST the uploaded CA. It used to be installed in memory
		// only, so an admin who uploaded their enterprise MITM CA got a gateway
		// that silently reverted to the previous (or no) CA on the next restart —
		// the same swallowed-durability shape CHAOS-28 fixed for rotation, on the
		// other CA-install path. The response now states which happened, and the
		// recorded load failure is cleared only when the bundle actually landed.
		// Install + persist + latch clear run as one operation under caMutationMu.
		persisted, err := installAndPersistCustomMITMCA(certPEM, keyPEM)
		if err != nil {
			logger.Printf("certs upload MITM: %v", err)
			http.Error(w, "invalid CA cert/key pair", http.StatusBadRequest)
			return
		}
		if !persisted {
			auditEvent(r, "certs.upload_mitm", "custom MITM CA", "NOT PERSISTED — in-memory only")
			jsonOK(w, map[string]any{
				"status":    "ok",
				"target":    "mitm",
				"persisted": false,
				"warning": "The uploaded CA is active but was not persisted — it exists in memory only " +
					"and will be LOST on restart. Configure a persistent CA bundle path (-ca-path / " +
					"proxy.ca_path) or restore write access to it, then upload again.",
			})
			return
		}
		auditEvent(r, "certs.upload_mitm", "custom MITM CA", "")
		jsonOK(w, map[string]any{"status": "ok", "target": "mitm", "persisted": true})
		return
	}
	// UI cert — validate, then PERSIST it (CHAOS-50 durability idiom) so a
	// restart genuinely activates it instead of silently discarding the
	// upload while telling the admin "restart required".
	if _, err := certMgr.ParseTLSPair(certPEM, keyPEM); err != nil {
		logger.Printf("certs upload UI: %v", err)
		http.Error(w, "invalid cert/key pair", http.StatusBadRequest)
		return
	}
	if err := persistCustomUITLS(certPEM, keyPEM); err != nil {
		logger.Printf("certs upload UI: persist failed: %v", err)
		auditEvent(r, "certs.upload_ui", "custom UI cert", "NOT PERSISTED — validation only")
		jsonOK(w, map[string]any{
			"status":    "ok",
			"target":    "ui",
			"persisted": false,
			"warning": "The uploaded certificate is valid but could not be saved — it will NOT " +
				"be active after a restart, and the current UI certificate is unchanged. Restore " +
				"write access to the data directory, then upload again.",
		})
		return
	}
	// The pair just written already passed certMgr.ParseTLSPair above, so any
	// PRIOR corruption latch (a leftover pair from an earlier interrupted
	// upload, surfaced as ui_custom_cert_corrupt) no longer describes what's
	// on disk — clear it, or a successful re-upload would still show as
	// "corrupt, restart won't help" until the next restart re-evaluates it.
	uiCustomTLSCorrupt = false
	auditEvent(r, "certs.upload_ui", "custom UI cert (requires restart)", "")
	jsonOK(w, map[string]any{
		"status":    "ok",
		"target":    "ui",
		"persisted": true,
		"note":      "Saved. Restart the proxy to activate this certificate.",
	})
}

// apiContentScan manages DPI signature patterns.
//
//	GET/POST/DELETE /api/dpi             — canonical path (terminology governance T-10)
//	GET/POST/DELETE /api/content-scan    — deprecated alias, retained for compat
func apiContentScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		patterns := dpiScanner.List()
		jsonOK(w, map[string]any{
			"patterns":      patterns,
			"count":         len(patterns),
			"blocked_total": statDPIBlocked,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Pattern  string   `json:"pattern"`
			Patterns []string `json:"patterns"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Pattern != "" {
			body.Patterns = append(body.Patterns, body.Pattern)
		}
		added := 0
		for _, p := range body.Patterns {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if err := dpiScanner.Add(p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			logger.Printf("UI: DPI pattern added %q", p)
			added++
		}
		dpiScanner.Save()
		auditEvent(r, "dpi.add", fmt.Sprintf("%d pattern(s)", added),
			strings.Join(body.Patterns, ", "))
		saveConfigVersion(sessionAdmin(r), "dpi.add")
		jsonOK(w, map[string]any{"added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		pattern := strings.TrimSpace(r.URL.Query().Get("pattern"))
		if pattern == "" {
			http.Error(w, "missing pattern param", http.StatusBadRequest)
			return
		}
		dpiScanner.Remove(pattern)
		dpiScanner.Save()
		logger.Printf("UI: DPI pattern removed %q", pattern)
		auditEvent(r, "dpi.remove", pattern, "")
		saveConfigVersion(sessionAdmin(r), "dpi.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST/DELETE /api/fileblock — manage the file-extension block profile
func apiFileblock(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		exts := fileBlocker.List()
		sort.Strings(exts)
		jsonOK(w, map[string]any{"extensions": exts, "count": len(exts)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Extensions []string `json:"extensions"` // bulk add
			Extension  string   `json:"extension"`  // single add
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Extension != "" {
			body.Extensions = append(body.Extensions, body.Extension)
		}
		added := 0
		for _, ext := range body.Extensions {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				fileBlocker.Add(ext)
				logger.Printf("UI: file block extension added %q", sanitizeLog(ext))
				added++
			}
		}
		auditEvent(r, "fileblock.add", fmt.Sprintf("%d extension(s)", added), "")
		saveConfigVersion(sessionAdmin(r), "fileblock.add")
		jsonOK(w, map[string]any{"added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		ext := strings.TrimSpace(r.URL.Query().Get("ext"))
		if ext == "" {
			http.Error(w, "missing ext param", http.StatusBadRequest)
			return
		}
		fileBlocker.Remove(ext)
		logger.Printf("UI: file block extension removed %q", sanitizeLog(ext))
		auditEvent(r, "fileblock.remove", ext, "")
		saveConfigVersion(sessionAdmin(r), "fileblock.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── File Extension Profiles API ───────────────────────────────────────────────
//
// GET    /api/fileblock/profiles          → list all profiles
// POST   /api/fileblock/profiles          → create profile {name, extensions[]}
// PUT    /api/fileblock/profiles?id=X     → update profile
// DELETE /api/fileblock/profiles?id=X     → delete profile
func apiFileblockProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, globalProfileStore.List())

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Name       string   `json:"name"`
			Extensions []string `json:"extensions"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		prof, err := globalProfileStore.Create(body.Name, body.Extensions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		auditEvent(r, "fileprofile.create", prof.Name, fmt.Sprintf("%d extensions", len(prof.Extensions)))
		jsonOK(w, prof)

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "missing id param", http.StatusBadRequest)
			return
		}
		var body struct {
			Name       string   `json:"name"`
			Extensions []string `json:"extensions"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := globalProfileStore.Update(id, body.Name, body.Extensions); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEvent(r, "fileprofile.update", body.Name, fmt.Sprintf("%d extensions", len(body.Extensions)))
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "missing id param", http.StatusBadRequest)
			return
		}
		// The DELETE addresses a profile by id, but rules reference it by
		// NAME. Resolve the name under the store lock (NameByID copies it —
		// reading GetByID().Name outside the lock races a concurrent rename).
		// A bad/stale id falls through to Delete's own 404 (never a spurious
		// 409). Then block via the shared walk if any rule still references
		// the profile — deleting a referenced profile was fail-open for the
		// file-control dimension.
		// NOTE: this closes DELETE only. A profile RENAME still dangles every
		// rule holding the old name (profiles are id-keyed with a mutable
		// name) — an open fail-open the object-ID work (P3) closes; see
		// roadmap/POLICY-REFS-PLAN.md.
		if profName, ok := globalProfileStore.NameByID(id); ok {
			if deleteBlockedByReferences(w, r, "file-profile", profName, "fileprofile.delete.blocked") {
				return
			}
		}
		if err := globalProfileStore.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEvent(r, "fileprofile.delete", id, "")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiSecScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, secScanStatusMap())
}

// POST /api/security-scan/feeds/sync — trigger an immediate threat feed sync.
// Returns the updated status after the sync completes.
func apiSecFeedsSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if !globalThreatFeed.Enabled() {
		http.Error(w, "threat feeds not enabled", http.StatusServiceUnavailable)
		return
	}
	// Run the sync synchronously so the response reflects the updated data.
	globalThreatFeed.Sync()
	// Audit the manual sync — admin-only operation that mutates the data
	// driving every block decision. See docs/C15_UNKNOWN_AUDIT.md §3.2.
	auditEvent(r, "threatfeed.sync", "manual", "")
	jsonOK(w, secScanStatusMap())
}

// GET /api/security-scan/feeds/domain-allowlist — list domains exempt from
// domain-level threat feed blocking (URL-level blocking still applies).
// PUT /api/security-scan/feeds/domain-allowlist — replace the allowlist.
//
// Allowlist state is HA-distributed via ConfigSnapshot.ThreatDomainAllowlist
// (controlplane.go:104) and intentionally OUT of the config-version
// rollback surface — putting it on rollback would create a CP/DP
// dual-authority hazard. Do NOT add saveConfigVersion here.
// See roadmap/DOMAIN-ALLOWLIST-ROLLBACK-CLASSIFICATION.md.
func apiDomainAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		list := globalThreatFeed.DomainAllowlist()
		if list == nil {
			list = []string{}
		}
		jsonOK(w, map[string]any{"domains": list})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Domains []string `json:"domains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := globalThreatFeed.SetDomainAllowlist(body.Domains); err != nil {
			// The allowlist is already live in memory (fail-safe apply,
			// same posture as the DP snapshot path) — until restart it
			// bypasses domain-level threat blocking even though the
			// client sees a 500. That transient bypass must stay
			// attributable, so record a distinct audit action instead
			// of silently dropping the trail with the success entry.
			auditEvent(r, "threatfeed.allowlist.update_unpersisted",
				fmt.Sprintf("%d domain(s) applied in memory; persist failed", len(globalThreatFeed.DomainAllowlist())), "")
			http.Error(w, "domain allowlist applied in memory but failed to persist", http.StatusInternalServerError)
			return
		}
		logger.Printf("ThreatFeed: domain allowlist updated (%d entries)", len(body.Domains))
		// Push the change to DP nodes now (mirrors the IdP handlers in
		// ui_auth.go). Without a version bump DPs keep enforcing the OLD
		// allowlist until some unrelated admin action publishes a
		// snapshot — the exact "unblock this false positive NOW" latency
		// this control exists to remove. No-op when not running as CP.
		_ = publishCurrentConfigSnapshot()
		// Closes the audit gap flagged by
		// roadmap/DOMAIN-ALLOWLIST-ROLLBACK-CLASSIFICATION.md §3.5 and
		// ui_routes_meta.go:291 ("no direct auditEvent observed"). The
		// PUT is an admin-only, security-relevant mutation (it edits
		// the set of domains that bypass threat-feed blocking — see
		// threatfeed.go:236 DomainAllowlisted) and must leave an audit
		// trail. Object holds a count summary; detail stays empty to
		// avoid writing admin-supplied domain strings into the audit
		// ring (matches the connlimit / blockpage / upstream sibling
		// pattern in ui_config.go).
		//
		// Count is read AFTER SetDomainAllowlist via the post-normalization
		// DomainAllowlist() (threatfeed.go:255 trims, lowercases, skips
		// empty, dedupes via map), so the audit reflects what was actually
		// stored — raw len(body.Domains) over-reports when clients send
		// blanks, duplicates, or case/whitespace variants (Codex P2 on PR #284).
		count := len(globalThreatFeed.DomainAllowlist())
		auditEvent(r, "threatfeed.allowlist.update", fmt.Sprintf("%d domain(s)", count), "")
		jsonOK(w, map[string]any{"ok": true, "count": count})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/security-scan/yara/reload — reload YARA rules from the configured
// directory without restarting the proxy.
func apiSecYARAReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	dir := globalYARA.Dir() // engine moved to internal/yara; use the exported getter
	if dir == "" {
		http.Error(w, "no YARA rules directory configured", http.StatusServiceUnavailable)
		return
	}
	if err := globalYARA.LoadDir(dir); err != nil {
		http.Error(w, "YARA reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Tier 1.1: Clear hash cache so content scanned as clean under old rules
	// is re-scanned under the new rule set. Without this, new rules don't
	// apply to previously-cached content until the 1-hour TTL expires.
	globalSecScanner.CacheClear()
	auditEvent(r, "security.yara_reload", dir, "YARA rules reloaded and hash cache cleared")
	jsonOK(w, map[string]any{
		"yara_rules":    globalYARA.Count(),
		"directory":     dir,
		"cache_cleared": true,
		"warnings":      globalYARA.Warnings(),
	})
}

// apiSecYARARules handles list + CRUD for YARA rule files:
//
//	GET    /api/security-scan/yara/rules           — list rule files + contained rule names
//	GET    /api/security-scan/yara/rules/{name}    — read one rule file source (name = file stem)
//	POST   /api/security-scan/yara/rules           — create rule file (JSON body)
//	PUT    /api/security-scan/yara/rules/{name}    — update rule file (JSON body)
//	DELETE /api/security-scan/yara/rules/{name}    — remove rule file
//
// yaraSettingsMap returns the current YARA engine runtime config as a map
// suitable for JSON serialisation.
func yaraSettingsMap() map[string]any {
	return map[string]any{
		"enabled":        yaraGetEnabled(),
		"timeout_secs":   yaraGetTimeoutSecs(),
		"max_inflight":   yaraGetMaxInflight(),
		"on_timeout":     yaraGetOnTimeout(),
		"on_saturation":  yaraGetOnSaturation(),
		"alert_degraded": yaraGetAlertDegraded(),
	}
}

// validateYARASettings returns an error if any setting value is out of range.
func validateYARASettings(timeoutSecs, maxInflight int64, onTimeout, onSaturation string) error {
	if timeoutSecs < 1 || timeoutSecs > 60 {
		return fmt.Errorf("timeout_secs must be between 1 and 60")
	}
	if maxInflight < 1 || maxInflight > 500 {
		return fmt.Errorf("max_inflight must be between 1 and 500")
	}
	valid := map[string]bool{yaraFailClosed: true, yaraFailOpenWithAlert: true}
	if !valid[onTimeout] {
		return fmt.Errorf("on_timeout must be %q or %q", yaraFailClosed, yaraFailOpenWithAlert)
	}
	if !valid[onSaturation] {
		return fmt.Errorf("on_saturation must be %q or %q", yaraFailClosed, yaraFailOpenWithAlert)
	}
	return nil
}

// GET /api/security-scan/yara/settings — read YARA engine runtime config.
// PUT /api/security-scan/yara/settings — update YARA engine runtime config.
func apiSecYARASettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, yaraSettingsMap())

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Enabled       bool   `json:"enabled"`
			TimeoutSecs   int64  `json:"timeout_secs"`
			MaxInflight   int64  `json:"max_inflight"`
			OnTimeout     string `json:"on_timeout"`
			OnSaturation  string `json:"on_saturation"`
			AlertDegraded bool   `json:"alert_degraded"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := validateYARASettings(body.TimeoutSecs, body.MaxInflight, body.OnTimeout, body.OnSaturation); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		prev := yaraSettingsMap()
		yaraSetEnabled(body.Enabled)
		yaraSetTimeoutSecs(body.TimeoutSecs)
		yaraSetMaxInflight(body.MaxInflight)
		yaraSetOnTimeout(body.OnTimeout)
		yaraSetOnSaturation(body.OnSaturation)
		yaraSetAlertDegraded(body.AlertDegraded)
		auditEventDiff(r, "security.yara_settings", "yara_engine", "", prev, yaraSettingsMap())
		adminSettingsSave()
		// Intentionally NOT calling saveConfigVersion: YARA engine
		// settings are out of the rollback surface by design (D-sec,
		// CONFIG-VERSIONING-TRIAGE.md §4.2). Rolling back could
		// un-harden yara_on_timeout / yara_on_saturation / yara_enabled
		// — silently relaxing a scanner posture the operator chose to
		// tighten.
		jsonOK(w, yaraSettingsMap())

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// "name" in the path / body always refers to the *file stem* (no extension).
// Rule files may bundle many YARA rules; the `file_rules` field in the GET
// response maps each file to its contained rule identifiers for display.
//
// Writes go to globalYARA.Dir() (persistent /data/yara/ in Docker). Each
// mutation validates the rule source with ValidateYARASource BEFORE touching
// disk and atomically replaces the full rule set via LoadDir. Tier 2.1 + 3.2.
func apiSecYARARules(w http.ResponseWriter, r *http.Request) {
	// Extract {name} from the URL path if present.
	const prefix = "/api/security-scan/yara/rules"
	name := ""
	if len(r.URL.Path) > len(prefix) && r.URL.Path[len(prefix)] == '/' {
		name = strings.TrimPrefix(r.URL.Path, prefix+"/")
	}

	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		if name == "" {
			jsonOK(w, map[string]any{
				"directory":  globalYARA.Dir(),
				"files":      globalYARA.Files(),     // file stems — use for CRUD
				"file_rules": globalYARA.FileRules(), // filename → rule names inside
				"rules":      globalYARA.Names(),     // compiled rule names (display only)
				"warnings":   globalYARA.Warnings(),
				"count":      globalYARA.Count(),
			})
			return
		}
		src, err := globalYARA.ReadRule(name)
		if err != nil {
			http.Error(w, "read rule: "+err.Error(), http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]any{
			"name":   name,
			"source": src,
		})

	case http.MethodPost, http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var req struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&req); err != nil {
			http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		// URL {name} overrides body name for PUT so the admin can't rename a
		// rule via the body payload unexpectedly.
		if name != "" {
			req.Name = name
		}
		if req.Name == "" {
			http.Error(w, "missing rule name", http.StatusBadRequest)
			return
		}
		warnings, err := globalYARA.WriteRule(req.Name, req.Source)
		if err != nil {
			http.Error(w, "write rule: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Hash cache must be cleared on any rule change (Tier 1.1 applies to CRUD).
		globalSecScanner.CacheClear()
		auditEvent(r, "security.yara_write", req.Name, fmt.Sprintf("%d warning(s)", len(warnings)))
		// Intentionally NOT calling saveConfigVersion: YARA rule files
		// are out of the rollback surface by design (D-ops,
		// CONFIG-VERSIONING-TRIAGE.md §4.2). Rules are filesystem
		// artifacts compiled at engine load, typically managed in an
		// operator's external VCS — not JSON-blob admin state.
		jsonOK(w, map[string]any{
			"name":          req.Name,
			"warnings":      warnings,
			"yara_rules":    globalYARA.Count(),
			"cache_cleared": true,
		})

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		if name == "" {
			// Also accept ?name= for clients that can't DELETE with a path.
			name = r.URL.Query().Get("name")
		}
		if name == "" {
			http.Error(w, "missing rule name", http.StatusBadRequest)
			return
		}
		if err := globalYARA.DeleteRule(name); err != nil {
			http.Error(w, "delete rule: "+err.Error(), http.StatusBadRequest)
			return
		}
		globalSecScanner.CacheClear()
		auditEvent(r, "security.yara_remove", name, "rule removed and cache cleared")
		// Intentionally NOT calling saveConfigVersion: YARA rule files
		// are out of the rollback surface by design (D-ops,
		// CONFIG-VERSIONING-TRIAGE.md §4.2). See the yara_write branch.
		jsonOK(w, map[string]any{
			"deleted":       name,
			"yara_rules":    globalYARA.Count(),
			"cache_cleared": true,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiSecYARAValidate dry-runs ValidateYARASource against a rule body so admins
// can check a new rule in the UI before persisting it. Tier 3.1.
func apiSecYARAValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	var req struct {
		Source string `json:"source"`
		Rule   string `json:"rule"` // alias accepted for convenience
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&req); err != nil {
		http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	src := req.Source
	if src == "" {
		src = req.Rule
	}
	if strings.TrimSpace(src) == "" {
		http.Error(w, "missing source", http.StatusBadRequest)
		return
	}
	names, warnings, err := ValidateYARASource(src)
	if err != nil {
		jsonOK(w, map[string]any{
			"valid":    false,
			"error":    err.Error(),
			"warnings": warnings,
		})
		return
	}
	jsonOK(w, map[string]any{
		"valid":      true,
		"rule_names": names,
		"warnings":   warnings,
	})
}

// apiSecScanExclusions exposes the admin-managed ScanExclusionStore.
//
//	GET /api/security-scan/exclusions        — return current lists
//	PUT /api/security-scan/exclusions        — replace lists ({hashes, hosts})
//
// Tier 3.3.
func apiSecScanExclusions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		hashes, hosts := globalScanExclusions.Lists()
		jsonOK(w, map[string]any{
			"hashes": hashes,
			"hosts":  hosts,
		})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var req struct {
			Hashes []string `json:"hashes"`
			Hosts  []string `json:"hosts"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		globalScanExclusions.Replace(req.Hashes, req.Hosts)
		if err := globalScanExclusions.Save(); err != nil {
			logger.Printf("ScanExclusions: save error: %v", err)
		}
		auditEvent(r, "security.scan_exclusions", "update", fmt.Sprintf("%d hash(es), %d host(s)", len(req.Hashes), len(req.Hosts)))
		// Intentionally NOT calling saveConfigVersion: scan exclusions
		// are out of the rollback surface by design (D-sec,
		// CONFIG-VERSIONING-TRIAGE.md §4.2). Exclusions are
		// trust-elevation lists (excluded hashes/hosts skip scanning);
		// a rollback could re-add a removed exclusion, re-trusting a
		// binary/host the operator just chose to scan. Same shape as
		// auth.password_change.
		hashes, hosts := globalScanExclusions.Lists()
		jsonOK(w, map[string]any{
			"hashes": hashes,
			"hosts":  hosts,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiContentScanBypass exposes the DPI per-host bypass list.
//
//	GET/PUT /api/dpi/bypass             — canonical path (terminology governance T-10)
//	GET/PUT /api/content-scan/bypass    — deprecated alias, retained for compat
//
// Tier 3.4.
func apiContentScanBypass(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{"hosts": dpiScanner.BypassHosts()})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var req struct {
			Hosts []string `json:"hosts"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
			http.Error(w, "bad JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		dpiScanner.SetBypassHosts(req.Hosts)
		dpiScanner.Save()
		auditEvent(r, "security.dpi_bypass", "update", fmt.Sprintf("%d host(s)", len(req.Hosts)))
		// Bypass hosts are in the rollback surface as of
		// roadmap/SCANNER-ROLLBACK-EXTENSION-SPEC.md (configBackup
		// .ContentScanBypassHosts); snapshot so rollback restores them.
		saveConfigVersion(sessionAdmin(r), "security.dpi_bypass")
		jsonOK(w, map[string]any{"hosts": dpiScanner.BypassHosts()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/security-scan/svc — returns scan microservice configuration.
func apiScanSvcConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	resp := map[string]interface{}{
		"remote_enabled": globalRemoteScanner.Enabled(),
		"remote_url":     globalRemoteScanner.URL(),
	}
	if globalRemoteScanner.Enabled() {
		if err := globalRemoteScanner.Health(); err != nil {
			resp["remote_status"] = "unreachable: " + err.Error()
		} else {
			resp["remote_status"] = "connected"
		}
	}
	jsonOK(w, resp)
}

// GET    /api/security-scan/cache          — return cache stats (hits, misses, size).
// DELETE /api/security-scan/cache          — clear entire scan hash cache.
// DELETE /api/security-scan/cache?hash=xxx — evict a single hash from the cache.
func apiScanCache(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		if !globalSecScanner.CacheReady() {
			jsonOK(w, map[string]any{"enabled": false})
			return
		}
		hits, misses, size := globalSecScanner.CacheStats()
		jsonOK(w, map[string]any{
			"enabled":      true,
			"cache_hits":   hits,
			"cache_misses": misses,
			"cache_size":   size,
		})

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		if !globalSecScanner.CacheReady() {
			http.Error(w, "scan cache not enabled", http.StatusServiceUnavailable)
			return
		}
		hash := r.URL.Query().Get("hash")
		if hash != "" {
			found := globalSecScanner.CacheEvict(hash)
			auditEvent(r, "scan_cache.evict", sanitizeLog(hash), "")
			jsonOK(w, map[string]any{"evicted": found, "hash": hash})
		} else {
			globalSecScanner.CacheClear()
			auditEvent(r, "scan_cache.clear", "all", "")
			jsonOK(w, map[string]any{"cleared": true})
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CA Management API
// ═══════════════════════════════════════════════════════════════════════════════

func apiCAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	info := certMgr.CACertInfo()
	info["cacheSize"] = certMgr.CertCacheLen()
	info["cacheMax"] = 10_000
	info["cacheTTL"] = "1h"
	info["leafValidity"] = "24h"
	info["autoRotation"] = true
	info["rotationOverlapDays"] = 30
	info["keyProvider"] = certMgr.KeyProviderName()
	expiry := certMgr.CAExpiry()
	if !expiry.IsZero() {
		info["expiresIn"] = time.Until(expiry).Round(time.Hour).String()
	}
	// CHAOS-28 usability posture. `ready` only says a CA is LOADED; a CA outside
	// its own validity window is loaded, signs nothing a client accepts, and
	// used to render as a perfectly healthy panel. These fields are what an
	// operator sees when inspected HTTPS stops working fleet-wide.
	usabilityErr := certMgr.Usable()
	info["usable"] = usabilityErr == nil
	if usabilityErr != nil {
		info["unusableReason"] = usabilityErr.Error()
	}
	caFaults := caUsabilityFailures()
	info["inspectBlocked"] = caFaults.Blocks
	info["signRefused"] = certMgr.SignRefusals()
	// rotationPersistFailures is the CUMULATIVE history; rotationPersistDegraded
	// is whether the ACTIVE CA may be memory-only right now. The panel banner
	// keys on the latter so it clears once a rotation actually persists.
	info["rotationPersistFailures"] = caFaults.PersistFailures
	info["rotationPersistDegraded"] = caFaults.PersistDegraded
	if caFaults.PersistDegraded && caFaults.PersistErr != "" {
		info["rotationPersistError"] = caFaults.PersistErr
	}
	// CHAOS-50 load/recovery posture. `ready:false` alone does not distinguish
	// "no CA configured on this node" from "the configured CA could not be
	// loaded and every inspect-matched CONNECT is being forwarded UNINSPECTED" —
	// opposite operator instructions from the same field. `inspectBypassed` is
	// the fail-OPEN counterpart to `inspectBlocked` above.
	loadFailure := sslInspectionLoadFailure()
	info["loadFailed"] = loadFailure != ""
	if loadFailure != "" {
		info["loadFailureReason"] = loadFailure
	}
	info["inspectBypassed"] = caInspectBypassCount()
	rec := caLoadRecoveryStatus()
	info["loadRecoveryAttempts"] = rec.Attempts
	info["loadRecoveryGaveUp"] = rec.GaveUp
	if rec.LastErr != "" {
		info["loadRecoveryError"] = rec.LastErr
	}
	// Dual-CA overlap status.
	info["dualCAActive"] = certMgr.SecondaryCAActive()
	if secInfo := certMgr.SecondaryCAInfo(); secInfo != nil {
		info["secondaryCA"] = secInfo
	}
	jsonOK(w, info)
}

// persistRotatedCA writes the freshly-rotated Root CA to the configured bundle
// path and reports whether it landed. It is the manual force-rotate half of the
// CHAOS-28 / CA-2 fix: this path carried the same swallowed-save defect as
// auto-rotation — it logged the error, then answered 200 and bumped the success
// counter for a CA that lives only in RAM. An operator force-rotating to RECOVER
// from an expiry outage is exactly the person who must not be told it worked.
//
// Returns true when nothing needed writing (no bundle path configured), because
// there is no durability claim to fail in that configuration.
func persistRotatedCA() bool {
	if caRuntime.path == "" {
		return true
	}
	if err := certMgr.SaveCA(caRuntime.path, caRuntime.passphrase); err != nil {
		logger.Printf("CA force-rotate: save failed: %v", err)
		noteCARotationPersistFailure(err.Error())
		return false
	}
	noteCARotationPersisted()
	return true
}

// apiCADownload is a back-compat alias of apiCACert's PEM-download branch,
// reached from the CA Management panel. See writeCACertPEM.
func apiCADownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	writeCACertPEM(w)
}

// apiCACacheClear flushes the in-memory leaf-certificate LRU cache.
//
// Intentionally OUT of the config-version rollback surface — the leaf cache is
// ephemeral in-memory runtime state (rebuilt on demand from the Root CA), with
// no persistent config to version. Classified runtime-only (category E). Do
// NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §3 (category E).
func apiCACacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	certMgr.ClearCache()
	auditEvent(r, "ca.cache_clear", "leaf_cert_cache", "")
	jsonOK(w, map[string]any{"ok": true})
}

// apiCARotate rotates the Root CA.
//
// Intentionally OUT of the config-version rollback surface — CA
// rotation is a forward-only trust decision; rolling back would
// silently restore a superseded CA, plus risk writing CA private-key
// material in plaintext to config-version snapshot files. Do NOT add
// saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (D-sec).
func apiCARotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}

	// Parse request body for two-step confirmation flow.
	var req struct {
		Confirm bool   `json:"confirm"`
		Token   string `json:"confirmation_token"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck // empty body is valid (step 1)
	}

	if !req.Confirm {
		// Step 1: generate confirmation token and return warning.
		var tokenBytes [16]byte
		if _, err := rand.Read(tokenBytes[:]); err != nil {
			http.Error(w, "failed to generate confirmation token", http.StatusInternalServerError)
			return
		}
		token := hex.EncodeToString(tokenBytes[:])

		pendingCARotation.Lock()
		pendingCARotation.token = token
		pendingCARotation.expires = time.Now().Add(60 * time.Second)
		pendingCARotation.Unlock()

		auditEvent(r, "ca.rotate_requested", "root_ca", "rotation confirmation token issued")
		jsonOK(w, map[string]any{
			"status":             "pending_confirmation",
			"confirmation_token": token,
			"expires_in_seconds": 60,
			"warning":            "Rotating the Root CA will invalidate all existing leaf certificates and the current CA trust chain. All client workstations and devices will need to trust the new CA certificate. This action cannot be undone.",
		})
		return
	}

	// Step 2: verify confirmation token and perform rotation.
	pendingCARotation.Lock()
	storedToken := pendingCARotation.token
	expires := pendingCARotation.expires
	pendingCARotation.token = ""
	pendingCARotation.expires = time.Time{}
	pendingCARotation.Unlock()

	if storedToken == "" || time.Now().After(expires) {
		http.Error(w, "confirmation token expired or not found — please request rotation again", http.StatusBadRequest)
		return
	}
	if req.Token != storedToken {
		http.Error(w, "invalid confirmation token", http.StatusForbidden)
		return
	}

	// Under caMutationMu so an in-flight automatic recovery attempt cannot land
	// between the install and the persist and overwrite this rotation with the
	// bundle it was already reading (see rootca_recovery.go). The HTTP response
	// is written after the lock is released.
	info, persisted, err := installAndPersistRotatedCA()
	if err != nil {
		http.Error(w, "rotation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !persisted {
		// Still 200: the rotation DID happen and the new CA is active, so
		// reporting an error would be wrong in the other direction. The caller
		// is told what did not happen instead.
		info["persisted"] = false
		info["warning"] = "The new Root CA could not be written to disk — it exists in memory only and will be LOST on restart. Restore write access to the CA bundle path and rotate again."
		auditEvent(r, "ca.rotate", "root_ca", "force rotation via admin API (confirmed) — NOT PERSISTED, in-memory only")
		jsonOK(w, info)
		return
	}
	statCARotations.Add(1)
	auditEvent(r, "ca.rotate", "root_ca", "force rotation via admin API (confirmed)")
	jsonOK(w, info)
}

// installAndPersistRotatedCA mints a new Root CA, writes it to the configured
// bundle path, and clears the recorded load failure — as ONE operation under
// caMutationMu, so the automatic recovery loop cannot interleave with it.
//
// The latch clear is deliberately gated on the persist. A force-rotate is the
// documented manual recovery from a failed CA load and is the EVIDENCE that
// clears the recorded failure (without it, /healthz, /readyz?strict=1 and the
// support-telemetry readiness row keep reporting the fault after the operator has
// fixed it — a red probe that outlives what it describes). But a rotation that did
// not reach disk resolves only the load half, not the durability half, so the
// failure must stay recorded.
func installAndPersistRotatedCA() (info map[string]any, persisted bool, err error) {
	caMutationMu.Lock()
	defer caMutationMu.Unlock()

	if err := certMgr.InitCA(); err != nil {
		return nil, false, err
	}
	info = certMgr.CACertInfo()
	if !persistRotatedCA() {
		return info, false, nil
	}
	noteSSLInspectionRecovered("force rotation via admin API")
	return info, true, nil
}

// installAndPersistCustomMITMCA is the custom-CA-upload counterpart of
// installAndPersistRotatedCA, under the same lock for the same reason.
func installAndPersistCustomMITMCA(certPEM, keyPEM []byte) (persisted bool, err error) {
	caMutationMu.Lock()
	defer caMutationMu.Unlock()

	if err := certMgr.LoadCustomCA(certPEM, keyPEM); err != nil {
		return false, err
	}
	// Unlike persistRotatedCA's force-rotate caller — where an ephemeral,
	// in-memory-only CA was already the documented behavior with no bundle
	// path configured, so "no failure" is the right answer — an uploaded
	// custom CA is an admin-supplied secret the admin was just told is
	// "persisted". No bundle path configured means there is nowhere to
	// write it, so this must report false (in-memory only), not reuse
	// persistRotatedCA's "no durability claim to fail" semantics.
	if caRuntime.path == "" {
		return false, nil
	}
	if !persistRotatedCA() {
		return false, nil
	}
	noteSSLInspectionRecovered("custom MITM CA uploaded via admin API")
	return true, nil
}

// apiCAKeyProvider returns the current key provider status for HSM/KMS UI.
func apiCAKeyProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	providerName := certMgr.KeyProviderName()
	jsonOK(w, map[string]any{
		"provider":     providerName,
		"isExternal":   providerName != "local",
		"caReady":      certMgr.Ready(),
		"dualCAActive": certMgr.SecondaryCAActive(),
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// OCSP Management API
// ═══════════════════════════════════════════════════════════════════════════════

// apiOCSPConfig manages OCSP/CRL revocation-check posture.
//
// Intentionally OUT of the config-version rollback surface — relaxing
// revocation checking via rollback would silently re-permit traffic
// to certs the admin deliberately tightened against. Do NOT add
// saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (D-sec).
func apiOCSPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var lastFailClosedAt string
		if t := globalOCSP.LastFailClosedAt(); !t.IsZero() {
			lastFailClosedAt = t.Format(time.RFC3339)
		}
		jsonOK(w, map[string]any{
			"enabled":          globalOCSP.Enabled(),
			"cacheLen":         globalOCSP.CacheLen(),
			"failClosedTotal":  globalOCSP.FailClosedTotal(),
			"revokedTotal":     globalOCSP.RevokedTotal(),
			"lastFailClosedAt": lastFailClosedAt,
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Enabled {
			globalOCSP.Enable()
			// P5.3: route through swapUpstreamTransport so the OCSP
			// verify callbacks land on the operator's TLS template
			// (upstreamOpTLSCfg). The swap attaches a Clone of the
			// updated template to the new transport — the stdlib's
			// lazy h2 setup mutates the clone, not the template.
			swapUpstreamTransport(func(old *http.Transport) *http.Transport {
				if upstreamOpTLSCfg == nil {
					upstreamOpTLSCfg = &tls.Config{MinVersion: tls.VersionTLS13}
				}
				if upstreamOpTLSCfg.MinVersion == 0 {
					upstreamOpTLSCfg.MinVersion = tls.VersionTLS13
				}
				ConfigureTLSConfigOCSP(upstreamOpTLSCfg)
				return cloneTransport(old)
			})
		} else {
			globalOCSP.Disable()
		}
		auditEvent(r, "ocsp.toggle", fmt.Sprintf("enabled=%v", body.Enabled), "")
		jsonOK(w, map[string]any{"ok": true, "enabled": globalOCSP.Enabled()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// GeoIP Config API
// ═══════════════════════════════════════════════════════════════════════════════

func apiGeoIPConfig(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	resp := map[string]any{
		"enabled": geoip.Enabled(),
		"dbPath":  uiCfgGeoIPDB,
	}
	if built, ok := geoip.BuildTime(); ok && !built.IsZero() {
		resp["dbBuildDate"] = built.Format(time.RFC3339)
		resp["dbAgeDays"] = int(time.Since(built).Hours() / 24)
	}
	// Surface a failed database load (bad path, corrupt/expired .mmdb) so an
	// admin can tell "disabled — never configured" apart from "disabled — the
	// configured database won't open" without reading the process log. See
	// destCountry policy rules, which fail closed (no match) the same way in
	// both cases.
	if msg, at, ok := geoip.LoadError(); ok {
		resp["lastError"] = msg
		resp["lastErrorAt"] = at.UTC().Format(time.RFC3339)
	}
	jsonOK(w, resp)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Logger Config API
// ═══════════════════════════════════════════════════════════════════════════════

// registerSecurityRoutes wires the security panel: TLS inspect (CA + cert
// upload + SSL bypass), DPI content scanning, ClamAV/YARA/threat-feed
// scanning, alert webhooks, OCSP, and GeoIP status. All routes are gated
// by uiAuthMiddleware; per-handler RBAC is the handler's responsibility.
func registerSecurityRoutes(mux *http.ServeMux) {
	// ── Core security knobs + TLS inspect ─────────────────────────────────
	mux.HandleFunc("/api/security", apiSecurity)
	mux.HandleFunc("/api/ca-cert", apiCACert)
	mux.HandleFunc("/api/certs/upload", apiCertsUpload)
	mux.HandleFunc("/api/ssl-bypass", apiSSLBypass)
	mux.HandleFunc("/api/content-scan", apiContentScan) // legacy alias; canonical path is /api/dpi (terminology governance T-10)
	mux.HandleFunc("/api/dpi", apiContentScan)

	// ── Security scanning (ClamAV / YARA / Threat Feeds) ─────────────────
	mux.HandleFunc("/api/security-scan/status", apiSecScanStatus)                   // GET
	mux.HandleFunc("/api/security-scan/feeds/sync", apiSecFeedsSync)                // POST — force immediate sync
	mux.HandleFunc("/api/security-scan/feeds/domain-allowlist", apiDomainAllowlist) // GET/PUT — threat feed domain allowlist
	mux.HandleFunc("/api/security-scan/yara/reload", apiSecYARAReload)              // POST — reload YARA rules from dir
	mux.HandleFunc("/api/security-scan/yara/rules", apiSecYARARules)                // GET/POST/PUT/DELETE — list / CRUD YARA rule files
	mux.HandleFunc("/api/security-scan/yara/rules/", apiSecYARARules)               // PUT/DELETE /api/security-scan/yara/rules/{name}
	mux.HandleFunc("/api/security-scan/yara/validate", apiSecYARAValidate)          // POST — dry-run validate a YARA rule source
	mux.HandleFunc("/api/security-scan/yara/settings", apiSecYARASettings)          // GET/PUT — YARA engine runtime config
	mux.HandleFunc("/api/security-scan/exclusions", apiSecScanExclusions)           // GET/PUT — scan exclusion hashes/hosts
	mux.HandleFunc("/api/security-scan/svc", apiScanSvcConfig)                      // GET — scan service mode info
	mux.HandleFunc("/api/security-scan/cache", apiScanCache)                        // GET/DELETE — scan hash cache stats & purge
	mux.HandleFunc("/api/content-scan/bypass", apiContentScanBypass)                // GET/PUT — legacy alias; canonical path is /api/dpi/bypass (T-10)
	mux.HandleFunc("/api/dpi/bypass", apiContentScanBypass)                         // GET/PUT — DPI bypass host list

	// ── Alert webhooks ───────────────────────────────────────────────────
	mux.HandleFunc("/api/alerts/webhooks", apiAlertsWebhooks)             // GET list / POST create
	mux.HandleFunc("/api/alerts/webhooks/test", apiAlertsWebhookTest)     // POST — test-fire
	mux.HandleFunc("/api/alerts/webhooks/history", apiAlertsDeliveryHist) // GET — delivery history (Finding 8.1)

	// ── CA management ────────────────────────────────────────────────────
	mux.HandleFunc("/api/ca/status", apiCAStatus)            // GET — CA info + cache + rotation + dual-CA
	mux.HandleFunc("/api/ca/key-provider", apiCAKeyProvider) // GET key provider status
	mux.HandleFunc("/api/ca/download", apiCADownload)        // GET — PEM download
	mux.HandleFunc("/api/ca/cache-clear", apiCACacheClear)   // POST — clear leaf cert cache
	mux.HandleFunc("/api/ca/rotate", apiCARotate)            // POST — force CA rotation

	// ── OCSP management ─────────────────────────────────────────────────
	mux.HandleFunc("/api/ocsp", apiOCSPConfig) // GET status / POST toggle

	// ── GeoIP status ────────────────────────────────────────────────────
	mux.HandleFunc("/api/geoip", apiGeoIPConfig)
}
