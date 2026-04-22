package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)


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
	ok2 := deliverWebhook(globalAlertStore, h, payload)
	jsonOK(w, map[string]any{"ok": ok2, "delivered": ok2})
}

// GET /api/alerts/webhooks/history — delivery history (Finding 8.1).
func apiAlertsDeliveryHist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{"deliveries": globalAlertStore.DeliveryHistory()})
}

func apiSecurity(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"ipFilterMode":       ipf.Mode(),
			"ipList":             ipf.List(),
			"rateLimitRPM":       rl.Limit(),
			"rateLimitOn":        rl.Enabled(),
			"rateLimitExempt":    rl.ListExemptions(),
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
		pem := certMgr.CACertPEM()
		if pem == nil {
			http.Error(w, "CA not initialised", http.StatusServiceUnavailable)
			return
		}
		// Return JSON metadata or raw PEM depending on Accept header.
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			info := certMgr.CACertInfo()
			jsonOK(w, info)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="culvert-ca.pem"`)
		w.Write(pem) //nolint:errcheck // HTTP response write
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/certs/upload — upload a custom TLS certificate+key for the UI or MITM engine.
// Body: multipart/form-data with fields: "cert" (PEM), "key" (PEM), "target" ("ui"|"mitm")
func apiCertsUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // enforce 1 MB limit before parsing
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
		if err := certMgr.LoadCustomCA(certPEM, keyPEM); err != nil {
			logger.Printf("certs upload MITM: %v", err)
			http.Error(w, "invalid CA cert/key pair", http.StatusBadRequest)
			return
		}
		auditEvent(r, "certs.upload_mitm", "custom MITM CA", "")
		jsonOK(w, map[string]string{"status": "ok", "target": "mitm"})
		return
	}
	// UI cert — validate only; actual rotation requires restart.
	if _, err := certMgr.ParseTLSPair(certPEM, keyPEM); err != nil {
		logger.Printf("certs upload UI: %v", err)
		http.Error(w, "invalid cert/key pair", http.StatusBadRequest)
		return
	}
	auditEvent(r, "certs.upload_ui", "custom UI cert (requires restart)", "")
	jsonOK(w, map[string]string{"status": "ok", "target": "ui", "note": "restart required to activate"})
}

// GET/POST /api/default-action — read or update the default policy action at runtime.
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
			logger.Printf("UI: content-scan pattern added %q", p)
			added++
		}
		dpiScanner.Save()
		auditEvent(r, "content_scan.add", fmt.Sprintf("%d pattern(s)", added),
			strings.Join(body.Patterns, ", "))
		saveConfigVersion(sessionAdmin(r), "content_scan.add")
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
		logger.Printf("UI: content-scan pattern removed %q", pattern)
		auditEvent(r, "content_scan.remove", pattern, "")
		saveConfigVersion(sessionAdmin(r), "content_scan.remove")
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
	jsonOK(w, secScanStatusMap())
}

// GET /api/security-scan/feeds/domain-allowlist — list domains exempt from
// domain-level threat feed blocking (URL-level blocking still applies).
// PUT /api/security-scan/feeds/domain-allowlist — replace the allowlist.
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
		globalThreatFeed.SetDomainAllowlist(body.Domains)
		logger.Printf("ThreatFeed: domain allowlist updated (%d entries)", len(body.Domains))
		jsonOK(w, map[string]any{"ok": true, "count": len(body.Domains)})
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
	globalYARA.mu.RLock()
	dir := globalYARA.dir
	globalYARA.mu.RUnlock()

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
	globalSecScanner.cache.Clear()
	auditEvent(r, "security.yara-reload", dir, "YARA rules reloaded and hash cache cleared")
	jsonOK(w, map[string]any{
		"yara_rules":    globalYARA.Count(),
		"directory":     dir,
		"cache_cleared": true,
		"warnings":      globalYARA.Warnings(),
	})
}

// apiSecYARARules handles list + CRUD for YARA rule files:
//
//   GET    /api/security-scan/yara/rules           — list rule files + contained rule names
//   GET    /api/security-scan/yara/rules/{name}    — read one rule file source (name = file stem)
//   POST   /api/security-scan/yara/rules           — create rule file (JSON body)
//   PUT    /api/security-scan/yara/rules/{name}    — update rule file (JSON body)
//   DELETE /api/security-scan/yara/rules/{name}    — remove rule file
//
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
		globalSecScanner.cache.Clear()
		auditEvent(r, "security.yara-write", req.Name, fmt.Sprintf("%d warning(s)", len(warnings)))
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
		globalSecScanner.cache.Clear()
		auditEvent(r, "security.yara-delete", name, "rule removed and cache cleared")
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
//   GET /api/security-scan/exclusions        — return current lists
//   PUT /api/security-scan/exclusions        — replace lists ({hashes, hosts})
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
		auditEvent(r, "security.scan-exclusions", "update", fmt.Sprintf("%d hash(es), %d host(s)", len(req.Hashes), len(req.Hosts)))
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
//   GET /api/content-scan/bypass             — return current bypass hosts
//   PUT /api/content-scan/bypass             — replace bypass hosts ({hosts})
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
		auditEvent(r, "security.dpi-bypass", "update", fmt.Sprintf("%d host(s)", len(req.Hosts)))
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
		if globalSecScanner == nil || globalSecScanner.cache == nil {
			jsonOK(w, map[string]any{"enabled": false})
			return
		}
		hits, misses, size := globalSecScanner.cache.Stats()
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
		if globalSecScanner == nil || globalSecScanner.cache == nil {
			http.Error(w, "scan cache not enabled", http.StatusServiceUnavailable)
			return
		}
		hash := r.URL.Query().Get("hash")
		if hash != "" {
			found := globalSecScanner.cache.Evict(hash)
			auditEvent(r, "scan_cache.evict", sanitizeLog(hash), "")
			jsonOK(w, map[string]any{"evicted": found, "hash": hash})
		} else {
			globalSecScanner.cache.Clear()
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
	// Dual-CA overlap status.
	info["dualCAActive"] = certMgr.SecondaryCAActive()
	if secInfo := certMgr.SecondaryCAInfo(); secInfo != nil {
		info["secondaryCA"] = secInfo
	}
	jsonOK(w, info)
}

func apiCADownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	pem := certMgr.CACertPEM()
	if pem == nil {
		http.Error(w, "CA not initialised", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="culvert-ca.pem"`)
	w.Write(pem) //nolint:errcheck
}

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

	if err := certMgr.InitCA(); err != nil {
		http.Error(w, "rotation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if caRuntime.path != "" {
		if err := certMgr.SaveCA(caRuntime.path, caRuntime.passphrase); err != nil {
			logger.Printf("CA force-rotate: save failed: %v", err)
		}
	}
	auditEvent(r, "ca.rotate", "root_ca", "force rotation via admin API (confirmed)")
	jsonOK(w, certMgr.CACertInfo())
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

func apiOCSPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]any{
			"enabled":  globalOCSP.Enabled(),
			"cacheLen": globalOCSP.CacheLen(),
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
			ConfigureTransportOCSP(upstreamTransport)
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
	jsonOK(w, map[string]any{
		"enabled": geoEnabled(),
		"dbPath":  uiCfgGeoIPDB,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// Logger Config API
// ═══════════════════════════════════════════════════════════════════════════════

