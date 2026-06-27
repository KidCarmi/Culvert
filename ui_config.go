package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// GET /api/audit — return configuration-change audit entries (newest first).
// Supports pagination via ?offset=N&limit=M (default: offset=0, limit=500).
// Supports date filtering via ?from=UNIX_MS&to=UNIX_MS.
// Use ?source=file to read from the persistent JSONL audit log file instead of
// the in-memory ring buffer (default: memory for backwards compat) (Finding 6.2).
func apiAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	fromTS, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	toTS, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	var entries []AuditEntry
	var total int
	if q.Get("source") == "file" {
		entries, total = auditGetPersistent(offset, limit, fromTS, toTS)
	} else {
		entries, total = auditGetMemory(offset, limit, fromTS, toTS)
	}
	jsonOK(w, map[string]any{"entries": entries, "count": len(entries), "total": total, "offset": offset, "limit": limit})
}

// GET /api/stats
func apiStats(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	total := atomic.LoadInt64(&statTotal)
	blocked := atomic.LoadInt64(&statBlocked)
	authFail := atomic.LoadInt64(&statAuthFail)
	allowed := total - blocked - authFail
	if allowed < 0 {
		allowed = 0
	}
	jsonOK(w, map[string]any{
		"total":       total,
		"allowed":     allowed,
		"blocked":     blocked,
		"authFail":    authFail,
		"blocklistSz": bl.Count(),
		"uptime":      uptime(),
		"proxyPort":   cfg.ProxyPort,
		"uiPort":      cfg.UIPort,
		"authEnabled": cfg.AuthEnabled(),
		"serverTime":  time.Now().Format("2006-01-02 15:04:05"),
		// Persistent request-log health: non-zero means writes are failing
		// (e.g. disk full) and the on-disk history is incomplete.
		"logWriteErrors": atomic.LoadInt64(&statReqLogWriteErrors),
	})
}

// GET /api/dashboard/health — System health data
func apiDashboardHealth(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	jsonOK(w, map[string]any{
		"memAllocMB":    float64(mem.Alloc) / 1024 / 1024,
		"memSysMB":      float64(mem.Sys) / 1024 / 1024,
		"goroutines":    runtime.NumGoroutine(),
		"numGC":         mem.NumGC,
		"sseClients":    hub.ClientCount(),
		"blocklistSize": bl.Count(),
		"logStore":      logStoreHealth(),
	})
}

// GET /api/dashboard/threats — Threat engine breakdown
func apiDashboardThreats(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{
		"clamav":     atomic.LoadInt64(&statClamBlocked),
		"yara":       atomic.LoadInt64(&statYARABlocked),
		"dpi":        atomic.LoadInt64(&statDPIBlocked),
		"threatFeed": atomic.LoadInt64(&statThreatFeedBlocked),
	})
}

// GET /api/dashboard/top-rules — Top policy rules by hit count
func apiDashboardTopRules(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	rules := policyStore.List()
	// Sort by HitCount descending, take top 10
	sort.Slice(rules, func(i, j int) bool { return rules[i].HitCount > rules[j].HitCount })
	if len(rules) > 10 {
		rules = rules[:10]
	}
	type ruleHit struct {
		Name   string `json:"name"`
		Action string `json:"action"`
		Hits   int64  `json:"hits"`
	}
	result := make([]ruleHit, 0, len(rules))
	for i := range rules {
		if rules[i].HitCount > 0 {
			name := rules[i].Name
			if name == "" {
				name = fmt.Sprintf("Rule #%d", rules[i].Priority)
			}
			result = append(result, ruleHit{Name: name, Action: string(rules[i].Action), Hits: rules[i].HitCount})
		}
	}
	jsonOK(w, map[string]any{"rules": result})
}

// GET /api/timeseries
func apiTimeseries(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	total, allowed, blocked := tsGet()
	jsonOK(w, map[string]any{"data": total, "allowed": allowed, "blocked": blocked})
}

// apiLogsSource returns the log entries the caller wants to filter over:
// either the in-memory ring buffer (default) or the persistent JSONL file
// when source=file is set. On file read error it writes an HTTP 500 and
// returns ok=false; on success it returns the entries newest-first.
func apiLogsSource(w http.ResponseWriter, r *http.Request) (entries []LogEntry, ok bool) {
	if r.URL.Query().Get("source") != "file" {
		return logGet(), true
	}
	fileEntries, err := requestLogReadPersistent()
	if err != nil {
		logger.Printf("WARN apiLogs: persistent log read: %v", err)
		http.Error(w, "persistent log read error", http.StatusInternalServerError)
		return nil, false
	}
	return fileEntries, true
}

// GET /api/logs?filter=...&status=...&level=...&method=...&from=...&to=...&source=file
// from/to accept Unix timestamps (seconds) or ISO 8601 (RFC 3339) strings.
// source=file reads from the persistent JSONL request log file (newest-first,
// capped at requestLogMaxPersistentReturn entries); any other value reads from
// the in-memory ring buffer.
func apiLogs(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	// source=store queries the Badger-backed history store (deep pagination
	// over retained history that survives restart). Handled separately because
	// it pushes the time range + offset/limit down into the store rather than
	// loading every entry into memory.
	if r.URL.Query().Get("source") == "store" {
		apiLogsServeStore(w, r)
		return
	}
	all, ok := apiLogsSource(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	fromMs, toMs, offsetVal, limitVal, errMsg := parseLogQueryWindow(q)
	if errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	pred := buildLogFilterPredicate(q)

	// Index-based range + pointer to avoid copying each LogEntry (~320 bytes)
	// per iteration. all[:0:0] has cap 0 so the first append reallocates — the
	// shared (cached) backing array is never mutated.
	filtered := all[:0:0]
	for i := range all {
		e := &all[i]
		if fromMs != 0 && e.TS < fromMs {
			continue
		}
		if toMs != 0 && e.TS > toMs {
			continue
		}
		if !pred(e) {
			continue
		}
		filtered = append(filtered, *e)
	}
	total := len(filtered)
	// Apply offset/limit pagination.
	if offsetVal >= total {
		filtered = nil
	} else {
		end := offsetVal + limitVal
		if end > total {
			end = total
		}
		filtered = filtered[offsetVal:end]
	}
	jsonOK(w, map[string]any{"logs": filtered, "total": total})
}

// apiLogsMaxLimit clamps a single /api/logs page so one query cannot demand an
// unbounded response (CWE-770); offset pagination still reaches every entry.
const apiLogsMaxLimit = 5000

// buildLogFilterPredicate returns a predicate matching the host/IP, status,
// level, method, and identity query params. Shared by the in-memory and history
// query paths so the filter semantics stay identical.
func buildLogFilterPredicate(q url.Values) func(*LogEntry) bool {
	filterHost := strings.ToLower(q.Get("filter"))
	filterStatus := strings.ToUpper(q.Get("status"))
	filterLevel := strings.ToUpper(q.Get("level"))
	filterMethod := strings.ToUpper(q.Get("method"))
	filterIdentity := strings.ToLower(q.Get("identity"))
	return func(e *LogEntry) bool {
		if filterHost != "" && !strings.Contains(strings.ToLower(e.Host), filterHost) &&
			!strings.Contains(strings.ToLower(e.IP), filterHost) {
			return false
		}
		if filterStatus != "" && e.Status != filterStatus {
			return false
		}
		if filterLevel != "" && e.Level != filterLevel {
			return false
		}
		if filterMethod != "" && e.Method != filterMethod {
			return false
		}
		if filterIdentity != "" && !strings.Contains(strings.ToLower(e.Identity), filterIdentity) {
			return false
		}
		return true
	}
}

// parseLogQueryWindow parses from/to (Unix seconds → millis, per
// parseTimestampParam; LogEntry.TS is millis), offset, and a clamped limit.
// Returns a non-empty errMsg (for a 400) when from/to are malformed.
func parseLogQueryWindow(q url.Values) (fromMs, toMs int64, offset, limit int, errMsg string) {
	fromTS, fromErr := parseTimestampParam(q.Get("from"))
	if fromErr != nil {
		return 0, 0, 0, 0, "invalid 'from' parameter: use Unix timestamp or ISO 8601"
	}
	toTS, toErr := parseTimestampParam(q.Get("to"))
	if toErr != nil {
		return 0, 0, 0, 0, "invalid 'to' parameter: use Unix timestamp or ISO 8601"
	}
	if fromTS != 0 {
		fromMs = fromTS * 1000
	}
	if toTS != 0 {
		toMs = toTS*1000 + 999 // include the whole second
	}
	limit = 1000
	if lq := q.Get("limit"); lq != "" {
		if v, err := strconv.Atoi(lq); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > apiLogsMaxLimit {
		limit = apiLogsMaxLimit
	}
	if oq := q.Get("offset"); oq != "" {
		if v, err := strconv.Atoi(oq); err == nil && v >= 0 {
			offset = v
		}
	}
	return fromMs, toMs, offset, limit, ""
}

// apiLogsServeStore answers GET /api/logs?source=store by querying the
// Badger-backed history store. Time range (from/to), filters, and offset/limit
// are pushed down so deep pages ("page 20 = yesterday") are served without
// loading the whole history into memory. Returns an empty result when the
// history store is disabled. from/to are Unix seconds (parseTimestampParam),
// converted to the store's millisecond keys here.
func apiLogsServeStore(w http.ResponseWriter, r *http.Request) {
	ls := globalLogStore.Load()
	if ls == nil {
		jsonOK(w, map[string]any{"logs": []LogEntry{}, "total": 0, "history": false})
		return
	}
	q := r.URL.Query()
	fromMs, toMs, offsetVal, limitVal, errMsg := parseLogQueryWindow(q)
	if errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	logs, total, err := ls.Query(fromMs, toMs, offsetVal, limitVal, buildLogFilterPredicate(q))
	if err != nil {
		logger.Printf("WARN apiLogs: history store query: %v", err)
		http.Error(w, "history query error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"logs": logs, "total": total, "history": true})
}

// apiLogsRetention serves the history-store on/off switch, retention policy,
// usage, and a live disk-usage estimate.
//
//	GET (viewer): enabled state, retention days / max GB, usage, estimate.
//	PUT (admin):  enable/disable saving and/or update retention. Persisted to
//	              admin_settings.json so it survives restart (no YAML needed).
func apiLogsRetention(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, logStoreRetentionView())
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiLogsRetentionUpdate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiLogsRetentionUpdate handles the admin PUT: parse + validate retention, then
// apply the enable/disable/retention change and persist.
func apiLogsRetentionUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled         *bool    `json:"enabled"`
		RetentionDays   *int     `json:"retentionDays"`
		RetentionMaxGB  *float64 `json:"retentionMaxGB"`
		CriticalDiskPct *int     `json:"criticalDiskPct"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Critical disk threshold is independent of the store being enabled.
	if !applyCriticalDiskPct(w, body.CriticalDiskPct) {
		return // out-of-range error already written
	}
	// Settings-only change (just the critical-disk threshold): apply, audit, and
	// return without requiring the store to be on. An all-nil body falls through
	// to the retention path below, which audits its own no-op/409 — so we never
	// return a 2xx without an audit (keeps C2c's AuditExpected contract honest).
	if body.CriticalDiskPct != nil && body.Enabled == nil && body.RetentionDays == nil && body.RetentionMaxGB == nil {
		auditEvent(r, "logstore.disk_threshold", "history", fmt.Sprintf("criticalDiskPct=%d", *body.CriticalDiskPct))
		adminSettingsSave()
		jsonOK(w, logStoreRetentionView())
		return
	}
	days, gb, ok := resolveRetentionTarget(w, body.RetentionDays, body.RetentionMaxGB)
	if !ok {
		return // validation error already written
	}
	if !applyRetentionUpdate(w, r, body.Enabled, days, gb) {
		return // applyRetentionUpdate already wrote the error response
	}
	// Enforce a (possibly lowered) size cap promptly in the background.
	if ls := globalLogStore.Load(); ls != nil {
		go ls.RunRetention()
	}
	adminSettingsSave()
	jsonOK(w, logStoreRetentionView())
}

// applyCriticalDiskPct validates and applies an optional critical-disk-usage
// threshold (50–99). Returns false after writing a 400 if out of range; nil
// pointer is a no-op success.
func applyCriticalDiskPct(w http.ResponseWriter, p *int) bool {
	if p == nil {
		return true
	}
	if *p < 50 || *p > 99 {
		http.Error(w, "criticalDiskPct must be between 50 and 99", http.StatusBadRequest)
		return false
	}
	setCriticalDiskPct(*p)
	return true
}

// resolveRetentionTarget resolves the effective retention (provided value, else
// the current store's, else 0) and validates the bounds. Returns ok=false after
// writing a 400 on a range violation.
func resolveRetentionTarget(w http.ResponseWriter, rdays *int, rgb *float64) (days int, gb float64, ok bool) {
	if ls := globalLogStore.Load(); ls != nil {
		days, gb = ls.RetentionDays(), ls.RetentionMaxGB()
	}
	if rdays != nil {
		days = *rdays
	}
	if rgb != nil {
		gb = *rgb
	}
	if days < 0 || days > 3650 {
		http.Error(w, "retentionDays must be between 0 and 3650", http.StatusBadRequest)
		return 0, 0, false
	}
	if gb < 0 || gb > 10000 {
		http.Error(w, "retentionMaxGB must be between 0 and 10000", http.StatusBadRequest)
		return 0, 0, false
	}
	return days, gb, true
}

// applyRetentionUpdate performs the enable/disable/retention-only action. It
// writes the HTTP error and returns false on failure; true on success.
func applyRetentionUpdate(w http.ResponseWriter, r *http.Request, enabled *bool, days int, gb float64) bool {
	switch {
	case enabled != nil && !*enabled:
		setLogStoreDesired(days, gb) // remember retention across the disable
		disableLogStore()
		auditEvent(r, "logstore.disable", "history", "")
	case enabled != nil && *enabled:
		if err := enableLogStore(resolveLifecycleCtx(), logStoreDir, days, gb); err != nil {
			// enableLogStore records the desired retention only on success, so a
			// failure leaves it intact.
			if errors.Is(err, errLogStoreEncMismatch) {
				http.Error(w, "saved logs use a different encryption key — purge saved logs, then enable again", http.StatusConflict)
				return false
			}
			// Log the detail; return a generic message so a filesystem path
			// can't leak in the HTTP response.
			logger.Printf("WARN apiLogsRetention: enable failed: %v", err)
			http.Error(w, "cannot enable history store", http.StatusInternalServerError)
			return false
		}
		auditEvent(r, "logstore.enable", "history", fmt.Sprintf("days=%d maxGB=%g", days, gb))
	default:
		// No enable change: update retention only (store must be on).
		ls := globalLogStore.Load()
		if ls == nil {
			http.Error(w, "history store is off — enable it first", http.StatusConflict)
			return false
		}
		ls.SetRetention(days, gb)
		setLogStoreDesired(days, gb)
		auditEvent(r, "logstore.retention", "history", fmt.Sprintf("days=%d maxGB=%g", days, gb))
	}
	return true
}

// apiLogsPurge deletes all stored history (admin only). Works whether saving is
// on (drops the live store) or off (resets the on-disk store — the migration
// path when switching encryption on/off).
func apiLogsPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if err := purgeLogStore(); err != nil {
		logger.Printf("WARN apiLogsPurge: %v", err)
		http.Error(w, "purge failed", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "logstore.purge", "history", "all entries deleted")
	jsonOK(w, logStoreRetentionView())
}

// parseTimestampParam parses a timestamp string that is either a Unix timestamp
// (integer seconds) or an ISO 8601 / RFC 3339 datetime string.
// Returns (0, nil) for empty input, (unix, nil) on success, or (0, err) on failure.
// GET /api/top-hosts?n=20
func apiTopHosts(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	n := 20
	if s := r.URL.Query().Get("n"); s != "" {
		if v, err := fmt.Sscanf(s, "%d", &n); v == 0 || err != nil {
			n = 20
		}
	}
	if n <= 0 || n > 100 {
		n = 20
	}
	jsonOK(w, map[string]any{"hosts": topHosts.Top(n)})
}

// GET/POST/DELETE /api/blocklist
func apiConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}

	// F30: Section-specific export via ?section= query parameter.
	// Supported: blocklist, policy, rewrite, sslbypass, fileblock, ipfilter, all (default).
	section := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("section")))

	b := configBackup{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
	}
	filename := "culvert-backup"

	switch section {
	case "blocklist":
		b.BlocklistMode = bl.Mode()
		b.Blocklist = bl.List()
		filename = "culvert-blocklist"
	case "policy":
		b.PolicyRules = policyStore.List()
		b.DefaultAction = defaultPolicyAction()
		filename = "culvert-policy"
	case "rewrite":
		b.RewriteRules = rewriter.List()
		filename = "culvert-rewrite"
	case "sslbypass":
		b.SSLBypass = sslBypass.List()
		filename = "culvert-sslbypass"
	case "fileblock":
		b.FileBlockExtensions = fileBlocker.List()
		filename = "culvert-fileblock"
	case "ipfilter":
		b.IPFilterMode = ipf.Mode()
		b.IPList = ipf.List()
		filename = "culvert-ipfilter"
	case "pac":
		pc := pacStore.Get()
		b.PACProxyHost = pc.ProxyHost
		b.PACProxyPort = pc.ProxyPort
		b.PACExclusions = pc.Exclusions
		filename = "culvert-pac"
	case "alerts":
		b.AlertWebhooks = globalAlertStore.List()
		filename = "culvert-alerts"
	case "blockpage":
		b.BlockPageHTML = getBlockPageHTML()
		filename = "culvert-blockpage"
	case "upstream":
		for _, us := range upstreamPool.List() {
			b.UpstreamProxies = append(b.UpstreamProxies, UpstreamEntry{URL: us.URL})
		}
		filename = "culvert-upstream"
	case "connlimit":
		b.ConnLimitEnabled = connLimiter.enabled.Load()
		b.ConnLimitMaxPerIP = connLimiter.MaxPerIP()
		filename = "culvert-connlimit"
	default: // "all" or empty — full export
		b.BlocklistMode = bl.Mode()
		b.Blocklist = bl.List()
		b.PolicyRules = policyStore.List()
		b.DefaultAction = defaultPolicyAction()
		b.RewriteRules = rewriter.List()
		b.SSLBypass = sslBypass.List()
		b.ContentScanPatterns = dpiScanner.List()
		b.FileBlockExtensions = fileBlocker.List()
		b.IPFilterMode = ipf.Mode()
		b.IPList = ipf.List()
		b.RateLimitRPM = rl.Limit()
		b.RateLimitExempt = rl.ListExemptions()
		pc := pacStore.Get()
		b.PACProxyHost = pc.ProxyHost
		b.PACProxyPort = pc.ProxyPort
		b.PACExclusions = pc.Exclusions
		// Alert webhooks (secrets excluded by List()).
		b.AlertWebhooks = globalAlertStore.List()
		// Block page template.
		if html := getBlockPageHTML(); html != "" {
			b.BlockPageHTML = html
		}
		// Upstream proxies.
		for _, us := range upstreamPool.List() {
			b.UpstreamProxies = append(b.UpstreamProxies, UpstreamEntry{URL: us.URL})
		}
		// Connection limits.
		b.ConnLimitEnabled = connLimiter.enabled.Load()
		b.ConnLimitMaxPerIP = connLimiter.MaxPerIP()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
	json.NewEncoder(w).Encode(b) //nolint:errcheck
	auditEvent(r, "config.export", filename, fmt.Sprintf("section=%s exported at %s", section, b.ExportedAt))
}

// POST /api/config/import — restore configuration from a backup JSON.
// Each section is applied atomically; partial failures are logged but do not abort.
func apiConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var b configBackup
	if err := decodeJSON(r, &b); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if b.Version != 1 {
		http.Error(w, "unsupported backup version", http.StatusBadRequest)
		return
	}

	// Import mode: "replace" clears existing state before importing;
	// "merge" (default) appends to existing state.
	replaceMode := r.URL.Query().Get("mode") == "replace"

	// Blocklist. Feed attribution is carried across a replace-mode
	// rebuild — ClearAll+Add would otherwise strand every feed entry as
	// unattributed (Codex P1, PR #447).
	feedSrcSnap := bl.SnapshotFeedSources()
	if replaceMode && len(b.Blocklist) > 0 {
		bl.ClearAll()
	}
	for _, h := range b.Blocklist {
		bl.Add(h)
	}
	bl.RestoreFeedSources(feedSrcSnap)
	bl.Save()
	if b.BlocklistMode == "allow" || b.BlocklistMode == "block" {
		bl.SetMode(b.BlocklistMode)
	}

	// Policy rules — validate each before importing.
	if replaceMode && len(b.PolicyRules) > 0 {
		policyStore.ReplaceAll(b.PolicyRules)
	} else {
		for _, rule := range b.PolicyRules {
			if err := validatePolicyRule(rule, policyStore.List(), -1); err != nil {
				logger.Printf("ConfigImport: skipping rule %q: %s", sanitizeLog(rule.Name), strings.ReplaceAll(err.Error(), "\n", ""))
				continue
			}
			policyStore.Add(rule)
		}
	}
	policyStore.Save()
	if b.DefaultAction == "allow" || b.DefaultAction == "deny" {
		setDefaultPolicyAction(b.DefaultAction)
	}

	// Rewrite rules.
	if replaceMode && len(b.RewriteRules) > 0 {
		rewriter.SetRules(b.RewriteRules)
	} else {
		for _, rule := range b.RewriteRules {
			rewriter.Add(rule)
		}
	}

	// SSL bypass.
	if replaceMode && len(b.SSLBypass) > 0 {
		_ = sslBypass.Set(b.SSLBypass)
	} else {
		for _, p := range b.SSLBypass {
			_ = sslBypass.Add(p)
		}
	}
	sslBypass.Save()

	// Content scan patterns.
	if replaceMode && len(b.ContentScanPatterns) > 0 {
		_ = dpiScanner.Set(b.ContentScanPatterns)
	} else {
		for _, p := range b.ContentScanPatterns {
			_ = dpiScanner.Add(p)
		}
	}
	dpiScanner.Save()

	// File block extensions.
	if replaceMode && len(b.FileBlockExtensions) > 0 {
		fileBlocker.ClearAll()
	}
	for _, ext := range b.FileBlockExtensions {
		fileBlocker.Add(ext)
	}

	// Security.
	if b.IPFilterMode != "" {
		ipf.SetMode(b.IPFilterMode)
	}
	if replaceMode && len(b.IPList) > 0 {
		ipf.ClearAll()
	}
	for _, ip := range b.IPList {
		_ = ipf.Add(ip)
	}
	if b.RateLimitRPM > 0 {
		rl.Configure(b.RateLimitRPM, time.Minute)
	}
	for _, ex := range b.RateLimitExempt {
		_ = rl.AddExemption(ex)
	}

	// PAC configuration.
	if b.PACProxyHost != "" || b.PACProxyPort != 0 || len(b.PACExclusions) > 0 {
		pc := pacStore.Get()
		if replaceMode {
			pc = PACConfig{}
		}
		if b.PACProxyHost != "" {
			pc.ProxyHost = b.PACProxyHost
		}
		if b.PACProxyPort != 0 {
			pc.ProxyPort = b.PACProxyPort
		}
		if len(b.PACExclusions) > 0 {
			if replaceMode {
				pc.Exclusions = b.PACExclusions
			} else {
				pc.Exclusions = append(pc.Exclusions, b.PACExclusions...)
			}
		}
		_ = pacStore.Set(pc)
	}

	// Alert webhooks (Finding 10.3).
	if len(b.AlertWebhooks) > 0 {
		if replaceMode {
			// Clear existing webhooks before importing.
			for _, wh := range globalAlertStore.List() {
				globalAlertStore.Delete(wh.ID)
			}
		}
		for _, wh := range b.AlertWebhooks {
			globalAlertStore.Add(wh)
		}
	}

	// Block page template (Finding 10.3).
	if b.BlockPageHTML != "" {
		if err := setBlockPageHTML(b.BlockPageHTML); err != nil {
			logger.Printf("ConfigImport: block page template error: %s", strings.ReplaceAll(err.Error(), "\n", ""))
		}
	}

	// Upstream proxies (Finding 10.3).
	if len(b.UpstreamProxies) > 0 {
		upstreamPool.Configure(b.UpstreamProxies, 5, 60*time.Second)
	}

	// Connection limits (Finding 10.3).
	if b.ConnLimitMaxPerIP > 0 {
		if b.ConnLimitEnabled {
			connLimiter.Enable(b.ConnLimitMaxPerIP)
		} else {
			connLimiter.Disable()
		}
	}

	importMode := "merge"
	if replaceMode {
		importMode = "replace"
	}
	auditEvent(r, "config.import", importMode, fmt.Sprintf("from backup exported %s", b.ExportedAt))
	saveConfigVersion(sessionAdmin(r), "config.import")
	jsonOK(w, map[string]any{"ok": true, "mode": importMode, "exportedAt": b.ExportedAt})
}

// GET/POST /api/session-secret — shared session signing key management.
func apiSessionSecret(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		shared := os.Getenv("CULVERT_SESSION_SECRET") != ""
		jsonOK(w, map[string]any{"shared": shared})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Secret string `json:"secret"` // hex-encoded, ≥64 chars (32 bytes)
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Secret == "" {
			http.Error(w, "secret is required (64+ hex chars)", http.StatusBadRequest)
			return
		}
		key, err := hex.DecodeString(body.Secret)
		if err != nil || len(key) < 32 {
			http.Error(w, "secret must be ≥32 bytes of hex (64 hex chars)", http.StatusBadRequest)
			return
		}
		sessionSecret = key
		auditEvent(r, "settings.session_secret", "rotated", "shared session key updated via GUI")
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/session-timeout — read or change the UI session lifetime.
func apiSessionTimeout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{"hours": int(getSessionTTL().Hours())})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Hours int `json:"hours"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Hours < 1 || body.Hours > 168 {
			http.Error(w, "hours must be 1–168", http.StatusBadRequest)
			return
		}
		SetSessionTTL(time.Duration(body.Hours) * time.Hour)
		auditEvent(r, "settings.session_timeout", fmt.Sprintf("%dh", body.Hours), "")
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true, "hours": body.Hours})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/ui-allow-ips — manage the admin panel IP access allowlist.
// GET    → returns current list (empty = all IPs allowed).
// POST   → {"ips": ["10.0.0.0/8", "192.168.1.5"]} — replaces the full list.
//
//	Send empty array [] to remove all restrictions.
func apiUIAllowIPs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, map[string]any{"ips": ListUIAllowedCIDRs()})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			IPs []string `json:"ips"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := SetUIAllowedCIDRs(body.IPs); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "settings.ui_allow_ips", fmt.Sprintf("%d entries", len(body.IPs)), strings.Join(body.IPs, ", "))
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true, "ips": ListUIAllowedCIDRs()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// syslogConfigured tracks whether syslog was initialised so the UI can reflect it.
var syslogConfigured string // the addr string, empty = not configured

// GET/POST /api/syslog — configure remote syslog/SIEM forwarding at runtime.
// GET  → returns current syslog address and format.
// POST → {"addr": "udp://10.0.0.1:514", "format": "rfc5424"} — reconnects immediately.
//
//	Send addr="" to disable forwarding.
func apiSyslogConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		format := "rfc3164"
		if globalSyslog != nil {
			format = globalSyslog.Format()
		}
		jsonOK(w, map[string]any{"addr": syslogConfigured, "format": format})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Addr   string `json:"addr"`
			Format string `json:"format"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Addr = strings.TrimSpace(body.Addr)
		body.Format = strings.TrimSpace(body.Format)
		if body.Format != "" && body.Format != "rfc3164" && body.Format != "rfc5424" {
			http.Error(w, "format must be \"rfc3164\" or \"rfc5424\"", http.StatusBadRequest)
			return
		}
		if body.Addr == "" {
			// Disable syslog.
			if globalSyslog != nil {
				globalSyslog.Close()
				globalSyslog = nil
			}
			syslogConfigured = ""
			auditEvent(r, "settings.syslog", "disabled", "")
			adminSettingsSave()
			jsonOK(w, map[string]any{"ok": true, "addr": "", "format": "rfc3164"})
			return
		}
		if err := InitSyslog(body.Addr, body.Format); err != nil {
			http.Error(w, "syslog connect error: "+err.Error(), http.StatusBadRequest)
			return
		}
		syslogConfigured = body.Addr
		auditEvent(r, "settings.syslog", body.Addr, "syslog forwarding enabled (format="+globalSyslog.Format()+")")
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true, "addr": body.Addr, "format": globalSyslog.Format()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/syslog/test — send a test message to the configured syslog target.
func apiSyslogTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if globalSyslog == nil {
		http.Error(w, "syslog not configured", http.StatusServiceUnavailable)
		return
	}
	globalSyslog.writeMsg(14, "Culvert syslog test message — connectivity verified")
	jsonOK(w, map[string]any{"ok": true, "message": "test message sent"})
}

// GET/POST /api/security — IP filter + rate limiter config
func apiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]any{
			"authEnabled":        cfg.AuthEnabled(),
			"user":               cfg.GetUser(), // password is NEVER returned
			"proxyPort":          cfg.ProxyPort,
			"uiPort":             cfg.UIPort,
			"defaultAuthOutcome": string(cfg.DefaultAuthOutcome()), // "Default" | "Exempt"
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Pass != "" {
			if err := validatePasswordComplexity(body.Pass); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if err := cfg.SetAuth(body.User, body.Pass); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		logger.Printf("UI: auth settings updated (user=%q)", sanitizeLog(body.User))
		auditEvent(r, "settings.update", "auth", fmt.Sprintf("user=%s", body.User))
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// PUT /api/settings/unauth-mode — set the global default authentication behavior.
// (Route name is legacy; the contract is the defaultAuthOutcome string. Scoped
// auth rules always evaluate first; this default applies only to unmatched
// traffic, and Exempt is NOT an allow — Stage-2 policy and default-deny still
// apply.) Accepts {"defaultAuthOutcome":"Default"|"Exempt"}.
func apiUnauthMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var body struct {
		DefaultAuthOutcome string `json:"defaultAuthOutcome"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Only the two v1 global defaults are valid; anything else is rejected
	// (reserved outcomes like CredentialRequired are not valid global defaults).
	switch AuthOutcome(body.DefaultAuthOutcome) {
	case OutcomeDefault, OutcomeExempt:
	default:
		http.Error(w, `defaultAuthOutcome must be "Default" or "Exempt"`, http.StatusBadRequest)
		return
	}
	outcome := AuthOutcome(body.DefaultAuthOutcome)
	cfg.SetDefaultAuthOutcome(outcome)
	adminSettingsSave()
	if outcome == OutcomeExempt {
		auditEvent(r, "settings.update", "defaultAuthOutcome", "Exempt — unmatched traffic is open (not Allow; Stage-2 policy still governs); scoped auth rules still enforce")
	} else {
		auditEvent(r, "settings.update", "defaultAuthOutcome", "Default — unmatched traffic requires authentication")
	}
	logger.Printf("UI: default authentication set to %q", sanitizeLog(string(outcome)))
	jsonOK(w, map[string]any{"ok": true, "defaultAuthOutcome": string(outcome)})
}

// GET/PUT /api/settings/log-level — view/change runtime log level.
func apiLogLevel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]string{"level": GetLogLevel().String()})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Level string `json:"level"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(body.Level))
		if upper != "DEBUG" && upper != "INFO" && upper != "WARN" && upper != "ERROR" {
			http.Error(w, "level must be DEBUG/INFO/WARN/ERROR", http.StatusBadRequest)
			return
		}
		SetLogLevel(ParseLogLevel(upper))
		logger.Printf("UI: log level changed to %s", strings.ReplaceAll(upper, "\n", ""))
		auditEvent(r, "settings.log_level", upper, "")
		adminSettingsSave()
		jsonOK(w, map[string]string{"level": upper})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/settings/network — network & TLS settings (base_url, ui_sans, trust_forwarded_headers).
func apiNetworkSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"base_url":                proxyExternalBaseURL,
			"ui_sans":                 uiExtraSANs,
			"trust_forwarded_headers": trustForwardedHeaders,
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			BaseURL               string   `json:"base_url"`
			UISANs                []string `json:"ui_sans"`
			TrustForwardedHeaders bool     `json:"trust_forwarded_headers"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		SetProxyBaseURL(body.BaseURL)
		uiExtraSANs = body.UISANs
		trustForwardedHeaders = body.TrustForwardedHeaders
		safeSANs := make([]string, len(body.UISANs))
		for i, s := range body.UISANs {
			safeSANs[i] = strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", "")
		}
		safeTrustFwd := strings.ReplaceAll(fmt.Sprintf("%v", body.TrustForwardedHeaders), "\n", "")
		logger.Printf("UI: network settings updated (base_url=%q, ui_sans=%v, trust_fwd=%s)",
			sanitizeLog(body.BaseURL), safeSANs, safeTrustFwd)
		auditEvent(r, "settings.network", "updated", fmt.Sprintf("base_url=%s trust_fwd=%s sans=%v",
			strings.ReplaceAll(body.BaseURL, "\n", ""), safeTrustFwd, safeSANs))
		adminSettingsSave()
		// Intentionally NOT calling saveConfigVersion: these operational
		// settings are not in the rollback capture/apply surface.
		// Automatic rollback would be genuinely dangerous in ways the
		// rollback API doesn't communicate:
		//   - trustForwardedHeaders flip-back can re-enable a
		//     previously-disabled header-spoofing attack vector;
		//   - uiExtraSANs changes trigger UI cert regeneration —
		//     rollback causes cert churn that breaks browser
		//     cert-pin caches;
		//   - proxyExternalBaseURL controls OIDC redirect URIs and
		//     PAC generation — rolling back to an old URL breaks
		//     OIDC because registered redirect URIs on the IdP side
		//     don't change in sync.
		// Operators who need to revert these specific settings should
		// re-POST with the old values. Category D' (direction A)
		// finding from roadmap/CONFIG-VERSIONING-TRIAGE.md +
		// roadmap/CATEGORY-D-PRIME-DIRECTION.md §4.
		// Keep connected DPs aligned for SAML/OIDC callback generation.
		publishCurrentConfigSnapshot()
		jsonOK(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST/DELETE /api/rewrite — manage header rewrite rules
func apiLoggerConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"logFile":   uiCfgLogFile,
			"logMaxMB":  uiCfgLogMaxMB,
			"logFormat": uiCfgLogFormat,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Metrics Config API
// ═══════════════════════════════════════════════════════════════════════════════

func apiMetricsConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"tokenSet": metricsToken != "",
			"path":     "/metrics",
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		metricsToken = body.Token
		auditEvent(r, "settings.metrics_token", "updated", "")
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Connection Limit API
// ═══════════════════════════════════════════════════════════════════════════════

func apiConnLimit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"enabled":   connLimiter.enabled.Load(),
			"maxPerIP":  connLimiter.MaxPerIP(),
			"activeIPs": connLimiter.ActiveIPs(),
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Enabled  *bool `json:"enabled"`
			MaxPerIP int   `json:"maxPerIP"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Enabled != nil && !*body.Enabled {
			connLimiter.Disable()
		} else if body.MaxPerIP > 0 {
			connLimiter.Enable(body.MaxPerIP)
		}
		auditEvent(r, "connlimit.update", fmt.Sprintf("enabled=%v max=%d", connLimiter.enabled.Load(), connLimiter.MaxPerIP()), "")
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true, "enabled": connLimiter.enabled.Load(), "maxPerIP": connLimiter.MaxPerIP()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Block Page Template API
// ═══════════════════════════════════════════════════════════════════════════════

func apiBlockPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{"html": getBlockPageHTML()})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			HTML string `json:"html"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.HTML == "" {
			http.Error(w, "html is required", http.StatusBadRequest)
			return
		}
		if err := setBlockPageHTML(body.HTML); err != nil {
			http.Error(w, "invalid template: "+err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "blockpage.update", "block_page_template", "")
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Upstream Proxy Chaining API
// ═══════════════════════════════════════════════════════════════════════════════

func apiUpstream(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]any{
			"enabled": upstreamPool.Enabled(),
			"proxies": upstreamPool.List(),
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Proxies []UpstreamEntry `json:"proxies"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		upstreamPool.Configure(body.Proxies, 5, 60*time.Second)
		applyUpstreamProxy()
		auditEvent(r, "upstream.update", fmt.Sprintf("%d proxies", len(body.Proxies)), "")
		jsonOK(w, map[string]any{"ok": true, "proxies": upstreamPool.List()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiUpstreamSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, map[string]any{
		"enabled": upstreamPool.Enabled(),
		"proxies": upstreamPool.List(),
	})
}

func apiUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	upstreamPool.HealthCheck()
	jsonOK(w, map[string]any{"ok": true, "proxies": upstreamPool.List()})
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cluster / Multi-Node API
// ═══════════════════════════════════════════════════════════════════════════════

func resolveOTLPHeaders(name, value string) map[string]string {
	n := strings.TrimSpace(name)
	v := strings.TrimSpace(value)
	if n != "" && v != "" {
		return map[string]string{n: v}
	}
	globalOTLP.mu.RLock()
	defer globalOTLP.mu.RUnlock()
	if len(globalOTLP.headers) > 0 {
		return globalOTLP.headers
	}
	return nil
}

// GET/POST /api/otlp - configure OpenTelemetry OTLP/HTTP export (metrics + traces).
func apiOTLPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		// Check if auth headers are configured (don't expose the actual value).
		globalOTLP.mu.RLock()
		hasAuth := len(globalOTLP.headers) > 0
		authName := ""
		for k := range globalOTLP.headers {
			authName = k // return the header NAME (not value) so UI can show it
			break
		}
		globalOTLP.mu.RUnlock()
		jsonOK(w, map[string]any{
			"enabled":        globalOTLP.Enabled(),
			"endpoint":       globalOTLP.Endpoint(),
			"hasAuth":        hasAuth,
			"authHeaderName": authName,
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Endpoint        string `json:"endpoint"`
			AuthHeaderName  string `json:"authHeaderName"`
			AuthHeaderValue string `json:"authHeaderValue"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Endpoint = strings.TrimSpace(body.Endpoint)
		if body.Endpoint == "" {
			globalOTLP.Stop()
			globalOTLPTraces.Stop()
			auditEvent(r, "settings.otlp", "disabled", "")
			adminSettingsSave()
			jsonOK(w, map[string]any{"ok": true, "enabled": false})
			return
		}
		// Inline SSRF guard: validate scheme + reject private hosts (CodeQL CWE-918).
		epURL, err := url.Parse(body.Endpoint)
		if err != nil || (epURL.Scheme != "http" && epURL.Scheme != "https") {
			http.Error(w, "endpoint must use http or https scheme", http.StatusBadRequest)
			return
		}
		if err := isPrivateHost(epURL.Hostname()); err != nil {
			http.Error(w, "endpoint must not resolve to a private network", http.StatusBadRequest)
			return
		}
		headers := resolveOTLPHeaders(body.AuthHeaderName, body.AuthHeaderValue)
		globalOTLP.Configure(body.Endpoint, headers)
		globalOTLPTraces.Configure(body.Endpoint, headers)
		auditEvent(r, "settings.otlp", sanitizeLog(body.Endpoint), "OTLP export enabled (metrics + traces)")
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true, "enabled": true, "endpoint": body.Endpoint})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// registerDashboardRoutes wires the dashboard / live-stats endpoints. All
// routes are gated by uiAuthMiddleware; per-handler RBAC is the handler's
// responsibility.
func registerDashboardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/stats", apiStats)
	mux.HandleFunc("/api/dashboard/health", apiDashboardHealth)
	mux.HandleFunc("/api/dashboard/threats", apiDashboardThreats)
	mux.HandleFunc("/api/dashboard/top-rules", apiDashboardTopRules)
	mux.HandleFunc("/api/timeseries", apiTimeseries)
	mux.HandleFunc("/api/logs", apiLogs)
	mux.HandleFunc("/api/logs/retention", apiLogsRetention)
	mux.HandleFunc("/api/logs/purge", apiLogsPurge)
	mux.HandleFunc("/api/top-hosts", apiTopHosts)
	mux.HandleFunc("/api/audit", apiAudit)
	mux.HandleFunc("/api/events", apiEvents) // SSE live dashboard
	mux.HandleFunc("/api/country-traffic", apiCountryTraffic)
}

// registerSettingsRoutes wires the Settings admin panel — Option A panel
// grouping: handlers may live in logger.go, metrics.go, otlp.go,
// connlimit.go, etc., but they are registered here because the admin
// panel groups them under "Settings". All routes are gated by
// uiAuthMiddleware; per-handler RBAC is the handler's responsibility.
func registerSettingsRoutes(mux *http.ServeMux) {
	// ── Core settings + raw export ────────────────────────────────────────
	mux.HandleFunc("/api/settings", apiSettings)
	mux.HandleFunc("/api/export", apiExport)

	// ── Backup / restore / config versioning ──────────────────────────────
	mux.HandleFunc("/api/config/export", apiConfigExport)     // GET — download backup JSON
	mux.HandleFunc("/api/config/import", apiConfigImport)     // POST — restore from backup JSON
	mux.HandleFunc("/api/config/versions", apiConfigVersions) // GET list / POST rollback
	mux.HandleFunc("/api/config/diff", apiConfigDiff)         // GET diff between versions

	// ── Auth / network / session settings ─────────────────────────────────
	mux.HandleFunc("/api/settings/unauth-mode", apiUnauthMode)  // PUT — toggle proxy auth requirement
	mux.HandleFunc("/api/settings/log-level", apiLogLevel)      // GET/PUT runtime log level
	mux.HandleFunc("/api/settings/network", apiNetworkSettings) // GET/POST network & TLS settings
	mux.HandleFunc("/api/session-timeout", apiSessionTimeout)   // GET/POST session TTL (hours)
	mux.HandleFunc("/api/session-secret", apiSessionSecret)     // GET/POST shared signing key
	mux.HandleFunc("/api/ui-allow-ips", apiUIAllowIPs)          // GET/POST UI access IP allowlist

	// ── Syslog / logger / metrics / OTLP / connlimit (handlers in
	// dedicated files, registered here per Option A). ─────────────────────
	mux.HandleFunc("/api/syslog", apiSyslogConfig)          // GET/POST syslog forwarding
	mux.HandleFunc("/api/syslog/test", apiSyslogTest)       // POST syslog test message
	mux.HandleFunc("/api/logger", apiLoggerConfig)          //
	mux.HandleFunc("/api/metrics-config", apiMetricsConfig) //
	mux.HandleFunc("/api/otlp", apiOTLPConfig)              //
	mux.HandleFunc("/api/connlimit", apiConnLimit)          // GET status / POST update
}
