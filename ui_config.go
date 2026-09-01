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

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/KidCarmi/Culvert/internal/reqlog"
	"github.com/KidCarmi/Culvert/internal/secscan"
	"github.com/KidCarmi/Culvert/internal/session"
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
	// Fleet-freeze status: non-empty when the CP's last config publish was
	// rejected at commit (over cap/bytes), so the fleet is stuck on the last
	// valid snapshot. Surfaced on the always-polled /api/stats so the dashboard
	// can raise a persistent banner instead of the operator having to run the
	// diagnose verb (the failure this feature exists to make un-silent).
	publishRejected, publishRejectedAt := globalConfigStore.LastPublishError()
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
		"logWriteErrors": reqlog.WriteErrors(),
		// Persistent AUDIT-log health. Non-zero means admin-action entries did
		// not reach the durable JSONL file (disk full, read-only remount, failed
		// post-rotation reopen), so the compliance record is incomplete — the
		// in-memory ring keeps only the newest 500 entries and is wiped on
		// restart, so this is the only way an operator can see the gap.
		"auditLogWriteErrors": auditWriteErrors(),
		// Non-zero means the async JSONL persistence queue saturated: no
		// entry was lost, but request goroutines waited on the disk.
		"logBackpressure": reqlog.Backpressure(),
		// Non-zero means the async PROCESS-log queue (internal/logsink; every
		// POLICY_ALLOW/BLOCK/DROP line plus general logger.Printf output)
		// saturated: no line was lost, but the caller waited for queue room.
		// A distinct subsystem from logBackpressure above (request-log JSONL
		// persistence) — previously visible only via the culvert_logsink_
		// backpressure_total Prometheus metric, invisible to an operator
		// without a metrics scraper wired up.
		"processLogBackpressure": logSinkBackpressure(),
		// Process-log write failures (console + process log file). Same fault
		// class as logWriteErrors/auditLogWriteErrors above, but for the
		// POLICY_ALLOW/BLOCK/DROP line-per-request stream — previously visible
		// only via the culvert_logsink_write_errors_total Prometheus metric,
		// invisible to an operator without a metrics scraper wired up.
		"processLogWriteErrors": logSinkWriteErrors(),
		// Audit/request-log persistence state: if the operator configured a
		// file path but the engine could not open it at startup (bad
		// permissions, missing directory, full disk), both silently fall
		// back to volatile in-memory storage — wiped on every restart — with
		// only a startup log line as evidence. "Configured" true + "Persisted"
		// false means that silent fallback is currently active.
		"auditLogConfigured":   auditLogConfiguredPath != "",
		"auditLogPersisted":    auditPersistActive(),
		"auditLogPath":         auditLogConfiguredPath,
		"requestLogConfigured": requestLogConfiguredPath != "",
		"requestLogPersisted":  requestLogPersistActive(),
		"requestLogPath":       requestLogConfiguredPath,
		// Admin-API RBAC enforcement mode ("enforce"/"shadow"). Surfaced here
		// (in addition to the Governance panel) so shadow mode — where the
		// metadata-driven role gate is log-only, not blocking — is visible
		// on the Dashboard instead of requiring the admin to know to check
		// the Governance nav item.
		"c2Mode": c2Mode(),
		// Cluster config-publish freeze (empty = healthy).
		"configPublishRejected":   publishRejected,
		"configPublishRejectedAt": publishRejectedAt,
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
		"sseEvicted":    hub.Evicted(),
		"sseRejected":   hub.Rejected(),
		"blocklistSize": bl.Count(),
		"logStore":      logStoreHealth(),
	})
}

// GET /api/dashboard/threats — Threat engine breakdown
func apiDashboardThreats(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	scanCounters := secscan.Counters()
	jsonOK(w, map[string]any{
		"clamav":     scanCounters.ClamBlocked,
		"yara":       scanCounters.YARABlocked,
		"dpi":        atomic.LoadInt64(&statDPIBlocked),
		"threatFeed": scanCounters.ThreatFeedBlocked,
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
// capped at reqlog.MaxPersistentReturn entries); any other value reads from
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
	// ADR-0011 Phase 3 drill-down: structured dec.* filters on the nested decryption block.
	// The enum fields (outcome/decision_source/fail_category) are bounded lowercase tokens,
	// so an exact case-folded match is right; profile_id is an opaque ID, matched exactly.
	// A record with no dec block never matches ANY dec.* filter — those select decryption
	// sessions specifically. The predicate is shared by the in-memory ring and the history
	// store, so both drill-down paths stay consistent.
	filterDecOutcome := q.Get("dec_outcome")
	filterDecSource := q.Get("dec_decision_source")
	filterDecFailCat := q.Get("dec_fail_category")
	filterDecProfile := q.Get("dec_profile_id")
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
		if filterDecOutcome != "" && (e.Dec == nil || !strings.EqualFold(e.Dec.Outcome, filterDecOutcome)) {
			return false
		}
		if filterDecSource != "" && (e.Dec == nil || !strings.EqualFold(e.Dec.DecisionSource, filterDecSource)) {
			return false
		}
		if filterDecFailCat != "" && (e.Dec == nil || !strings.EqualFold(e.Dec.FailCategory, filterDecFailCat)) {
			return false
		}
		if filterDecProfile != "" && (e.Dec == nil || e.Dec.ProfileID != filterDecProfile) {
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
	// ADR-FE-002 Monitor contract: a `cursor` parameter (present, even
	// empty = first page) selects keyset pagination with NO exact total.
	// Requests without it keep the legacy offset/limit/total behavior
	// byte-compatible for existing clients.
	if r.URL.Query().Has("cursor") {
		apiLogsServeStoreCursor(w, r)
		return
	}
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
	filename := "culvert-config-export"

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
		profCfg := pacProfiles.Get() // single Get (torn-capture guard)
		b.PACProfiles = nonNilProfiles(profCfg.Profiles)
		b.PACPools = nonNilPools(profCfg.Pools)
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
		b.ConnLimitEnabled = connLimiter.Enabled()
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
		fullProfCfg := pacProfiles.Get() // single Get (torn-capture guard)
		b.PACProfiles = nonNilProfiles(fullProfCfg.Profiles)
		b.PACPools = nonNilPools(fullProfCfg.Pools)
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
		b.ConnLimitEnabled = connLimiter.Enabled()
		b.ConnLimitMaxPerIP = connLimiter.MaxPerIP()
		// Category taxonomy + DPI bypass hosts (config-surface registry rows
		// url_categories / category_groups / content_scan_bypass_hosts).
		// Previously rollback-only: a "full" export could not round-trip
		// category policy, so a restored backup silently dropped every
		// category-group rule's referents.
		b.URLCategories = catStore.All()
		b.CategoryGroups = globalCategoryGroups.List()
		b.DecryptionProfiles = globalDecryptionProfiles.List()
		b.ContentScanBypassHosts = dpiScanner.BypassHosts()
		// SaaS signed category-feed CONFIGURATION + overrides (F3a-2). Exported as
		// configuration only — never the node-local runtime/activation/floor state,
		// which is off every surface by construction (no configBackup binding). The
		// URL/protocol are captured RESOLVED (always non-empty), so a same-version
		// round-trip restores them exactly; a pre-F3a-2 backup lacks these fields.
		b.SaaSFeedManaged = captureSaaSFeedManaged()
		b.SaaSFeedEnabled = captureSaaSFeedEnabled()
		b.SaaSFeedURL = captureSaaSFeedURL()
		b.SaaSFeedProtocol = captureSaaSFeedProtocol()
		b.SaaSFeedRefreshSeconds = getSaaSFeedDurable().RefreshSeconds
		b.CategoryOverrides = captureCategoryOverrides()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
	json.NewEncoder(w).Encode(b) //nolint:errcheck
	auditEvent(r, "config.export", filename, fmt.Sprintf("section=%s exported at %s", section, b.ExportedAt))
}

// importPreviewSection describes the effect an import would have on one
// collection-typed config section: how many entries the backup carries
// (Incoming), how many currently exist (Current), and a human-readable Effect.
// Only sections the import would actually touch (Incoming > 0) are emitted.
type importPreviewSection struct {
	Section  string `json:"section"`
	Incoming int    `json:"incoming"`
	Current  int    `json:"current"`
	Effect   string `json:"effect"`
	Note     string `json:"note,omitempty"`
}

// importPreviewSetting describes a scalar (non-collection) setting the import
// would apply. Unlike collections these overwrite rather than accumulate, so
// they carry no count — just the value that would be set.
type importPreviewSetting struct {
	Setting string `json:"setting"`
	Value   string `json:"value"`
}

// importSectionEffect renders the effect string for a collection section under
// the given mode. Callers only invoke this for incoming > 0 (a zero-incoming
// section is a no-op in both modes — import never wipes on an absent field).
func importSectionEffect(replaceMode bool, incoming, current int) string {
	if replaceMode {
		return fmt.Sprintf("replace %d existing with %d incoming", current, incoming)
	}
	return fmt.Sprintf("add %d to %d existing", incoming, current)
}

// buildImportPreview computes the read-only preview of an import: the
// per-collection change summary and the scalar settings that would be applied.
// It mirrors apiConfigImport's section membership and mode semantics exactly
// (replace clears then loads; merge appends/upserts) but mutates nothing —
// every count is read from the live store, every incoming count from the
// parsed backup.
func buildImportPreview(b *configBackup, replaceMode bool) ([]importPreviewSection, []importPreviewSetting) {
	var sections []importPreviewSection
	add := func(name string, incoming, current int, note string) {
		if incoming == 0 {
			return // absent/empty field — no change in either mode
		}
		sections = append(sections, importPreviewSection{
			Section:  name,
			Incoming: incoming,
			Current:  current,
			Effect:   importSectionEffect(replaceMode, incoming, current),
			Note:     note,
		})
	}
	// addFixed emits a section whose effect is FIXED regardless of the import
	// mode — for the two sections whose apply path ignores the mode flag
	// (upstream proxies always replace via SetProxies; rate-limit exemptions
	// always append). Using the generic mode-aware add() for these would make
	// the preview claim the opposite of what the import does.
	addFixed := func(name string, incoming, current int, effect, note string) {
		if incoming == 0 {
			return
		}
		sections = append(sections, importPreviewSection{
			Section:  name,
			Incoming: incoming,
			Current:  current,
			Effect:   effect,
			Note:     note,
		})
	}

	// Policy rules: merge now UPSERTS by identity (ID then name), so report the
	// real update/add split instead of a flat "add N" — and drop the old
	// duplicate-accumulation warning, which no longer applies.
	polCur := len(policyStore.List())
	if replaceMode || len(b.PolicyRules) == 0 {
		add("Policy Rules", len(b.PolicyRules), polCur, "")
	} else {
		updates, adds := policyStore.countImportUpserts(b.PolicyRules)
		addFixed("Policy Rules", len(b.PolicyRules), polCur,
			fmt.Sprintf("upsert %d: %d update, %d add", len(b.PolicyRules), updates, adds),
			"merge upserts by ID then name — duplicates no longer accumulate")
	}
	add("Blocklist", len(b.Blocklist), bl.Count(), "")

	taxonomyNote := ""
	if !replaceMode {
		taxonomyNote = "merge upserts by name"
	}
	add("URL Categories", len(b.URLCategories), len(catStore.All()), taxonomyNote)
	add("Category Groups", len(b.CategoryGroups), len(globalCategoryGroups.List()), taxonomyNote)
	add("Decryption Profiles", len(b.DecryptionProfiles), len(globalDecryptionProfiles.List()), taxonomyNote)

	// Category overrides (F3a-2): mirror importCategoryOverrides — an empty/absent
	// set skips (import never wipes), a populated set merges (upsert by host) or
	// replaces. add()'s incoming==0 guard matches the never-wipe apply semantics.
	ovInc := 0
	if b.CategoryOverrides != nil {
		ovInc = categoryOverridesCount(*b.CategoryOverrides)
	}
	ovCur := 0
	if cur := captureCategoryOverrides(); cur != nil {
		ovCur = categoryOverridesCount(*cur)
	}
	add("Category Overrides", ovInc, ovCur, taxonomyNote)

	add("Rewrite Rules", len(b.RewriteRules), len(rewriter.List()), "")
	add("SSL Bypass", len(b.SSLBypass), len(sslBypass.List()), "")
	add("Content Scan Patterns", len(b.ContentScanPatterns), len(dpiScanner.List()), "")
	add("Content Scan Bypass Hosts", len(b.ContentScanBypassHosts), len(dpiScanner.BypassHosts()), "")
	add("File Block Extensions", len(b.FileBlockExtensions), fileBlocker.Count(), "")
	add("IP Filter List", len(b.IPList), len(ipf.List()), "")
	// Rate-limit exemptions: apiConfigImport always APPENDS (rl.AddExemption),
	// even in replace mode — the effect is additive regardless of mode.
	rlExemptCur := len(rl.ListExemptions())
	addFixed("Rate Limit Exemptions", len(b.RateLimitExempt), rlExemptCur,
		fmt.Sprintf("add %d to %d existing", len(b.RateLimitExempt), rlExemptCur),
		"import always appends exemptions (mode-independent)")
	add("PAC Exclusions", len(b.PACExclusions), len(pacStore.Get().Exclusions), "")
	add("Alert Webhooks", len(b.AlertWebhooks), len(globalAlertStore.List()), "")
	// Upstream proxies: apiConfigImport always REPLACES the pool via SetProxies
	// when the backup carries any — the effect is a full replace regardless of mode.
	upstreamCur := len(upstreamPool.List())
	addFixed("Upstream Proxies", len(b.UpstreamProxies), upstreamCur,
		fmt.Sprintf("replace %d existing with %d incoming", upstreamCur, len(b.UpstreamProxies)),
		"import always replaces the upstream pool (mode-independent)")

	return sections, buildImportSettingsPreview(b)
}

// buildImportSettingsPreview reports the scalar (non-collection) settings an
// import would apply. Split from buildImportPreview to keep each under the
// cyclop threshold; mirrors apiConfigImport's scalar-field guards exactly.
func buildImportSettingsPreview(b *configBackup) []importPreviewSetting {
	var settings []importPreviewSetting
	setting := func(name, value string) {
		settings = append(settings, importPreviewSetting{Setting: name, Value: value})
	}
	if b.DefaultAction == "allow" || b.DefaultAction == "deny" {
		setting("Default Policy Action", b.DefaultAction)
	}
	if b.BlocklistMode == "allow" || b.BlocklistMode == "block" {
		setting("Blocklist Mode", b.BlocklistMode)
	}
	if b.IPFilterMode != "" {
		setting("IP Filter Mode", b.IPFilterMode)
	}
	if b.RateLimitRPM > 0 {
		setting("Rate Limit", fmt.Sprintf("%d req/min", b.RateLimitRPM))
	}
	if b.PACProxyHost != "" {
		setting("PAC Proxy Host", b.PACProxyHost)
	}
	if b.PACProxyPort != 0 {
		setting("PAC Proxy Port", fmt.Sprintf("%d", b.PACProxyPort))
	}
	if b.BlockPageHTML != "" {
		setting("Block Page", "custom template")
	}
	if b.ConnLimitMaxPerIP > 0 {
		state := "disabled"
		if b.ConnLimitEnabled {
			state = "enabled"
		}
		setting("Connection Limit", fmt.Sprintf("%d per IP (%s)", b.ConnLimitMaxPerIP, state))
	}
	// SaaS feed config (F3a-2): gated on SaaSFeedProtocol != "" to mirror
	// importSaaSFeedConfig's apply gate exactly — a pre-extension backup (protocol
	// absent) applies nothing, so the preview must report nothing.
	if b.SaaSFeedProtocol != "" {
		mgmt := "unmanaged"
		if b.SaaSFeedManaged {
			mgmt = "managed"
		}
		state := "disabled"
		if b.SaaSFeedEnabled {
			state = "enabled"
		}
		setting("SaaS Feed", fmt.Sprintf("%s, %s (%s)", mgmt, state, b.SaaSFeedProtocol))
		if b.SaaSFeedURL != "" {
			setting("SaaS Feed URL", b.SaaSFeedURL)
		}
		if b.SaaSFeedRefreshSeconds != 0 {
			setting("SaaS Feed Refresh", fmt.Sprintf("%ds", b.SaaSFeedRefreshSeconds))
		}
	}
	return settings
}

// writeImportPreview renders the read-only dry-run response for an import: the
// per-section change summary and the scalar settings that would be applied. It
// mutates nothing (the audit-ring append mirrors the also-read-only
// config.export path and satisfies the route's AuditExpected metadata).
func writeImportPreview(w http.ResponseWriter, r *http.Request, b *configBackup, replaceMode bool) {
	sections, settings := buildImportPreview(b, replaceMode)
	mode := "merge"
	if replaceMode {
		mode = "replace"
	}
	auditEvent(r, "config.import.preview", mode, fmt.Sprintf("from config exported %s", b.ExportedAt))
	jsonOK(w, map[string]any{
		"dryRun":     true,
		"mode":       mode,
		"exportedAt": b.ExportedAt,
		"sections":   sections,
		"settings":   settings,
	})
}

// importPolicyRules applies the backup's policy rules under the given mode.
// Replace mode swaps the whole set; merge mode UPSERTS by identity — match by
// stable ULID first (idempotent re-import), then a one-time name fallback for
// pre-ID / hand-authored backups, else create fresh — so a re-import does not
// accumulate duplicates (POLICY-ARCHITECTURE-FUTURE §1).
func importPolicyRules(b *configBackup, replaceMode bool) {
	// Object-reference IDs are re-derived from the submitted NAMES, exactly like
	// the interactive write path (stampObjectRefIDs): enforcement is
	// ID-authoritative (failOpenScopeForRule, MatchesCategoryByID), so a backup
	// carrying a hand-edited decryptionProfileId/destCategoryGroupId that
	// disagrees with the displayed name would otherwise enforce the hidden ID
	// while UI/export/diff review shows the benign name. The taxonomy +
	// profiles sections import before this (leaf-first), so names resolve
	// against the just-imported objects; an unknown name leaves the ID empty
	// (name fallback, same as interactive).
	if replaceMode && len(b.PolicyRules) > 0 {
		rules := make([]PolicyRule, len(b.PolicyRules))
		copy(rules, b.PolicyRules)
		for i := range rules {
			stampObjectRefIDs(&rules[i])
		}
		policyStore.ReplaceAll(rules)
		return
	}
	// Index-based range: PolicyRule is a large struct (CLAUDE.md rangeValCopy).
	for i := range b.PolicyRules {
		rule := b.PolicyRules[i]
		stampObjectRefIDs(&rule)
		existing := policyStore.matchForImport(rule)
		editPriority := -1
		if existing != nil {
			// UpdateByID keeps the live rule's position and DISCARDS the payload
			// priority — so validate against the priority it will actually apply,
			// not the backup's. Otherwise a re-import after the rulebase was
			// reordered (payload priority now owned by a different live rule)
			// would spuriously fail the priority-uniqueness check and silently
			// drop the content update, defeating idempotency.
			rule.Priority = existing.Priority
			editPriority = existing.Priority
		}
		if err := validatePolicyRule(rule, policyStore.List(), editPriority); err != nil {
			logger.Printf("ConfigImport: skipping rule %q: %s", sanitizeLog(rule.Name), strings.ReplaceAll(err.Error(), "\n", ""))
			continue
		}
		if existing == nil {
			policyStore.Add(rule)
			continue
		}
		rule.ID = existing.ID // carry identity for the name-match upsert path
		if !policyStore.UpdateByID(existing.ID, rule) {
			// The matched rule vanished between match and update (concurrent
			// delete / import of the same rule). Don't silently drop the
			// incoming content — add it fresh rather than lose it.
			policyStore.Add(rule)
		}
	}
}

// POST /api/config/import — import configuration from an exported JSON file.
// Each section is applied atomically; partial failures are logged but do not abort.
// With ?dryRun=true the handler returns a read-only preview and applies nothing.
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

	// Dry-run/preview: compute what the import WOULD change and return the
	// summary WITHOUT touching any store. Read-only — no audit, no config
	// version, no admin-settings write. This is the safety gate the import UI
	// shows before an admin commits a (potentially destructive replace-mode)
	// import (P2 import-preview, POLICY-ARCHITECTURE-FUTURE §6).
	if r.URL.Query().Get("dryRun") == "true" {
		writeImportPreview(w, r, &b, replaceMode)
		return
	}

	// SaaS feed config (F3a-2). A managed Data Plane node must not import
	// CP-authoritative feed policy locally — reject the whole import with a
	// deterministic error before any mutation. And strict-validate the incoming
	// feed config through the F3a-1 boundary (reject legacy/unsupported protocol or
	// URL, and any invalid override) so a bad backup is refused whole, never
	// partially applied.
	if backupCarriesSaaSFeed(&b) && isManagedDataPlane() {
		http.Error(w, "saas feed config is control-plane managed on a data-plane node; import it on the control plane", http.StatusConflict)
		return
	}
	if err := validateSaaSFeedImport(&b); err != nil {
		http.Error(w, "invalid saas feed config: "+sanitizeLog(err.Error()), http.StatusBadRequest)
		return
	}

	// PAC pre-validation (before ANY store mutation): strictly validate the
	// IMPORTED PAC fields themselves so a malformed backup is rejected whole
	// with actionable errors instead of silently importing junk. Pre-existing
	// live entries are untouched by this gate — only the incoming payload is
	// judged, and the tolerant apply below never rejects.
	if !importPACPreValidationOK(w, &b, replaceMode) {
		return
	}

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

	// URL categories + category groups — BEFORE policy rules, matching
	// applyConfigBackup's leaf-first dependency order (rules reference groups,
	// groups reference categories by name).
	importCategoryTaxonomy(&b, replaceMode)

	// Category overrides (F3a-2) — leaf-first, before policy rules. Import never
	// wipes: an absent/empty override set skips in both modes (an explicit clear is
	// a rollback-only capability). Pre-validated above.
	importCategoryOverrides(&b, replaceMode)

	// Policy rules — replace or upsert-by-identity (extracted to keep the
	// handler under the nestif complexity threshold).
	importPolicyRules(&b, replaceMode)
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

	// Content scan patterns. Track replace-mode success: bypass hosts share
	// the content_scan.json envelope, and a failed pattern replace must not
	// be followed by a bypass import + Save — that would persist a mixed
	// old-patterns/new-bypass envelope matching neither the backup nor the
	// prior state. Mirrors applyConfigBackup's guard on the same envelope
	// (PR #557 Codex review). Merge-mode Add failures stay per-pattern and
	// additive, so they don't gate the bypass import.
	patternsOK := true
	if replaceMode && len(b.ContentScanPatterns) > 0 {
		if err := dpiScanner.Set(b.ContentScanPatterns); err != nil {
			patternsOK = false
			logger.Printf("ConfigImport: content scan patterns rejected: %s — skipping bypass-host import (shared envelope)", strings.ReplaceAll(err.Error(), "\n", ""))
		}
	} else {
		for _, p := range b.ContentScanPatterns {
			_ = dpiScanner.Add(p)
		}
	}
	if patternsOK {
		// DPI bypass hosts — applied before the single Save so both halves
		// of the envelope persist atomically.
		importScanBypassHosts(&b, replaceMode)
		dpiScanner.Save()
	}

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
	// Bulk load: one pass, one view publish (an Add loop is quadratic).
	// Invalid entries stay silently skipped, as the Add loop did.
	_ = ipf.AddAll(b.IPList)
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

	// PAC profiles/pools (PAC initiative PR 2): import never wipes —
	// absent/empty fields skip in both modes; merge upserts by ID; replace
	// replaces the whole set. Pre-validated above; tolerant Set here.
	if len(b.PACProfiles) > 0 || len(b.PACPools) > 0 {
		_ = pacProfiles.Set(importPACProfilesCandidate(pacProfiles.Get(), &b, replaceMode))
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

	// Upstream proxies (Finding 10.3). SetProxies keeps the YAML-configured
	// circuit-breaker parameters (previously hardcoded to 5/60s here).
	if len(b.UpstreamProxies) > 0 {
		upstreamPool.SetProxies(b.UpstreamProxies)
		applyUpstreamProxy()
	}

	// Connection limits (Finding 10.3).
	if b.ConnLimitMaxPerIP > 0 {
		if b.ConnLimitEnabled {
			connLimiter.Enable(b.ConnLimitMaxPerIP)
		} else {
			connLimiter.Disable()
		}
	}

	// SaaS feed config (F3a-2). Never-wipe: applied only when the backup carries it
	// (SaaSFeedProtocol set). Pre-validated above; publishes to the durable holder
	// only (persisted by adminSettingsSave below) — no downloader/legacy syncer.
	importSaaSFeedConfig(&b)

	importMode := "merge"
	if replaceMode {
		importMode = "replace"
	}
	auditEvent(r, "config.import", importMode, fmt.Sprintf("from config exported %s", b.ExportedAt))
	saveConfigVersion(sessionAdmin(r), "config.import")
	// Snapshot the admin-settings layer (rate limit, IP filter, rewrite
	// rules, block page, conn limit, upstream pool, …) so the imported state
	// survives a restart — import previously left it runtime-only.
	adminSettingsSave()
	// Republish the cluster snapshot: import is a recovery path operators use
	// interchangeably with rollback (which already republishes) — DPs must
	// converge on the imported state without waiting for an unrelated
	// mutation (Palo fleet review, ops finding 2). The imported config is
	// applied locally regardless; if it exceeds a cluster-sync cap the publish
	// is rejected at commit — report that inline so the admin knows the fleet
	// did not receive it (the local import still succeeded).
	pubErr := publishCurrentConfigSnapshot()
	resp := map[string]any{"ok": true, "mode": importMode, "exportedAt": b.ExportedAt}
	if pubErr != nil {
		resp["cluster_publish_rejected"] = pubErr.Error()
	}
	jsonOK(w, resp)
}

// importPACPreValidationOK strictly validates the PAC fields of an import
// payload BEFORE any store mutation, writing a structured 400 and returning
// false on failure. Only the incoming payload is judged; the tolerant apply
// path never rejects.
func importPACPreValidationOK(w http.ResponseWriter, b *configBackup, replaceMode bool) bool {
	var issues []pac.ValidationIssue
	if b.PACProxyHost != "" || b.PACProxyPort != 0 || len(b.PACExclusions) > 0 {
		_, is := pac.ValidateConfig(PACConfig{
			ProxyHost:  b.PACProxyHost,
			ProxyPort:  b.PACProxyPort,
			Exclusions: b.PACExclusions,
		})
		issues = append(issues, is...)
	}
	// Profiles/pools are validated as the EXACT candidate the apply step
	// would install (merged against existing state), so a profile that
	// references an already-present pool passes and a dangling reference
	// fails — before any mutation.
	if len(b.PACProfiles) > 0 || len(b.PACPools) > 0 {
		candidate := importPACProfilesCandidate(pacProfiles.Get(), b, replaceMode)
		issues = append(issues, pac.ValidateProfilesConfig(candidate)...)
	}
	if len(issues) == 0 {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort error body
		"error":  "PAC configuration in import failed validation",
		"issues": issues,
	})
	return false
}

// importPACProfilesCandidate builds the exact profiles/pools config an
// import would install: replace mode swaps whole non-empty sets; merge mode
// upserts by ID (existing objects updated in place, new ones appended).
// Import never wipes — absent/empty payload fields keep the current set.
func importPACProfilesCandidate(cur pac.ProfilesConfig, b *configBackup, replaceMode bool) pac.ProfilesConfig {
	if replaceMode {
		if len(b.PACPools) > 0 {
			cur.Pools = b.PACPools
		}
		if len(b.PACProfiles) > 0 {
			cur.Profiles = b.PACProfiles
		}
		return cur
	}
	for pi := range b.PACPools {
		in := b.PACPools[pi]
		replaced := false
		for i := range cur.Pools {
			if cur.Pools[i].ID == in.ID {
				cur.Pools[i] = in
				replaced = true
				break
			}
		}
		if !replaced {
			cur.Pools = append(cur.Pools, in)
		}
	}
	for pi := range b.PACProfiles {
		in := b.PACProfiles[pi]
		replaced := false
		for i := range cur.Profiles {
			if cur.Profiles[i].ID == in.ID {
				in.Revision = cur.Profiles[i].Revision + 1
				cur.Profiles[i] = in
				replaced = true
				break
			}
		}
		if !replaced {
			cur.Profiles = append(cur.Profiles, in)
		}
	}
	return cur
}

// importCategoryTaxonomy applies URL categories then category groups from an
// import backup, in that order — groups reference categories by name and
// policy rules (applied by the caller AFTER this) reference groups, the same
// leaf-first chain as applyConfigBackup (configversion.go). Empty/absent
// slices are skipped in BOTH modes: import never wipes (an old backup without
// these fields must not clear live taxonomy); explicit wipes are a
// rollback-surface capability only. Merge mode upserts by name (incoming
// wins) so re-importing an edited backup updates entries instead of
// duplicating them.
func importCategoryTaxonomy(b *configBackup, replaceMode bool) {
	if len(b.URLCategories) > 0 {
		if replaceMode {
			catStore.ReplaceAll(b.URLCategories)
		} else {
			catStore.ReplaceAll(mergeByName(catStore.All(), b.URLCategories,
				func(e CategoryEntry) string { return e.Name }))
		}
		catStore.Save()
		// The imported taxonomy's BuiltIn entries are served from the effective view, so
		// the import only reaches policy evaluation after a recompose. importCategoryOverrides
		// runs its own recompose but early-returns on an absent/empty override set, which is
		// the common case for a taxonomy-only import.
		recomposeSignedFeedTaxonomy()
	}
	if len(b.CategoryGroups) > 0 {
		if replaceMode {
			globalCategoryGroups.ReplaceAll(b.CategoryGroups)
		} else {
			globalCategoryGroups.ReplaceAll(mergeByName(globalCategoryGroups.List(), b.CategoryGroups,
				func(g CategoryGroup) string { return g.Name }))
		}
		globalCategoryGroups.Save()
	}
	// Decryption profiles — import never wipes (absent/empty skips); merge = upsert
	// by name. Applied before policy rules (this runs inside importCategoryTaxonomy,
	// called before the rule import) so a rule's DecryptionProfile ref resolves.
	if len(b.DecryptionProfiles) > 0 {
		if replaceMode {
			globalDecryptionProfiles.ReplaceAll(b.DecryptionProfiles)
		} else {
			globalDecryptionProfiles.ReplaceAll(mergeByName(globalDecryptionProfiles.List(), b.DecryptionProfiles,
				func(p DecryptionProfile) string { return p.Name }))
		}
		globalDecryptionProfiles.Save()
	}
}

// importScanBypassHosts applies the DPI bypass-host half of the
// content_scan.json envelope. The caller runs this before its single
// dpiScanner.Save() so patterns and bypass hosts persist in one atomic
// envelope write. Empty/absent is skipped in both modes (no import wipes).
func importScanBypassHosts(b *configBackup, replaceMode bool) {
	if len(b.ContentScanBypassHosts) == 0 {
		return
	}
	if replaceMode {
		dpiScanner.SetBypassHosts(b.ContentScanBypassHosts)
		return
	}
	merged := b.ContentScanBypassHosts
	existing := dpiScanner.BypassHosts()
	seen := make(map[string]struct{}, len(existing)+len(merged))
	union := make([]string, 0, len(existing)+len(merged))
	for _, h := range append(existing, merged...) {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		union = append(union, h)
	}
	dpiScanner.SetBypassHosts(union)
}

// mergeByName upserts incoming entries into existing by case-insensitive
// name: matches are replaced in place (incoming wins), new names are
// appended. Existing order is preserved so a merge-mode import doesn't
// reshuffle the operator's list.
func mergeByName[T any](existing, incoming []T, name func(T) string) []T {
	merged := make([]T, len(existing))
	copy(merged, existing)
	idx := make(map[string]int, len(merged))
	for i := range merged {
		idx[strings.ToLower(name(merged[i]))] = i
	}
	for i := range incoming {
		key := strings.ToLower(name(incoming[i]))
		if j, ok := idx[key]; ok {
			merged[j] = incoming[i]
		} else {
			idx[key] = len(merged)
			merged = append(merged, incoming[i])
		}
	}
	return merged
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
		// Synchronized setter — rotation happens while concurrent requests
		// compute session MACs (internal/session owns the lock).
		session.SetSigningKey(key)
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

// syslogConfigured tracks whether syslog was initialised SUCCESSFULLY so the UI
// can reflect it AND so admin_settings persistence only re-saves a working addr
// (see admin_settings.go:447 — never persist a connect-failed target).
var syslogConfigured string // the addr string, empty = not configured

// syslogConfiguredAddr records the operator-configured syslog/SIEM target
// regardless of whether InitSyslog actually connected (mirrors
// auditLogConfiguredPath). buildOperatorContract's checkSyslogFeed compares
// it against the live globalSyslog handle so the Diagnostics panel can tell an
// intentional "no SIEM feed" apart from a configured feed that silently failed
// to connect at startup — the latter previously left only one startup log line
// as signal while the /api/syslog readback reported the feed as "not
// configured". Kept in sync at both startup paths (loadObservability,
// applyAdminServices) and the runtime API (apiSyslogConfig enable/disable).
var syslogConfiguredAddr string

// auditLogConfiguredPath / requestLogConfiguredPath record the operator-
// configured persistent-log path (set in loadObservability regardless of
// whether the underlying engine's Init() actually succeeded). apiStats
// compares these against {audit,requestLog}PersistActive() so the GUI can
// tell an intentional in-memory-only setup apart from a configured path
// that silently fell back to volatile storage on open failure.
var (
	auditLogConfiguredPath   string
	requestLogConfiguredPath string
)

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
		var drops, panics uint64
		if globalSyslog != nil {
			format = globalSyslog.Format()
			// Read panics before drops: deliverGuarded's recover branch always
			// increments panics first, then drops (independent atomics, no
			// combined snapshot). Reading in the same order means a report can
			// only ever lag panics behind drops, never the reverse — so the
			// UI's `drops > 0` gate can never hide a real panic behind a
			// stale-looking drops==0.
			panics = globalSyslog.Panics()
			drops = globalSyslog.Drops()
		}
		jsonOK(w, map[string]any{"addr": syslogConfigured, "format": format, "drops": drops, "panics": panics})
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
			syslogConfiguredAddr = ""
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
		syslogConfiguredAddr = body.Addr
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
	// Write sends a single PRI=14 message — same path as the old writeMsg(14, …),
	// now via the exported io.Writer surface (writeMsg is package-internal).
	_, _ = globalSyslog.Write([]byte("Culvert syslog test message — connectivity verified"))
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

// PUT /api/settings/default-auth-outcome — set the global default authentication
// behavior. (Also reachable at the legacy /api/settings/unauth-mode path, kept
// as a back-compat alias.) Scoped auth rules always evaluate first; this
// default applies only to unmatched traffic, and Exempt is NOT an allow —
// Stage-2 policy and default-deny still apply.) Accepts
// {"defaultAuthOutcome":"Default"|"Exempt"}.
func apiDefaultAuthOutcome(w http.ResponseWriter, r *http.Request) {
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
			"trusted_proxy_cidrs":     ListTrustedProxyCIDRs(),
			"ui_tls_fallback":         uiTLSFallbackActive,
			"ui_tls_fallback_reason":  uiTLSFallbackReason,
			"ui_custom_cert_uploaded": customUITLSFilesPresent(),
			"ui_custom_cert_active":   uiCustomTLSActive,
			"ui_custom_cert_corrupt":  uiCustomTLSCorrupt,
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			BaseURL               string   `json:"base_url"`
			UISANs                []string `json:"ui_sans"`
			TrustForwardedHeaders bool     `json:"trust_forwarded_headers"`
			TrustedProxyCIDRs     []string `json:"trusted_proxy_cidrs"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Validate + apply the trusted-proxy set BEFORE the other mutations so
		// an invalid CIDR rejects the whole update without partial application.
		if err := SetTrustedProxyCIDRs(body.TrustedProxyCIDRs); err != nil {
			http.Error(w, "invalid trusted_proxy_cidrs: "+err.Error(), http.StatusBadRequest)
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
		_ = publishCurrentConfigSnapshot()
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
			"enabled":       connLimiter.Enabled(),
			"maxPerIP":      connLimiter.MaxPerIP(),
			"activeIPs":     connLimiter.ActiveIPs(),
			"rejectedTotal": connLimiter.Rejected(),
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
		auditEvent(r, "connlimit.update", fmt.Sprintf("enabled=%v max=%d", connLimiter.Enabled(), connLimiter.MaxPerIP()), "")
		adminSettingsSave()
		jsonOK(w, map[string]any{"ok": true, "enabled": connLimiter.Enabled(), "maxPerIP": connLimiter.MaxPerIP()})
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

// upstreamDirectFallbackStatus is the CHAOS-11 fail-open visibility block
// shared by the upstream GET surfaces: whether the pool is currently
// bypassed to direct egress and how many requests have fallen back.
func upstreamDirectFallbackStatus() map[string]any {
	active, total := upstreamPool.DirectFallback()
	return map[string]any{"active": active, "total": total}
}

func apiUpstream(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]any{
			"enabled":         upstreamPool.Enabled(),
			"proxies":         upstreamPool.List(),
			"direct_fallback": upstreamDirectFallbackStatus(),
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
		// SetProxies keeps the YAML-configured circuit-breaker parameters;
		// adminSettingsSave makes the change survive a restart (the pool is
		// otherwise runtime-only — Finding 10.3 out-of-scope observation).
		upstreamPool.SetProxies(body.Proxies)
		applyUpstreamProxy()
		auditEvent(r, "upstream.update", fmt.Sprintf("%d proxies", len(body.Proxies)), "")
		adminSettingsSave()
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
		"enabled":         upstreamPool.Enabled(),
		"proxies":         upstreamPool.List(),
		"direct_fallback": upstreamDirectFallbackStatus(),
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
	if h := globalOTLP.Headers(); len(h) > 0 {
		return h
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
		headers := globalOTLP.Headers()
		hasAuth := len(headers) > 0
		authName := ""
		for k := range headers {
			authName = k // return the header NAME (not value) so UI can show it
			break
		}
		jsonOK(w, map[string]any{
			"enabled":        globalOTLP.Enabled(),
			"endpoint":       globalOTLP.Endpoint(),
			"hasAuth":        hasAuth,
			"authHeaderName": authName,
			"metricsHealth":  globalOTLP.Health(),
			"tracesHealth":   globalOTLPTraces.Health(),
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
	mux.HandleFunc("/api/config/export", apiConfigExport)     // GET — download exported config JSON
	mux.HandleFunc("/api/config/import", apiConfigImport)     // POST — restore from exported config JSON
	mux.HandleFunc("/api/config/versions", apiConfigVersions) // GET list / POST rollback
	mux.HandleFunc("/api/config/diff", apiConfigDiff)         // GET diff between versions

	// ── Auth / network / session settings ─────────────────────────────────
	mux.HandleFunc("/api/settings/default-auth-outcome", apiDefaultAuthOutcome) // PUT — toggle proxy auth requirement
	mux.HandleFunc("/api/settings/unauth-mode", apiDefaultAuthOutcome)          // PUT — legacy alias, kept for back-compat
	mux.HandleFunc("/api/settings/log-level", apiLogLevel)                      // GET/PUT runtime log level
	mux.HandleFunc("/api/settings/network", apiNetworkSettings)                 // GET/POST network & TLS settings
	mux.HandleFunc("/api/session-timeout", apiSessionTimeout)                   // GET/POST session TTL (hours)
	mux.HandleFunc("/api/session-secret", apiSessionSecret)                     // GET/POST shared signing key
	mux.HandleFunc("/api/ui-allow-ips", apiUIAllowIPs)                          // GET/POST UI access IP allowlist

	// ── Syslog / logger / metrics / OTLP / connlimit (handlers in
	// dedicated files, registered here per Option A). ─────────────────────
	mux.HandleFunc("/api/syslog", apiSyslogConfig)          // GET/POST syslog forwarding
	mux.HandleFunc("/api/syslog/test", apiSyslogTest)       // POST syslog test message
	mux.HandleFunc("/api/logger", apiLoggerConfig)          //
	mux.HandleFunc("/api/metrics-config", apiMetricsConfig) //
	mux.HandleFunc("/api/otlp", apiOTLPConfig)              //
	mux.HandleFunc("/api/connlimit", apiConnLimit)          // GET status / POST update
}
