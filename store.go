package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// ─── Uptime ───────────────────────────────────────────────────────────────────

var startTime = time.Now()

// ─── Stats ────────────────────────────────────────────────────────────────────

var (
	statTotal       int64
	statBlocked     int64
	statAuthFail    int64
	statFileBlocked int64 // requests blocked by the file-extension profile
	statBytesSent   int64 // total bytes sent upstream (request bodies)
	statBytesRecv   int64 // total bytes received from upstream (response bodies)
	statAuthExempt  int64 // Stage-1 Exempt decisions (Phase 1 Slice 5: defined, NOT incremented from runtime yet)

	statAuthCredentialRequired int64 // Stage-1 CredentialRequired decisions (Phase 2 Slice 2: defined, NOT incremented from runtime yet)
)

// ─── Time-series: requests per minute, last 60 minutes ───────────────────────

type timeSeries struct {
	mu      sync.Mutex
	buckets [60]int64
	allowed [60]int64
	blocked [60]int64
	cur     int
	lastMin int64
}

var ts = &timeSeries{}

func tsAdvance() {
	now := time.Now().Unix() / 60
	if ts.lastMin == 0 {
		ts.lastMin = now
	}
	diff := now - ts.lastMin
	if diff > 0 {
		if diff > 60 {
			diff = 60
		}
		for i := int64(0); i < diff; i++ {
			ts.cur = (ts.cur + 1) % 60
			ts.buckets[ts.cur] = 0
			ts.allowed[ts.cur] = 0
			ts.blocked[ts.cur] = 0
		}
		ts.lastMin = now
	}
}

func tsRecord() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	tsAdvance()
	ts.buckets[ts.cur]++
}

func tsRecordResult(isAllowed bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	tsAdvance()
	ts.buckets[ts.cur]++
	if isAllowed {
		ts.allowed[ts.cur]++
	} else {
		ts.blocked[ts.cur]++
	}
}

func tsGet() (total, allowed, blocked []int64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	total = make([]int64, 60)
	allowed = make([]int64, 60)
	blocked = make([]int64, 60)
	for i := 0; i < 60; i++ {
		idx := (ts.cur - i + 60) % 60
		total[59-i] = ts.buckets[idx]
		allowed[59-i] = ts.allowed[idx]
		blocked[59-i] = ts.blocked[idx]
	}
	return
}

// ─── Request log ──────────────────────────────────────────────────────────────

type LogEntry struct {
	TS          int64  `json:"ts"`
	Time        string `json:"time"`
	IP          string `json:"ip"`
	Identity    string `json:"identity,omitempty"` // authenticated username/email, empty if unauthenticated
	Method      string `json:"method"`
	Host        string `json:"host"`
	URI         string `json:"uri,omitempty"`       // full request URL (host+path, no query); only set when the matched rule has LogFullURI
	Status      string `json:"status"`              // OK | BLOCKED | AUTH_FAIL | RATE_LIMITED | IP_BLOCKED | POLICY_*
	Level       string `json:"level"`               // INFO | WARN | ERROR
	RuleMatched string `json:"ruleMatched"`         // policy rule name that matched, if any
	ActionTaken string `json:"actionTaken"`         // policy action taken, if any
	BytesSent   int64  `json:"bytesSent,omitempty"` // bytes sent to upstream (request body)
	BytesRecv   int64  `json:"bytesRecv,omitempty"` // bytes received from upstream (response body)
	SSLAction   string `json:"sslAction,omitempty"` // "inspect", "bypass", or empty (non-CONNECT)

	// Normalized authentication-policy SIEM fields (Phase 0 seam, §1.8; the
	// auth_* observability block is finalized in Phase 1 Slice 5). Declared as the
	// durable SIEM contract but populated only when an auth decision supplies them
	// — all are omitempty so wire output stays byte-identical for requests with no
	// auth decision. NO identity is carried in the auth_* block: an Exempt decision
	// is logged by outcome + rule id/name (+ low-cardinality subject predicate
	// types and the matched rule's subject schema version) only.
	SchemaVersion         int      `json:"schema_version,omitempty"`           // event schema version
	AuthSource            string   `json:"auth_source,omitempty"`              // categorical: idp|local|oidc:x|saml:x|exempt|unauth
	AuthOutcome           string   `json:"auth_outcome,omitempty"`             // Stage-1 outcome (e.g. "Exempt"); "" = none
	AuthPolicyRuleID      string   `json:"auth_policy_rule_id,omitempty"`      // ULID of matched Stage-1 rule
	AuthPolicyRuleName    string   `json:"auth_policy_rule_name,omitempty"`    // display name of matched Stage-1 rule
	AccessRuleID          string   `json:"access_rule_id,omitempty"`           // ULID of matched Stage-2 rule
	AuthSubjectMatchTypes []string `json:"auth_subject_match_types,omitempty"` // low-cardinality predicate type names (e.g. ["cidr"])
	AuthSchemaVersion     int      `json:"auth_schema_version,omitempty"`      // matched rule's SubjectMatch schema version
}

// AuthLogFields carries the low-cardinality Stage-1 authentication-policy
// observability fields attached to a request log entry. The zero value adds
// nothing to the wire output (every target field is omitempty). It deliberately
// carries NO identity — see the LogEntry auth_* contract above. Populate it only
// from an actual auth decision (authLogFieldsFor); existing recordRequest call
// sites pass the zero value implicitly and stay byte-identical.
type AuthLogFields struct {
	Outcome           AuthOutcome
	PolicyRuleID      string
	PolicyRuleName    string
	SubjectMatchTypes []string
	SchemaVersion     int
}

// applyTo copies the auth observability fields onto a log entry. It never touches
// Identity (Exempt is logged by outcome + rule id/name only).
func (a AuthLogFields) applyTo(e *LogEntry) {
	e.AuthOutcome = string(a.Outcome)
	e.AuthPolicyRuleID = a.PolicyRuleID
	e.AuthPolicyRuleName = a.PolicyRuleName
	e.AuthSubjectMatchTypes = a.SubjectMatchTypes
	e.AuthSchemaVersion = a.SchemaVersion
}

func levelForStatus(status string) string {
	switch status {
	case "OK", "POLICY_ALLOW":
		return "INFO"
	case "BLOCKED", "THREAT_BLOCKED", "FILE_BLOCKED", "SCAN_BLOCKED",
		"DPI_BLOCKED", "POLYGLOT_BLOCKED", "CDR_BLOCKED", "CDR_SANITIZED",
		"RATE_LIMITED", "IP_BLOCKED",
		"POLICY_BLOCK", "POLICY_DROP", "POLICY_REDIRECT", "POLICY_DEFAULT_DENY":
		return "WARN"
	default: // AUTH_FAIL, CDR_ERROR, and anything unexpected
		return "ERROR"
	}
}

const maxLogs = 5000

var (
	logsMu sync.Mutex
	logs   []LogEntry
)

// ─── Persistent JSONL request log ────────────────────────────────────────────

var (
	requestLogWriter   io.Writer // *rotatingFile; nil = file persistence disabled
	requestLogCloser   io.Closer
	requestLogFilePath string // path to JSONL file for paginated reads; "" = disabled
)

// requestLogMaxPersistentReturn caps the newest-N entries returned from the
// persistent JSONL request log so admin queries remain bounded regardless of
// the on-disk rotation size. Roughly one day of traffic at ~100 req/s.
const requestLogMaxPersistentReturn = 20000

// Persistent request-log failure counters. A full disk or corrupt file must
// not silently destroy the request history — both are counted, surfaced via
// /metrics, /api/stats, and /healthz, and logged once (not per occurrence).
var (
	statReqLogWriteErrors  int64 // failed JSONL marshals/writes in logAdd
	statReqLogSkippedLines int64 // corrupt JSONL lines skipped on read
)

// reqLogReadCache memoises the parsed persistent log for a short TTL so N
// concurrent dashboard pollers share one file parse instead of each re-reading
// up to requestLogMaxPersistentReturn JSON lines per request. Keyed by path so
// a re-init (config change, tests) never serves entries from the old file.
// Cached entries are shared read-only between callers — never mutate them.
var reqLogReadCache struct {
	mu      sync.Mutex
	path    string
	expires time.Time
	entries []LogEntry
}

// requestLogReadCacheTTL bounds staleness; the dashboard polls every 3 s.
const requestLogReadCacheTTL = 2 * time.Second

// initRequestLog opens a rotating JSONL file for persistent request logging.
// Each LogEntry is appended as a single JSON line. The file rotates at maxMB.
// If path is empty this is a no-op (backwards-compatible).
func initRequestLog(path string, maxMB int) error {
	if path == "" {
		return nil
	}
	if maxMB <= 0 {
		maxMB = 100
	}
	rf, err := newRotatingFile(path, maxMB)
	if err != nil {
		return fmt.Errorf("request log open %s: %w", path, err)
	}
	requestLogWriter = rf
	requestLogCloser = rf
	requestLogFilePath = path

	// Drop any cached parse from a previous file.
	reqLogReadCache.mu.Lock()
	reqLogReadCache.path = ""
	reqLogReadCache.entries = nil
	reqLogReadCache.mu.Unlock()
	return nil
}

// requestLogReadPersistent streams the persistent JSONL request log file and
// returns the newest-first slice of parsed entries, capped at
// requestLogMaxPersistentReturn so memory stays bounded regardless of file
// size. Callers should apply their own filter + pagination loop on top — the
// same loop they use on the in-memory ring buffer — so there is a single
// filter code path to maintain.
//
// Returns (nil, nil) when persistence is disabled (no file configured) or
// when the file has not yet been created. Only the active (non-rotated) log
// file is consulted; the rotated ".1" archive is intentionally skipped to
// keep each query bounded to one rotation window.
func requestLogReadPersistent() ([]LogEntry, error) {
	path := requestLogFilePath
	if path == "" {
		return nil, nil
	}
	// Serialise readers through the cache lock: the first poller parses the
	// file, concurrent pollers wait and then reuse the fresh cached result.
	reqLogReadCache.mu.Lock()
	defer reqLogReadCache.mu.Unlock()
	if reqLogReadCache.path == path && time.Now().Before(reqLogReadCache.expires) {
		return reqLogReadCache.entries, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("request log open: %w", err)
	}
	defer f.Close() //nolint:errcheck -- read-only close

	sc := bufio.NewScanner(f)
	// SSL-inspected entries with long identity/rule strings occasionally
	// exceed the 64 KB default scanner buffer; lift the ceiling to 1 MB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// Amortized O(N) truncate-to-cap: grow up to 2× cap, then drop the oldest
	// half. Peak memory is ~2× cap parsed structs (~8 MB at cap=20k).
	const cap_ = requestLogMaxPersistentReturn
	buf := make([]LogEntry, 0, 2*cap_)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e LogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			// Count corrupt lines instead of dropping them invisibly; log only
			// the first so a damaged file cannot flood the logger.
			if atomic.AddInt64(&statReqLogSkippedLines, 1) == 1 {
				logger.Printf("WARN request log: skipping corrupt JSONL line (further occurrences counted silently): %v", err)
			}
			continue
		}
		buf = append(buf, e)
		if len(buf) >= 2*cap_ {
			copy(buf, buf[len(buf)-cap_:])
			buf = buf[:cap_]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("request log scan: %w", err)
	}
	if len(buf) > cap_ {
		buf = buf[len(buf)-cap_:]
	}
	// Reverse in place to newest-first.
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	reqLogReadCache.path = path
	reqLogReadCache.expires = time.Now().Add(requestLogReadCacheTTL)
	reqLogReadCache.entries = buf
	return buf, nil
}

func logAdd(e LogEntry) {
	logsMu.Lock()
	logs = append(logs, e)
	if len(logs) > maxLogs {
		logs = logs[len(logs)-maxLogs:]
	}
	logsMu.Unlock()

	// Persist to JSONL file (outside the lock to avoid blocking callers).
	if w := requestLogWriter; w != nil {
		b, err := json.Marshal(e)
		if err == nil {
			b = append(b, '\n')
			_, err = w.Write(b)
		}
		if err != nil {
			// A full disk must not silently destroy the request history:
			// count every failure, log only the first to avoid flooding.
			if atomic.AddInt64(&statReqLogWriteErrors, 1) == 1 {
				logger.Printf("ERROR request log: persistent write failed (further failures counted silently): %v", err)
			}
		}
	}

	// Persist to the queryable history store (async, non-blocking, nil-safe).
	globalLogStore.Add(e)
}

func logGet() []LogEntry {
	logsMu.Lock()
	cp := make([]LogEntry, len(logs))
	copy(cp, logs)
	logsMu.Unlock()
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}

// ─── Audit Log ────────────────────────────────────────────────────────────────
//
// AuditEntry captures every configuration change made through the UI/API so
// operators can answer "Who changed What, and When?" — a core SOC requirement.
//
// Actor is the client IP of the UI caller.  When the UI gains its own
// authentication layer the Actor field will be upgraded to a username.
// Action follows a "resource.verb" naming scheme (e.g. "policy.add").

type AuditEntry struct {
	TS     int64  `json:"ts"`               // Unix milliseconds
	Time   string `json:"time"`             // human-readable "2006-01-02 15:04:05"
	Actor  string `json:"actor"`            // client IP (or authenticated username)
	Action string `json:"action"`           // "policy.add" | "blocklist.remove" | …
	Object string `json:"object"`           // the specific item that changed
	Detail string `json:"detail"`           // extra context (never contains credentials)
	Before string `json:"before,omitempty"` // JSON snapshot before the change
	After  string `json:"after,omitempty"`  // JSON snapshot after the change
}

const maxAuditLogs = 500

var (
	auditMu          sync.Mutex
	auditLog         []AuditEntry
	auditLogFile     io.Writer // persistent JSONL file; nil = in-memory only
	auditCloser      io.Closer // close on shutdown
	auditLogFilePath string    // path to JSONL file for paginated reads
)

// clusterRoleIsDP is set to true when this node is a Data Plane in a cluster.
// Enables audit event queuing for centralized logging on the Control Plane.
var clusterRoleIsDP atomic.Bool

// InitAuditLog opens path for append-only JSONL persistence with rotation.
// Existing entries are loaded into the in-memory ring buffer on startup.
// If path is empty this is a no-op (backwards-compatible).
// F18: Rotates at 50 MB (same as system log) to prevent unbounded disk growth.
func InitAuditLog(path string) error {
	if path == "" {
		return nil
	}
	// Load existing entries first.
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var e AuditEntry
			if json.Unmarshal([]byte(line), &e) == nil {
				auditLog = append(auditLog, e)
			}
		}
		if len(auditLog) > maxAuditLogs {
			auditLog = auditLog[len(auditLog)-maxAuditLogs:]
		}
	}
	rf, err := newRotatingFile(path, 50) // 50 MB max before rotation
	if err != nil {
		return fmt.Errorf("audit log open %s: %w", path, err)
	}
	auditLogFile = rf
	auditCloser = rf
	auditLogFilePath = path
	return nil
}

// auditGetPersistent reads the JSONL audit log file with pagination.
// Returns entries newest-first. If from/to are non-zero, filters by timestamp.
// Falls back to in-memory buffer if no file is configured.
func auditGetPersistent(offset, limit int, fromTS, toTS int64) ([]AuditEntry, int) {
	if auditLogFilePath == "" {
		all := auditGet()
		// Apply timestamp filters.
		if fromTS > 0 || toTS > 0 {
			filtered := make([]AuditEntry, 0, len(all))
			for i := range all {
				if fromTS > 0 && all[i].TS < fromTS {
					continue
				}
				if toTS > 0 && all[i].TS > toTS {
					continue
				}
				filtered = append(filtered, all[i])
			}
			all = filtered
		}
		total := len(all)
		if offset >= total {
			return nil, total
		}
		end := offset + limit
		if end > total {
			end = total
		}
		return all[offset:end], total
	}

	data, err := os.ReadFile(auditLogFilePath)
	if err != nil {
		return auditGet(), 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// Parse all entries.
	entries := make([]AuditEntry, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			if fromTS > 0 && e.TS < fromTS {
				continue
			}
			if toTS > 0 && e.TS > toTS {
				continue
			}
			entries = append(entries, e)
		}
	}
	// Reverse to newest-first.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	total := len(entries)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return entries[offset:end], total
}

// auditAdd appends an entry to the in-memory ring buffer and, when configured,
// to the persistent JSONL file and the syslog forwarder.
func auditAdd(e AuditEntry) {
	auditMu.Lock()
	auditLog = append(auditLog, e)
	if len(auditLog) > maxAuditLogs {
		auditLog = auditLog[len(auditLog)-maxAuditLogs:]
	}
	f := auditLogFile
	auditMu.Unlock()

	// Persist to JSONL file (outside the lock to avoid blocking callers).
	if f != nil {
		if b, err := json.Marshal(e); err == nil {
			b = append(b, '\n')
			f.Write(b) //nolint:errcheck
		}
	}
	// Forward to syslog/SIEM if configured.
	if globalSyslog != nil {
		globalSyslog.WriteAudit(e)
	}
	// Queue for CP push when running as Data Plane.
	if clusterRoleIsDP.Load() {
		queueAuditForCluster(e)
	}
}

// ─── Pending audit events for Data Plane → Control Plane push ───────────────

var (
	pendingAuditMu     sync.Mutex
	pendingAuditEvents []AuditEntry
)

// queueAuditForCluster adds an audit event to the pending queue for CP push.
// Called by auditAdd when running in data-plane mode.
func queueAuditForCluster(e AuditEntry) {
	pendingAuditMu.Lock()
	pendingAuditEvents = append(pendingAuditEvents, e)
	// Cap at 1000 to prevent unbounded growth if CP is unreachable.
	if len(pendingAuditEvents) > 1000 {
		pendingAuditEvents = pendingAuditEvents[len(pendingAuditEvents)-1000:]
	}
	pendingAuditMu.Unlock()
}

// drainPendingAuditEvents returns and clears the pending audit event queue.
func drainPendingAuditEvents() []AuditEntry {
	pendingAuditMu.Lock()
	defer pendingAuditMu.Unlock()
	if len(pendingAuditEvents) == 0 {
		return nil
	}
	events := pendingAuditEvents
	pendingAuditEvents = nil
	return events
}

// requeueAuditEvents prepends failed events back into the pending queue
// so they are retried on the next push interval instead of being lost.
func requeueAuditEvents(events []AuditEntry) {
	pendingAuditMu.Lock()
	// Prepend old events before any new ones that arrived since drain.
	pendingAuditEvents = append(events, pendingAuditEvents...)
	// Cap at 1000 (keep newest).
	if len(pendingAuditEvents) > 1000 {
		pendingAuditEvents = pendingAuditEvents[len(pendingAuditEvents)-1000:]
	}
	pendingAuditMu.Unlock()
}

// auditGet returns a newest-first snapshot of the audit log.
func auditGet() []AuditEntry {
	auditMu.Lock()
	cp := make([]AuditEntry, len(auditLog))
	copy(cp, auditLog)
	auditMu.Unlock()
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}

// auditGetMemory returns paginated, optionally time-filtered entries from the
// in-memory ring buffer (newest-first).
func auditGetMemory(offset, limit int, fromTS, toTS int64) ([]AuditEntry, int) {
	all := auditGet()
	if fromTS > 0 || toTS > 0 {
		filtered := make([]AuditEntry, 0, len(all))
		for i := range all {
			if fromTS > 0 && all[i].TS < fromTS {
				continue
			}
			if toTS > 0 && all[i].TS > toTS {
				continue
			}
			filtered = append(filtered, all[i])
		}
		all = filtered
	}
	total := len(all)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}

// ─── Blocklist ────────────────────────────────────────────────────────────────

// Blocklist holds two separate maps for O(1) host lookups:
//   - exact:     e.g. "ads.example.com"
//   - wildcards: keyed by dot-prefix, e.g. ".example.com" (from "*.example.com")
//
// IsBlocked walks the host's own dot-labels to probe the wildcards map, so
// lookup cost is O(labels) ≈ O(1) for real-world domain names, regardless of
// how many wildcard rules are loaded.
// BlocklistEntry is a single blocklist host with its origin.
type BlocklistEntry struct {
	Host   string `json:"host"`
	Source string `json:"source"`         // "manual" or "feed"
	Feed   string `json:"feed,omitempty"` // feed URL that imported this entry, when known
}

type Blocklist struct {
	mu         sync.RWMutex
	exact      map[string]bool   // exact hostnames
	wildcards  map[string]bool   // dot-prefixes: ".example.com"
	manual     map[string]bool   // subset added by an admin (not the feed)
	exceptions map[string]bool   // hosts that are NEVER blocked, even if listed
	feedSrc    map[string]string // host → feed URL attribution (lazily initialized)
	path       string
	mode       string // "block" (default) or "allow"
}

var bl = &Blocklist{
	exact:      map[string]bool{},
	wildcards:  map[string]bool{},
	manual:     map[string]bool{},
	exceptions: map[string]bool{},
}

func (b *Blocklist) Mode() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.mode == "allow" {
		return "allow"
	}
	return "block"
}

func (b *Blocklist) SetMode(mode string) {
	if mode != "allow" {
		mode = "block"
	}
	b.mu.Lock()
	b.mode = mode
	b.mu.Unlock()
	b.saveMode()
}

// saveMode persists the mode to a sidecar file (<blocklist>.mode).
func (b *Blocklist) saveMode() {
	if b.path == "" {
		return
	}
	_ = atomicWriteFile(b.path+".mode", []byte(b.mode), 0o600)
}

// loadHostSidecar reads a one-host-per-line sidecar (".manual" /
// ".exceptions"), warning on lines that don't look like hostnames
// (D1.2-flag-F4) but accepting them anyway. lower controls whether
// lines are lowercased (exceptions yes, manual no — preserving the
// pre-extraction byte-for-byte behavior of each loop).
func loadHostSidecar(path, kind string, lower bool) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if lower {
			line = strings.ToLower(line)
		}
		if line == "" {
			continue
		}
		if !looksLikeHostname(line) {
			logger.Printf("Loader: blocklist.%s: line %d at %q does not look like a hostname: %q — accepting anyway (D1.2-flag-F4)", kind, i+1, sanitizeLog(path), sanitizeLog(line))
		}
		out[line] = true
	}
	return out
}

// loadFeedSources reads the ".sources" attribution sidecar (host → feed URL).
func loadFeedSources(path string) map[string]string {
	feedSrc := map[string]string{}
	if data, err := os.ReadFile(path); err == nil {
		if jerr := json.Unmarshal(data, &feedSrc); jerr != nil {
			logger.Printf("Loader: blocklist.sources: unparseable %q: %v — attribution reset", sanitizeLog(path), jerr)
			feedSrc = map[string]string{}
		}
	}
	return feedSrc
}

// scanBlocklistEntries reads the main blocklist file, normalizing every line
// (see normalizeBlocklistLine). Entries stored verbatim by pre-normalization
// feed imports ("0.0.0.0 ads.example") are repaired into blockable hostnames;
// unblockable junk rows are dropped, with one summary log line.
func scanBlocklistEntries(f io.Reader, path string) (exact, wildcards map[string]bool, err error) {
	exact = map[string]bool{}
	wildcards = map[string]bool{}
	repaired := 0
	dropped := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Text()
		line, ok := normalizeBlocklistLine(raw)
		if !ok {
			if t := strings.TrimSpace(raw); t != "" && !strings.HasPrefix(t, "#") {
				dropped++ // junk entry from a pre-normalization feed import
			}
			continue
		}
		if line != strings.ToLower(strings.TrimSpace(raw)) {
			repaired++ // e.g. "0.0.0.0 ads.example" stored verbatim by old imports
		}
		if strings.HasPrefix(line, "*.") {
			wildcards[line[1:]] = true
		} else {
			exact[line] = true
		}
	}
	if repaired > 0 || dropped > 0 {
		logger.Printf("Blocklist: normalized %d hosts-format entries and dropped %d unblockable entries from %q (pre-normalization feed import); file rewritten on next save", repaired, dropped, sanitizeLog(path))
	}
	return exact, wildcards, sc.Err()
}

func (b *Blocklist) Load(path string) error {
	b.path = path
	// Load mode sidecar.
	if data, err := os.ReadFile(path + ".mode"); err == nil {
		m := strings.TrimSpace(string(data))
		switch {
		case m == "allow":
			b.mode = "allow"
		case m != "":
			// D1.1h: anything other than "allow" silently keeps the
			// default ("block"). Surface it so operators can see typos
			// or case mistakes; behavior unchanged.
			logger.Printf("Loader: blocklist.mode: unrecognized value %q at %q, mode left at default (D1.2-flag-F3)", sanitizeLog(m), sanitizeLog(path+".mode"))
		}
	}
	// Sidecars: admin attribution, never-block exceptions, feed attribution.
	manual := loadHostSidecar(path+".manual", "manual", false)
	exceptions := loadHostSidecar(path+".exceptions", "exceptions", true)
	feedSrc := loadFeedSources(path + ".sources")

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	exact, wildcards, scanErr := scanBlocklistEntries(f, path)

	b.mu.Lock()
	b.exact = exact
	b.wildcards = wildcards
	b.manual = manual
	b.exceptions = exceptions
	b.feedSrc = feedSrc
	b.mu.Unlock()
	return scanErr
}

func (b *Blocklist) Save() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	var buf strings.Builder
	for h := range b.exact {
		buf.WriteString(h)
		buf.WriteByte('\n')
	}
	for suffix := range b.wildcards {
		// ".example.com" → "*.example.com"
		buf.WriteByte('*')
		buf.WriteString(suffix)
		buf.WriteByte('\n')
	}
	// Feed-source attribution sidecar, pruned to currently-listed,
	// non-manual entries so removed hosts don't accumulate stale rows.
	sources := map[string]string{}
	for h, src := range b.feedSrc {
		if b.manual[h] {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			if !b.wildcards[h[1:]] {
				continue
			}
		} else if !b.exact[h] {
			continue
		}
		sources[h] = src
	}
	path := b.path
	b.mu.RUnlock()
	// CL-1 / Bucket-4 durability hardening: atomicWriteFile gives
	// unique tmp + chmod + fsync(file) + rename + best-effort
	// fsync(parent dir) — replaces the previous os.OpenFile+os.Rename
	// path which was atomic-via-rename but NOT fsynced.
	_ = atomicWriteFile(path, []byte(buf.String()), 0o600)
	if data, err := json.Marshal(sources); err == nil {
		_ = atomicWriteFile(path+".sources", data, 0o600)
	}
}

// isListed reports whether host matches any entry in the list (mode-agnostic).
func (b *Blocklist) isListed(host string) bool {
	if b.exact[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && b.wildcards[host[i:]] {
			return true
		}
	}
	return b.wildcards["."+host]
}

// isExcepted returns true when host or any of its parent domains is in the
// exceptions list. Supports exact hosts, parent-domain inheritance, and
// wildcard entries (stored as "*.example.com").
// Must be called with b.mu held (at least RLock).
func (b *Blocklist) isExcepted(host string) bool {
	if b.exceptions[host] {
		return true
	}
	// Check if a wildcard exception covers this exact host
	// e.g. "*.raw.githubusercontent.com" should match "raw.githubusercontent.com"
	if b.exceptions["*."+host] {
		return true
	}
	// Walk parent domains: sub.example.com → example.com → com
	// Each dot boundary is also checked as a wildcard pattern *.parent.
	for i, ch := range host {
		if ch == '.' {
			parent := host[i+1:]
			if b.exceptions[parent] {
				return true
			}
			// e.g. "*.example.com" stored literally in exceptions
			if b.exceptions["*."+parent] {
				return true
			}
		}
	}
	return false
}

// AddException marks host as permanently exempt from blocking.
// Feed syncs will still add the host to the blocklist, but IsBlocked will
// always return false for it.
func (b *Blocklist) AddException(host string) {
	host = normalizeHost(strings.TrimSpace(host))
	if host == "" {
		return
	}
	// Warn on overly broad exceptions that may exempt many domains.
	bare := strings.TrimPrefix(host, "*.")
	parts := strings.Split(bare, ".")
	if len(parts) <= 1 || (len(parts) == 2 && strings.HasPrefix(host, "*.")) {
		logWarnf("Blocklist: broad exception added: %q — may exempt many domains", sanitizeLog(host))
	}
	b.mu.Lock()
	b.exceptions[host] = true
	b.mu.Unlock()
	b.saveExceptions()
}

// RemoveException removes an exception, allowing the host to be blocked again.
func (b *Blocklist) RemoveException(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	delete(b.exceptions, host)
	b.mu.Unlock()
	b.saveExceptions()
}

// ListExceptions returns a sorted list of all exception hosts.
func (b *Blocklist) ListExceptions() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.exceptions))
	for h := range b.exceptions {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// saveExceptions persists the exceptions set to a sidecar file.
func (b *Blocklist) saveExceptions() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	var sb strings.Builder
	for h := range b.exceptions {
		fmt.Fprintln(&sb, h)
	}
	_ = atomicWriteFile(b.path+".exceptions", []byte(sb.String()), 0o600)
}

// looksLikeHostname returns true if s plausibly resembles a hostname.
// Used only by Blocklist.Load for D1.1h observability logging — the
// loader still accepts arbitrary lines regardless. The check is
// intentionally loose: just enough to flag obviously-not-a-host
// content (whitespace, special chars, control bytes).
func looksLikeHostname(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '*':
		default:
			return false
		}
	}
	return true
}

// IsBlocked reports whether a request to host should be blocked.
// In "block" mode (default): listed hosts are blocked.
// In "allow" mode:           only listed hosts are allowed; all others blocked.
// Exceptions always pass through regardless of mode or list membership.
func (b *Blocklist) IsBlocked(host string) bool {
	host = normalizeHost(host)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.isExcepted(host) {
		return false
	}
	listed := b.isListed(host)
	if b.mode == "allow" {
		return !listed
	}
	return listed
}

func (b *Blocklist) Add(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	if strings.HasPrefix(host, "*.") {
		b.wildcards[host[1:]] = true
	} else {
		b.exact[host] = true
	}
	b.mu.Unlock()
}

// ReplaceFeedEntries replaces the feed-pushed entries (exact +
// wildcards) in place, leaving DP-local state (path, mode, manual,
// exceptions) intact. Used by applyConfigSnapshot to avoid the
// wholesale-replacement pattern that previously zeroed those
// local fields and orphaned the persistence path. Per-host parsing
// mirrors Add: "*.example.com" → wildcard, otherwise → exact.
//
// IMPORTANT: AddManual (store.go:847–857) writes admin-added hosts
// to BOTH the metadata map (b.manual) AND the enforcement maps
// (b.exact / b.wildcards). The enforcement maps are what IsBlocked
// consults; b.manual is just the attribution set. We therefore
// re-inject every b.manual host into the new enforcement maps
// before the swap so admin-added blocks survive every cluster
// sync. Without this re-injection (pre-fix and my first-pass
// ReplaceFeedEntries had the same defect; flagged by Codex on
// PR #249), admin manual blocks would silently disappear from
// enforcement on every snapshot apply.
func (b *Blocklist) ReplaceFeedEntries(hosts []string) {
	newExact := map[string]bool{}
	newWildcards := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			newWildcards[h[1:]] = true
		} else {
			newExact[h] = true
		}
	}
	b.mu.Lock()
	// Re-inject admin-added manual entries into the enforcement
	// maps. b.manual is the attribution set; the entries are also
	// normalised at AddManual time so no further trim/lowercase is
	// needed here.
	for h := range b.manual {
		if strings.HasPrefix(h, "*.") {
			newWildcards[h[1:]] = true
		} else {
			newExact[h] = true
		}
	}
	b.exact = newExact
	b.wildcards = newWildcards
	b.mu.Unlock()
}

// AddManual adds a host and marks it as manually managed by an admin.
// Unlike Add (used by the feed syncer), this persists both the source
// attribution (the .manual sidecar via saveManual) AND the enforcement
// state (the main blocklist file via Save). The dual save makes the call
// self-durable so a caller path that bails before its own deferred Save
// (e.g. the apiBlocklist POST handler returning early on an invalid
// wildcard mid-loop, ui_policy.go) cannot leave manual entries in
// memory + sidecar but missing from the main file — which would not
// survive restart, because Load reads the main file into b.exact /
// b.wildcards (the maps IsBlocked consults) and the .manual sidecar
// only restores attribution metadata.
//
// For bulk admin requests, prefer AddManualBulk: it does one save for
// N hosts instead of N saves, avoiding the O(hosts × blocklist-size)
// rewrite when the main file is large (e.g. a feed-backed blocklist
// with hundreds of thousands of entries). Codex P2 review on PR #283.
func (b *Blocklist) AddManual(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	if strings.HasPrefix(host, "*.") {
		b.wildcards[host[1:]] = true
	} else {
		b.exact[host] = true
	}
	b.manual[host] = true
	b.mu.Unlock()
	b.saveManual()
	b.Save()
}

// AddManualBulk adds multiple hosts as manually-managed admin entries
// under a single write lock with a single saveManual + single Save call,
// instead of one save per host. Use this for bulk admin requests; the
// per-host normalization and dedupe match AddManual exactly (lowercase
// + trim, empty hosts skipped, "*." → wildcard, otherwise exact). The
// caller is responsible for any validation (length cap, wildcard
// format) before invoking this method — invalid entries reaching here
// are silently accepted, mirroring AddManual.
//
// Returns the number of unique normalized entries actually stored by
// THIS call — i.e. hosts whose admin attribution (b.manual) went from
// false to true. Within-batch duplicates count once; cross-call repeats
// of an already-attributed host count as 0. This matches the caller's
// expectation that "added: N" in the API response and audit line
// reflects net new admin entries, not raw non-empty input count. A
// zero return means no on-disk write happens, so calling with an empty
// or all-blank slice (or an all-duplicates slice) is a cheap no-op.
//
// Added per the Codex P2 review on PR #283: with per-call Save() inside
// AddManual, a bulk POST of N hosts to a feed-backed blocklist rewrote
// the entire main file N times (O(hosts × blocklist-size) disk work).
// This save-once path preserves the durability guarantee while keeping
// bulk cost O(blocklist-size).
func (b *Blocklist) AddManualBulk(hosts []string) int {
	if len(hosts) == 0 {
		return 0
	}
	added := 0
	// dirty tracks whether ANY map (b.exact, b.wildcards, b.manual)
	// flipped a key from false to true during this call. Save() must
	// run on any flip — not only on a b.manual flip — so that recovery
	// paths (e.g. a pre-fix-era stale main file where b.manual still
	// has an entry but b.exact lost it) re-persist the now-corrected
	// enforcement state. added is kept separate because it only counts
	// net new admin attributions (b.manual false→true), which is the
	// honest "stored by this call" number the API response and audit
	// line should report.
	dirty := false
	b.mu.Lock()
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if strings.HasPrefix(host, "*.") {
			if !b.wildcards[host[1:]] {
				b.wildcards[host[1:]] = true
				dirty = true
			}
		} else {
			if !b.exact[host] {
				b.exact[host] = true
				dirty = true
			}
		}
		if !b.manual[host] {
			b.manual[host] = true
			dirty = true
			added++
		}
	}
	b.mu.Unlock()
	if dirty {
		b.saveManual()
		b.Save()
	}
	return added
}

// saveManual persists the set of manually-added hosts to a sidecar file.
func (b *Blocklist) saveManual() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	var sb strings.Builder
	for h := range b.manual {
		fmt.Fprintln(&sb, h)
	}
	_ = atomicWriteFile(b.path+".manual", []byte(sb.String()), 0o600)
}

func (b *Blocklist) Remove(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	if strings.HasPrefix(host, "*.") {
		delete(b.wildcards, host[1:])
	} else {
		delete(b.exact, host)
	}
	delete(b.manual, host)
	delete(b.feedSrc, host)
	b.mu.Unlock()
	b.saveManual()
}

func (b *Blocklist) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.exact)+len(b.wildcards))
	for h := range b.exact {
		out = append(out, h)
	}
	for suffix := range b.wildcards {
		out = append(out, "*"+suffix)
	}
	return out
}

// ListWithSource returns all blocklist entries annotated with their origin:
// "manual" if added by an admin via the UI/API, "feed" if imported from a feed.
func (b *Blocklist) ListWithSource() []BlocklistEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]BlocklistEntry, 0, len(b.exact)+len(b.wildcards))
	for h := range b.exact {
		src, feed := "feed", b.feedSrc[h]
		if b.manual[h] {
			src, feed = "manual", ""
		}
		out = append(out, BlocklistEntry{Host: h, Source: src, Feed: feed})
	}
	for suffix := range b.wildcards {
		h := "*" + suffix
		src, feed := "feed", b.feedSrc[h]
		if b.manual[h] {
			src, feed = "manual", ""
		}
		out = append(out, BlocklistEntry{Host: h, Source: src, Feed: feed})
	}
	return out
}

func (b *Blocklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.exact) + len(b.wildcards)
}

// MergeFromLines adds all valid host entries from lines to the blocklist and
// saves it. Existing entries are NOT removed — safe to call on a live blocklist.
// ClearAll removes all blocklist entries (exact, wildcard, manual) but preserves
// exceptions and mode. Used by config import "replace" mode.
func (b *Blocklist) ClearAll() {
	b.mu.Lock()
	b.exact = map[string]bool{}
	b.wildcards = map[string]bool{}
	b.manual = map[string]bool{}
	b.feedSrc = map[string]string{}
	b.mu.Unlock()
}

// RemoveByFeedSource removes every entry attributed to feedURL (cascade
// delete when the admin removes a feed AND opts to purge its imports).
// Admin-added (manual) entries always survive. Returns the removed count.
func (b *Blocklist) RemoveByFeedSource(feedURL string) int {
	b.mu.Lock()
	removed := 0
	for h, src := range b.feedSrc {
		if src != feedURL || b.manual[h] {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			if b.wildcards[h[1:]] {
				delete(b.wildcards, h[1:])
				removed++
			}
		} else if b.exact[h] {
			delete(b.exact, h)
			removed++
		}
		delete(b.feedSrc, h)
	}
	b.mu.Unlock()
	if removed > 0 {
		b.Save()
	}
	return removed
}

// CountByFeedSource reports how many currently-listed, non-manual entries
// are attributed to feedURL (the number a cascade delete would remove).
func (b *Blocklist) CountByFeedSource(feedURL string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := 0
	for h, src := range b.feedSrc {
		if src != feedURL || b.manual[h] {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			if b.wildcards[h[1:]] {
				n++
			}
		} else if b.exact[h] {
			n++
		}
	}
	return n
}

// SnapshotFeedSources returns a copy of the per-entry feed attribution map.
// Taken before a wholesale rebuild (config rollback / import-replace) so
// RestoreFeedSources can re-stamp surviving entries afterwards.
func (b *Blocklist) SnapshotFeedSources() map[string]string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	snap := make(map[string]string, len(b.feedSrc))
	for h, src := range b.feedSrc {
		snap[h] = src
	}
	return snap
}

// RestoreFeedSources re-stamps feed attribution onto currently-listed,
// non-manual entries after a wholesale rebuild. Config rollback and
// import-replace go through Remove/ClearAll + Add, which would otherwise
// strand every feed entry as "unknown origin" — making them prey for the
// unattributed-cleanup operation (Codex P1, PR #447). Attribution already
// present (e.g. re-stamped by a sync mid-rebuild) is not overwritten.
func (b *Blocklist) RestoreFeedSources(snap map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.feedSrc == nil {
		b.feedSrc = map[string]string{}
	}
	for h, src := range snap {
		if b.manual[h] {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			if !b.wildcards[h[1:]] {
				continue
			}
		} else if !b.exact[h] {
			continue
		}
		if _, exists := b.feedSrc[h]; !exists {
			b.feedSrc[h] = src
		}
	}
}

// RemoveUnattributedFeedEntries removes every feed-owned entry with no
// recorded source — the legacy cohort imported before per-feed attribution
// existed and no longer present in any current feed (a host still carried
// by a configured feed is re-stamped on every sync, so it never stays
// unattributed for long). Admin-added entries always survive. Returns the
// removed count.
func (b *Blocklist) RemoveUnattributedFeedEntries() int {
	b.mu.Lock()
	removed := 0
	for h := range b.exact {
		if b.manual[h] || b.feedSrc[h] != "" {
			continue
		}
		delete(b.exact, h)
		removed++
	}
	for suffix := range b.wildcards {
		h := "*" + suffix
		if b.manual[h] || b.feedSrc[h] != "" {
			continue
		}
		delete(b.wildcards, suffix)
		removed++
	}
	b.mu.Unlock()
	if removed > 0 {
		b.Save()
	}
	return removed
}

// hostsFileBoilerplate lists names that appear in the standard header of
// /etc/hosts-format feeds (e.g. StevenBlack). They are never legitimately
// blockable upstream hosts, so hosts-format lines naming them are skipped.
var hostsFileBoilerplate = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true,
}

// normalizeBlocklistLine extracts the blockable host from one feed or
// blocklist-file line. It handles plain domain lists, /etc/hosts format
// ("0.0.0.0 domain" / "127.0.0.1 domain"), inline comments, accidental
// schemes, and trailing paths/ports. Returns ok=false for lines that carry
// no blockable host (comments, hosts-file boilerplate, unspecified/loopback
// IPs). Wildcard entries ("*.example.com") pass through untouched.
func normalizeBlocklistLine(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	// Inline comment: "0.0.0.0 ads.example # comment".
	if i := strings.Index(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	// /etc/hosts format: "<ip> <host> [aliases…]" — take the first host.
	hostsFormat := false
	if fields := strings.Fields(line); len(fields) == 0 {
		return "", false
	} else if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
		line = fields[1]
		hostsFormat = true
	} else {
		line = fields[0]
	}
	// Strip scheme if someone accidentally includes it.
	if i := strings.Index(line, "://"); i >= 0 {
		line = line[i+3:]
	}
	// Strip path/query/port.
	if i := strings.IndexAny(line, "/:?"); i >= 0 {
		line = line[:i]
	}
	line = strings.ToLower(line)
	// Canonicalize FQDN trailing dot ("example.com." ≡ "example.com") so
	// both spellings can't coexist as near-duplicate entries.
	line = strings.TrimSuffix(line, ".")
	if line == "" {
		return "", false
	}
	// "0.0.0.0 0.0.0.0" and friends: an unspecified/loopback IP is not a
	// blockable upstream host.
	if ip := net.ParseIP(line); ip != nil && (ip.IsUnspecified() || ip.IsLoopback()) {
		return "", false
	}
	if hostsFormat && hostsFileBoilerplate[line] {
		return "", false
	}
	return line, true
}

// Lines starting with '#' or empty are skipped; /etc/hosts-format lines are
// normalized to their hostname (see normalizeBlocklistLine).
// source is the feed URL recorded as per-entry attribution ("" = none).
// Returns the number of newly-added entries.
func (b *Blocklist) MergeFromLines(lines []string, source string) int {
	added := 0
	attributed := false
	b.mu.Lock()
	for _, raw := range lines {
		line, ok := normalizeBlocklistLine(raw)
		if !ok {
			continue
		}
		if strings.HasPrefix(line, "*.") {
			key := line[1:] // ".example.com"
			if !b.wildcards[key] {
				b.wildcards[key] = true
				added++
			}
		} else {
			if !b.exact[line] {
				b.exact[line] = true
				added++
			}
		}
		// Stamp attribution on feed-owned entries (also retroactively on
		// re-sync, so pre-attribution entries converge). Admin-added
		// entries keep their "manual" badge — ListWithSource checks
		// b.manual first. attributed only flips on an actual change so
		// steady-state re-syncs (already attributed, nothing new) don't
		// trigger a full-file rewrite.
		if source != "" && !b.manual[line] {
			if b.feedSrc == nil {
				b.feedSrc = map[string]string{}
			}
			if b.feedSrc[line] != source {
				b.feedSrc[line] = source
				attributed = true
			}
		}
	}
	b.mu.Unlock()
	// attributed alone must also save: a re-sync that only stamps
	// attribution on already-listed hosts (e.g. entries repaired by Load
	// or imported before the .sources sidecar existed) would otherwise
	// hold the attribution in memory only and lose it on restart
	// (Codex P2, PR #438).
	if added > 0 || attributed {
		b.Save()
	}
	return added
}

// ─── Auth cache ───────────────────────────────────────────────────────────────
//
// bcrypt is intentionally slow (~100 ms). For a proxy that authenticates on
// every request we cache the result for authCacheTTL to avoid a CPU bottleneck
// while still rotating frequently enough to catch revoked credentials.

const authCacheTTL = 5 * time.Minute

type authCacheEntry struct {
	ok     bool
	expiry time.Time
}

type authCacheStore struct {
	mu      sync.Mutex
	entries map[string]*authCacheEntry
}

func (a *authCacheStore) get(user, pass string) (ok, hit bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := cacheKey(user, pass)
	if e, found := a.entries[k]; found && time.Now().Before(e.expiry) {
		return e.ok, true
	}
	return false, false
}

// maxAuthCacheSize caps the number of cached auth results to prevent unbounded
// memory growth from credential-stuffing attacks with unique user/pass pairs.
const maxAuthCacheSize = 5_000

func (a *authCacheStore) set(user, pass string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) >= maxAuthCacheSize {
		// Evict one expired entry first; if none found, drop an arbitrary one.
		now := time.Now()
		evicted := false
		for k, e := range a.entries {
			if now.After(e.expiry) {
				delete(a.entries, k)
				evicted = true
				break
			}
		}
		if !evicted {
			for k := range a.entries {
				delete(a.entries, k)
				break
			}
		}
	}
	a.entries[cacheKey(user, pass)] = &authCacheEntry{ok: ok, expiry: time.Now().Add(authCacheTTL)}
}

func (a *authCacheStore) clear() {
	a.mu.Lock()
	a.entries = map[string]*authCacheEntry{}
	a.mu.Unlock()
}

// cacheKeySecret is a per-process random key used to HMAC credential cache
// lookups. Using HMAC instead of a bare hash prevents offline brute-force
// if heap memory is ever dumped.
var cacheKeySecret = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return b
}()

// cacheKey derives an HMAC-SHA256 tag from (user+pass) so we never store
// plaintext credentials as map keys in heap-visible memory.
func cacheKey(user, pass string) string {
	mac := hmac.New(sha256.New, cacheKeySecret)
	mac.Write([]byte(user + ":" + pass))
	return hex.EncodeToString(mac.Sum(nil))
}

// ─── UI RBAC roles ────────────────────────────────────────────────────────────

// UIRole defines the permission level for admin UI users.
type UIRole string

const (
	RoleAdmin    UIRole = "admin"    // full system access
	RoleOperator UIRole = "operator" // manage content (policy, blocklist, etc.)
	RoleViewer   UIRole = "viewer"   // read-only dashboard access
)

// rolePriority maps roles to numeric levels for comparison.
var rolePriority = map[UIRole]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
}

// HasRole returns true when r's level is at least the level of min.
func (r UIRole) HasRole(min UIRole) bool {
	return rolePriority[r] >= rolePriority[min]
}

// uiAdminUser holds credentials and role for a single UI admin user.
type uiAdminUser struct {
	passHash        []byte
	role            UIRole
	totpSecret      string   // base32 TOTP secret; empty = TOTP not enrolled
	backupCodes     []string // bcrypt-hashed backup codes
	totpLastCounter int64    // last successfully-used TOTP time-step; prevents replay
}

// UIUserInfo is the public (no hash) view of a UI admin user.
type UIUserInfo struct {
	Username    string `json:"username"`
	Role        UIRole `json:"role"`
	TOTPEnabled bool   `json:"totpEnabled"`
}

// ─── Config (live-editable) ───────────────────────────────────────────────────

type Config struct {
	mu        sync.RWMutex
	ProxyPort int
	UIPort    int

	// Local (bcrypt) auth fields — used when no external AuthProvider is set.
	user     string
	passHash []byte // bcrypt hash; nil = no auth
	cache    authCacheStore

	// External auth provider (LDAP or OIDC). When non-nil, takes precedence
	// over the local bcrypt credentials for Verify calls.
	provider AuthProvider

	// unauthMode marks setup as complete without requiring credentials.
	// When true the proxy forwards all traffic without any authentication check.
	unauthMode bool

	// uiUsers holds the multi-user admin roster with per-user roles.
	// When nil/empty, falls back to the legacy single-user (user/passHash).
	uiUsers map[string]*uiAdminUser

	// uiUsersFile is the path to persist UI users across restarts.
	// Empty = in-memory only (auth resets on every restart).
	uiUsersFile string
}

var cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}

// SetProvider replaces the active authentication backend.
// Pass nil to fall back to local bcrypt auth.
func (c *Config) SetProvider(p AuthProvider) {
	c.mu.Lock()
	c.provider = p
	c.mu.Unlock()
	if p != nil {
		logger.Printf("Auth: provider %s", p.Name())
	}
}

// GetUser returns the configured local username (never returns the password).
func (c *Config) GetUser() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user
}

// SetAuth hashes pass with bcrypt and clears the auth cache.
// Call with empty user to disable local authentication.
// Has no effect on an external AuthProvider.
func (c *Config) SetAuth(user, pass string) error {
	if user == "" {
		c.mu.Lock()
		c.user = ""
		c.passHash = nil
		c.mu.Unlock()
		c.cache.clear()
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.user = user
	c.passHash = hash
	// Mirror into the RBAC user roster so the RBAC path works immediately.
	if c.uiUsers == nil {
		c.uiUsers = map[string]*uiAdminUser{}
	}
	c.uiUsers[user] = &uiAdminUser{passHash: hash, role: RoleAdmin}
	c.mu.Unlock()
	c.cache.clear()
	return nil
}

// VerifyAuth checks credentials against the active auth backend:
//   - External provider (LDAP / OIDC) if configured, otherwise
//   - Local bcrypt hash with a short-lived cache.
func (c *Config) VerifyAuth(user, pass string) bool {
	c.mu.RLock()
	p := c.provider
	storedUser := c.user
	storedHash := c.passHash
	c.mu.RUnlock()

	// External provider takes precedence.
	if p != nil {
		return p.Verify(user, pass)
	}

	// Local bcrypt auth.
	if storedUser == "" {
		return true // auth disabled
	}
	if user != storedUser {
		return false
	}
	if ok, hit := c.cache.get(user, pass); hit {
		return ok
	}
	ok := bcrypt.CompareHashAndPassword(storedHash, []byte(pass)) == nil
	c.cache.set(user, pass, ok)
	return ok
}

// AuthEnabled returns true when any form of authentication is active,
// or when unauthMode is explicitly set (setup is considered complete).
func (c *Config) AuthEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user != "" || c.provider != nil || c.unauthMode
}

// UnauthMode returns true when the proxy is explicitly configured to run
// without authentication (open proxy mode, setup is still considered done).
func (c *Config) UnauthMode() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.unauthMode
}

// SetUnauthMode enables or disables explicit unauthenticated (open) mode.
func (c *Config) SetUnauthMode(enabled bool) {
	c.mu.Lock()
	c.unauthMode = enabled
	c.mu.Unlock()
	if enabled {
		logger.Printf("Auth: mode UNAUTH (open proxy, no credentials required)")
	}
	// Persist so the setting survives restarts.
	if err := c.SaveUIUsersFile(); err != nil {
		logWarnf("Auth: failed to persist unauthMode: %v", err)
	}
}

// ─── UI multi-user admin management ──────────────────────────────────────────

// validatePasswordComplexity enforces minimum password strength:
// at least 8 characters, one uppercase letter, one lowercase letter, one digit.
func validatePasswordComplexity(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	var hasUpper, hasLower, hasDigit bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, and one digit")
	}
	return nil
}

// SetUIUser creates or updates an admin UI user with the given role.
// Call with empty password to update only the role (password unchanged).
func (c *Config) SetUIUser(username, password string, role UIRole) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uiUsers == nil {
		c.uiUsers = map[string]*uiAdminUser{}
	}
	existing := c.uiUsers[username]
	if password != "" {
		if err := validatePasswordComplexity(password); err != nil {
			return err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		c.uiUsers[username] = &uiAdminUser{passHash: hash, role: role}
	} else if existing != nil {
		existing.role = role
	}
	return nil
}

// DeleteUIUser removes a UI admin user.
// Returns an error if this would leave the roster with no admin.
func (c *Config) DeleteUIUser(username string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	u := c.uiUsers[username]
	if u != nil && u.role == RoleAdmin {
		adminCount := 0
		for _, usr := range c.uiUsers {
			if usr.role == RoleAdmin {
				adminCount++
			}
		}
		if adminCount <= 1 {
			return fmt.Errorf("cannot delete the last admin user")
		}
	}
	delete(c.uiUsers, username)
	return nil
}

// ListUIUsers returns a snapshot of all admin UI users (without password hashes).
func (c *Config) ListUIUsers() []UIUserInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]UIUserInfo, 0, len(c.uiUsers))
	for name, u := range c.uiUsers {
		out = append(out, UIUserInfo{Username: name, Role: u.role, TOTPEnabled: u.totpSecret != ""})
	}
	return out
}

// SetUIUsersFile sets the path used to persist UI users across restarts.
// Call before LoadUIUsersFile / SaveUIUsersFile.
func (c *Config) SetUIUsersFile(path string) {
	c.mu.Lock()
	c.uiUsersFile = path
	c.mu.Unlock()
}

// uiUserRecord is the on-disk representation of a UI admin user.
type uiUserRecord struct {
	Username        string   `json:"username"`
	PassHash        string   `json:"pass_hash"` // hex-encoded bcrypt hash
	Role            UIRole   `json:"role"`
	TOTPSecret      string   `json:"totp_secret,omitempty"`       // base32 TOTP secret
	BackupCodes     []string `json:"backup_codes,omitempty"`      // bcrypt-hashed one-time codes
	TOTPLastCounter int64    `json:"totp_last_counter,omitempty"` // last successfully-used TOTP step (replay protection)
}

// uiUsersFileEnvelope is the on-disk JSON structure that wraps the user
// roster along with global settings that must survive restarts.
type uiUsersFileEnvelope struct {
	UnauthMode bool           `json:"unauth_mode,omitempty"`
	Users      []uiUserRecord `json:"users"`
}

// LoadUIUsersFile reads persisted UI users from disk and populates the roster.
// Silently returns nil if the file does not exist yet (first run).
func (c *Config) LoadUIUsersFile() error {
	c.mu.RLock()
	path := c.uiUsersFile
	c.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		logger.Printf("Loader: ui_users.json: file %q missing — caller may bootstrap defaults (D1.2-flag-F1)", sanitizeLog(path))
		return nil
	}
	if err != nil {
		return err
	}
	// Try new envelope format first, fall back to bare array for backward compat.
	var env uiUsersFileEnvelope
	var records []uiUserRecord
	if err := json.Unmarshal(data, &env); err == nil && env.Users != nil {
		records = env.Users
	} else if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unauthMode = env.UnauthMode
	if c.uiUsers == nil {
		c.uiUsers = map[string]*uiAdminUser{}
	}
	for _, rec := range records {
		hash, err := hex.DecodeString(rec.PassHash)
		if err != nil {
			continue
		}
		c.uiUsers[rec.Username] = &uiAdminUser{
			passHash:        hash,
			role:            rec.Role,
			totpSecret:      rec.TOTPSecret,
			backupCodes:     rec.BackupCodes,
			totpLastCounter: rec.TOTPLastCounter,
		}
		// Keep legacy single-user in sync with the first admin found.
		if rec.Role == RoleAdmin && c.user == "" {
			c.user = rec.Username
			c.passHash = hash
		}
	}
	return nil
}

// SaveUIUsersFile writes the current UI user roster to disk atomically.
// No-op when no file path is configured.
func (c *Config) SaveUIUsersFile() error {
	c.mu.RLock()
	path := c.uiUsersFile
	env := uiUsersFileEnvelope{
		UnauthMode: c.unauthMode,
		Users:      make([]uiUserRecord, 0, len(c.uiUsers)),
	}
	for name, u := range c.uiUsers {
		env.Users = append(env.Users, uiUserRecord{
			Username:        name,
			PassHash:        hex.EncodeToString(u.passHash),
			Role:            u.role,
			TOTPSecret:      u.totpSecret,
			BackupCodes:     u.backupCodes,
			TOTPLastCounter: u.totpLastCounter,
		})
	}
	c.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// VerifyUIUser checks credentials against the admin user roster and returns
// the user's role.  Falls back to the legacy single-user when the roster is
// empty, assigning RoleAdmin for backwards compatibility.
// UIUserExists returns true if the named user exists in the roster.
// Used to reject session cookies for deleted users.
func (c *Config) UIUserExists(username string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uiUsers[username] != nil
}

func (c *Config) VerifyUIUser(username, password string) (UIRole, bool) {
	c.mu.RLock()
	uiU := c.uiUsers[username]
	legacyUser := c.user
	legacyHash := c.passHash
	c.mu.RUnlock()

	// Multi-user roster takes precedence.
	if uiU != nil {
		if bcrypt.CompareHashAndPassword(uiU.passHash, []byte(password)) == nil {
			return uiU.role, true
		}
		return "", false
	}

	// Legacy single-user fallback (pre-RBAC deployments).
	if legacyUser != "" && username == legacyUser {
		if bcrypt.CompareHashAndPassword(legacyHash, []byte(password)) == nil {
			return RoleAdmin, true
		}
	}
	return "", false
}

// UserHasTOTP returns true if the user has TOTP enrolled.
func (c *Config) UserHasTOTP(username string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if u, ok := c.uiUsers[username]; ok {
		return u.totpSecret != ""
	}
	return false
}

// GetTOTPSecret returns the base32 TOTP secret for a user (empty if not enrolled).
func (c *Config) GetTOTPSecret(username string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if u, ok := c.uiUsers[username]; ok {
		return u.totpSecret
	}
	return ""
}

// SetTOTPSecret stores a TOTP secret and backup codes for a user.
func (c *Config) SetTOTPSecret(username, secret string, backupCodes []string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.uiUsers[username]
	if !ok {
		return false
	}
	u.totpSecret = secret
	u.backupCodes = backupCodes
	return true
}

// ClearTOTP removes TOTP enrollment for a user.
func (c *Config) ClearTOTP(username string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.uiUsers[username]
	if !ok {
		return false
	}
	u.totpSecret = ""
	u.backupCodes = nil
	return true
}

// GetTOTPLastCounter returns the last successfully-used TOTP time-step for a
// user (0 if none). Callers use this to detect replay of an OTP within the
// ±skew window (RFC 6238 §5.2).
func (c *Config) GetTOTPLastCounter(username string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if u, ok := c.uiUsers[username]; ok {
		return u.totpLastCounter
	}
	return 0
}

// SetTOTPLastCounter records the TOTP time-step just consumed by a successful
// validation. Subsequent codes whose matched counter is <= this value are
// rejected as replays. Returns false if the user does not exist.
func (c *Config) SetTOTPLastCounter(username string, counter int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.uiUsers[username]
	if !ok {
		return false
	}
	if counter > u.totpLastCounter {
		u.totpLastCounter = counter
	}
	return true
}

// ConsumeBackupCode checks and consumes a backup code (one-time use).
// Returns true if code was valid and has been removed.
func (c *Config) ConsumeBackupCode(username, code string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.uiUsers[username]
	if !ok {
		return false
	}
	for i, hashed := range u.backupCodes {
		if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(code)) == nil {
			u.backupCodes = append(u.backupCodes[:i], u.backupCodes[i+1:]...)
			return true
		}
	}
	return false
}

// ProviderEnabled returns true when an external auth provider (LDAP/OIDC) is set.
func (c *Config) ProviderEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.provider != nil
}

// oidcLoginURL stores the OIDC authorization/login URL for browser redirects.
var oidcLoginURL string

// proxyExternalBaseURL is the externally-visible base URL of the proxy UI
// (e.g. "https://proxy.corp.com:9090").  Set by SetProxyBaseURL() at startup.
// Used to build OIDC/SAML callback redirect_uris.
var proxyExternalBaseURL string

// trustForwardedHeaders controls whether X-Forwarded-Host / X-Forwarded-Proto
// are trusted for deriving the external base URL from requests.  Default false;
// set via --trust-forwarded-headers or proxy.trust_forwarded_headers in config.
// Must be explicitly enabled when running behind a reverse proxy.
var trustForwardedHeaders bool

// SetProxyBaseURL sets the external base URL used for OIDC/SAML callbacks.
func SetProxyBaseURL(u string) { proxyExternalBaseURL = strings.TrimRight(u, "/") }

// ProxyBaseURL returns the configured external base URL (empty if not set).
func (c *Config) ProxyBaseURL() string { return proxyExternalBaseURL }

// SetOIDCLoginURL stores the OIDC authorization URL so the proxy can redirect
// unauthenticated browser requests to the OIDC captive portal.
func SetOIDCLoginURL(u string) { oidcLoginURL = u }

// OIDCLoginURL returns the configured OIDC login redirect URL (empty if not set).
func (c *Config) OIDCLoginURL() string { return oidcLoginURL }

func uptime() string {
	d := time.Since(startTime).Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	return fmt.Sprintf("%dm %ds", m, s)
}

func recordRequest(ip, method, host, status, ruleMatched, actionTaken, identity, sslAction string) {
	recordRequestBytes(ip, method, host, status, ruleMatched, actionTaken, identity, 0, 0, sslAction)
}

func recordRequestBytes(ip, method, host, status, ruleMatched, actionTaken, identity string, bytesSent, bytesRecv int64, sslAction string) {
	recordRequestBytesAuth(ip, method, host, status, ruleMatched, actionTaken, identity, bytesSent, bytesRecv, sslAction, AuthLogFields{})
}

// recordRequestAuth records a request log entry carrying the Stage-1 auth
// observability block. A zero AuthLogFields adds nothing to the wire output, so
// call sites converted from recordRequest stay byte-identical for requests with
// no auth decision (every non-exempt request). All current call sites are the
// pre-tunnel stage of handleRequest, where sslAction is not yet determined —
// hence no sslAction parameter; use recordRequestBytesAuth directly if a future
// inspect-stage call site needs one.
func recordRequestAuth(ip, method, host, status, ruleMatched, actionTaken, identity string, auth AuthLogFields) {
	recordRequestBytesAuth(ip, method, host, status, ruleMatched, actionTaken, identity, 0, 0, "", auth)
}

// recordRequestAuthURI is recordRequestAuth plus a captured request URI
// (host+path, no query) for the per-rule "log full URL" option. It is the only
// recorder that populates LogEntry.URI; every other path leaves it empty so the
// field is omitted from the wire output (omitempty), keeping behavior unchanged
// for rules without LogFullURI set.
func recordRequestAuthURI(ip, method, host, status, ruleMatched, actionTaken, identity, sslAction, uri string, auth AuthLogFields) {
	recordRequestFull(ip, method, host, status, ruleMatched, actionTaken, identity, 0, 0, sslAction, uri, auth)
}

// recordRequestBytesAuth is the core recorder; it attaches the Stage-1 auth
// observability block (AuthLogFields) to the log entry. recordRequest /
// recordRequestBytes delegate here with a zero AuthLogFields, so their wire
// output is unchanged. Reached from proxy.go (Slice 7) via recordRequestAuth at
// the post-auth-gate call sites in handleRequest.
func recordRequestBytesAuth(ip, method, host, status, ruleMatched, actionTaken, identity string, bytesSent, bytesRecv int64, sslAction string, auth AuthLogFields) {
	recordRequestFull(ip, method, host, status, ruleMatched, actionTaken, identity, bytesSent, bytesRecv, sslAction, "", auth)
}

// recordStats records the metric/time-series/alert/top-host side effects of a
// request WITHOUT writing a request-log entry. It is the shared core of
// recordRequestFull and the path used when a policy rule has traffic logging
// disabled ("Log traffic" off): the request still counts toward stats and
// dashboards, it just produces no feed/history/syslog entry.
func recordStats(ip, host, status, ruleMatched, actionTaken string) {
	atomic.AddInt64(&statTotal, 1)
	isAllowed := status == "OK" || status == "POLICY_ALLOW" || status == "POLICY_REDIRECT"
	tsRecordResult(isAllowed)
	// Fire webhook alerts for security events (async, non-blocking).
	switch status {
	case "THREAT_BLOCKED", "SCAN_BLOCKED", "DPI_BLOCKED":
		go fireAlert("threat_detected", AlertPayload{
			Actor: ip, Host: host, Detail: ruleMatched + " " + actionTaken, Source: ruleMatched,
		})
	case "POLICY_BLOCK", "POLICY_DROP":
		go fireAlert("policy_block", AlertPayload{
			Actor: ip, Host: host, Detail: ruleMatched, Source: "policy",
		})
	}
	if status == "OK" || status == "POLICY_ALLOW" {
		topHosts.Record(host)
	}
}

// recordRequestFull is the implementation behind every recorder. uri is the
// captured request URL (host+path, no query) or "" when not logged.
func recordRequestFull(ip, method, host, status, ruleMatched, actionTaken, identity string, bytesSent, bytesRecv int64, sslAction, uri string, auth AuthLogFields) {
	recordStats(ip, host, status, ruleMatched, actionTaken)
	persistLogEntry(ip, method, host, status, ruleMatched, actionTaken, identity, bytesSent, bytesRecv, sslAction, uri, auth)
}

// recordRequestLogOnly writes a request-log entry WITHOUT the stats/alert/
// top-host side effects. It is used for SSL-inspected inner requests (per-URL
// "log full URL" entries): the enclosing CONNECT was already counted by the
// allow path, so counting each inner request again would inflate statTotal
// (a CONNECT carrying N requests would count as 1+N).
func recordRequestLogOnly(ip, method, host, status, ruleMatched, actionTaken, identity, sslAction, uri string, auth AuthLogFields) {
	persistLogEntry(ip, method, host, status, ruleMatched, actionTaken, identity, 0, 0, sslAction, uri, auth)
}

// persistLogEntry builds the LogEntry and writes it to the ring, JSONL file,
// history store, and syslog — the logging half shared by recordRequestFull and
// recordRequestLogOnly.
func persistLogEntry(ip, method, host, status, ruleMatched, actionTaken, identity string, bytesSent, bytesRecv int64, sslAction, uri string, auth AuthLogFields) {
	entry := LogEntry{
		TS:          time.Now().UnixMilli(),
		Time:        time.Now().Format("15:04:05"),
		IP:          ip,
		Identity:    identity,
		Method:      method,
		Host:        host,
		URI:         uri,
		Status:      status,
		Level:       levelForStatus(status),
		RuleMatched: ruleMatched,
		ActionTaken: actionTaken,
		BytesSent:   bytesSent,
		BytesRecv:   bytesRecv,
		SSLAction:   sslAction,
	}
	auth.applyTo(&entry)
	logAdd(entry)
	// Forward request log entry to syslog/SIEM if configured (Finding 17.2).
	if globalSyslog != nil {
		globalSyslog.WriteRequest(entry)
	}
}

// ─── Top hosts ────────────────────────────────────────────────────────────────

// HostStat is a hostname with its request count, used for top-hosts ranking.
type HostStat struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

type hostCounter struct {
	mu    sync.Mutex
	hosts map[string]int64
}

var topHosts = &hostCounter{hosts: map[string]int64{}}

func (hc *hostCounter) Record(host string) {
	hc.mu.Lock()
	hc.hosts[host]++
	hc.mu.Unlock()
}

// Top returns the n most-requested hosts, sorted descending by count.
func (hc *hostCounter) Top(n int) []HostStat {
	hc.mu.Lock()
	all := make([]HostStat, 0, len(hc.hosts))
	for h, c := range hc.hosts {
		all = append(all, HostStat{Host: h, Count: c})
	}
	hc.mu.Unlock()

	// Simple selection: sort descending.
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}
