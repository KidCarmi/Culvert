package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	total   = make([]int64, 60)
	allowed = make([]int64, 60)
	blocked = make([]int64, 60)
	for i := 0; i < 60; i++ {
		idx        := (ts.cur - i + 60) % 60
		total[59-i]   = ts.buckets[idx]
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
	Status      string `json:"status"`      // OK | BLOCKED | AUTH_FAIL | RATE_LIMITED | IP_BLOCKED | POLICY_*
	Level       string `json:"level"`       // INFO | WARN | ERROR
	RuleMatched string `json:"ruleMatched"` // policy rule name that matched, if any
	ActionTaken string `json:"actionTaken"` // policy action taken, if any
}

func levelForStatus(status string) string {
	switch status {
	case "OK", "POLICY_ALLOW", "PAC_DOWNLOAD":
		return "INFO"
	case "BLOCKED", "RATE_LIMITED", "IP_BLOCKED",
		"POLICY_BLOCK", "POLICY_DROP", "POLICY_REDIRECT":
		return "WARN"
	default: // AUTH_FAIL and anything unexpected
		return "ERROR"
	}
}

const maxLogs = 1000

var (
	logsMu sync.Mutex
	logs   []LogEntry
)

func logAdd(e LogEntry) {
	logsMu.Lock()
	defer logsMu.Unlock()
	logs = append(logs, e)
	if len(logs) > maxLogs {
		logs = logs[len(logs)-maxLogs:]
	}
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
	TS     int64  `json:"ts"`     // Unix milliseconds
	Time   string `json:"time"`   // human-readable "2006-01-02 15:04:05"
	Actor  string `json:"actor"`  // client IP (or authenticated username)
	Action string `json:"action"` // "policy.add" | "blocklist.remove" | …
	Object string `json:"object"` // the specific item that changed
	Detail string `json:"detail"` // extra context (never contains credentials)
	Before string `json:"before,omitempty"` // JSON snapshot before the change
	After  string `json:"after,omitempty"`  // JSON snapshot after the change
}

const maxAuditLogs = 500

var (
	auditMu      sync.Mutex
	auditLog     []AuditEntry
	auditLogFile *os.File // persistent JSONL file; nil = in-memory only
)

// InitAuditLog opens path for append-only JSONL persistence.
// Existing entries are loaded into the in-memory ring buffer on startup.
// If path is empty this is a no-op (backwards-compatible).
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("audit log open %s: %w", path, err)
	}
	auditLogFile = f
	return nil
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
	Source string `json:"source"` // "manual" or "feed"
}

type Blocklist struct {
	mu         sync.RWMutex
	exact      map[string]bool // exact hostnames
	wildcards  map[string]bool // dot-prefixes: ".example.com"
	manual     map[string]bool // subset added by an admin (not the feed)
	exceptions map[string]bool // hosts that are NEVER blocked, even if listed
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
	os.WriteFile(b.path+".mode", []byte(b.mode), 0600) //nolint:errcheck
}

func (b *Blocklist) Load(path string) error {
	b.path = path
	// Load mode sidecar.
	if data, err := os.ReadFile(path + ".mode"); err == nil {
		m := strings.TrimSpace(string(data))
		if m == "allow" {
			b.mode = "allow"
		}
	}
	// Load manual sidecar — tracks which hosts were added by an admin.
	manual := map[string]bool{}
	if data, err := os.ReadFile(path + ".manual"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				manual[line] = true
			}
		}
	}
	// Load exceptions sidecar — hosts that are never blocked regardless of the list.
	exceptions := map[string]bool{}
	if data, err := os.ReadFile(path + ".exceptions"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.ToLower(strings.TrimSpace(line))
			if line != "" {
				exceptions[line] = true
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	exact := map[string]bool{}
	wildcards := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(line)
		if strings.HasPrefix(line, "*.") {
			wildcards[line[1:]] = true
		} else {
			exact[line] = true
		}
	}
	b.mu.Lock()
	b.exact = exact
	b.wildcards = wildcards
	b.manual = manual
	b.exceptions = exceptions
	b.mu.Unlock()
	return sc.Err()
}

func (b *Blocklist) Save() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	// Write to a temp file first, then rename for an atomic replace so a crash
	// mid-write never leaves a partially-written (corrupt) blocklist on disk.
	tmp := b.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304 -- path is operator-configured
	if err != nil {
		return
	}
	for h := range b.exact {
		fmt.Fprintln(f, h)
	}
	for suffix := range b.wildcards {
		fmt.Fprintln(f, "*"+suffix) // ".example.com" → "*.example.com"
	}
	if err := f.Close(); err != nil {
		return
	}
	os.Rename(tmp, b.path) //nolint:errcheck
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
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	// Warn on overly broad exceptions that may exempt many domains.
	bare := strings.TrimPrefix(host, "*.")
	parts := strings.Split(bare, ".")
	if len(parts) <= 1 || (len(parts) == 2 && strings.HasPrefix(host, "*.")) {
		logger.Printf("WARN broad blocklist exception added: %s — may exempt many domains", sanitizeLog(host))
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
	tmp := b.path + ".exceptions.tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304
	if err != nil {
		return
	}
	for h := range b.exceptions {
		fmt.Fprintln(f, h)
	}
	if err := f.Close(); err != nil {
		return
	}
	os.Rename(tmp, b.path+".exceptions") //nolint:errcheck
}

// IsBlocked reports whether a request to host should be blocked.
// In "block" mode (default): listed hosts are blocked.
// In "allow" mode:           only listed hosts are allowed; all others blocked.
// Exceptions always pass through regardless of mode or list membership.
func (b *Blocklist) IsBlocked(host string) bool {
	host = strings.ToLower(host)
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

// AddManual adds a host and marks it as manually managed by an admin.
// Unlike Add (used by the feed syncer), this persists the source attribution.
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
}

// saveManual persists the set of manually-added hosts to a sidecar file.
func (b *Blocklist) saveManual() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	tmp := b.path + ".manual.tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304
	if err != nil {
		return
	}
	for h := range b.manual {
		fmt.Fprintln(f, h)
	}
	if err := f.Close(); err != nil {
		return
	}
	os.Rename(tmp, b.path+".manual") //nolint:errcheck
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
		src := "feed"
		if b.manual[h] {
			src = "manual"
		}
		out = append(out, BlocklistEntry{Host: h, Source: src})
	}
	for suffix := range b.wildcards {
		h := "*" + suffix
		src := "feed"
		if b.manual[h] {
			src = "manual"
		}
		out = append(out, BlocklistEntry{Host: h, Source: src})
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
// Lines starting with '#' or empty are skipped.
// Returns the number of newly-added entries.
func (b *Blocklist) MergeFromLines(lines []string) int {
	added := 0
	b.mu.Lock()
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
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
		if line == "" {
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
	}
	b.mu.Unlock()
	if added > 0 {
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
	passHash    []byte
	role        UIRole
	totpSecret  string   // base32 TOTP secret; empty = TOTP not enrolled
	backupCodes []string // bcrypt-hashed backup codes
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
		logger.Printf("Auth provider → %s", p.Name())
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
		logger.Printf("Auth mode → UNAUTH (open proxy, no credentials required)")
	}
}

// ─── UI multi-user admin management ──────────────────────────────────────────

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
	Username    string   `json:"username"`
	PassHash    string   `json:"pass_hash"`               // hex-encoded bcrypt hash
	Role        UIRole   `json:"role"`
	TOTPSecret  string   `json:"totp_secret,omitempty"`   // base32 TOTP secret
	BackupCodes []string `json:"backup_codes,omitempty"`  // bcrypt-hashed one-time codes
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
		return nil
	}
	if err != nil {
		return err
	}
	var records []uiUserRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uiUsers == nil {
		c.uiUsers = map[string]*uiAdminUser{}
	}
	for _, rec := range records {
		hash, err := hex.DecodeString(rec.PassHash)
		if err != nil {
			continue
		}
		c.uiUsers[rec.Username] = &uiAdminUser{
			passHash:    hash,
			role:        rec.Role,
			totpSecret:  rec.TOTPSecret,
			backupCodes: rec.BackupCodes,
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
	records := make([]uiUserRecord, 0, len(c.uiUsers))
	for name, u := range c.uiUsers {
		records = append(records, uiUserRecord{
			Username:    name,
			PassHash:    hex.EncodeToString(u.passHash),
			Role:        u.role,
			TOTPSecret:  u.totpSecret,
			BackupCodes: u.backupCodes,
		})
	}
	c.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(records, "", "  ")
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

func recordRequest(ip, method, host, status, ruleMatched, actionTaken, identity string) {
	atomic.AddInt64(&statTotal, 1)
	isAllowed := status == "OK" || status == "POLICY_ALLOW" || status == "POLICY_REDIRECT" || status == "PAC_DOWNLOAD"
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
	logAdd(LogEntry{
		TS:          time.Now().UnixMilli(),
		Time:        time.Now().Format("15:04:05"),
		IP:          ip,
		Identity:    identity,
		Method:      method,
		Host:        host,
		Status:      status,
		Level:       levelForStatus(status),
		RuleMatched: ruleMatched,
		ActionTaken: actionTaken,
	})
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
