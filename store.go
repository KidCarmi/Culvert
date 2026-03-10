package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
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
	cur     int
	lastMin int64
}

var ts = &timeSeries{}

func tsRecord() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
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
		}
		ts.lastMin = now
	}
	ts.buckets[ts.cur]++
}

func tsGet() []int64 {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]int64, 60)
	for i := 0; i < 60; i++ {
		out[59-i] = ts.buckets[(ts.cur-i+60)%60]
	}
	return out
}

// ─── Request log ──────────────────────────────────────────────────────────────

type LogEntry struct {
	TS          int64  `json:"ts"`
	Time        string `json:"time"`
	IP          string `json:"ip"`
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
	auditMu  sync.Mutex
	auditLog []AuditEntry
)

// auditAdd appends an entry to the in-memory audit ring buffer.
func auditAdd(e AuditEntry) {
	auditMu.Lock()
	defer auditMu.Unlock()
	auditLog = append(auditLog, e)
	if len(auditLog) > maxAuditLogs {
		auditLog = auditLog[len(auditLog)-maxAuditLogs:]
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
type Blocklist struct {
	mu        sync.RWMutex
	exact     map[string]bool // exact hostnames
	wildcards map[string]bool // dot-prefixes: ".example.com"
	path      string
}

var bl = &Blocklist{exact: map[string]bool{}, wildcards: map[string]bool{}}

func (b *Blocklist) Load(path string) error {
	b.path = path
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
	f.Close()
	os.Rename(tmp, b.path) //nolint:errcheck
}

// IsBlocked checks exact match first (O(1)), then walks the host's dot-labels
// to probe the wildcards map (O(labels) ≈ O(1)).
//
// Example: host "sub.ads.example.com", wildcard "*.example.com" (stored as ".example.com"):
//   dot-walk checks ".ads.example.com" → not matched
//             checks ".example.com"    → matched ✓
// Apex match: host "example.com" vs "*.example.com" → checks ".example.com" directly.
func (b *Blocklist) IsBlocked(host string) bool {
	host = strings.ToLower(host)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.exact[host] {
		return true
	}
	// Dot-walk: "sub.ads.example.com" → check ".ads.example.com", ".example.com", ".com"
	for i, ch := range host {
		if ch == '.' && b.wildcards[host[i:]] {
			return true
		}
	}
	// Apex match: "example.com" should match "*.example.com" (stored as ".example.com")
	if b.wildcards["."+host] {
		return true
	}
	return false
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

func (b *Blocklist) Remove(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	if strings.HasPrefix(host, "*.") {
		delete(b.wildcards, host[1:])
	} else {
		delete(b.exact, host)
	}
	b.mu.Unlock()
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

func (b *Blocklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.exact) + len(b.wildcards)
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

// cacheKey hashes (user+pass) with SHA-256 so we never store plaintext creds
// as map keys in heap-visible memory.
func cacheKey(user, pass string) string {
	h := sha256.Sum256([]byte(user + ":" + pass))
	return hex.EncodeToString(h[:])
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
	passHash []byte
	role     UIRole
}

// UIUserInfo is the public (no hash) view of a UI admin user.
type UIUserInfo struct {
	Username string `json:"username"`
	Role     UIRole `json:"role"`
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
func (c *Config) DeleteUIUser(username string) {
	c.mu.Lock()
	delete(c.uiUsers, username)
	c.mu.Unlock()
}

// ListUIUsers returns a snapshot of all admin UI users (without password hashes).
func (c *Config) ListUIUsers() []UIUserInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]UIUserInfo, 0, len(c.uiUsers))
	for name, u := range c.uiUsers {
		out = append(out, UIUserInfo{Username: name, Role: u.role})
	}
	return out
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

func recordRequest(ip, method, host, status, ruleMatched, actionTaken string) {
	atomic.AddInt64(&statTotal, 1)
	tsRecord()
	if status == "OK" || status == "POLICY_ALLOW" {
		topHosts.Record(host)
	}
	logAdd(LogEntry{
		TS:          time.Now().UnixMilli(),
		Time:        time.Now().Format("15:04:05"),
		IP:          ip,
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
	for i := 0; i < len(all)-1; i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].Count > all[i].Count {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}
