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
	statTotal    int64
	statBlocked  int64
	statAuthFail int64
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
	TS     int64  `json:"ts"`
	Time   string `json:"time"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Host   string `json:"host"`
	Status string `json:"status"` // OK | BLOCKED | AUTH_FAIL | RATE_LIMITED | IP_BLOCKED
	Level  string `json:"level"`  // INFO | WARN | ERROR
}

func levelForStatus(status string) string {
	switch status {
	case "OK":
		return "INFO"
	case "BLOCKED", "RATE_LIMITED", "IP_BLOCKED":
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

// ─── Blocklist ────────────────────────────────────────────────────────────────

type Blocklist struct {
	mu    sync.RWMutex
	hosts map[string]bool
	path  string
}

var bl = &Blocklist{hosts: map[string]bool{}}

func (b *Blocklist) Load(path string) error {
	b.path = path
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	m := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = true
	}
	b.mu.Lock()
	b.hosts = m
	b.mu.Unlock()
	return sc.Err()
}

func (b *Blocklist) Save() {
	if b.path == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	f, err := os.Create(b.path)
	if err != nil {
		return
	}
	defer f.Close()
	for h := range b.hosts {
		fmt.Fprintln(f, h)
	}
}

func (b *Blocklist) IsBlocked(host string) bool {
	host = strings.ToLower(host)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.hosts[host] {
		return true
	}
	for pattern := range b.hosts {
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // .example.com
			if strings.HasSuffix(host, suffix) || host == pattern[2:] {
				return true
			}
		}
	}
	return false
}

func (b *Blocklist) Add(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	b.hosts[host] = true
	b.mu.Unlock()
}

func (b *Blocklist) Remove(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	b.mu.Lock()
	delete(b.hosts, host)
	b.mu.Unlock()
}

func (b *Blocklist) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.hosts))
	for h := range b.hosts {
		out = append(out, h)
	}
	return out
}

func (b *Blocklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.hosts)
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

func (a *authCacheStore) set(user, pass string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
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

// AuthEnabled returns true when any form of authentication is active.
func (c *Config) AuthEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user != "" || c.provider != nil
}

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

func recordRequest(ip, method, host, status string) {
	atomic.AddInt64(&statTotal, 1)
	tsRecord()
	if status == "OK" {
		topHosts.Record(host)
	}
	logAdd(LogEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("15:04:05"),
		IP:     ip,
		Method: method,
		Host:   host,
		Status: status,
		Level:  levelForStatus(status),
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
