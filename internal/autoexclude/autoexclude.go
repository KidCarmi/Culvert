// Package autoexclude is the adaptive decryption-exclusion cache: a bounded,
// TTL-bounded, in-memory learned set of hosts that could not be SSL-inspected,
// so that subsequent CONNECTs to them can fail open (bypass decryption) instead
// of breaking. It is the ADAPTIVE half of decryption exclusion; the MANUAL half
// (operator-authored bypass patterns) lives in internal/sslbypass.
//
// This is PAN-OS's "local SSL decryption exclusion cache" modeled for a
// multi-tenant forward proxy. Four design choices make it safe to auto-disable
// inspection for a host based on a runtime signal:
//
//  1. SCOPED KEY. Every entry is keyed by (scope, host), where scope is an
//     explicit policy boundary — the matched decryption profile's identity. A
//     host learned under one fail-open profile is consulted ONLY for sessions
//     matched to that same profile, so one fail-open rule/profile/tenant can
//     never create a bypass consumed by another rule targeting the same host.
//     Host-only keying is NOT policy isolation; the scope is.
//
//  2. CONFIRM-COUNT over distinct CLIENT-EVIDENCE tokens. A host is not excluded
//     on the first failure. The cache holds a PENDING observation per
//     (scope, host, reason) accumulating the distinct client-evidence tokens
//     (authenticated identity when available, else client address — the caller
//     decides; the engine treats the token opaquely) that hit a qualifying
//     failure within a rolling window; only when the count reaches confirmN is
//     the host promoted. A single endpoint therefore cannot self-poison.
//
//  3. The CALLER gates BOTH the learn (Observe) and the read (Contains) on the
//     matched rule's fail-open opt-in. This engine stores and answers; it never
//     decides policy. Critical origins kept on fail-close rules are never learned
//     or consulted, so they are un-poisonable by design.
//
//  4. VOLATILE. In-memory only, never persisted, never synced CP->DP, off every
//     config surface. A restart re-learns cheaply. (Per-node exclusions match
//     PAN-OS's per-firewall local cache.)
//
// Concurrency: a single Mutex guards both maps. Contains is on the per-CONNECT
// hot path but only for fail-open rules (a rare opt-in), and the critical
// section is a map lookup + expiry check, so a plain Mutex is adequate.
package autoexclude

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Reason classifies WHY a host was learned. The set is bounded (safe as a metric
// label). Only these are ever learned; an untrusted/expired origin cert and every
// generic/ambiguous origin-controlled TLS alert are dropped by the caller's
// classifier, because auto-bypassing them is an exfil vector, not a compat fix.
type Reason string

const (
	// ReasonClientCertRequired is the origin-demanded-a-client-certificate reason:
	// the origin sent a CertificateRequest we cannot satisfy (a specific,
	// structured TLS signal — the one origin-leg reason allowed to live-rescue).
	ReasonClientCertRequired Reason = "client_cert_required"
	// ReasonUnsupportedParams is a genuine TLS-parameter incompatibility detected
	// LOCALLY by our own stack (no supported version overlap / no cipher overlap).
	// Learn-only: it enters pending learning but never live-rescues the triggering
	// session (it is lower-confidence than client-cert-required).
	ReasonUnsupportedParams Reason = "unsupported_params"
	// ReasonClientPinned is the client-rejected-our-forged-leaf reason (a pinned
	// app). Spoofable from the client side, so it is the reason most reliant on
	// the confirm-count and gets the shorter TTL. Learn-only.
	ReasonClientPinned Reason = "client_pinned"
)

// Defaults. TTL matches the PAN-OS local-cache default (12h) for the
// server-observed reasons; PinnedTTL is shorter because the client signal is the
// spoofable class. ConfirmN=2 distinct client-evidence tokens blocks
// single-endpoint poisoning while letting a real fleet-wide incompatibility
// promote quickly. Window bounds how long partial observations accumulate.
const (
	DefaultTTL        = 12 * time.Hour
	DefaultPinnedTTL  = 1 * time.Hour
	DefaultConfirmN   = 2
	DefaultWindow     = 10 * time.Minute
	DefaultMaxEntries = 4096
)

// Config parameterizes a Cache. Zero fields fall back to the Default* constants.
type Config struct {
	TTL        time.Duration
	PinnedTTL  time.Duration
	ConfirmN   int
	Window     time.Duration
	MaxEntries int
	// Now is injectable for deterministic tests; nil ⇒ time.Now.
	Now func() time.Time
}

// Entry is one active exclusion (a (scope, host) inspection is currently OFF for).
type Entry struct {
	ScopeID   string    `json:"scope_id"`   // decryption-profile identity that owns this exclusion
	ScopeName string    `json:"scope_name"` // human-readable scope (profile name) for the UI/audit
	Host      string    `json:"host"`
	Reason    Reason    `json:"reason"`
	LearnedAt time.Time `json:"learned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Hits counts sessions that bypassed inspection because of this entry — the
	// blast-radius signal a security team triages against.
	Hits int64 `json:"hits"`
	// ClientCount is how many distinct client-evidence tokens were observed
	// failing before promotion (provenance for the learn decision).
	ClientCount int `json:"client_count"`
}

type entry struct {
	scopeID     string
	scopeName   string
	host        string
	reason      Reason
	learnedAt   time.Time
	expiresAt   time.Time
	hits        int64
	clientCount int
}

// pend is an in-progress observation awaiting confirmN distinct client tokens.
type pend struct {
	reason    Reason
	scopeName string
	clients   map[string]struct{}
	firstSeen time.Time
}

// Cache is the learned-exclusion store. The zero value is NOT ready; use New.
type Cache struct {
	mu     sync.Mutex
	active map[string]*entry // key: scopeID \x00 host
	pend   map[string]*pend  // key: scopeID \x00 host \x00 reason

	ttl        time.Duration
	pinnedTTL  time.Duration
	confirmN   int
	window     time.Duration
	maxEntries int
	maxPending int // cap on in-progress observations (bounds c.pend independently of promotion)
	now        func() time.Time
}

// New builds a Cache from cfg, applying Default* for any zero field.
func New(cfg Config) *Cache {
	c := &Cache{
		active:     make(map[string]*entry),
		pend:       make(map[string]*pend),
		ttl:        cfg.TTL,
		pinnedTTL:  cfg.PinnedTTL,
		confirmN:   cfg.ConfirmN,
		window:     cfg.Window,
		maxEntries: cfg.MaxEntries,
		now:        cfg.Now,
	}
	if c.ttl <= 0 {
		c.ttl = DefaultTTL
	}
	if c.pinnedTTL <= 0 {
		c.pinnedTTL = DefaultPinnedTTL
	}
	if c.confirmN <= 0 {
		c.confirmN = DefaultConfirmN
	}
	if c.window <= 0 {
		c.window = DefaultWindow
	}
	if c.maxEntries <= 0 {
		c.maxEntries = DefaultMaxEntries
	}
	c.maxPending = c.maxEntries // in-progress observations share the entry cap
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// normHost host-only-normalizes a key. Callers pass raw request hosts (possibly
// with a port and arbitrary casing/trailing dot); we key on the same host-only
// space the policy matcher and sslBypass use, so an attacker cannot vary the
// port or casing to dodge the operator's view.
func normHost(host string) string {
	return hostutil.NormalizeHost(hostutil.StripHostPort(host))
}

// key composes the scoped active-map key. scopeID is treated opaquely.
func key(scopeID, host string) string { return scopeID + "\x00" + host }

func (c *Cache) reasonTTL(r Reason) time.Duration {
	if r == ReasonClientPinned {
		return c.pinnedTTL
	}
	return c.ttl
}

// Observe records a qualifying inspect failure for (scopeID, host) under reason,
// attributing it to the opaque distinct-evidence token `client` (the caller
// derives it — authenticated identity preferred, else client address). It reports
// whether this observation PROMOTED the (scope, host) to an active exclusion
// (promoted=true is the security-relevant "inspection just went dark" event — the
// caller fires the audit/alert/metric on it). If already actively excluded, it is
// a no-op returning false. An empty scopeID or host is ignored (fail-safe).
func (c *Cache) Observe(scopeID, scopeName, host string, reason Reason, client string) (promoted bool) {
	h := normHost(host)
	if scopeID == "" || h == "" {
		return false
	}
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	ak := key(scopeID, h)
	if e, ok := c.active[ak]; ok && now.Before(e.expiresAt) {
		return false // already excluded for this scope
	}

	pk := ak + "\x00" + string(reason)
	p := c.pend[pk]
	switch {
	case p == nil:
		// A brand-new observation grows c.pend. Bound it: without this, a fail-open
		// rule seeing many never-confirming hosts would grow the pending map without
		// bound, since promotion — the only path that pruned it — never fires.
		if len(c.pend) >= c.maxPending {
			c.evictPendingLocked(now)
		}
		p = &pend{reason: reason, scopeName: scopeName, clients: make(map[string]struct{}), firstSeen: now}
		c.pend[pk] = p
	case now.Sub(p.firstSeen) > c.window:
		// Stale window on an existing key — reset in place (no net growth).
		p = &pend{reason: reason, scopeName: scopeName, clients: make(map[string]struct{}), firstSeen: now}
		c.pend[pk] = p
	}
	if client != "" {
		p.clients[client] = struct{}{}
	}
	if len(p.clients) < c.confirmN {
		return false // still gathering confirmation
	}

	// Promote to an active exclusion for this scope.
	c.active[ak] = &entry{
		scopeID:     scopeID,
		scopeName:   scopeName,
		host:        h,
		reason:      reason,
		learnedAt:   now,
		expiresAt:   now.Add(c.reasonTTL(reason)),
		clientCount: len(p.clients),
	}
	delete(c.pend, pk)
	// Drop any other pending observations for the SAME (scope, host) — it's excluded.
	prefix := ak + "\x00"
	for k := range c.pend {
		if strings.HasPrefix(k, prefix) {
			delete(c.pend, k)
		}
	}
	c.evictLocked(now)
	return true
}

// Contains reports whether (scopeID, host) is actively excluded, returning the
// learn reason. On a hit it increments that entry's blast-radius hit counter.
// Expired entries read as absent (lazy — physical removal happens in evict/List).
func (c *Cache) Contains(scopeID, host string) (Reason, bool) {
	h := normHost(host)
	if scopeID == "" || h == "" {
		return "", false
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.active[key(scopeID, h)]
	if !ok || !now.Before(e.expiresAt) {
		return "", false
	}
	e.hits++
	return e.reason, true
}

// evictLocked drops expired active entries and, if still over the cap, the oldest
// by learnedAt. Caller holds the lock. Eviction only ever RE-ENABLES inspection
// (fail-closed), so a flood can at worst restore inspection.
func (c *Cache) evictLocked(now time.Time) {
	for k, e := range c.active {
		if !now.Before(e.expiresAt) {
			delete(c.active, k)
		}
	}
	for k, p := range c.pend {
		if now.Sub(p.firstSeen) > c.window {
			delete(c.pend, k)
		}
	}
	if len(c.active) <= c.maxEntries {
		return
	}
	type ka struct {
		k  string
		at time.Time
	}
	all := make([]ka, 0, len(c.active))
	for k, e := range c.active {
		all = append(all, ka{k, e.learnedAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for i := 0; i < len(all) && len(c.active) > c.maxEntries; i++ {
		delete(c.active, all[i].k)
	}
}

// evictPendingLocked bounds the in-progress observation map: it drops entries
// whose window has elapsed, then — if still over maxPending — the oldest by
// firstSeen. Caller holds the lock. Runs only when a new key would push c.pend
// over the cap, so the common (under-cap) path pays nothing. Evicting a pending
// observation only forces its (scope,host) to re-accumulate confirmations; it can
// never create an exclusion, so the direction is fail-closed.
func (c *Cache) evictPendingLocked(now time.Time) {
	for k, p := range c.pend {
		if now.Sub(p.firstSeen) > c.window {
			delete(c.pend, k)
		}
	}
	if len(c.pend) < c.maxPending {
		return
	}
	type kf struct {
		key string
		at  time.Time
	}
	all := make([]kf, 0, len(c.pend))
	for k, p := range c.pend {
		all = append(all, kf{k, p.firstSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for i := 0; i < len(all) && len(c.pend) >= c.maxPending; i++ {
		delete(c.pend, all[i].key)
	}
}

// List returns a stable, expired-filtered snapshot of active exclusions, sorted
// by learnedAt (newest first) for a predictable UI ordering.
func (c *Cache) List() []Entry {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Entry, 0, len(c.active))
	for _, e := range c.active {
		if !now.Before(e.expiresAt) {
			continue
		}
		out = append(out, Entry{
			ScopeID:     e.scopeID,
			ScopeName:   e.scopeName,
			Host:        e.host,
			Reason:      e.reason,
			LearnedAt:   e.learnedAt,
			ExpiresAt:   e.expiresAt,
			Hits:        e.hits,
			ClientCount: e.clientCount,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LearnedAt.After(out[j].LearnedAt) })
	return out
}

// Remove evicts one (scopeID, host). Returns true if it was present.
func (c *Cache) Remove(scopeID, host string) bool {
	h := normHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key(scopeID, h)
	if _, ok := c.active[k]; !ok {
		return false
	}
	delete(c.active, k)
	return true
}

// Clear evicts every active exclusion and pending observation. Returns the
// number of active entries removed.
func (c *Cache) Clear() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.active)
	c.active = make(map[string]*entry)
	c.pend = make(map[string]*pend)
	return n
}

// Len is the current count of active (non-expired) exclusions.
func (c *Cache) Len() int {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.active {
		if now.Before(e.expiresAt) {
			n++
		}
	}
	return n
}

// PendingLen is the current count of in-progress (unconfirmed) observations.
func (c *Cache) PendingLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pend)
}

// Stats reports the cache posture for the read-only governance/API surface, so
// an operator can prove the feature's configuration (and that a no-fail-open
// deployment has an inert, empty cache).
type Stats struct {
	Active     int `json:"active"`
	Pending    int `json:"pending"`
	ConfirmN   int `json:"confirm_n"`
	TTLSecs    int `json:"ttl_secs"`
	PinnedSecs int `json:"pinned_ttl_secs"`
	WindowSecs int `json:"window_secs"`
	MaxEntries int `json:"max_entries"`
}

// Stats returns a snapshot of the cache configuration and occupancy.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	active := 0
	for _, e := range c.active {
		if now.Before(e.expiresAt) {
			active++
		}
	}
	return Stats{
		Active:     active,
		Pending:    len(c.pend),
		ConfirmN:   c.confirmN,
		TTLSecs:    int(c.ttl / time.Second),
		PinnedSecs: int(c.pinnedTTL / time.Second),
		WindowSecs: int(c.window / time.Second),
		MaxEntries: c.maxEntries,
	}
}
