// Package autoexclude is the adaptive decryption-exclusion cache: a bounded,
// TTL-bounded, in-memory learned set of hosts that could not be SSL-inspected,
// so that subsequent CONNECTs to them can fail open (bypass decryption) instead
// of breaking. It is the ADAPTIVE half of decryption exclusion; the MANUAL half
// (operator-authored bypass patterns) lives in internal/sslbypass.
//
// This is PAN-OS's "local SSL decryption exclusion cache" modeled for a
// multi-tenant forward proxy. Two design choices make it safe to auto-disable
// inspection for a host based on a runtime signal:
//
//  1. CONFIRM-COUNT over DISTINCT client IPs. A host is not excluded on the
//     first failure. The cache holds a PENDING observation per (host, reason)
//     accumulating the distinct client IPs that hit a qualifying failure within
//     a rolling window; only when the count reaches confirmN is the host
//     promoted to an active exclusion. A single (possibly malicious) endpoint
//     therefore cannot self-poison the cache to disable inspection for a host of
//     its choosing — a genuine fleet-wide incompatibility (a pinned app on many
//     devices) crosses the threshold quickly, a lone insider never does.
//
//  2. The CALLER gates BOTH the learn (Observe) and the read (Contains) on the
//     matched rule's fail-open opt-in. This engine stores and answers; it never
//     decides policy. A host learned under a fail-open rule cannot bypass a
//     fail-close rule for the same host, because the caller never consults this
//     cache on a fail-close decision. That gating is the never-exclude control:
//     critical origins kept on fail-close rules are un-poisonable by design.
//
// Volatility is intentional (matches PAN-OS's per-firewall local cache): the
// cache is in-memory only, never persisted, never synced CP->DP, and therefore
// off every config surface. A restart re-learns cheaply.
//
// Concurrency: a single Mutex guards both maps. Contains is on the per-CONNECT
// hot path but only for fail-open rules (a rare opt-in), and the critical
// section is a map lookup + expiry check, so a plain Mutex is adequate and
// keeps the confirm-count / hit-count bookkeeping race-free.
package autoexclude

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Reason classifies WHY a host was learned. The set is bounded (safe as a
// metric label). Only these three are ever learned; an untrusted/expired origin
// cert (ReasonCertVerify-like) is deliberately NOT a reason here — the caller's
// classifier drops it, because auto-bypassing a bad cert is an exfil vector, not
// a compatibility fix.
type Reason string

const (
	// ReasonUnsupported is the origin TLS could-not-be-inspected reason: a
	// version/cipher/protocol incompatibility (the canonical PAN-OS trigger).
	ReasonUnsupported Reason = "unsupported"
	// ReasonClientCertRequired is the origin-demanded-a-client-certificate reason:
	// we cannot present one (server-observed CertificateRequest — non-spoofable).
	ReasonClientCertRequired Reason = "client_cert_required"
	// ReasonClientPinned is the client-rejected-our-forged-leaf reason (a pinned
	// app). Spoofable from the client side, so it is the reason most reliant on
	// the confirm-count and gets the shorter TTL.
	ReasonClientPinned Reason = "client_pinned"
)

// Defaults. TTL matches the PAN-OS local-cache default (12h) for the
// server-observed reasons; PinnedTTL is shorter because the client signal is the
// spoofable class. ConfirmN=2 distinct client IPs blocks single-endpoint
// poisoning while letting a real fleet-wide incompatibility promote almost
// immediately. Window bounds how long partial observations accumulate.
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

// Entry is one active exclusion (a host inspection is currently OFF for).
type Entry struct {
	Host      string    `json:"host"`
	Reason    Reason    `json:"reason"`
	LearnedAt time.Time `json:"learned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Hits counts sessions that bypassed inspection because of this entry — the
	// blast-radius signal a security team triages against.
	Hits int64 `json:"hits"`
	// ClientCount is how many distinct client IPs were observed failing before
	// promotion (provenance for the learn decision).
	ClientCount int `json:"client_count"`
}

type entry struct {
	reason      Reason
	learnedAt   time.Time
	expiresAt   time.Time
	hits        int64
	clientCount int
}

// pend is an in-progress observation awaiting confirmN distinct client IPs.
type pend struct {
	reason    Reason
	clients   map[string]struct{}
	firstSeen time.Time
}

// Cache is the learned-exclusion store. The zero value is NOT ready; use New.
type Cache struct {
	mu     sync.Mutex
	active map[string]*entry // key: normalized host-only
	pend   map[string]*pend  // key: host-only \x00 reason

	ttl        time.Duration
	pinnedTTL  time.Duration
	confirmN   int
	window     time.Duration
	maxEntries int
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
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// normHost host-only-normalizes a key. Callers pass raw request hosts (possibly
// with a port and arbitrary casing/trailing dot); we key on the same host-only
// space the policy matcher and sslBypass use, so an attacker cannot vary the
// port or casing to dodge the fail-close scoping or the operator's view.
func normHost(host string) string {
	return hostutil.NormalizeHost(hostutil.StripHostPort(host))
}

// clientBucket collapses a client IP to its provider-assignable prefix so the
// "distinct client" confirm-count cannot be gamed by one host that owns many
// addresses. A single machine legitimately holds an entire IPv6 /64 (SLAAC /
// privacy extensions) and often a NATed IPv4 /24, so counting raw addresses
// would let one attacker present N "distinct" sources against a fail-open rule.
// We count distinct /64 (v6) and /24 (v4) buckets instead. An unparseable IP
// falls back to itself (still requires confirmN distinct such values).
func clientBucket(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String()
}

func (c *Cache) reasonTTL(r Reason) time.Duration {
	if r == ReasonClientPinned {
		return c.pinnedTTL
	}
	return c.ttl
}

// Observe records a qualifying inspect failure for host from clientIP under
// reason, and reports whether this observation PROMOTED the host to an active
// exclusion (promoted=true is the security-relevant "inspection just went dark"
// event — the caller fires the audit/alert/metric on it). If the host is already
// actively excluded, Observe is a no-op returning false.
func (c *Cache) Observe(host string, reason Reason, clientIP string) (promoted bool) {
	h := normHost(host)
	if h == "" {
		return false
	}
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Already excluded (and not expired) — nothing to do.
	if e, ok := c.active[h]; ok && now.Before(e.expiresAt) {
		return false
	}

	key := h + "\x00" + string(reason)
	p := c.pend[key]
	if p == nil || now.Sub(p.firstSeen) > c.window {
		// New or stale observation window — start fresh.
		p = &pend{reason: reason, clients: make(map[string]struct{}), firstSeen: now}
		c.pend[key] = p
	}
	if clientIP != "" {
		p.clients[clientBucket(clientIP)] = struct{}{} // count distinct subnets, not raw addresses
	}
	if len(p.clients) < c.confirmN {
		return false // still gathering confirmation
	}

	// Promote to an active exclusion.
	c.active[h] = &entry{
		reason:      reason,
		learnedAt:   now,
		expiresAt:   now.Add(c.reasonTTL(reason)),
		clientCount: len(p.clients),
	}
	delete(c.pend, key)
	// Drop any other pending observations for the same host (it's excluded now).
	for k, pp := range c.pend {
		if pp == p {
			continue
		}
		if len(k) > len(h) && k[:len(h)] == h && k[len(h)] == 0 {
			delete(c.pend, k)
		}
	}
	c.evictLocked(now)
	return true
}

// Contains reports whether host is actively excluded, returning the learn reason.
// On a hit it increments that entry's blast-radius hit counter. Expired entries
// read as absent (lazy — physical removal happens in evict/List/Len).
func (c *Cache) Contains(host string) (Reason, bool) {
	h := normHost(host)
	if h == "" {
		return "", false
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.active[h]
	if !ok || !now.Before(e.expiresAt) {
		return "", false
	}
	e.hits++
	return e.reason, true
}

// evictLocked drops expired entries and, if still over the cap, the oldest by
// learnedAt. Caller holds the lock. Eviction only ever RE-ENABLES inspection
// (fail-closed), so a distinct-host flood can at worst restore inspection — it
// can never create an exclusion.
func (c *Cache) evictLocked(now time.Time) {
	for h, e := range c.active {
		if !now.Before(e.expiresAt) {
			delete(c.active, h)
		}
	}
	// Prune stale pending windows opportunistically.
	for k, p := range c.pend {
		if now.Sub(p.firstSeen) > c.window {
			delete(c.pend, k)
		}
	}
	if len(c.active) <= c.maxEntries {
		return
	}
	type ha struct {
		host string
		at   time.Time
	}
	all := make([]ha, 0, len(c.active))
	for h, e := range c.active {
		all = append(all, ha{h, e.learnedAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for i := 0; i < len(all) && len(c.active) > c.maxEntries; i++ {
		delete(c.active, all[i].host)
	}
}

// List returns a stable, expired-filtered snapshot of active exclusions, sorted
// by learnedAt (newest first) for a predictable UI ordering.
func (c *Cache) List() []Entry {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Entry, 0, len(c.active))
	for h, e := range c.active {
		if !now.Before(e.expiresAt) {
			continue
		}
		out = append(out, Entry{
			Host:        h,
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

// Remove evicts one host by (normalized) name. Returns true if it was present.
func (c *Cache) Remove(host string) bool {
	h := normHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.active[h]; !ok {
		return false
	}
	delete(c.active, h)
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
