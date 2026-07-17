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
// Concurrency: an RWMutex guards both maps. Contains (the per-CONNECT hot read,
// fail-open rules only) takes the READ lock and bumps the per-entry hit counter
// ATOMICALLY, so concurrent reads on different hosts run fully parallel; writers
// (Observe/Remove/Clear/evict) take the write lock, which excludes all readers so
// an entry is never mutated or deleted while a reader holds it.
package autoexclude

import (
	"sort"
	"sync"
	"sync/atomic"
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

// allReasons is the fixed reason set, used for O(#reasons) same-host pending
// cleanup on promotion (avoids an O(pending) map scan under the write lock).
var allReasons = []Reason{ReasonClientCertRequired, ReasonUnsupportedParams, ReasonClientPinned}

// AllReasons returns a copy of the canonical bounded reason set. Exported so callers
// that must bound an untrusted Reason to the closed vocabulary (the ADR-0011
// decryption-observability projection) can check membership without duplicating the
// list — keeping them drift-free if a reason is ever added. Returns a fresh slice so
// the canonical set stays immutable.
func AllReasons() []Reason {
	out := make([]Reason, len(allReasons))
	copy(out, allReasons)
	return out
}

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
	mu     sync.RWMutex
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
	// Drop any other pending observations for the SAME (scope, host) under a
	// different reason — it's excluded now. Keyed on the fixed reason set, so this
	// is O(#reasons), NOT an O(pending) scan (which would be a per-promotion CPU/
	// lock-hold cost under load).
	for _, r := range allReasons {
		if r != reason {
			delete(c.pend, ak+"\x00"+string(r))
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
	// RLock (not Lock): the read path only reads the map + immutable entry fields
	// and bumps the hit counter atomically, so concurrent Contains on DIFFERENT
	// hosts run fully parallel. Writers (Observe/Remove/Clear/evict) still take the
	// write Lock, which excludes all readers, so an entry cannot be mutated/deleted
	// while a reader holds it. hits MUST be atomic because multiple RLock-holding
	// readers may bump the same counter concurrently.
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.active[key(scopeID, h)]
	if !ok || !now.Before(e.expiresAt) {
		return "", false
	}
	atomic.AddInt64(&e.hits, 1)
	return e.reason, true
}

// lowWater returns the batch-eviction floor (~94% of cap). Evicting DOWN to the
// low-water mark (rather than to exactly the cap) amortizes the O(n log n) sort:
// under a sustained over-cap flood the sort fires once per (cap-lowWater) inserts
// instead of on every insert — turning an O(cap log cap)-per-Observe CPU/lock-hold
// DoS into an amortized O(log cap) per insert.
func lowWater(size int) int {
	lw := size - size/16
	if lw < 1 {
		lw = 1
	}
	return lw
}

// evictLess is the DETERMINISTIC eviction ordering used everywhere the cache trims
// by age: oldest first by the learn/first-seen time, and — critically — ties are
// broken by the map key (lexicographic). Without the key tiebreaker, two entries
// sharing a timestamp (common under an injected test clock, and possible in
// production within a clock tick) would be ordered by Go's randomized map-iteration
// order, making WHICH entry is evicted non-deterministic. Keying the tiebreaker on
// the (already unique, opaque) map key makes eviction reproducible across runs and
// independent of map iteration order.
func evictLess(atI time.Time, keyI string, atJ time.Time, keyJ string) bool {
	if atI.Equal(atJ) {
		return keyI < keyJ
	}
	return atI.Before(atJ)
}

// evictLocked drops expired active entries and, if still over the cap, the oldest
// by learnedAt DOWN TO the low-water mark (batched — see lowWater). Caller holds
// the lock. Eviction only ever RE-ENABLES inspection (fail-closed), so a flood can
// at worst restore inspection.
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
	target := lowWater(c.maxEntries)
	type ka struct {
		k  string
		at time.Time
	}
	all := make([]ka, 0, len(c.active))
	for k, e := range c.active {
		all = append(all, ka{k, e.learnedAt})
	}
	sort.Slice(all, func(i, j int) bool { return evictLess(all[i].at, all[i].k, all[j].at, all[j].k) })
	for i := 0; i < len(all) && len(c.active) > target; i++ {
		delete(c.active, all[i].k)
	}
}

// evictPendingLocked bounds the in-progress observation map: it drops entries
// whose window has elapsed, then — if still over maxPending — the oldest by
// firstSeen DOWN TO the low-water mark (batched, same amortization as
// evictLocked). Caller holds the lock. Runs only when a new key would push c.pend
// over the cap. Evicting a pending observation only forces its (scope,host) to
// re-accumulate confirmations; it can never create an exclusion (fail-closed).
func (c *Cache) evictPendingLocked(now time.Time) {
	for k, p := range c.pend {
		if now.Sub(p.firstSeen) > c.window {
			delete(c.pend, k)
		}
	}
	if len(c.pend) < c.maxPending {
		return
	}
	target := lowWater(c.maxPending)
	type kf struct {
		key string
		at  time.Time
	}
	all := make([]kf, 0, len(c.pend))
	for k, p := range c.pend {
		all = append(all, kf{k, p.firstSeen})
	}
	sort.Slice(all, func(i, j int) bool { return evictLess(all[i].at, all[i].key, all[j].at, all[j].key) })
	for i := 0; i < len(all) && len(c.pend) > target; i++ {
		delete(c.pend, all[i].key)
	}
}

// Reconfigure atomically applies new tunables to a LIVE cache, preserving learned
// entries. It is the runtime seam for admin-editable tunables (F10 / ADR-0010): it
// mutates the five scalar tunables IN PLACE under the write lock and NEVER replaces
// the cache pointer, so the mutex alone makes it race-free against concurrent
// Observe/Contains (which take the same lock) — a reader can never observe a
// half-applied configuration. It never calls out to external code while holding the
// lock, and it can never partially apply: all fields are resolved to locals first,
// then assigned together.
//
// Semantics (deliberate, per ADR-0010):
//   - Each field <= 0 resolves to its Default* (identical to New), so a zeroed field
//     means "reset this tunable to default".
//   - pinnedTTL is clamped to <= ttl DEFENSIVELY. This is the engine's last line of
//     defense: the API layer (F10 PR3) also validates the merged set, but the engine
//     guarantees a valid state for ANY caller — the spoofable client_pinned class can
//     never outlive the server-observed class even if outer validation is bypassed.
//   - maxPending is re-established to maxEntries (the New invariant), so the pending
//     bound never desyncs from the active cap.
//   - TTL / PinnedTTL changes are FORWARD-ONLY (ADR-0010 Model A): existing active
//     entries KEEP their already-computed ExpiresAt; a new TTL applies only to
//     entries promoted AFTER this call. This avoids retroactively moving live expiry
//     times (no coverage blip, clean rollback). To shorten or drop EXISTING
//     exclusions immediately, the operator uses Remove/Clear — TTL is forward policy.
//   - If maxEntries is lowered below the current active count, the excess is evicted
//     IMMEDIATELY and DETERMINISTICALLY (evictLess: oldest by learnedAt, ties by key)
//     down to EXACTLY the new cap; the pending map is likewise bounded to the new
//     maxPending. Eviction only ever RE-ENABLES inspection (fail-closed).
//   - cfg.Now is IGNORED: Reconfigure tunes parameters, not the clock.
func (c *Cache) Reconfigure(cfg Config) {
	// Resolve every field to a local FIRST (default-floor + cross-field clamp), so
	// the apply under the lock is a single atomic assignment with no window in which
	// the cache holds a partially-updated configuration.
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	pinnedTTL := cfg.PinnedTTL
	if pinnedTTL <= 0 {
		pinnedTTL = DefaultPinnedTTL
	}
	if pinnedTTL > ttl {
		pinnedTTL = ttl // defensive: the spoofable pinned TTL never exceeds the server-observed TTL
	}
	confirmN := cfg.ConfirmN
	if confirmN <= 0 {
		confirmN = DefaultConfirmN
	}
	window := cfg.Window
	if window <= 0 {
		window = DefaultWindow
	}
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}

	// Snapshot the clock BEFORE locking. c.now may be caller-injected (tests /
	// future instrumentation); calling it under c.mu could deadlock a wrapper that
	// re-enters the cache (Len/Stats). This mirrors Observe/Contains, which both
	// read now := c.now() before taking the lock.
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
	c.pinnedTTL = pinnedTTL
	c.confirmN = confirmN
	c.window = window
	c.maxEntries = maxEntries
	c.maxPending = maxEntries // maintain the New invariant (pending shares the entry cap)
	// Enforce the (possibly lowered) caps immediately and deterministically. Existing
	// entries within the caps are preserved (Model A); only the excess is dropped.
	c.evictToExactLocked(maxEntries, now)
}

// evictToExactLocked deterministically trims the active map to AT MOST `target`
// entries and the pending map to AT MOST c.maxPending, dropping oldest-first
// (evictLess: learnedAt/firstSeen, ties by key). Unlike the hot-path evictLocked
// (which batches to a low-water mark to amortize the sort under a sustained flood),
// this evicts to EXACTLY the target — it runs once per admin Reconfigure, not per
// Observe, so exactness is affordable and is the operator-visible contract ("lower
// the cap ⇒ the cache is at the cap"). Caller holds the write lock.
func (c *Cache) evictToExactLocked(target int, now time.Time) {
	// Expired/stale entries first — they should not count against the cap.
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
	if len(c.active) > target {
		type ka struct {
			k  string
			at time.Time
		}
		all := make([]ka, 0, len(c.active))
		for k, e := range c.active {
			all = append(all, ka{k, e.learnedAt})
		}
		sort.Slice(all, func(i, j int) bool { return evictLess(all[i].at, all[i].k, all[j].at, all[j].k) })
		for i := 0; i < len(all) && len(c.active) > target; i++ {
			delete(c.active, all[i].k)
		}
	}
	if len(c.pend) > c.maxPending {
		type kf struct {
			k  string
			at time.Time
		}
		all := make([]kf, 0, len(c.pend))
		for k, p := range c.pend {
			all = append(all, kf{k, p.firstSeen})
		}
		sort.Slice(all, func(i, j int) bool { return evictLess(all[i].at, all[i].k, all[j].at, all[j].k) })
		for i := 0; i < len(all) && len(c.pend) > c.maxPending; i++ {
			delete(c.pend, all[i].k)
		}
	}
}

// List returns a stable, expired-filtered snapshot of active exclusions, sorted
// by learnedAt (newest first) for a predictable UI ordering.
func (c *Cache) List() []Entry {
	now := c.now()
	c.mu.RLock()
	defer c.mu.RUnlock()
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
			Hits:        atomic.LoadInt64(&e.hits),
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
	c.mu.RLock()
	defer c.mu.RUnlock()
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
	c.mu.RLock()
	defer c.mu.RUnlock()
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
	c.mu.RLock()
	defer c.mu.RUnlock()
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
