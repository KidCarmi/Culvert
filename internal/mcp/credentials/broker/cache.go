package broker

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// maxVersionsPerProfile bounds cache entries per profile (the current version plus
// at most one previous version inside a rotation grace window), which — combined
// with the per-tenant/per-server profile limits — bounds each partition
// deterministically.
const maxVersionsPerProfile = 2

// cacheKey partitions the encrypted cache by tenant, server, profile and version.
// A get for one partition can never return another's entry (capability/tenant/
// server/profile isolation is structural).
type cacheKey struct {
	tenant  identity.TenantID
	server  registry.ServerID
	profile profile.ID
	version profile.CredentialVersion
}

// cacheEntry holds ONLY an encrypted envelope plus non-secret lease metadata. No
// plaintext is ever stored; the envelope is opened into a fresh scoped handle on
// each materialization.
type cacheEntry struct {
	env        []byte // encrypted PSCA envelope (never plaintext)
	kind       profile.CredentialKind
	lease      provider.Lease
	insertedAt time.Time
	expiry     time.Time
	key        cacheKey
}

// cache is a bounded, time-expiring, partitioned encrypted-envelope cache. It holds
// no plaintext, uses an injected clock, evicts deterministically (oldest-inserted
// first), zeroizes evicted envelopes, and fails closed when full. There are no
// per-entry goroutines.
type cache struct {
	mu         sync.Mutex
	lim        limits.CredentialLimits
	now        func() time.Time
	entries    map[cacheKey]*cacheEntry
	order      []cacheKey // insertion order for deterministic eviction
	totalBytes int
	perProfile map[profile.ID]int
}

func newCache(lim limits.CredentialLimits, clk func() time.Time) *cache {
	if clk == nil {
		clk = time.Now
	}
	return &cache{
		lim:        lim,
		now:        clk,
		entries:    make(map[cacheKey]*cacheEntry),
		perProfile: make(map[profile.ID]int),
	}
}

// put stores an encrypted envelope. It enforces the per-envelope byte bound, the
// per-profile version cap, and the global entry/byte bounds (evicting oldest
// entries and zeroizing them to make room). It fails closed (cacheFull) only if no
// room can be reclaimed. A replace of an existing key updates in place.
func (c *cache) put(e *cacheEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(e.env) > c.lim.MaxEnvelopeBytes() {
		return errInvalidMaterial("encrypted envelope exceeds the maximum size")
	}
	// Replace-in-place if the key already exists.
	if old, ok := c.entries[e.key]; ok {
		c.totalBytes -= len(old.env)
		zeroize(old.env)
		c.totalBytes += len(e.env)
		c.entries[e.key] = e
		return nil
	}
	// Per-profile version cap: evict this profile's oldest version if at cap.
	if c.perProfile[e.key.profile] >= maxVersionsPerProfile {
		c.evictOldestForProfile(e.key.profile)
	}
	// Global bounds: evict oldest until there is room for one more entry + bytes.
	guard := 0
	for (len(c.entries) >= c.lim.MaxCacheEntries() || c.totalBytes+len(e.env) > c.lim.MaxCacheBytes()) && len(c.order) > 0 {
		c.evictOldest()
		guard++
		if guard > c.lim.MaxCleanupPerOp() {
			break
		}
	}
	if len(c.entries) >= c.lim.MaxCacheEntries() || c.totalBytes+len(e.env) > c.lim.MaxCacheBytes() {
		return errCacheFull("encrypted cache is full and no room could be reclaimed")
	}
	c.entries[e.key] = e
	c.order = append(c.order, e.key)
	c.totalBytes += len(e.env)
	c.perProfile[e.key.profile]++
	return nil
}

// get returns a live (unexpired) entry for key. An expired entry is removed and
// zeroized, and (nil,false) returned (a miss).
func (c *cache) get(key cacheKey) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.expiry) {
		c.remove(key)
		return nil, false
	}
	return e, true
}

// invalidateProfile removes and zeroizes every entry for a profile (revocation).
func (c *cache) invalidateProfile(id profile.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		if key.profile == id {
			c.remove(key)
		}
	}
}

// invalidateVersion removes and zeroizes a single (profile,version) entry family.
func (c *cache) invalidateVersion(id profile.ID, v profile.CredentialVersion) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		if key.profile == id && key.version == v {
			c.remove(key)
		}
	}
}

// size returns the entry count (tests/metrics).
func (c *cache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// evictOldest removes the oldest-inserted live entry. Caller holds mu.
func (c *cache) evictOldest() {
	for len(c.order) > 0 {
		key := c.order[0]
		c.order = c.order[1:]
		if _, ok := c.entries[key]; ok {
			c.removeKeepOrder(key)
			return
		}
	}
}

// evictOldestForProfile removes the oldest entry belonging to a profile.
func (c *cache) evictOldestForProfile(id profile.ID) {
	for _, key := range c.order {
		if key.profile == id {
			if _, ok := c.entries[key]; ok {
				c.remove(key)
				return
			}
		}
	}
}

// remove deletes an entry, zeroizes its envelope, and fixes counters + order.
func (c *cache) remove(key cacheKey) {
	c.removeKeepOrder(key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

// removeKeepOrder deletes an entry and fixes counters without scanning order (the
// caller has already advanced/pruned order).
func (c *cache) removeKeepOrder(key cacheKey) {
	e, ok := c.entries[key]
	if !ok {
		return
	}
	c.totalBytes -= len(e.env)
	zeroize(e.env)
	delete(c.entries, key)
	if c.perProfile[key.profile] > 0 {
		c.perProfile[key.profile]--
		if c.perProfile[key.profile] == 0 {
			delete(c.perProfile, key.profile)
		}
	}
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
