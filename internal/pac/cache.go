package pac

// cache.go — compiled-artifact cache (Palo fleet review, perf/security
// BLOCKER). /proxy.pac and /pac/{id}.pac are unauthenticated and were
// recompiling a ~1 MB artifact (≈38 ms, ≈16 MB alloc at the exclusion cap)
// on EVERY request — a compute/allocation amplifier on the same process that
// relays tunnels. The compiled artifact is deterministic and the stores
// already track a mod-time, so a mod-time-keyed cache turns the steady state
// into a map read; 304 revalidations become free.
//
// Host-fallback artifacts (ProxyHost unset) vary per request Host and are
// NOT cached — see ArtifactCache.Legacy. Configuring an explicit ProxyHost
// (the enterprise norm) makes the legacy PAC cacheable.

import (
	"sync"
	"time"
)

// ArtifactCache memoizes compiled PAC artifacts keyed on the owning store's
// ModTime. The zero value is a ready, empty cache.
type ArtifactCache struct {
	mu       sync.Mutex
	legacy   *Artifact
	legacyAt time.Time
	profiles map[string]profileCacheEntry
	profAt   time.Time
}

type profileCacheEntry struct {
	art Artifact
}

// Legacy returns the compiled default-profile artifact, recompiling only when
// the store changed. Fallback-mode artifacts (HostFallback) are never cached
// (they embed the per-request host); the caller compiles those directly.
func (c *ArtifactCache) Legacy(s *Store, fallbackAddr string) Artifact {
	mt := s.ModTime()
	c.mu.Lock()
	if c.legacy != nil && c.legacyAt.Equal(mt) {
		hit := *c.legacy
		c.mu.Unlock()
		return hit
	}
	c.mu.Unlock()

	art := s.Compile(fallbackAddr)
	if art.HostFallback {
		return art // per-host body: do not cache
	}
	c.mu.Lock()
	c.legacy = &art
	c.legacyAt = mt
	c.mu.Unlock()
	return art
}

// Profile returns the compiled artifact for one profile, recompiling the
// whole profile map only when the profile store changed. A store mutation
// invalidates all cached profiles at once (coarse but correct; profile
// mutations are admin-rate).
func (c *ArtifactCache) Profile(s *ProfileStore, p Profile) Artifact {
	mt := s.ModTime()
	c.mu.Lock()
	if !c.profAt.Equal(mt) {
		c.profiles = nil
		c.profAt = mt
	}
	if e, ok := c.profiles[p.ID]; ok {
		c.mu.Unlock()
		return e.art
	}
	c.mu.Unlock()

	art := CompileProfile(p, s.PoolMap())
	c.mu.Lock()
	if !c.profAt.Equal(mt) { // store changed under us — drop this compile
		c.mu.Unlock()
		return art
	}
	if c.profiles == nil {
		c.profiles = make(map[string]profileCacheEntry)
	}
	c.profiles[p.ID] = profileCacheEntry{art: art}
	c.mu.Unlock()
	return art
}
