package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/identcache"
)

// identityResultCache is package main's binding of the identity-backend result
// cache (internal/identcache, ADR-0041) shared by the LDAP directory bind
// (auth_ldap.go), the legacy OIDC introspection backend (auth_oidc.go) and the
// IdP-registry introspection provider (auth_oidc_flow.go). The eviction policy,
// and why it is a security control (CHAOS-76), are documented on the package.
//
// This file is composition only. It supplies the two application dependencies
// the engine takes at construction:
//
//   - the cap, maxAuthCacheSize — the same one the local credential cache in
//     store.go uses;
//   - the eviction sink, which accumulates the process-wide total /metrics
//     exports (identityCacheEvictionsTotal).
//
// The zero value is usable, because every backend embeds one by value and many
// tests build backends as literals: the engine is constructed on first use. All
// methods are safe for concurrent use.
type identityResultCache[T any] struct {
	once sync.Once
	c    *identcache.Cache[T]
}

func (r *identityResultCache[T]) engine() *identcache.Cache[T] {
	r.once.Do(func() {
		r.c = identcache.New[T](identcache.Options{
			MaxEntries: maxAuthCacheSize,
			OnEvict:    noteIdentityCacheEviction,
		})
	})
	return r.c
}

// get returns a live cached verdict; an expired entry is reclaimed and reported
// as absent.
func (r *identityResultCache[T]) get(key string) (val T, ok, hit bool) {
	return r.engine().Get(key)
}

// set records a verdict attributed to client, live for the backend's ttl.
func (r *identityResultCache[T]) set(key, client string, val T, ok bool, ttl time.Duration) {
	r.engine().Set(key, client, val, ok, ttl)
}

// setUntil records a verdict that stops being served at an absolute deadline
// the caller has already computed (see identcache.Cache.SetUntil for why a
// clamped deadline must not be re-derived from a duration).
func (r *identityResultCache[T]) setUntil(key, client string, val T, ok bool, expiry time.Time) {
	r.engine().SetUntil(key, client, val, ok, expiry)
}

// Evictions reports how many cached verdicts this cache has displaced to stay
// under the cap.
func (r *identityResultCache[T]) Evictions() uint64 { return r.engine().Evictions() }

// len reports the number of entries currently held, live or expired.
func (r *identityResultCache[T]) len() int { return r.engine().Len() }

// expiryForTest returns the recorded deadline under key without applying the
// expiry check, for tests that assert ON it (that a positive verdict was
// clamped to the token's own declared lifetime rather than the backend's TTL).
func (r *identityResultCache[T]) expiryForTest(key string) (time.Time, bool) {
	return r.engine().Expiry(key)
}

// identityCacheEvictions is the process-wide displacement total across every
// identityResultCache instance, live or long since replaced. It is what
// /metrics exports. A sum over live instances is not a usable counter: the IdP
// registry compiles a fresh provider, with a fresh zero cache, whenever an
// operator edits a profile, so that sum would FALL, and a Prometheus counter
// that decreases reads as a restart (Codex review, PR #1633).
var identityCacheEvictions atomic.Uint64

// noteIdentityCacheEviction is every binding's OnEvict sink. The engine calls it
// under its own lock, which is why it is a single atomic add.
func noteIdentityCacheEviction() { identityCacheEvictions.Add(1) }

// identityCacheEvictionsTotal reports displacement across every identity
// backend that keeps a result cache — the legacy provider on Config and the
// registry credential providers alike, including instances the registry has
// since retired.
//
// It deliberately does NOT walk idpRegistry. In a registry deployment those
// providers ARE the caches this sweep changed (proxy.go tries them before the
// legacy fallback) and an LDAP registry cutover unwires Config.provider
// entirely, so the counter must cover them — but reading them live made the
// total fall whenever a profile was edited. Accumulating at the point of
// eviction covers both deployments and cannot regress.
func identityCacheEvictionsTotal() uint64 { return identityCacheEvictions.Load() }
