package main

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/geoip"
)

// ---------------------------------------------------------------------------
// GeoIP host resolution + dashboard counters (package main side)
//
// The GeoIP *lookup engine* (MaxMind .mmdb reader + IP→country cache) lives in
// internal/geoip. This file keeps the parts that depend on package main:
//
//   - resolveHost: host → public net.IP, applying the shared SSRF private-range
//     check (isPrivateIP/privateRanges). It stays here because that SSRF backbone
//     is shared by proxy/security/threatfeed/release and must not be forked.
//   - geo: a thin host-based wrapper preserving the LookupFull/Lookup/LookupCached
//     API used by callers (enrollment.go, policy.go, proxy.go), delegating to the
//     internal/geoip engine after resolution.
//   - countryTraffic / activeConns: dashboard/runtime counters, unrelated to the
//     GeoIP engine (deliberately left in main, ADR-0002 option F).
// ---------------------------------------------------------------------------

// lookupHostFn is the DNS-resolution seam used by lookupPublicHostIP. A var
// (not a direct call) so tests can stub the resolver deterministically and
// count invocations; production never reassigns it.
var lookupHostFn = net.LookupHost

// geoTrackEnabledFn is the enabled-probe seam for the per-request geo-track
// dispatch (maybeTrackDestinationCountry, proxy.go): with no GeoIP DB loaded
// the tracker goroutine is never spawned. A var (not a direct call) so tests
// can stub the enabled state without a .mmdb fixture — same pattern as
// lookupHostFn above; production never reassigns it.
var geoTrackEnabledFn = geoip.Enabled

// hostIPCache memoises resolveHost's hostname→public-IP resolutions with a
// TTL. The internal/geoip engine caches IP→country, but before this cache the
// host→IP step in front of it re-ran a BLOCKING net.LookupHost on every call:
// geo.LookupCached sits on the per-request policy hot path (one call per
// country-scoped rule per request when GeoIP is enabled — Go's resolver does
// not cache, so each call was a real getaddrinfo/DNS round-trip), and
// trackDestinationCountry fired one more resolution per allowed request,
// duplicating the lookup the upstream dial performs anyway. With the cache a
// host resolves at most once per TTL window process-wide.
//
// Semantics are unchanged — same results, memoised. GeoIP country attribution
// tolerates a resolution up to hostIPCacheTTL stale (the actual connection is
// dialled through the transport's own resolution, never this one). Failures
// (NXDOMAIN, resolver down, private-only answers) are negative-cached for the
// shorter hostIPCacheNegTTL so a dead host cannot re-block callers on every
// request, while transient resolver brownouts still heal quickly.
//
// The hostname is attacker-controllable (any client can request arbitrarily
// many distinct hosts), so the cache is hard-capped like the engine's geoCache
// and topHosts: at capacity ~10% of entries are evicted arbitrarily — the same
// thrash-avoidance posture as internal/geoip. Cached net.IP values are shared
// across goroutines and must be treated as READ-ONLY by callers (all current
// callers only read: isPrivateIP, ip.String()).
type hostIPCache struct {
	mu      sync.RWMutex
	entries map[string]hostIPEntry
}

type hostIPEntry struct {
	ip     net.IP // nil = negative entry (resolution failed or private-only)
	expiry time.Time
}

const (
	hostIPCacheTTL    = 5 * time.Minute  // positive entries — typical DNS-TTL order
	hostIPCacheNegTTL = 30 * time.Second // negative entries — heal transient failures fast
)

// hostIPCacheMaxEntries bounds the cache. A var (not const) so tests can lower it.
var hostIPCacheMaxEntries = 10_000

var resolvedHostCache = &hostIPCache{entries: map[string]hostIPEntry{}}

func (c *hostIPCache) get(host string) (net.IP, bool) {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	return e.ip, true
}

func (c *hostIPCache) put(host string, ip net.IP) {
	ttl := hostIPCacheTTL
	if ip == nil {
		ttl = hostIPCacheNegTTL
	}
	c.mu.Lock()
	if len(c.entries) >= hostIPCacheMaxEntries {
		// Evict ~10% of entries to avoid thrashing (mirrors internal/geoip's
		// geoCache eviction; one-at-a-time eviction under sustained unique-host
		// load would miss on nearly every insert).
		toEvict := hostIPCacheMaxEntries / 10
		if toEvict == 0 {
			toEvict = 1
		}
		for k := range c.entries {
			delete(c.entries, k)
			toEvict--
			if toEvict <= 0 {
				break
			}
		}
	}
	c.entries[host] = hostIPEntry{ip: ip, expiry: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// resolveHost returns the first public IP for a given host (or parses it
// directly). IP literals never touch the cache or the resolver; hostname
// resolutions are memoised in resolvedHostCache (blocking DNS at most once per
// host per TTL instead of per call). The returned net.IP may be shared with
// other goroutines — callers must not mutate it.
func resolveHost(host string) net.IP {
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if isPrivateIP(ip) {
			return nil
		}
		return ip
	}
	if cached, ok := resolvedHostCache.get(host); ok {
		return cached
	}
	resolved := lookupPublicHostIP(host)
	resolvedHostCache.put(host, resolved)
	return resolved
}

// lookupPublicHostIP is resolveHost's uncached core: resolve the hostname and
// return the first public answer (nil on failure or private-only answers —
// the shared SSRF posture). Concurrent misses for the same host may resolve in
// parallel; last write wins, which is benign (both hold live answers).
func lookupPublicHostIP(host string) net.IP {
	addrs, err := lookupHostFn(host) //nolint:noctx // pre-existing resolver call moved verbatim during the internal/geoip split (ADR-0002); context-aware DNS is a separate, out-of-scope change to this SSRF-adjacent path
	if err != nil || len(addrs) == 0 {
		return nil
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && !isPrivateIP(ip) {
			return ip
		}
	}
	return nil
}

// geoResolver is the host-based GeoIP facade used across package main. It owns
// host→IP resolution (with the SSRF check) and delegates the actual country
// lookup to the internal/geoip engine.
type geoResolver struct{}

// geo preserves the call-site API (geo.LookupFull/Lookup/LookupCached) that
// existed before the engine was extracted to internal/geoip.
var geo = &geoResolver{}

// Lookup returns the two-letter ISO country code for a host ("" on failure or disabled).
func (geoResolver) Lookup(host string) string {
	code, _ := geo.LookupFull(host)
	return code
}

// LookupFull returns the country code and full name for a host.
func (geoResolver) LookupFull(host string) (code, name string) {
	if !geoip.Enabled() {
		return "", ""
	}
	ip := resolveHost(host)
	if ip == nil {
		return "", ""
	}
	return geoip.LookupByIP(ip)
}

// LookupCached returns the country code only if already in the geo cache —
// it never triggers a new geo-DB lookup. Host→IP resolution is memoised in
// resolvedHostCache, so the policy hot path resolves a hostname (blocking DNS)
// at most once per host per TTL rather than on every evaluation.
// Returns ("", false) on cache miss or when GeoIP is disabled.
func (geoResolver) LookupCached(host string) (code string, ok bool) {
	if !geoip.Enabled() {
		return "", false
	}
	ip := resolveHost(host)
	if ip == nil {
		return "", false
	}
	return geoip.LookupCachedByIP(ip)
}

// ---------------------------------------------------------------------------
// Country traffic stats (dashboard)
// ---------------------------------------------------------------------------

type countryTrafficStore struct {
	mu    sync.RWMutex
	stats map[string]int64
	names map[string]string
}

var countryTraffic = &countryTrafficStore{
	stats: make(map[string]int64),
	names: make(map[string]string),
}

var activeConns int64

func recordActiveConn(delta int64) { atomic.AddInt64(&activeConns, delta) }
func getActiveConns() int64        { return atomic.LoadInt64(&activeConns) }

func (s *countryTrafficStore) Record(code, name string) {
	if code == "" {
		return
	}
	s.mu.Lock()
	s.stats[code]++
	if name != "" {
		s.names[code] = name
	}
	s.mu.Unlock()
}

type CountryCount struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func (s *countryTrafficStore) Top(n int) []CountryCount {
	s.mu.RLock()
	out := make([]CountryCount, 0, len(s.stats))
	for code, cnt := range s.stats {
		out = append(out, CountryCount{Code: code, Name: s.names[code], Count: cnt})
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
