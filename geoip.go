package main

import (
	"context"
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
//
// CHAOS-57 made the seam CONTEXT-AWARE. It used to be `net.LookupHost`, whose
// only bound is the operating system's — `resolv.conf` ships `timeout:5
// attempts:2` per nameserver, so a wedged resolver held the request goroutine
// for 10 s+ and, with a multi-nameserver configuration, considerably longer.
// This call sits on the policy hot path (geo.LookupCached, one call per
// DestCountry rule per request), so that budget is spent while holding a client
// connection and a per-IP connection-limiter slot.
var lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

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

	// inflight single-flights resolutions per host. Guarded by mu.
	//
	// Without it, concurrent misses for the SAME host each ran their own
	// resolution — measured 200 resolver invocations for 200 concurrent
	// requests to one host (CHAOS-57). During a resolver brownout that is one
	// blocked request goroutine per request AND one query per request aimed at
	// the resolver that is already failing: the WK-13 herd, pointed at the
	// customer's own DNS at the moment it is least able to answer. It is also
	// what made the negative cache useless as a shock absorber — a negative
	// entry is only written when a resolution COMPLETES, so during an outage
	// every request kept missing for the full length of the outage.
	inflight map[string]*hostIPFlight
}

// hostIPFlight is one in-progress resolution. Followers wait on done and read
// ip afterwards; ip is written by the leader before done is closed, so the
// close/receive pair is the happens-before edge.
type hostIPFlight struct {
	done chan struct{}
	ip   net.IP
}

type hostIPEntry struct {
	ip     net.IP // nil = negative entry (resolution failed or private-only)
	expiry time.Time
}

const (
	hostIPCacheTTL    = 5 * time.Minute  // positive entries — typical DNS-TTL order
	hostIPCacheNegTTL = 30 * time.Second // negative entries — heal transient failures fast

	// hostIPCacheStaleMax is how long PAST its expiry an entry may still be
	// SERVED, while a refresh runs behind it (stale-while-revalidate).
	//
	// Before CHAOS-57 an expired entry was discarded outright, which made the
	// first expiry during a resolver outage a synchronized stampede: every
	// popular host went cold within the same 5-minute window, every request
	// blocked on a resolver that could not answer, and geo.LookupCached started
	// returning ("", false). A DestCountry rule that does not match is SKIPPED
	// and evaluation continues to lower-priority rules, so a "block sanctioned
	// countries" rule silently stopped enforcing while a broad allow rule
	// beneath it took over. Serving the last known address instead is strictly
	// better on every axis that matters here: the address is used ONLY for
	// country attribution (the actual connection is dialled through the
	// transport's own resolution, never this one), an IP's country changes on a
	// timescale of months, and the alternative is not a fresher answer but NO
	// answer.
	//
	// Bounded at an hour so a decommissioned host cannot keep a stale country
	// forever, and so the degradation has a stated horizon an operator can plan
	// against rather than an open-ended one.
	hostIPCacheStaleMax = 1 * time.Hour

	// dnsResolveTimeout bounds ONE resolution attempt.
	//
	// Two seconds, against an OS default of 5 s × attempts × nameservers. The
	// call is on the request goroutine inside the policy scan, so the budget is
	// what a client pays for a cache miss; a resolver that has not answered a
	// cached-elsewhere destination in two seconds is not about to make the
	// request fast. Recovery does not depend on this value being generous —
	// stale-serving covers every host seen in the last hour, and a genuine
	// first-contact miss retries on the next request.
	//
	// Caveat, honestly stated: with the cgo resolver Go cannot cancel an
	// in-flight getaddrinfo, so the deadline bounds OUR wait, not the OS thread
	// behind it. That thread is bounded instead by the Go runtime's own 500-
	// thread cap on cgo lookups. The pure-Go resolver honours the deadline
	// fully. Either way the request goroutine is released on time, which is the
	// property this bound exists to provide.
	dnsResolveTimeout = 2 * time.Second
)

// hostIPCacheMaxEntries bounds the cache. A var (not const) so tests can lower it.
var hostIPCacheMaxEntries = 10_000

// dnsResolveSem bounds concurrent resolutions process-wide.
//
// Single-flight collapses a herd on ONE host; it does nothing about a herd
// across MANY hosts, and the hostname is attacker-controllable — any client can
// ask this proxy for arbitrarily many distinct destinations. Without a bound, a
// scanning client during a resolver brownout creates one blocked goroutine per
// distinct host, each holding a request, a connection and a connection-limiter
// slot, and each firing its own query at the failing resolver.
//
// On saturation the resolution is SHED immediately rather than queued: a queue
// here would just relocate the pileup, and the caller's fallback (no country,
// rule does not match) is the same one it already takes on a cache miss. The
// shed result is deliberately NOT cached — saturation is a fact about this
// node's load, not about the host, and caching it would let a transient
// overload suppress resolution of a legitimate destination for a full TTL.
//
// A var (not const) so tests can shrink the pool; production never reassigns it.
var dnsResolveSem = make(chan struct{}, 64)

var resolvedHostCache = &hostIPCache{
	entries:  map[string]hostIPEntry{},
	inflight: map[string]*hostIPFlight{},
}

// hostIPState classifies a cache probe.
type hostIPState int

const (
	hostIPMiss  hostIPState = iota // absent, or stale beyond the serving ceiling
	hostIPFresh                    // inside its TTL
	hostIPStale                    // expired but inside hostIPCacheStaleMax
)

func (c *hostIPCache) lookup(host string, now time.Time) (net.IP, hostIPState) {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	switch {
	case !ok:
		return nil, hostIPMiss
	case now.Before(e.expiry):
		return e.ip, hostIPFresh
	case now.Before(e.expiry.Add(hostIPCacheStaleMax)):
		return e.ip, hostIPStale
	}
	return nil, hostIPMiss
}

func (c *hostIPCache) put(host string, ip net.IP) {
	now := time.Now()
	ttl := hostIPCacheTTL
	if ip == nil {
		ttl = hostIPCacheNegTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// A failed resolution must NOT destroy a still-servable positive answer.
	// During a resolver outage the stale address is the only thing keeping
	// geo-scoped rules matching, and a negative entry would then be served as
	// FRESH for the negative TTL — taking geo dark for exactly the window the
	// stale answer existed to cover, and doing it as a side effect of the
	// background refresh that was supposed to help. The positive entry ages out
	// on its own once it passes hostIPCacheStaleMax, at which point a negative
	// result is written normally.
	if ip == nil {
		if e, ok := c.entries[host]; ok && e.ip != nil && now.Before(e.expiry.Add(hostIPCacheStaleMax)) {
			return
		}
	}

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
	c.entries[host] = hostIPEntry{ip: ip, expiry: now.Add(ttl)}
}

// joinFlight registers this caller against the in-progress resolution for host,
// creating one if none exists. leader is true for the caller that must perform
// the resolution and finish the flight.
func (c *hostIPCache) joinFlight(host string) (fl *hostIPFlight, leader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fl, ok := c.inflight[host]; ok {
		return fl, false
	}
	fl = &hostIPFlight{done: make(chan struct{})}
	c.inflight[host] = fl
	return fl, true
}

// finishFlight publishes the leader's result and releases the followers. It
// must run on every leader exit path, including the shed and panic paths —
// otherwise followers block forever on a flight nobody will complete, which
// would convert a bounded resolver fault into a permanent request-plane hang.
func (c *hostIPCache) finishFlight(host string, fl *hostIPFlight, ip net.IP) {
	c.mu.Lock()
	if c.inflight[host] == fl {
		delete(c.inflight, host)
	}
	c.mu.Unlock()
	fl.ip = ip
	close(fl.done)
}

// resolveHost returns the first public IP for a given host (or parses it
// directly). IP literals never touch the cache or the resolver.
//
// The contract, in order of how often each branch is taken:
//
//   - FRESH cache entry → returned immediately. Unchanged.
//   - STALE entry (expired, within hostIPCacheStaleMax) → returned immediately
//     and a bounded background refresh is kicked off. The request goroutine
//     NEVER blocks for a host that has been resolved in the last hour, whatever
//     the resolver is doing.
//   - MISS → one bounded, single-flighted resolution. Concurrent callers for
//     the same host wait on the leader (so they inherit its deadline rather
//     than each starting their own); callers for other hosts contend for the
//     bounded resolver pool and are shed when it is full.
//
// The returned net.IP may be shared with other goroutines — callers must not
// mutate it.
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

	cached, state := resolvedHostCache.lookup(host, time.Now())
	switch state {
	case hostIPFresh:
		return cached
	case hostIPStale:
		resolvedHostCache.refreshAsync(host)
		noteDNSStaleServed()
		return cached
	}
	return resolvedHostCache.resolveBlocking(host)
}

// resolveBlocking performs a single-flighted, pool-bounded, deadline-bounded
// resolution for a host with no servable cache entry.
func (c *hostIPCache) resolveBlocking(host string) net.IP {
	fl, leader := c.joinFlight(host)
	if !leader {
		// Followers inherit the leader's deadline: the leader is bounded by
		// dnsResolveTimeout (or sheds immediately), so this wait is bounded by
		// construction and needs no timer of its own. A timer here would be
		// worse than useless — it would release the follower to start a SECOND
		// resolution for the same host, which is the herd this collapses.
		<-fl.done
		return fl.ip
	}

	// finishFlight is deferred, not called on each exit path, because a panic
	// inside the resolution would otherwise leave followers blocked forever on
	// a flight nobody completes — converting a bounded resolver fault into a
	// permanent request-plane hang that no recover() upstream can undo.
	var ip net.IP
	defer func() { c.finishFlight(host, fl, ip) }()

	select {
	case dnsResolveSem <- struct{}{}:
	default:
		noteDNSResolveShed()
		return nil
	}
	defer func() { <-dnsResolveSem }()

	ip = lookupPublicHostIP(host)
	c.put(host, ip)
	return ip
}

// refreshAsync starts a background refresh for a stale host, at most one per
// host at a time and only when the resolver pool has room.
//
// The goroutine carries recoverGoroutine for the CHAOS-24 reason: it is
// detached, so no request-plane recover reaches it, and a panic here would kill
// an in-line security appliance over a cache refresh.
func (c *hostIPCache) refreshAsync(host string) {
	fl, leader := c.joinFlight(host)
	if !leader {
		return // a resolution for this host is already running
	}
	go func() {
		var ip net.IP
		// Registered FIRST so it runs LAST: on a panic the flight must be
		// finished (followers released) before the recover swallows it.
		// recoverGoroutine has to be its own defer statement — recover() only
		// returns non-nil when called directly by a deferred function.
		defer recoverGoroutine("dns-refresh")
		defer func() { c.finishFlight(host, fl, ip) }()

		select {
		case dnsResolveSem <- struct{}{}:
		default:
			noteDNSResolveShed()
			return
		}
		defer func() { <-dnsResolveSem }()

		ip = lookupPublicHostIP(host)
		c.put(host, ip)
	}()
}

// lookupPublicHostIP is the uncached, observed core: resolve the hostname under
// a bounded deadline and return the first public answer (nil on failure or
// private-only answers — the shared SSRF posture).
//
// Every outcome is charged to the health record (dns_health.go), because before
// CHAOS-57 a total resolution outage on this path was counted nowhere, logged
// nowhere and alerted nowhere: geo-scoped policy simply stopped matching while
// every probe stayed green.
func lookupPublicHostIP(host string) net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
	defer cancel()

	addrs, err := lookupHostFn(ctx, host)
	if err != nil {
		reason := classifyDNSFailure(ctx, err)
		if noteDNSResolveFailure(reason, time.Now()) {
			// The full error goes here and nowhere else — it embeds the queried
			// hostname, which is attacker-chosen, so it must not reach the alert
			// dedup key or the viewer-role contract row.
			logger.Printf("DNS resolution failed for %q (reason: %s): %v", sanitizeLog(host), reason, err)
		}
		return nil
	}
	if len(addrs) == 0 {
		// An empty successful answer is a working resolver reporting no
		// addresses; treat it as the private-only case, not as a fault.
		if suppressed := noteDNSNoPublicAnswer(); suppressed > 0 {
			logger.Printf("DNS resolution recovered (%d failure log lines suppressed during the outage)", suppressed)
		}
		return nil
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && !isPrivateIP(ip) {
			if suppressed := noteDNSResolveOK(); suppressed > 0 {
				logger.Printf("DNS resolution recovered (%d failure log lines suppressed during the outage)", suppressed)
			}
			return ip
		}
	}
	// Answered, but every address was private. The resolver is HEALTHY — on a
	// split-horizon estate this is the common case — so it clears a failure
	// episode exactly like a public answer does.
	if suppressed := noteDNSNoPublicAnswer(); suppressed > 0 {
		logger.Printf("DNS resolution recovered (%d failure log lines suppressed during the outage)", suppressed)
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
