package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// CHAOS-60 — the GeoIP resolution warmer and its health plane
//
// The per-request policy path (matchDestNorm → geo.LookupCached) must answer
// from cache only: it runs inside the request goroutine, holds the client
// connection and a per-IP connection slot while it runs, and has no deadline
// of its own. Filling those caches is therefore someone else's job, and this
// file is that someone.
//
// Three properties are load-bearing and must not be relaxed:
//
//  1. BOUNDED. net.LookupHost takes no context, so one resolution can run to
//     the system resolver's full budget (resolv.conf timeout × attempts ×
//     nameservers — commonly 10–40 s on a blackholed resolver). The bound is a
//     semaphore with DROP-ON-FULL, never a queue: a queue converts a resolver
//     outage into unbounded memory and unbounded staleness, whereas a drop
//     costs one host one warm window and is counted.
//
//     Deliberately NOT a context deadline. Under the cgo resolver a cancelled
//     lookup returns to the caller while the OS thread stays blocked in
//     getaddrinfo, so a deadline would release the semaphore slot without
//     releasing the thread — converting a bounded goroutine pool into an
//     unbounded thread pool, which is worse than the fault it treats. Holding
//     the slot for the TRUE duration of the call is what makes the bound real.
//
//  2. SINGLE-FLIGHTED, AND CLAIMED BEFORE A SLOT IS TAKEN. resolvedHostCache
//     collapses concurrent misses for one host into one resolution, and the
//     warmer reserves the host SYNCHRONOUSLY — before it consumes a pool slot
//     or spawns anything — so N concurrent callers for one host cost exactly
//     one slot. Without the single-flight, a reconnect storm against one host
//     multiplies into one DNS query per request; without the ORDER, it instead
//     multiplies into one held pool slot per request, which starves every
//     other host's warm just as effectively (see warmGeoHost).
//
//  3. OBSERVABLE. A dropped warm means a country-scoped rule did not enforce
//     on that request. That is a security-relevant degradation, so it is
//     counted, exported, and logged on onset — never silent.
// ---------------------------------------------------------------------------

// geoWarmConcurrency bounds resolutions in flight for the policy warmer. It is
// deliberately far below the tracker's 256: the tracker samples every allowed
// request, while the warmer fires only on a cache MISS for a host a
// country-scoped rule actually asked about, and each slot can be held for tens
// of seconds by a blackholed resolver.
const geoWarmConcurrency = 64

// geoWarmLogInterval rate-limits the saturation log line: the FIRST drop of an
// episode logs immediately, then at most one line per interval, then one
// recovery line naming the count the gate suppressed. Same discipline as the
// SOCKS5 accept loop (socks5_health.go) — signal in the log, magnitude in the
// counter.
const geoWarmLogInterval = time.Minute

var geoWarmSem = make(chan struct{}, geoWarmConcurrency)

// geoWarmHook, when non-nil, is invoked as each warm goroutine exits (both the
// completed and the dropped path). Test-only, so a test can join the
// goroutines it caused; nil in production, where the only cost is one pointer
// compare off the request path.
var geoWarmHook func()

var geoWarm struct {
	started    atomic.Int64 // warms actually spawned
	inflight   atomic.Int64 // warm goroutines currently running
	dropped    atomic.Int64 // warms refused because the pool was saturated
	failed     atomic.Int64 // warms whose resolution yielded no usable public IP
	unresolved atomic.Int64 // country-rule evaluations that fell through on an unknown country

	mu         sync.Mutex
	logAt      time.Time
	suppressed int64
	saturated  bool
}

// warmGeoHost arms an off-path resolution + country lookup for host so that a
// later evaluation of a country-scoped rule can answer from cache.
//
// It never blocks the caller. THE PER-HOST RESERVATION IS TAKEN BEFORE A SLOT
// IS CONSUMED, and that order is the load-bearing part (Codex P1 against the
// first version of this fix). The first shape pre-CHECKED whether the host was
// already being resolved and left the actual claim to the spawned goroutine,
// which registers it inside resolveHost. Concurrent evaluations for one
// uncached hostname — the reconnect-storm shape this change exists to survive
// — therefore all passed the check, all took a slot, and all but one parked as
// followers holding those slots for the resolver's full delay. One popular
// destination could drain the pool, so unrelated hosts had their warms dropped
// and their country rules left unresolved: the degradation this whole change
// fixes, re-entered through its own fix. Claiming first means N callers for
// one host cost exactly one slot, and the other N-1 return having touched
// nothing.
func warmGeoHost(host string) {
	key := geoHostKey(host)

	// An IP literal has no host half to resolve — only the country half can be
	// missing. Mirrors resolveHost/resolveHostCached so all three agree.
	if lit := net.ParseIP(key); lit != nil {
		if !isPrivateIP(lit) {
			spawnGeoWarm(func() { geoLookupIPFn(lit) })
		}
		return
	}

	// A servable entry (fresh OR stale-within-ceiling) means the address is
	// known; only the country half can be missing. resolveHost owns the stale
	// refresh — a warm must not start a second one.
	if cached, state, _ := resolvedHostCache.lookup(key, time.Now()); state != hostIPMiss {
		if cached != nil {
			spawnGeoWarm(func() { geoLookupIPFn(cached) })
		}
		return
	}

	fl, leader := resolvedHostCache.joinFlight(key)
	if !leader {
		// Another resolution already owns this host. Returning costs nothing;
		// waiting would cost a warm slot to do nothing.
		return
	}
	warmGeoResolve(key, fl)
}

// warmGeoResolve performs the resolution this caller was elected to lead, on
// the bounded pool, and hands the claim back if it never gets to run.
func warmGeoResolve(key string, fl *hostIPFlight) {
	spawned := spawnGeoWarm(func() {
		// finishFlight is idempotent, so this can never double-publish over
		// resolveAsFlightLeader's own deferred publish. It is here so that a
		// panic BEFORE resolveAsFlightLeader is entered cannot strand the claim
		// — a stranded claim blocks every later caller for this host forever.
		defer resolvedHostCache.finishFlight(key, fl, nil)
		ip := resolveAsFlightLeader(key, fl)
		if ip == nil {
			geoWarm.failed.Add(1)
			return
		}
		// Populates the IP→country cache that the policy path reads. The
		// return value is deliberately discarded — the cache write is the
		// whole point of the call.
		geoLookupIPFn(ip)
	})
	if !spawned {
		// Saturated: this warm is not going to happen, so hand the claim back
		// and release anyone who attached to it. Deliberately WITHOUT a cache
		// write — nothing was learned, and a negative entry would suppress the
		// retry for a full TTL over a transient pool shortage.
		resolvedHostCache.finishFlight(key, fl, nil)
	}
}

// spawnGeoWarm runs fn on the bounded, drop-on-full warm pool and reports
// whether it was admitted. A refused warm is counted and surfaced; it is never
// queued.
func spawnGeoWarm(fn func()) bool {
	// Capture the semaphore rather than reading the global again on release:
	// a slot must always be returned to the channel it was taken from, so a
	// goroutine outliving a swap of geoWarmSem cannot release into a channel
	// it never acquired.
	sem := geoWarmSem
	select {
	case sem <- struct{}{}:
	default:
		geoWarm.dropped.Add(1)
		noteGeoWarmSaturated()
		if h := geoWarmHook; h != nil {
			h()
		}
		return false
	}
	geoWarm.started.Add(1)
	geoWarm.inflight.Add(1)
	go func() {
		defer geoWarm.inflight.Add(-1)
		defer func() { <-sem }()
		if h := geoWarmHook; h != nil {
			defer h()
		}
		// Detached goroutine: no request-plane recover reaches here, and a
		// panic in the resolver seam must cost one warm, not the process.
		defer recoverGoroutine("geo-warm")
		noteGeoWarmProgress()
		fn()
	}()
	return true
}

// noteGeoCountryUnresolved records one country-scoped rule evaluation that
// could not be decided because the destination's country was unknown. The rule
// did NOT match (fail-closed), so on an allow-rule this is a user-visible
// block and on a deny-rule it is traffic that fell through to a lower-priority
// rule — either way it is the operator's only signal that a geo rule is
// evaluating against an unknown country. Hot path: one atomic add, no alloc,
// on the miss branch only.
func noteGeoCountryUnresolved() { geoWarm.unresolved.Add(1) }

// noteGeoWarmSaturated logs the onset of a saturation episode and rate-limits
// the rest of it.
func noteGeoWarmSaturated() {
	geoWarm.mu.Lock()
	now := time.Now()
	first := !geoWarm.saturated
	geoWarm.saturated = true
	if !first && now.Sub(geoWarm.logAt) < geoWarmLogInterval {
		geoWarm.suppressed++
		geoWarm.mu.Unlock()
		return
	}
	suppressed := geoWarm.suppressed
	geoWarm.suppressed = 0
	geoWarm.logAt = now
	geoWarm.mu.Unlock()

	if first {
		logger.Printf("GeoIP: resolution pool saturated (%d in flight) — country-scoped policy rules will not match hosts whose country is not yet cached", geoWarmConcurrency)
		return
	}
	logger.Printf("GeoIP: resolution pool still saturated — %d further warm requests dropped since the last line", suppressed)
}

// noteGeoWarmProgress clears the saturation state on OBSERVED evidence (a warm
// that actually got a slot), never on elapsed time — the same recovery
// discipline as storage_health.go and socks5_health.go.
func noteGeoWarmProgress() {
	geoWarm.mu.Lock()
	if !geoWarm.saturated {
		geoWarm.mu.Unlock()
		return
	}
	geoWarm.saturated = false
	suppressed := geoWarm.suppressed
	geoWarm.suppressed = 0
	geoWarm.mu.Unlock()
	logger.Printf("GeoIP: resolution pool recovered (%d warm requests were dropped while saturated)", suppressed)
}

// geoResolveHealth is the read model for /metrics and the diagnostics surface.
type geoResolveHealth struct {
	Started    int64
	Dropped    int64
	Failed     int64
	Unresolved int64
	Saturated  bool
	InFlight   int64
}

func geoResolveState() geoResolveHealth {
	geoWarm.mu.Lock()
	saturated := geoWarm.saturated
	geoWarm.mu.Unlock()
	return geoResolveHealth{
		Started:    geoWarm.started.Load(),
		Dropped:    geoWarm.dropped.Load(),
		Failed:     geoWarm.failed.Load(),
		Unresolved: geoWarm.unresolved.Load(),
		Saturated:  saturated,
		InFlight:   geoWarm.inflight.Load(),
	}
}

// swapGeoWarmSemForTest replaces the warm semaphore with a private one of
// capacity n and returns a restore func. Test support only: it gives a test
// that deliberately saturates the pool a channel no other test's in-flight
// goroutine can drain. Warms already running keep their own captured channel.
func swapGeoWarmSemForTest(n int) func() {
	orig := geoWarmSem
	geoWarmSem = make(chan struct{}, n)
	return func() { geoWarmSem = orig }
}

// checkGeoResolution is the `geo_resolution` operator-contract row (CHAOS-60).
//
// Before this check existed, the ONLY way an operator could see that
// country-scoped policy rules were failing to converge — culvert_geo_
// policy_unresolved_total climbing, or the warm pool saturated — was
// scraping the raw /metrics text endpoint or reading the process log; a rule
// silently not matching read identically to "no traffic matched this rule"
// from the admin UI. This adds the same evidence to GET /api/diagnostics,
// which the Diagnostics panel already renders generically, so a node whose
// country rules have stopped enforcing shows a warning without any curl.
//
// Severity policy mirrors checkDNSResolution() (dns_health.go), the sibling
// half of the same CHAOS-60 warmer, including its "never used → ok" shape:
// a permanent row would be noise on an appliance with no GeoIP database or
// no destination-country rules, and both postures leave Started/Unresolved
// at zero forever, which is indistinguishable from "not yet exercised" —
// exactly the message below.
//   - saturated now, or unresolved evaluations outnumber completed warms →
//     warn, never fail. The gateway is still proxying every request; what is
//     degraded is geo-scoped policy MATCHING, not the data plane.
//   - otherwise → ok, carrying the cumulative counts so a past saturation
//     episode stays visible after recovery.
func checkGeoResolution() OperatorContractCheck {
	gr := geoResolveState()
	if gr.Saturated {
		return OperatorContractCheck{
			Code:   "geo_resolution",
			Status: diagWarn,
			Message: fmt.Sprintf("GeoIP resolution warm pool is saturated (%d in flight, %d warms dropped since startup) — country-scoped policy rules are not matching hosts whose country is not yet cached",
				gr.InFlight, gr.Dropped),
			OperatorAction: "More distinct destination hosts are being asked about than the resolver pool can keep up with, usually because DNS is slow or a scanning/beaconing source is active. Traffic is still proxied; country-scoped rules stop matching new hosts until the pool recovers.",
		}
	}
	if gr.Unresolved > 0 && gr.Started > 0 && gr.Unresolved >= gr.Started {
		return OperatorContractCheck{
			Code:   "geo_resolution",
			Status: diagWarn,
			Message: fmt.Sprintf("Country-scoped policy rules are evaluating against an unknown country as often as hosts are being resolved (%d unresolved evaluations, %d warms started, %d dropped) — enforcement does not appear to be converging",
				gr.Unresolved, gr.Started, gr.Dropped),
			OperatorAction: "Check this node's DNS resolver reachability and whether the warm pool is dropping (culvert_geo_warm_dropped_total). A low, steady rate of unresolved evaluations is expected (one per host per cache lifetime); a rate tracking request volume means country rules are effectively not matching.",
		}
	}
	if gr.Started == 0 && gr.Unresolved == 0 {
		return OperatorContractCheck{
			Code:    "geo_resolution",
			Status:  diagOK,
			Message: "No destination-country policy resolution performed (no GeoIP database loaded, or no destination-country rules in use)",
		}
	}
	return OperatorContractCheck{
		Code:   "geo_resolution",
		Status: diagOK,
		Message: fmt.Sprintf("GeoIP destination-country policy resolution healthy (%d warms started, %d dropped, %d failed, %d unresolved evaluations since startup)",
			gr.Started, gr.Dropped, gr.Failed, gr.Unresolved),
	}
}

// resetGeoResolveHealthForTest isolates the process-global warm record between
// tests. Test support only.
func resetGeoResolveHealthForTest() {
	geoWarm.started.Store(0)
	geoWarm.dropped.Store(0)
	geoWarm.failed.Store(0)
	geoWarm.unresolved.Store(0)
	geoWarm.mu.Lock()
	geoWarm.logAt = time.Time{}
	geoWarm.suppressed = 0
	geoWarm.saturated = false
	geoWarm.mu.Unlock()
}
