package main

// dns_health.go — CHAOS-57: destination-host DNS resolution on the policy path.
//
// Why this file exists.
//
// `geo.LookupCached` runs inside `matchDestNorm` (policy.go), on the REQUEST
// goroutine, once per enabled access rule carrying a `DestCountry`. Behind it
// sits `resolveHost` → `lookupPublicHostIP` → the system resolver. Before
// CHAOS-57 that call had no deadline, no single-flight and no concurrency
// bound, and its failures were counted nowhere.
//
// Three consequences, each reproduced against the pre-fix tree
// (`dns_resolve_chaos_test.go`):
//
//  1. **No deadline.** A wedged resolver blocked the request goroutine for the
//     OS budget — `resolv.conf` ships `timeout:5 attempts:2` per nameserver, so
//     10 s+ is ordinary and 40 s is reachable. That goroutine is holding a
//     client connection, a per-IP `internal/connlimit` slot and a policy scan.
//
//  2. **No single-flight.** Concurrent misses for the SAME host each ran their
//     own resolution: measured 200 resolver invocations for 200 concurrent
//     requests to one host. During a resolver brownout that is one blocked
//     goroutine per request AND one query per request aimed at the resolver
//     that is already failing — the WK-13 herd, pointed at the customer's own
//     DNS infrastructure at the moment it is least able to answer.
//
//  3. **No stale serving.** An expired entry was discarded outright, so the
//     first cache expiry during an outage took every popular host cold at once
//     and `LookupCached` started returning `("", false)`. A `DestCountry`
//     rule that does not match is skipped, and evaluation CONTINUES to lower
//     priority rules — so a "block sanctioned countries" rule silently stops
//     enforcing while a broad allow rule beneath it takes over. Geo blocking
//     goes dark, with a green dashboard, on a DNS outage. That is the register's
//     §1 silent-fail-open theme reached through the resolver.
//
// What this file provides is the observability half; the resolver itself is in
// geoip.go. The posture half — that an unresolvable host cannot match a geo
// rule in EITHER direction — is deliberately unchanged and recorded as a
// residual risk (see `docs/operator/dns-resolution-health.md`): making an
// unknown country match a block rule would deny every host this node cannot
// resolve, which trades a bounded security gap for an unbounded availability
// one. The fix here is to make the dark window as small as possible (a host
// resolved in the last hour never goes dark at all) and to make it LOUD.
//
// Surfaces, all reusing existing operator vocabulary:
//
//   - `/api/diagnostics` — the `dns_resolution` operator-contract row.
//   - `/metrics` — culvert_dns_resolve_* (see metrics.go).
//   - alerts — the EXISTING `dns_failure` event with Source "policy". A new
//     event name would be silently unsubscribed on every already-configured
//     webhook (the cluster-CA `cert_expiry` precedent), and an operator paging
//     on "this gateway cannot resolve destinations" wants one signal, not two.
//
// Deliberately NOT on `/readyz`. A resolver outage is fleet-wide by
// construction — every node shares the customer's DNS — so failing readiness
// would eject the ENTIRE fleet from the load balancer simultaneously over a
// dependency none of them can fix by being restarted. That is the same rule the
// `ca` and `cluster_ca` rows already follow.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// dnsResolveLogInterval rate-limits the resolution-failure log line. The
	// FIRST failure of an episode is always logged (an operator must see the
	// onset), then at most one line per interval, then one recovery line
	// carrying the suppressed count. Same discipline as storage_health.go and
	// socks5_health.go, and for the same reason: the fault repeats at request
	// rate, so the log carries the SIGNAL and the counter carries the MAGNITUDE.
	//
	// It matters more here than on the SOCKS5 path. `internal/logsink` BLOCKS a
	// producer on a full queue, and `handleRequest` writes one POLICY_* line per
	// proxied request through that same sink, so an ungated per-request log line
	// during a resolver outage would add latency to every request on the node —
	// the CHAOS-54 amplification, reached from the request path instead of an
	// accept loop.
	dnsResolveLogInterval = 30 * time.Second

	// dnsResolveDegradedAfter is how long an uninterrupted run of resolution
	// failures must persist before the resolver is reported DEGRADED (warn row,
	// alert, gauge).
	//
	// A DURATION, not a count, for the socks5_health.go reason: a gateway can
	// see thousands of NXDOMAIN answers a minute from ordinary client typos and
	// beaconing malware, so any count threshold pages on healthy traffic. Sixty
	// seconds in which NOT ONE resolution succeeded is a different statement —
	// on a busy gateway that is a resolver that has stopped answering, not a run
	// of bad hostnames.
	dnsResolveDegradedAfter = 60 * time.Second
)

// dnsResolveHealth is the process-wide record of destination-host resolution.
// Mutex-guarded rather than atomic-per-field because every reader (contract
// row, metrics block) needs a consistent view across all of it.
type dnsResolveHealth struct {
	mu sync.Mutex

	// Cumulative totals. `failures` counts resolutions that produced no answer
	// because the RESOLVER did not answer; `noPublicAnswer` counts resolutions
	// that succeeded and returned only private addresses (the shared SSRF
	// posture rejects those). The split is load-bearing: a private-only answer
	// is evidence the resolver is HEALTHY, so it must never contribute to a
	// degradation verdict, and on a split-horizon estate it is the common case.
	total          int64
	failures       int64
	timeouts       int64
	shed           int64
	staleServed    int64
	noPublicAnswer int64

	// firstFailure is the start of the current run of consecutive failures;
	// zero when a resolution last succeeded. Degradation is measured from here,
	// so a resolver that fails, answers, and fails again never accumulates
	// toward the threshold across healthy periods.
	firstFailure time.Time
	lastFailure  time.Time
	lastReason   string

	// consecutive resets on an OBSERVED successful resolution; total never does.
	// Recovery is established by evidence — an answer from the resolver — never
	// by elapsed time. A gateway whose resolution failures stop because traffic
	// stopped has not recovered, and reporting that as recovery is the mistake
	// ca_health.go and storage_health.go both call out by name.
	consecutive int64

	// logAt gates the log line; suppressed counts what the gate swallowed since
	// the last emitted line, so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per DEGRADATION episode: one page when
	// resolution starts failing persistently, not one per request. Cleared by
	// an observed successful resolution, so a second incident pages again.
	alerted bool
}

var dnsResolve dnsResolveHealth

// dnsEverFailed short-circuits the success observer until the first failure, so
// a healthy resolution costs one atomic load rather than a mutex acquire (the
// storageEverFailed pattern). This one IS on a per-request path — every cache
// miss for a `DestCountry` policy reaches it — so the fault plane must not tax
// the healthy plane.
var dnsEverFailed atomic.Bool

// dnsResolveSnapshot is the lock-free view handed to the reporting surfaces.
type dnsResolveSnapshot struct {
	Total          int64
	Failures       int64
	Timeouts       int64
	Shed           int64
	StaleServed    int64
	NoPublicAnswer int64
	Consecutive    int64
	LastReason     string
	Failing        bool
	Degraded       bool
	FailingFor     time.Duration
}

// fireDNSResolveAlert delivers the degradation page on the EXISTING `dns_failure`
// event.
//
// Package-level seam so tests observe the transition SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches). HasSubscriber-gated for the reason documented on
// fireStorageWriteAlert: with no webhook configured — the default posture, and
// the state of every test binary — this must not spawn a goroutine at all.
var fireDNSResolveAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("dns_failure") {
		return
	}
	go fireAlert("dns_failure", AlertPayload{
		Detail: detail,
		Source: "policy",
	})
}

// classifyDNSFailure maps a resolver error to a BOUNDED reason class.
//
// Never a raw error string, for three reasons that all bite on this path. The
// alert dedup key is `event + ":" + Detail`, so an unbounded Detail yields one
// distinct key per failure — the 30 s dedup window cannot suppress it by
// construction, and the fan-out lands in the 500-entry retry queue where it
// evicts REAL threat alerts (the WK-12/RS-5 defect). A `*net.DNSError`'s text
// additionally embeds the QUERIED HOSTNAME, which is attacker-chosen here: any
// client can make this gateway emit arbitrary strings into an operator's alert
// pipeline. And the operator-contract row is a viewer-role surface carrying a
// standing no-sensitive-values guardrail. The full error goes to the
// rate-limited log line and nowhere else.
// It is a PURE function of the error and takes no context. The first draft
// accepted one as a fallback ("the ctx expired, so call it a timeout"), which
// forced every caller without a context — fireDNSFailureAlert, and every
// classification test — to pass nil, and staticcheck rightly rejects that
// (SA1012). Threading a context.TODO() through would have kept the smell and
// bought nothing: the deadline refinement needs a REAL context, and there is
// exactly one caller that has one. That caller (lookupPublicHostIP) now applies
// the refinement itself, against its own live context. See the note below on
// why the refinement can only ever upgrade `resolver_error`.
func classifyDNSFailure(err error) string {
	if err == nil {
		return "unknown"
	}

	// The RESOLVER's own classification is authoritative and is consulted FIRST.
	//
	// Order matters, in the one direction that must never be wrong. An
	// authoritative NXDOMAIN that lands microseconds before the deadline leaves
	// the caller's ctx.Err() non-nil, so a deadline-first reading would stamp it
	// "timeout" — and "timeout" escalates toward the degradation page while
	// "nxdomain" deliberately does not. Since the hostname is client-chosen,
	// that inversion would hand any client a way to fabricate the page by
	// requesting nonexistent hosts under mild resolver latency: exactly the
	// failure mode the NXDOMAIN exclusion exists to prevent. Nothing is lost —
	// net.Resolver surfaces a cancelled context as a *net.DNSError with
	// IsTimeout set, so a genuine deadline overrun is caught right here.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout:
			return "timeout"
		case dnsErr.IsNotFound:
			return "nxdomain"
		case dnsErr.IsTemporary:
			return "temporary"
		}
		return "resolver_error"
	}

	// Only an error the resolver did not classify can still be a deadline, and
	// only when it says so itself.
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "resolver_error"
}

// refineDNSFailureWithDeadline upgrades an UNCLASSIFIED failure to "timeout"
// when the resolution's own context had in fact expired.
//
// It can only ever act on "resolver_error", and that restriction is the whole
// point: an authoritative verdict from the resolver — above all "nxdomain" —
// must never be relabelled by the clock, or a client could fabricate the
// degradation page by requesting nonexistent hosts under mild resolver latency.
// In production this is unreachable (net.Resolver always returns a
// *net.DNSError, which classifyDNSFailure has already decided); it exists so an
// injected seam that reports a bare error at its deadline is still counted as
// the timeout it was, rather than as a resolver fault.
func refineDNSFailureWithDeadline(ctx context.Context, reason string) string {
	if reason == "resolver_error" && ctx.Err() != nil {
		return "timeout"
	}
	return reason
}

// noteDNSResolveFailure records one failed resolution and returns whether the
// caller should emit a log line for it.
//
// NXDOMAIN is counted but is deliberately NOT evidence of a broken resolver:
// an authoritative "this name does not exist" is a resolver that is working
// perfectly, and a gateway sees a steady stream of them from typos, expired
// domains and malware beaconing to sinkholed C2. Counting it toward degradation
// would page on healthy traffic and, worse, would let any client fabricate the
// page by requesting nonexistent hosts.
func noteDNSResolveFailure(reason string, now time.Time) (shouldLog bool) {
	dnsEverFailed.Store(true)

	dnsResolve.mu.Lock()

	dnsResolve.total++
	dnsResolve.failures++
	if reason == "timeout" {
		dnsResolve.timeouts++
	}
	dnsResolve.lastFailure = now
	dnsResolve.lastReason = reason

	if reason == "nxdomain" {
		// Counted, never escalated, and it does NOT clear an in-progress
		// episode either: an NXDOMAIN says nothing about whether the resolver
		// can answer the queries that matter.
		dnsResolve.mu.Unlock()
		return false
	}

	dnsResolve.consecutive++
	if dnsResolve.firstFailure.IsZero() {
		dnsResolve.firstFailure = now
	}

	if dnsResolve.logAt.IsZero() || now.Sub(dnsResolve.logAt) >= dnsResolveLogInterval {
		dnsResolve.logAt = now
		shouldLog = true
	} else {
		dnsResolve.suppressed++
	}

	degraded := now.Sub(dnsResolve.firstFailure) >= dnsResolveDegradedAfter
	alertNow := degraded && !dnsResolve.alerted
	if alertNow {
		dnsResolve.alerted = true
	}
	failures := dnsResolve.consecutive
	dnsResolve.mu.Unlock()

	if alertNow {
		fireDNSResolveAlert(fmt.Sprintf(
			"destination-host DNS resolution has been failing for over %s (%d consecutive failures, reason: %s); geo-scoped policy rules cannot match and are not being enforced",
			dnsResolveDegradedAfter, failures, reason))
	}
	return shouldLog
}

// noteDNSResolveShed records a resolution refused because the resolver pool was
// saturated.
//
// Shedding is charged to the failure counters but NOT to the consecutive-failure
// run, and that separation is deliberate: saturation is a statement about THIS
// gateway's load, not about the resolver, and letting it drive the
// `dns_failure` page would send an operator to inspect healthy DNS
// infrastructure. It gets its own counter and its own contract-row branch.
func noteDNSResolveShed() {
	dnsEverFailed.Store(true)
	dnsResolve.mu.Lock()
	dnsResolve.total++
	dnsResolve.shed++
	dnsResolve.mu.Unlock()
}

// noteDNSStaleServed records that an expired-but-servable answer was returned
// while a refresh ran. Not a failure — this is the mechanism working — but it
// is the leading indicator that resolution has stopped completing, and it moves
// before the degradation threshold does.
func noteDNSStaleServed() {
	dnsResolve.mu.Lock()
	dnsResolve.staleServed++
	dnsResolve.mu.Unlock()
}

// noteDNSNoPublicAnswer records a resolution that ANSWERED but yielded only
// private addresses, which the shared SSRF posture rejects. The resolver is
// healthy, so this clears a failure episode exactly like a public answer does.
func noteDNSNoPublicAnswer() int64 {
	dnsResolve.mu.Lock()
	dnsResolve.total++
	dnsResolve.noPublicAnswer++
	dnsResolve.mu.Unlock()
	return noteDNSResolveSuccess()
}

// noteDNSResolveSuccess records an OBSERVED successful resolution and returns
// the number of log lines the rate gate suppressed during the episode that just
// ended (zero when nothing was failing).
//
// This is the only thing that clears the degraded state.
func noteDNSResolveSuccess() (suppressed int64) {
	if !dnsEverFailed.Load() {
		return 0
	}
	dnsResolve.mu.Lock()
	defer dnsResolve.mu.Unlock()
	if dnsResolve.consecutive == 0 {
		return 0
	}
	suppressed = dnsResolve.suppressed
	dnsResolve.consecutive = 0
	dnsResolve.suppressed = 0
	dnsResolve.firstFailure = time.Time{}
	dnsResolve.alerted = false
	dnsResolve.logAt = time.Time{}
	return suppressed
}

// noteDNSResolveOK is the success path's single entry point: it counts the
// resolution and reports how many log lines the ending episode suppressed.
func noteDNSResolveOK() (suppressed int64) {
	dnsResolve.mu.Lock()
	dnsResolve.total++
	dnsResolve.mu.Unlock()
	return noteDNSResolveSuccess()
}

// dnsResolveState returns a consistent copy of the resolver's health.
func dnsResolveState() dnsResolveSnapshot {
	dnsResolve.mu.Lock()
	defer dnsResolve.mu.Unlock()
	snap := dnsResolveSnapshot{
		Total:          dnsResolve.total,
		Failures:       dnsResolve.failures,
		Timeouts:       dnsResolve.timeouts,
		Shed:           dnsResolve.shed,
		StaleServed:    dnsResolve.staleServed,
		NoPublicAnswer: dnsResolve.noPublicAnswer,
		Consecutive:    dnsResolve.consecutive,
		LastReason:     dnsResolve.lastReason,
	}
	if !dnsResolve.firstFailure.IsZero() {
		snap.Failing = true
		snap.FailingFor = dnsResolve.lastFailure.Sub(dnsResolve.firstFailure)
		snap.Degraded = snap.FailingFor >= dnsResolveDegradedAfter
	}
	return snap
}

// resetDNSResolveHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so `dnsResolve = dnsResolveHealth{}` under
// the lock replaces the held mutex with an unlocked zero value and the
// following Unlock is a fatal "unlock of unlocked mutex" (the
// resetSOCKS5HealthForTest note, same trap).
func resetDNSResolveHealthForTest() {
	dnsResolve.mu.Lock()
	defer dnsResolve.mu.Unlock()
	dnsResolve.total = 0
	dnsResolve.failures = 0
	dnsResolve.timeouts = 0
	dnsResolve.shed = 0
	dnsResolve.staleServed = 0
	dnsResolve.noPublicAnswer = 0
	dnsResolve.firstFailure = time.Time{}
	dnsResolve.lastFailure = time.Time{}
	dnsResolve.lastReason = ""
	dnsResolve.consecutive = 0
	dnsResolve.logAt = time.Time{}
	dnsResolve.suppressed = 0
	dnsResolve.alerted = false
	dnsEverFailed.Store(false)
}

// checkDNSResolution is the `dns_resolution` operator-contract row.
//
// Severity policy:
//   - never used → ok. Resolution runs only for a `DestCountry` rule on a node
//     with a GeoIP database, so a permanent row would be noise on the ordinary
//     appliance.
//   - degraded (sustained non-NXDOMAIN failures) → warn, NOT fail. The gateway
//     is still proxying every request; what has stopped is geo-scoped policy
//     MATCHING. A fail row here would be read as "this node is broken" and, on
//     a strict readiness deployment, would take out a fleet that is serving.
//     The message says what is actually not being enforced, because that is the
//     part an operator cannot infer from "DNS is down".
//   - shedding → warn. Different cause, different action: this node is
//     saturated, the resolver is fine.
//   - healthy → ok, carrying the cumulative failure count so a HISTORY of
//     transient outages stays visible after recovery.
func checkDNSResolution() OperatorContractCheck {
	snap := dnsResolveState()
	if snap.Total == 0 {
		return OperatorContractCheck{
			Code:    "dns_resolution",
			Status:  diagOK,
			Message: "No destination-host DNS resolution performed (no GeoIP-scoped policy rules in use)",
		}
	}
	if snap.Degraded {
		return OperatorContractCheck{
			Code:   "dns_resolution",
			Status: diagWarn,
			Message: fmt.Sprintf("Destination-host DNS resolution has been failing for %s (%d consecutive failures, reason: %s); geo-scoped policy rules cannot match and are NOT being enforced",
				snap.FailingFor.Round(time.Second), snap.Consecutive, snap.LastReason),
			OperatorAction: "Check this node's resolver reachability (/etc/resolv.conf, upstream DNS). Traffic is still proxied; rules scoped by destination country stop matching until resolution recovers. Hosts resolved within the last hour are served from cache and keep matching.",
		}
	}
	if snap.Shed > 0 && snap.Shed >= snap.Total/2 {
		return OperatorContractCheck{
			Code:   "dns_resolution",
			Status: diagWarn,
			Message: fmt.Sprintf("Destination-host DNS resolution is shedding under load (%d of %d resolutions refused because the resolver pool was saturated)",
				snap.Shed, snap.Total),
			OperatorAction: "This node is resolving more distinct destinations than the bounded resolver pool allows, usually a scanning or beaconing client. Identify the source in the request log; shed resolutions fail closed (geo-scoped rules do not match) and recover on their own as load drops.",
		}
	}
	if snap.Failures > 0 || snap.Shed > 0 {
		return OperatorContractCheck{
			Code:   "dns_resolution",
			Status: diagOK,
			Message: fmt.Sprintf("Destination-host DNS resolution healthy (%d resolutions, %d failures, %d timeouts, %d shed, %d served stale since startup)",
				snap.Total, snap.Failures, snap.Timeouts, snap.Shed, snap.StaleServed),
		}
	}
	return OperatorContractCheck{
		Code:    "dns_resolution",
		Status:  diagOK,
		Message: fmt.Sprintf("Destination-host DNS resolution healthy (%d resolutions since startup)", snap.Total),
	}
}
