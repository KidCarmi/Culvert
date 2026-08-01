package main

// auth_health.go — identity-provider reachability health (CHAOS-16, AU-7).
//
// The auth plane could not tell "no" from "I don't know". Both LDAPAuth.verify
// and OIDCAuth.introspect collapsed every outcome into a bare `false`: a wrong
// password, a directory that refused the TCP connect, an introspection endpoint
// returning 503, and a truncated JSON body were all the same value. Two
// consequences followed from that one conflation:
//
//  1. OUTAGE AMPLIFICATION. The bare `false` was then written into the
//     provider's negative cache for the full TTL (5 min LDAP / 2 min OIDC). A
//     directory that was unreachable for two seconds therefore denied every
//     user who authenticated during those two seconds for the next five
//     minutes — measured from the blip, and continuing long AFTER the
//     directory was healthy again. The cache existed to protect the IdP from
//     load; under failure it converted a momentary infrastructure fault into a
//     multi-minute, self-inflicted user outage that no amount of IdP recovery
//     could shorten.
//
//  2. INVISIBILITY. An IdP outage and a credential-stuffing spike produced
//     byte-identical telemetry: a burst of "auth FAIL" log lines and a rising
//     statAuthFail. The operator response to those two events is opposite —
//     page the directory team, or block the source — and there was no signal
//     to tell them apart.
//
// This file is the "I don't know" half of the tri-state. Providers classify
// each attempt as answered (idpAllowed / idpDenied) or unanswered
// (idpUnavailable) and report the unanswered ones here, which records them per
// backend, exports them, and pages — rate-gated, because a down IdP fails
// EVERY request and an un-gated producer would flood the bounded webhook queue
// and evict every other alert.
//
// Posture is deliberately unchanged: an unanswered attempt still DENIES the
// request. Fail-closed is the contract for a security gateway, and this change
// does not touch it. What changes is that the denial is no longer remembered
// as if it were a statement about the user's credentials.

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// idpResult is the tri-state outcome of one identity-provider verification.
//
// The distinction that matters is not allow-vs-deny but ANSWERED vs
// UNANSWERED. idpAllowed and idpDenied are both statements the IdP made about
// the credential and are therefore safe to cache; idpUnavailable is the
// absence of a statement and must never be cached, because caching it turns a
// transient fault into a sticky denial that outlives the fault.
type idpResult int

const (
	// idpDenied — the IdP answered, and the answer was no. Cacheable.
	idpDenied idpResult = iota
	// idpAllowed — the IdP answered, and the answer was yes. Cacheable.
	idpAllowed
	// idpUnavailable — the IdP did not answer: the request never reached it,
	// it refused to serve, or its reply was unintelligible. NOT cacheable.
	idpUnavailable
)

// idpUnavailableAlertInterval rate-limits the idp_unreachable alert and its
// log line, PER BACKEND. A down IdP fails every authenticating request, so an
// un-gated producer would saturate the bounded webhook queue and evict every
// other alert — the auth-plane fault would take the alerting channel down with
// it. The gate re-arms, so an IdP that stays down keeps paging rather than
// going quiet after one message. The COUNTER is never gated, so magnitude
// survives.
const idpUnavailableAlertInterval = 5 * time.Minute

// idpBackendHealth is the per-backend record. Gates are per-backend on
// purpose: an LDAP outage must not consume the alert budget for OIDC and
// silence the page for a second, unrelated failure — the same shared-gate
// mistake the storage-health work had to correct (CHAOS-45).
type idpBackendHealth struct {
	total  int64
	last   time.Time
	reason string

	// lastAnswered is the most recent OBSERVED definitive answer (allow or
	// deny) from this backend. Recovery is established by evidence, never by
	// elapsed time: an IdP that is still down looks exactly like a healthy one
	// if nothing happens to authenticate during the window. This mirrors the
	// storage-health rule (CHAOS-45) — silence is not recovery.
	lastAnswered time.Time

	logAt   time.Time
	alertAt time.Time
}

type idpHealthRegistry struct {
	mu       sync.Mutex
	backends map[string]*idpBackendHealth
}

var idpHealth idpHealthRegistry

// idpEverUnavailable short-circuits the answered-path bookkeeping until the
// first unavailability, keeping the cost of observing every successful
// authentication to a single relaxed atomic load. Auth runs on the proxy hot
// path, once per unauthenticated request.
var idpEverUnavailable atomic.Bool

// fireIdPUnreachableAlert delivers the idp_unreachable alert. Package-level
// seam so tests observe transitions synchronously instead of racing the
// process-global alerts sink (the -count/-shuffle determinism class the CI
// determinism gate catches).
//
// Like the storage producer, this is driven by an EXTERNAL fault and fires
// from arbitrary request goroutines: when nobody has subscribed it does
// nothing at all, and in particular does not spawn a goroutine, so a node with
// no webhooks configured (the default posture, and the state of every test
// binary) gets no goroutine churn from an IdP outage.
var fireIdPUnreachableAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("idp_unreachable") {
		return
	}
	go fireAlert("idp_unreachable", AlertPayload{
		Detail: detail,
		Source: "auth",
	})
}

// noteIdPUnavailable records one attempt that the identity provider did not
// answer.
//
// `reason` MUST come from the provider's fixed classification vocabulary
// (dial_failed, starttls_failed, service_bind_failed, search_failed,
// bind_transport_failed, request_failed, http_503, parse_failed, …) and never
// from a raw error string. That is a disclosure decision, not a style
// preference: this value reaches /api/diagnostics, which is a VIEWER-role
// surface, and LDAP/OIDC error text embeds directory hostnames, bind DNs and
// introspection URLs. A closed vocabulary cannot leak them, so no redaction
// pass is needed and no future consumer of the record can reintroduce a leak
// by formatting it somewhere new. The full error text still goes to the log,
// exactly as it did before this change.
func noteIdPUnavailable(backend, reason string) {
	now := time.Now()
	safeReason := sanitizeLog(reason)

	idpEverUnavailable.Store(true)

	idpHealth.mu.Lock()
	if idpHealth.backends == nil {
		idpHealth.backends = map[string]*idpBackendHealth{}
	}
	h := idpHealth.backends[backend]
	if h == nil {
		h = &idpBackendHealth{}
		idpHealth.backends[backend] = h
	}
	h.total++
	h.last = now
	h.reason = safeReason
	total := h.total
	// Both gates are evaluated under the lock so concurrent failing requests
	// cannot both pass.
	doLog := h.logAt.IsZero() || now.Sub(h.logAt) >= idpUnavailableAlertInterval
	if doLog {
		h.logAt = now
	}
	doAlert := h.alertAt.IsZero() || now.Sub(h.alertAt) >= idpUnavailableAlertInterval
	if doAlert {
		h.alertAt = now
	}
	idpHealth.mu.Unlock()

	if doLog && logger != nil {
		logger.Printf("Auth: identity provider %q UNAVAILABLE (%q, %d unanswered attempts since boot) — requests are being DENIED because the provider did not answer, not because the credentials were rejected",
			sanitizeLog(backend), safeReason, total)
	}
	if doAlert {
		fireIdPUnreachableAlert(fmt.Sprintf(
			"identity provider %s unreachable (%s, %d unanswered auth attempts since boot) — users are being denied while it is down",
			sanitizeLog(backend), safeReason, total))
	}
}

// noteIdPAnswered records that the backend gave a definitive answer — allow or
// deny, both count. This is the ONLY thing that clears the degraded state.
//
// Deny counts as recovery evidence on purpose: what degraded means here is
// "this provider is not answering", and a rejection is an answer. Requiring a
// SUCCESSFUL authentication would leave a healthy directory reported as down
// for as long as it happened to receive only bad passwords.
func noteIdPAnswered(backend string) {
	if !idpEverUnavailable.Load() {
		return
	}
	now := time.Now()
	idpHealth.mu.Lock()
	if h := idpHealth.backends[backend]; h != nil {
		h.lastAnswered = now
	}
	idpHealth.mu.Unlock()
}

// idpHealthEntry is a consistent read of one backend's record.
type idpHealthEntry struct {
	Backend      string
	Total        int64
	Last         time.Time
	Reason       string
	LastAnswered time.Time
}

// Degraded reports whether this backend should be treated as not answering
// RIGHT NOW: it has failed to answer at least once, and no definitive answer
// has been observed since.
func (e idpHealthEntry) Degraded() bool {
	return e.Total > 0 && !e.LastAnswered.After(e.Last)
}

// idpHealthSnapshot returns every backend that has ever failed to answer,
// sorted by backend name so /metrics output is stable across scrapes.
func idpHealthSnapshot() []idpHealthEntry {
	idpHealth.mu.Lock()
	out := make([]idpHealthEntry, 0, len(idpHealth.backends))
	for name, h := range idpHealth.backends {
		out = append(out, idpHealthEntry{
			Backend:      name,
			Total:        h.total,
			Last:         h.last,
			Reason:       h.reason,
			LastAnswered: h.lastAnswered,
		})
	}
	idpHealth.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Backend < out[j].Backend })
	return out
}

// idpDegradedBackends returns the backends that are currently not answering.
func idpDegradedBackends() []idpHealthEntry {
	var out []idpHealthEntry
	for _, e := range idpHealthSnapshot() {
		if e.Degraded() {
			out = append(out, e)
		}
	}
	return out
}

// resetIdPHealthForTest clears the record. Test-only helper kept in the
// production file so the state and its reset stay adjacent.
func resetIdPHealthForTest() {
	idpHealth.mu.Lock()
	idpHealth.backends = nil
	idpHealth.mu.Unlock()
	idpEverUnavailable.Store(false)
}
