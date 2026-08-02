package main

// auth_health.go — external auth-backend reachability health (CHAOS-16 / F-11).
//
// The defect this file exists for: both legacy external auth backends collapsed
// "the directory said no" and "the directory did not answer" into the same
// `false`, then CACHED it.
//
//	LDAPAuth.Verify   → a.verify(...) returned false for a dial error, a
//	                    STARTTLS error, a service-bind error and a search error
//	                    exactly as it did for a wrong password — then
//	                    cacheSet(key, false) pinned it for CacheTTL (5m default).
//	OIDCAuth.Verify   → introspect() returned active=false for a transport
//	                    error, a non-200 status and a parse error exactly as it
//	                    did for `{"active":false}` — then the entry was cached
//	                    for CacheTTL (2m default).
//
// So a 200 ms blip on the IdP became a 5-minute denial for every credential
// that happened to miss the cache during it. The outage was AMPLIFIED past its
// own duration, and the amplification was invisible: the log line said
// "LDAP auth FAIL", the same words a wrong password produces, so an IdP outage
// and a brute-force spike were indistinguishable on every operator surface.
//
// The fix is a three-valued result. A backend answer (allow / deny) is cached
// as before. A backend FAILURE is indeterminate: the request is still denied —
// the posture stays fail-closed, an unreachable directory must never admit
// anyone — but the denial is not recorded as a credential decision, so it
// expires with the outage instead of outliving it. See authIndeterminateTTL for
// the one bounded exception and why it exists.
//
// This file owns the shared machinery: the outcome type, the per-backend
// reachability record, and the operator signals (counter, gauge, contract row,
// alert) that make an auth-plane outage look different from a failed password.

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// authBackendOutcome is the three-valued result of asking an external auth backend
// about one credential.
//
// The distinction that matters is not allow-vs-deny, it is ANSWERED vs
// UNANSWERED. Only an answer is a fact about the credential; a failure is a
// fact about the infrastructure, and caching it as a credential decision is
// what turned a blip into an outage.
type authBackendOutcome int

const (
	// backendIndeterminate — the backend could not be reached or could not be
	// understood (dial/TLS/bind/search failure, transport error, non-200,
	// unparseable response). Says NOTHING about the credential.
	backendIndeterminate authBackendOutcome = iota
	// backendDeny — the backend answered and rejected the credential.
	backendDeny
	// backendAllow — the backend answered and accepted the credential.
	backendAllow
)

// allowed reports whether the outcome admits the request. Indeterminate denies:
// an auth backend that cannot answer must not admit anyone (fail closed).
func (o authBackendOutcome) allowed() bool { return o == backendAllow }

// determinate reports whether the outcome is a statement about the CREDENTIAL
// (and is therefore cacheable for the full backend TTL) rather than a statement
// about the infrastructure.
func (o authBackendOutcome) determinate() bool { return o != backendIndeterminate }

const (
	// authIndeterminateTTL bounds how long an UNANSWERED attempt is echoed
	// before the backend is consulted again.
	//
	// Zero would be more correct in isolation — an outage would then never
	// outlive itself by even a millisecond. It would also be a load amplifier
	// pointed at an auth backend that is already in trouble: every request that
	// misses the cache during the outage would open its own connection and hold
	// a goroutine for the full dial timeout, so a struggling directory would be
	// hit HARDER precisely while it was failing, and a recovering one could be
	// knocked straight back down by the queued retry storm.
	//
	// So an indeterminate result is remembered, but for seconds rather than
	// minutes: long enough to collapse a request storm into roughly one attempt
	// per credential per interval, short enough that recovery is felt almost
	// immediately. This is the residual — a user can still be denied for up to
	// this long after the IdP comes back — and it is three orders of magnitude
	// smaller than the 5m/2m credential TTLs that caused the finding.
	authIndeterminateTTL = 5 * time.Second

	// authBackendAlertInterval rate-limits the auth_backend_unreachable alert
	// and its log line, PER BACKEND. A down directory fails every request, so
	// an un-gated producer would flood the bounded webhook queue and evict
	// every other alert — the auth outage would take the alerting channel down
	// with it. The counter is never gated, so magnitude is preserved.
	authBackendAlertInterval = 5 * time.Minute

	// maxAuthBackendRecords bounds the reachability map. Backend names are
	// internal constants ("ldap", "oidc"), not user input, so this is a
	// belt-and-braces cap against a future caller passing something dynamic
	// into a map that feeds Prometheus labels.
	maxAuthBackendRecords = 16
)

// authBackendRecord is the reachability history of one external auth backend.
type authBackendRecord struct {
	// unreachable counts indeterminate outcomes since boot. Never rate-gated.
	unreachable int64
	// last is the most recent indeterminate outcome.
	last time.Time
	// lastOK is the most recent OBSERVED answer (allow or deny) from this
	// backend. Recovery is established by evidence, never by elapsed time: a
	// directory that is still down looks exactly like a healthy one if nothing
	// happens to ask it. This is the CHAOS-45 lesson applied to the auth plane.
	lastOK time.Time
	// lastErr is the sanitized reason text of the most recent failure.
	lastErr string
	// logAt / alertAt are PER-BACKEND rate gates. Per-backend, not global, so a
	// permanently-broken secondary backend cannot mute the page for the primary
	// one going down (the CHAOS-45 shared-gate hazard).
	logAt   time.Time
	alertAt time.Time
}

type authBackendHealth struct {
	mu       sync.Mutex
	backends map[string]*authBackendRecord
}

var authBackends = authBackendHealth{backends: map[string]*authBackendRecord{}}

// authEverUnreachable keeps the healthy path free. Every determinate auth
// outcome calls noteAuthBackendAnswered, which is on the proxy authentication
// hot path; until something has actually failed it costs one relaxed atomic
// load and no lock.
var authEverUnreachable atomic.Bool

// fireAuthBackendAlert delivers the auth_backend_unreachable alert.
// Package-level seam so tests observe the transition synchronously instead of
// racing the process-global alerts sink. The production value fires async: the
// caller is a request goroutine on the authentication path, and alerts.Dispatch
// can block on a disk write.
var fireAuthBackendAlert = func(detail string) {
	// Nobody subscribed → do nothing, and in particular do not spawn a
	// goroutine. This producer is driven by an EXTERNAL fault at request rate;
	// spawning a delivery goroutine per failure for an alert with no recipient
	// would inject goroutine churn into the default posture.
	if !globalAlertStore.HasSubscriber("auth_backend_unreachable") {
		return
	}
	go fireAlert("auth_backend_unreachable", AlertPayload{
		Detail: detail,
		Source: "auth",
	})
}

// endpointAddrPattern matches a bare IPv4[:port] or bracketed IPv6[:port] — the
// resolved peer address Go's net.OpError embeds in a dial error.
var endpointAddrPattern = regexp.MustCompile(`\[[0-9A-Fa-f:.]+](:\d+)?|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b`)

// redactAuthReason strips network-endpoint detail from a backend error before
// it reaches an operator surface.
//
// This is a disclosure decision, not cosmetics. The reason text is rendered on
// /api/diagnostics, which is a VIEWER-role surface, and the errors it comes
// from carry topology: an *url.Error embeds the configured introspection URL,
// and the *net.OpError under it embeds the RESOLVED address — so an
// unredacted reason would publish the corporate IdP's hostname and its internal
// IP to every read-only admin the moment the directory hiccupped. The
// surrounding diagnostics checks already follow this convention (the SAML
// base-URL rows describe the defect without ever echoing the configured value),
// and the CHAOS-45 run learned the same lesson the hard way with filesystem
// paths.
//
// What survives is the operator-actionable part: the failure class —
// "connection refused", "i/o timeout", "certificate has expired". Which
// endpoint it was is already known from the config, and the raw error is still
// written verbatim to the operator LOG by the calling provider.
//
// Redaction happens here, at the one boundary the record passes through, so
// every sink (log line, alert detail, contract row) is covered and a future
// consumer cannot reintroduce the leak by formatting the record somewhere new.
func redactAuthReason(msg, endpoint string) string {
	if endpoint != "" {
		msg = strings.ReplaceAll(msg, endpoint, "<endpoint>")
		if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
			msg = strings.ReplaceAll(msg, u.Host, "<endpoint>")
			if h := u.Hostname(); h != "" {
				msg = strings.ReplaceAll(msg, h, "<endpoint>")
			}
		}
	}
	return endpointAddrPattern.ReplaceAllString(msg, "<addr>")
}

// noteAuthBackendUnreachable records that `backend` could not answer, and is
// the ONLY producer of the auth-outage operator signals.
//
// reason is free text from the failing layer (an LDAP or HTTP error). It is
// sanitized here, at the recording boundary rather than at each sink, so every
// downstream consumer — log line, alert detail, /api/diagnostics row — is fed
// clean text and a future consumer cannot reintroduce an injection by
// formatting the record somewhere new.
func noteAuthBackendUnreachable(backend, reason string) {
	safeBackend := sanitizeLog(backend)
	safeReason := sanitizeLog(reason)
	now := time.Now()

	authEverUnreachable.Store(true)

	authBackends.mu.Lock()
	rec := authBackends.backends[safeBackend]
	if rec == nil {
		if len(authBackends.backends) >= maxAuthBackendRecords {
			authBackends.mu.Unlock()
			return
		}
		rec = &authBackendRecord{}
		authBackends.backends[safeBackend] = rec
	}
	rec.unreachable++
	rec.last = now
	rec.lastErr = safeReason
	total := rec.unreachable
	doLog := rec.logAt.IsZero() || now.Sub(rec.logAt) >= authBackendAlertInterval
	if doLog {
		rec.logAt = now
	}
	doAlert := rec.alertAt.IsZero() || now.Sub(rec.alertAt) >= authBackendAlertInterval
	if doAlert {
		rec.alertAt = now
	}
	authBackends.mu.Unlock()

	if doLog && logger != nil {
		// Deliberately NOT the words an authentication failure produces. An
		// operator grepping for auth failures during an incident must be able
		// to tell "the directory rejected them" from "the directory is gone".
		logger.Printf("Auth: backend %q UNREACHABLE — requests are being denied fail-closed (%d since boot): %q",
			safeBackend, total, safeReason)
	}
	if doAlert {
		fireAuthBackendAlert(fmt.Sprintf("auth backend %s unreachable (%d failures since boot): %s — requests are being denied fail-closed",
			safeBackend, total, safeReason))
	}
}

// noteAuthBackendAnswered records that `backend` produced a real answer. This
// is the only thing that clears the degraded state — see authBackendRecord.lastOK.
func noteAuthBackendAnswered(backend string) {
	if !authEverUnreachable.Load() {
		return
	}
	now := time.Now()
	authBackends.mu.Lock()
	if rec := authBackends.backends[sanitizeLog(backend)]; rec != nil {
		rec.lastOK = now
	}
	authBackends.mu.Unlock()
}

// noteAuthOutcome routes one backend result to the right recorder. Callers use
// this instead of the two functions above so the "indeterminate → unreachable,
// anything else → answered" mapping lives in exactly one place.
func noteAuthOutcome(backend string, outcome authBackendOutcome, reason string) {
	if outcome.determinate() {
		noteAuthBackendAnswered(backend)
		return
	}
	noteAuthBackendUnreachable(backend, reason)
}

// authBackendSnapshotEntry is a consistent read of one backend's record.
type authBackendSnapshotEntry struct {
	Backend     string
	Unreachable int64
	Last        time.Time
	LastErr     string
	Degraded    bool
}

// authBackendHealthSnapshot returns every backend that has EVER been
// unreachable, sorted by name for deterministic output.
//
// Backends that have never failed are absent by design. A row asserting a
// backend is healthy would be claiming knowledge this process does not have —
// nothing here probes, it only observes the results of real authentications, so
// "no failures recorded" can equally mean "nobody has authenticated". Reporting
// silence as health is the exact reasoning error the storage-health work had to
// undo (CHAOS-45).
func authBackendHealthSnapshot() []authBackendSnapshotEntry {
	authBackends.mu.Lock()
	out := make([]authBackendSnapshotEntry, 0, len(authBackends.backends))
	for name, rec := range authBackends.backends {
		out = append(out, authBackendSnapshotEntry{
			Backend:     name,
			Unreachable: rec.unreachable,
			Last:        rec.last,
			LastErr:     rec.lastErr,
			Degraded:    rec.unreachable > 0 && !rec.lastOK.After(rec.last),
		})
	}
	authBackends.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Backend < out[j].Backend })
	return out
}

// resetAuthBackendHealthForTest clears the record. Test-only helper kept beside
// the state it resets.
func resetAuthBackendHealthForTest() {
	authBackends.mu.Lock()
	authBackends.backends = map[string]*authBackendRecord{}
	authBackends.mu.Unlock()
	authEverUnreachable.Store(false)
}
