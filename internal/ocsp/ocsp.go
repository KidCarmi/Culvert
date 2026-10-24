// Package ocsp is the OCSP revocation-checking engine for upstream TLS
// certificates: a TTL'd verdict cache plus the responder query pipeline
// behind a tls.Config VerifyPeerCertificate callback. Extracted from package
// main per ADR-0002; the transport wiring (ConfigureTLSConfigOCSP /
// ConfigureTransportOCSP, under the P5.3 upstream-transport ownership
// contract) and the globalOCSP singleton stay in main (ocsp.go shim).
//
// When enabled, the proxy verifies that upstream server certificates have not
// been revoked by checking OCSP stapled responses and, as a fallback, querying
// OCSP responders listed in the certificate's AIA extension.
//
// # CHAOS-65 — the input to this engine is chosen by the party being checked
//
// Everything this package acts on comes out of the PEER's certificate: the
// responder URLs (`leaf.OCSPServer`), how many of them there are, and — because
// the peer names the responder — the bytes that come back. Four rules follow,
// and none of them may be relaxed:
//
//  1. A response is a verdict only when it is BOUND to the certificate under
//     test (ParseResponseForCert, never ParseResponse) and FRESH. Without the
//     binding, a genuine CA-signed "good" about any other certificate of the
//     same issuer answers for this one; without the freshness check, a "good"
//     captured before revocation replays forever, since the request carries no
//     nonce and OCSP rides plaintext HTTP.
//  2. A verdict must be AFFIRMATIVE — Good or Revoked. "Unknown" means the
//     issuer does not recognise the certificate, which is the answer a
//     mis-issued or forged certificate draws; it is not a pass. (Same rule as
//     CHAOS-53 for the scan sidecar.)
//  3. The responder URL is an SSRF sink. Scheme allow-list + ssrf.PrivateHost
//     before the request, an SSRF-controlled dialer under it, and redirects
//     refused outright — a guard on the first URL alone is bypassed by a 302.
//  4. The work is BOUNDED as an envelope, not per step: at most maxResponders
//     entries, all of them inside one queryBudget, single-flighted per
//     certificate. This runs on the request goroutine inside a TLS handshake.
package ocsp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
	cryptoocsp "golang.org/x/crypto/ocsp"
)

// Checker performs OCSP-based revocation checking for TLS connections.
type Checker struct {
	enabled atomic.Bool
	mu      sync.RWMutex
	cache   map[string]*cacheEntry // CertID key (see certKey) → result

	// flightMu guards inflight, the single-flight registry keyed the same way
	// as cache. Concurrent handshakes to one host all miss the same cold entry;
	// without this each one launched its own query, so the gateway amplified
	// client request rate 1:1 into load on a responder that is by hypothesis
	// already the slow dependency (CHAOS-65; same leader/follower shape as
	// hostIPCache and jwksCache).
	flightMu sync.Mutex
	inflight map[string]*flight

	// Fail-closed / revocation counters (P-blindspot: surfaced via
	// /api/ocsp so an admin can see mass HTTPS breakage caused by
	// unreachable OCSP responders without grepping logs for
	// "fail-closed").
	failClosedTotal   atomic.Int64
	revokedTotal      atomic.Int64
	lastFailClosedUTC atomic.Int64 // unix seconds; 0 = never

	// CHAOS-65 rejection counters. Each names a DIFFERENT cause with a
	// different operator action, so they are separate rather than one
	// "bad response" total; main renders them as one labelled series.
	notForCertTotal   atomic.Int64 // issuer-signed response, but about another certificate
	malformedTotal    atomic.Int64 // unparseable, badly signed, or otherwise unintelligible
	unauthorizedTotal atomic.Int64 // signer is not an RFC 6960 authorized responder
	staleTotal        atomic.Int64 // outside its ThisUpdate/NextUpdate window
	unknownTotal      atomic.Int64 // issuer does not recognise the certificate
	blockedTotal      atomic.Int64 // responder URL refused by the SSRF guard
	truncatedTotal    atomic.Int64 // certificates whose responder list hit the cap
	singleFlightTotal atomic.Int64 // handshakes that joined an in-flight query

	lastTruncationLog atomic.Int64 // unix nanos of the last responder-cap log line
}

// allowTruncationLog reports whether the responder-cap notice may be logged
// now, at most once per truncationLogEvery. A CAS keeps two concurrent
// handshakes from both emitting.
func (oc *Checker) allowTruncationLog(now time.Time) bool {
	// CHAOS-84: the stamp is unix nanos, so the comparison is a wall-clock one
	// and a BACKWARD clock step reads as "logged in the future", suppressing the
	// notice for the duration of the step. An interval that cannot be measured
	// counts as expired, so a capped responder stays reportable across a clock
	// correction.
	//
	// MAGNITUDE, not sign, decides: a concurrent handshake that loses the CAS
	// below also sees a stamp marginally ahead of its own sample, and that is an
	// ordering artifact rather than a clock step. The gate therefore suppresses
	// while the stamp is within one interval of now in EITHER direction, so a
	// rollback costs at most one suppressed notice — the rate limit already
	// allows that — and the two causes can never be confused. Same rule as the
	// scanner, YARA, crash-throttle and Sluice call-error gates. (The stamp
	// cannot simply move to a monotonic basis the way package main's roster
	// gates did in CHAOS-83: this gate takes an injected wall-clock now.)
	last := oc.lastTruncationLog.Load()
	if d := now.Sub(time.Unix(0, last)); last != 0 && d.Abs() < truncationLogEvery {
		return false
	}
	return oc.lastTruncationLog.CompareAndSwap(last, now.UnixNano())
}

type cacheEntry struct {
	revoked    bool
	failClosed bool // revoked BECAUSE responders were unreachable (not a confirmed revocation)
	expiresAt  time.Time
}

// flight is one in-progress responder query. Followers block on done and read
// the leader's verdict; they never start a second query and never arm a timer
// of their own (a follower timeout would release it to launch exactly the
// query the single-flight exists to collapse — CHAOS-64's rule).
type flight struct {
	done chan struct{}
	// Defaults are the fail-closed verdict, so a leader that panics before
	// publishing leaves its followers denied rather than admitted.
	revoked    bool
	failClosed bool
}

const (
	cacheTTL = 1 * time.Hour
	// indeterminateTTL bounds how long a fail-closed "all responders
	// unreachable" verdict is cached. The verdict stays fail-closed
	// (connections are rejected), but recovery must track the dependency,
	// not the cache: a seconds-long responder blip previously hard-failed
	// all TLS to the affected upstream for the full 1h cacheTTL, identical
	// to a genuine revocation (CHAOS-04 outage amplification).
	indeterminateTTL = 2 * time.Minute
	cacheMaxSize     = 5000

	// queryBudget bounds EVERY responder query for one certificate, end to
	// end. It was previously a 5 s timeout applied PER responder, and
	// leaf.OCSPServer is peer-supplied and was walked in full: a certificate
	// listing 200 blackholed responders parked the request goroutine — and its
	// client connection, FD and per-IP limiter slot — for ~17 minutes inside a
	// single TLS handshake, while aiming 200 outbound POSTs at whatever hosts
	// it named. An envelope, not a per-step allowance (CHAOS-58's rule). The
	// value is deliberately the old per-responder timeout, so the ordinary
	// one-responder certificate is unchanged and only the worst case shrinks.
	queryBudget = 5 * time.Second

	// maxResponders caps how many AIA entries are consulted. Real certificates
	// carry one, occasionally two; RFC 6960 sets no bound, and the field is
	// written by the party being checked.
	maxResponders = 4

	// responseClockSkew tolerates modest disagreement between this node's
	// clock and the responder's, in both directions. Matches the inspection
	// CA's caClockSkewTolerance rather than inventing a second value.
	responseClockSkew = 5 * time.Minute

	// maxResponseAge bounds a response that carries no NextUpdate. RFC 6960
	// §2.4 allows omitting it to mean "newer information is always available",
	// which without a ceiling is an unbounded replay window.
	maxResponseAge = 24 * time.Hour

	maxResponseBytes = 1 << 20 // 1 MiB

	// truncationLogEvery rate-limits the responder-cap notice. The list that
	// triggers it is written by the peer, and the line is emitted on a cache
	// MISS, so its rate is influenced by whoever is presenting certificates:
	// signal in the log, magnitude in RespondersTruncatedTotal.
	truncationLogEvery = time.Minute
)

// errResponderRedirect aborts a redirected responder query. A guard applied to
// the first URL alone is bypassed by a 302, and http.DefaultClient — which this
// path used to use — follows up to ten of them.
var errResponderRedirect = errors.New("ocsp: responder redirected; refusing to follow")

// responderClient is the dedicated outbound client for responder queries.
//
// It is deliberately NOT http.DefaultClient: that shares the process-wide
// default transport, follows redirects, and honours HTTP(S)_PROXY from the
// environment — none of which is wanted for a request whose URL is named by
// the peer being checked. ssrf.SafeDialContext closes the DNS-rebinding window
// that the pre-flight ssrf.PrivateHost check leaves open, by re-checking the
// resolved address immediately before connect(2).
var responderClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return errResponderRedirect },
	Transport: &http.Transport{
		DialContext:           ssrf.SafeDialContext,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	},
}

// New returns a Checker with an empty verdict cache (disabled until Enable).
func New() *Checker {
	return &Checker{
		cache:    make(map[string]*cacheEntry),
		inflight: make(map[string]*flight),
	}
}

// Enable turns on OCSP checking.
func (oc *Checker) Enable() {
	oc.enabled.Store(true)
}

// Disable turns off OCSP checking.
func (oc *Checker) Disable() {
	oc.enabled.Store(false)
}

// Enabled returns whether OCSP checking is active.
func (oc *Checker) Enabled() bool {
	return oc.enabled.Load()
}

// CacheLen returns the number of entries in the OCSP cache.
func (oc *Checker) CacheLen() int {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	return len(oc.cache)
}

// FailClosedTotal returns the number of times a peer certificate was treated
// as revoked because no OCSP responder listed on it produced a usable,
// affirmative verdict.
func (oc *Checker) FailClosedTotal() int64 { return oc.failClosedTotal.Load() }

// RevokedTotal returns the number of times an OCSP responder confirmed a
// peer certificate as actually revoked.
func (oc *Checker) RevokedTotal() int64 { return oc.revokedTotal.Load() }

// NotForCertificateTotal counts signed responses discarded because they were
// about a different certificate than the one being checked. Sustained growth
// means something is answering with borrowed responses — the revocation-bypass
// shape CHAOS-65 closed.
func (oc *Checker) NotForCertificateTotal() int64 { return oc.notForCertTotal.Load() }

// MalformedTotal counts responses discarded as unintelligible — unparseable
// DER, a bad signature, an HTML error page. A broken responder, not a hostile
// one; see NotForCertificateTotal for the accusation.
func (oc *Checker) MalformedTotal() int64 { return oc.malformedTotal.Load() }

// UnauthorizedResponderTotal counts responses whose signer is not an RFC 6960
// authorized responder for the issuer — most importantly a certificate signing
// a verdict about itself.
func (oc *Checker) UnauthorizedResponderTotal() int64 { return oc.unauthorizedTotal.Load() }

// StaleTotal counts responses discarded as outside their validity window
// (replay, or a badly skewed clock on either end).
func (oc *Checker) StaleTotal() int64 { return oc.staleTotal.Load() }

// UnknownTotal counts responders that answered "unknown" — the issuer does not
// recognise the certificate.
func (oc *Checker) UnknownTotal() int64 { return oc.unknownTotal.Load() }

// ResponderBlockedTotal counts responder URLs refused before any request was
// made (disallowed scheme, or an address inside a private range).
func (oc *Checker) ResponderBlockedTotal() int64 { return oc.blockedTotal.Load() }

// RespondersTruncatedTotal counts certificates whose AIA responder list was
// longer than maxResponders.
func (oc *Checker) RespondersTruncatedTotal() int64 { return oc.truncatedTotal.Load() }

// SingleFlightJoinedTotal counts handshakes that waited on another handshake's
// in-progress query instead of starting their own.
func (oc *Checker) SingleFlightJoinedTotal() int64 { return oc.singleFlightTotal.Load() }

// LastFailClosedAt returns the time of the most recent fail-closed event, or
// the zero time if none has occurred.
func (oc *Checker) LastFailClosedAt() time.Time {
	ts := oc.lastFailClosedUTC.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0).UTC()
}

// resolveIssuer extracts the issuer certificate from verified chains or raw certs.
func resolveIssuer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) *x509.Certificate {
	if len(verifiedChains) > 0 && len(verifiedChains[0]) > 1 {
		return verifiedChains[0][1]
	}
	if len(rawCerts) > 1 {
		issuer, err := x509.ParseCertificate(rawCerts[1])
		if err != nil {
			obs.Printf("OCSP: failed to parse issuer cert: %v", err)
		}
		return issuer
	}
	return nil
}

// certKey is the verdict-cache key: the three fields RFC 6960's CertID uses to
// name a certificate, hashed with SHA-256.
//
// A serial number is unique only WITHIN an issuer, which is exactly why CertID
// carries the issuer name and key hashes alongside it. Keying on the serial
// alone let one issuer's verdict answer for another's, in both directions — the
// dangerous one being a cached "good" admitting a genuinely revoked certificate
// from a different CA without a single responder query. Sequential serials are
// the norm in enterprise PKI, so the collision is ordinary, not exotic.
func certKey(leaf, issuer *x509.Certificate) string {
	name := sha256.Sum256(issuer.RawSubject)
	key := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(name[:]) + ":" + hex.EncodeToString(key[:]) + ":" + leaf.SerialNumber.Text(16)
}

// checkCached returns (revoked, failClosed, found). If found, the caller can
// return early. failClosed distinguishes a cached fail-closed verdict (no
// responder produced a usable verdict) from a cached confirmed revocation, so
// the caller can keep the fail-closed counter/timestamp current across the
// whole outage rather than only at the first cache miss.
func (oc *Checker) checkCached(key string) (revoked, failClosed, found bool) {
	oc.mu.RLock()
	entry, ok := oc.cache[key]
	oc.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.revoked, entry.failClosed, true
	}
	return false, false, false
}

// cacheResult stores an OCSP result and evicts if needed.
//
// The TTL is the EARLIER of the configured maximum and the responder's own
// authorization deadline (`validUntil`, zero when there is none). Freshness was
// previously checked only at the moment of receipt and every confirmed verdict
// then cached for the full cacheTTL, so a "good" whose NextUpdate was a minute
// away kept admitting the certificate for another 59 minutes after the
// responder stopped vouching for it — the replay window CHAOS-65 closed on the
// wire, reopened in the cache (Codex review, PR #1369). A verdict already at or
// past its deadline is not cached at all: the next handshake re-queries, which
// is exactly right for a response at its edge.
//
// A fail-closed verdict keeps the short indeterminateTTL so outage recovery
// tracks the responder rather than being pinned for the full cacheTTL
// (CHAOS-04 outage amplification).
func (oc *Checker) cacheResult(key string, revoked, failClosed bool, validUntil time.Time) {
	oc.mu.Lock()
	if len(oc.cache) >= cacheMaxSize {
		// Evict expired entries first, then oldest 10% if still over capacity.
		now := time.Now()
		for k, e := range oc.cache {
			if now.After(e.expiresAt) {
				delete(oc.cache, k)
			}
		}
		if len(oc.cache) >= cacheMaxSize {
			count := 0
			for k := range oc.cache {
				delete(oc.cache, k)
				count++
				if count >= cacheMaxSize/10 {
					break
				}
			}
		}
	}
	ttl := cacheTTL
	switch {
	case failClosed:
		ttl = indeterminateTTL
	case !validUntil.IsZero():
		if remaining := time.Until(validUntil); remaining < ttl {
			ttl = remaining
		}
	}
	if ttl <= 0 {
		oc.mu.Unlock()
		return
	}
	oc.cache[key] = &cacheEntry{
		revoked:    revoked,
		failClosed: failClosed,
		expiresAt:  time.Now().Add(ttl),
	}
	oc.mu.Unlock()
}

// VerifyPeerCertificate is a tls.Config.VerifyPeerCertificate callback that
// checks OCSP revocation status for the peer's leaf certificate.
func (oc *Checker) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if !oc.Enabled() || len(rawCerts) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("ocsp: parse leaf: %w", err)
	}

	issuer := resolveIssuer(rawCerts, verifiedChains)
	if issuer == nil {
		return nil // can't check without issuer; fail-open for OCSP
	}

	key := certKey(leaf, issuer)
	serialHex := leaf.SerialNumber.Text(16)

	if revoked, failClosed, found := oc.checkCached(key); found {
		if revoked {
			if failClosed {
				// Sustained outage: the cache short-circuits checkResponders,
				// so without this the fail-closed counter/timestamp would
				// reflect only the FIRST cache miss and the panel would
				// under-report a still-ongoing outage. Count every cached
				// fail-closed block and keep last-occurrence current.
				oc.failClosedTotal.Add(1)
				oc.lastFailClosedUTC.Store(time.Now().Unix())
				return fmt.Errorf("ocsp: certificate %s is revoked (fail-closed, cached)", serialHex)
			}
			return fmt.Errorf("ocsp: certificate %s is revoked (cached)", serialHex)
		}
		return nil
	}

	// resolve single-flights the responder query and caches its verdict; the
	// counters for the first-miss path are incremented inside checkResponders.
	revoked, failClosed := oc.resolve(key, leaf, issuer)

	if revoked {
		if failClosed {
			return fmt.Errorf("ocsp: certificate %s revocation status unavailable (no responder returned a usable verdict) — failing closed", serialHex)
		}
		return fmt.Errorf("ocsp: certificate %s is revoked", serialHex)
	}
	return nil
}

// resolve runs (or joins) exactly one responder query per certificate.
//
// The leader publishes its verdict to every follower on EVERY exit path,
// panic included: a leader that died without closing the channel would strand
// its followers on it forever, turning a bounded responder fault into a
// permanent request-plane hang no upstream recover() can undo (the defect
// CHAOS-60 introduced inside its own fix and caught there).
func (oc *Checker) resolve(key string, leaf, issuer *x509.Certificate) (revoked, failClosed bool) {
	oc.flightMu.Lock()
	if f, ok := oc.inflight[key]; ok {
		oc.flightMu.Unlock()
		oc.singleFlightTotal.Add(1)
		<-f.done
		oc.noteBorrowedFailClosed(f.revoked, f.failClosed)
		return f.revoked, f.failClosed
	}
	// The caller's cache lookup happened before this lock. A handshake that
	// missed the cache can be descheduled while the leader finishes and removes
	// its flight, so without this second look it would open a NEW flight and
	// issue a redundant query for a verdict already cached — defeating the
	// collapsing precisely during the cold-cache burst it exists for (Codex
	// review, PR #1369). Lock order is flightMu → mu, the only order this file
	// ever takes.
	if cachedRevoked, cachedFailClosed, found := oc.checkCached(key); found {
		oc.flightMu.Unlock()
		oc.noteBorrowedFailClosed(cachedRevoked, cachedFailClosed)
		return cachedRevoked, cachedFailClosed
	}
	f := &flight{done: make(chan struct{}), revoked: true, failClosed: true}
	oc.inflight[key] = f
	oc.flightMu.Unlock()

	published := false
	defer func() {
		if published {
			f.revoked, f.failClosed = revoked, failClosed
		} // otherwise the flight keeps its fail-closed defaults
		oc.flightMu.Lock()
		delete(oc.inflight, key)
		oc.flightMu.Unlock()
		close(f.done)
	}()

	var validUntil time.Time
	revoked, failClosed, validUntil = oc.checkResponders(leaf, issuer)
	oc.cacheResult(key, revoked, failClosed, validUntil)
	published = true
	return revoked, failClosed
}

// noteBorrowedFailClosed charges the fail-closed accounting for a handshake
// refused on a verdict somebody else produced — a follower of an in-flight
// query, or a late arrival that found the leader's verdict already cached.
//
// failClosedTotal means "handshakes refused for want of a usable verdict", and
// the cached-fail-closed path in VerifyPeerCertificate already charges every
// hit for exactly this reason: collapsing N queries into one must not also
// collapse N refusals into one, or a fail-closed storm under-reports itself by
// however many handshakes happened to arrive together — worst exactly when the
// storm is worst. revokedTotal is deliberately NOT charged here: it counts
// responder CONFIRMATIONS, and the cached confirmed-revocation path does not
// charge it either.
func (oc *Checker) noteBorrowedFailClosed(revoked, failClosed bool) {
	if revoked && failClosed {
		oc.failClosedTotal.Add(1)
		oc.lastFailClosedUTC.Store(time.Now().Unix())
	}
}

// checkResponders queries the OCSP responders listed in the leaf certificate,
// bounded by maxResponders entries inside one queryBudget.
//
// Fail-closed: returns revoked=true unless some responder produced an
// AFFIRMATIVE verdict. "Affirmative" is Good or Revoked and nothing else — a
// response that cannot be bound to this certificate, one outside its validity
// window, and an explicit "unknown" are all discarded, each under its own
// counter. failClosed reports whether the revoked verdict came from that path
// rather than a confirmed revocation, so the caller can cache the reason on the
// short indeterminateTTL and keep the fail-closed observability current.
func (oc *Checker) checkResponders(leaf, issuer *x509.Certificate) (revoked, failClosed bool, expires time.Time) {
	responders := leaf.OCSPServer
	if len(responders) == 0 {
		return false, false, time.Time{} // nothing to check — unchanged
	}
	if len(responders) > maxResponders {
		oc.truncatedTotal.Add(1)
		if oc.allowTruncationLog(time.Now()) {
			obs.Printf("OCSP: certificate %s lists %d responders — consulting the first %d (see culvert_ocsp_responders_truncated_total for the rate)",
				leaf.SerialNumber.Text(16), len(responders), maxResponders)
		}
		responders = responders[:maxResponders]
	}

	ctx, cancel := context.WithTimeout(context.Background(), queryBudget)
	defer cancel()

	// REVOKED WINS OVER GOOD, so a Good does NOT short-circuit the loop.
	//
	// The peer writes the AIA list AND its order, so returning on the first
	// Good hands the verdict to the party being checked — this sweep's own
	// finding, reintroduced as a side effect of bounding the loop (Codex
	// review, PR #1369). It also accepts a certificate during ordinary
	// responder replication lag. The pre-CHAOS-65 loop continued past every
	// non-revoked answer and denied if ANY responder reported revocation; that
	// posture is restored, now inside the bounded list and the one envelope.
	// A cost change must not quietly move a security posture.
	var (
		sawGood        bool
		goodValidUntil time.Time
	)
	for _, responderURL := range responders {
		status, validUntil, err := oc.queryOCSP(ctx, leaf, issuer, responderURL)
		if err != nil {
			if ctx.Err() != nil {
				break // the envelope is spent; the remaining entries get nothing
			}
			continue
		}
		switch status {
		case cryptoocsp.Revoked:
			oc.revokedTotal.Add(1)
			return true, false, validUntil // confirmed revoked — nothing outranks it
		case cryptoocsp.Good:
			// Remember it, keep asking. The EARLIEST deadline among the Good
			// answers is the one the cache may rely on.
			if !sawGood || validUntil.Before(goodValidUntil) {
				goodValidUntil = validUntil
			}
			sawGood = true
		default:
			// Unknown: the issuer does not recognise this certificate. Under
			// the CA/Browser Forum baseline requirements a CA must not answer
			// "good" for a certificate it never issued, so "unknown" is the
			// answer a mis-issued or forged certificate draws. It is not a
			// pass; try the next responder, then fail closed.
			oc.unknownTotal.Add(1)
		}
	}
	if sawGood {
		return false, false, goodValidUntil
	}

	obs.Printf("OCSP: no usable verdict from %d responder(s) for cert %s — fail-closed (treating as revoked)",
		len(responders), leaf.SerialNumber.Text(16))
	oc.failClosedTotal.Add(1)
	oc.lastFailClosedUTC.Store(time.Now().Unix())
	return true, true, time.Time{}
}

// queryOCSP sends an OCSP request to one responder and returns the status it
// affirmed for leaf. An error means this responder produced nothing usable.
func (oc *Checker) queryOCSP(ctx context.Context, leaf, issuer *x509.Certificate, responderURL string) (int, time.Time, error) {
	// SSRF guard, inline so CodeQL sees it on the path to the request (repo
	// convention). The URL is read from the PEER's certificate, so any operator
	// of any destination this gateway reaches can name an address inside the
	// trust boundary and have the proxy POST to it.
	u, err := url.Parse(responderURL)
	if err != nil {
		oc.blockedTotal.Add(1)
		return 0, time.Time{}, fmt.Errorf("ocsp: unparseable responder URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		oc.blockedTotal.Add(1)
		return 0, time.Time{}, fmt.Errorf("ocsp: responder scheme %q not allowed", u.Scheme)
	}
	// PrivateHostContext, not PrivateHost: the plain form resolves under
	// context.Background(), so on a wedged resolver the GUARD becomes the
	// unbounded call inside a TLS handshake on the request goroutine — the
	// CHAOS-64 fault re-imported through the fix for CHAOS-65's SSRF hole.
	// The budget it runs under is the same envelope the query itself gets.
	if err := ssrf.PrivateHostContext(ctx, u.Host); err != nil {
		// blockedTotal is an ACCUSATION — its metric reason is
		// `responder_blocked` and the runbook tells the operator it means this
		// responder resolved to a private address. So it is charged only for a
		// demonstrated refusal (errors.Is ErrBlocked), never for the guard's
		// other failure mode: a DNS outage, or this query's own budget expiring
		// mid-lookup, where nothing about the host was established.
		//
		// Both still fail closed and both still skip the responder — only the
		// counter distinguishes them. A resolution failure is an UNREACHABLE
		// responder and is already accounted as such by the fail-closed path,
		// so it gets no `response_rejected_total` reason: no response existed
		// to reject (Codex review, PR #1369).
		//
		// This is the same rule as the `not_for_certificate` finding earlier in
		// this PR, one counter over: the surfaces that accuse have to be right,
		// because their whole value is being believed.
		if errors.Is(err, ssrf.ErrBlocked) {
			oc.blockedTotal.Add(1)
			return 0, time.Time{}, fmt.Errorf("ocsp: responder blocked: %w", err)
		}
		return 0, time.Time{}, fmt.Errorf("ocsp: responder unresolvable: %w", err)
	}

	ocspReq, err := cryptoocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("ocsp create request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, responderURL, bytes.NewReader(ocspReq))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("ocsp http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := responderClient.Do(httpReq) // #nosec G107 -- scheme + ssrf.PrivateHost guard above, SSRF-controlled dialer below
	if err != nil {
		// A dial-time refusal is the SSRF guard doing the job the pre-flight
		// check cannot: ssrf.SafeDialContext re-checks the resolved address
		// immediately before connect(2), catching a responder host that
		// answered public to the pre-check and private to the dial. That is
		// the DNS-rebinding attack the dialer exists for, and charging it to
		// the generic transport branch left it invisible on the very surface
		// built to expose it (Codex review, PR #1369).
		if errors.Is(err, ssrf.ErrBlocked) {
			oc.blockedTotal.Add(1)
			return 0, time.Time{}, fmt.Errorf("ocsp: responder blocked at dial: %w", err)
		}
		return 0, time.Time{}, fmt.Errorf("ocsp request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body, best-effort close

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("ocsp read response: %w", err)
	}

	// ParseResponseForCert, never ParseResponse: with a nil certificate the
	// library takes SingleResponse[0] and never matches the serial, so a
	// genuine CA-signed response about ANY other certificate of the same issuer
	// — trivially obtained by asking that CA about a live certificate — was
	// accepted as this certificate's verdict. The peer picks the responder, so
	// the peer picked the answer.
	ocspResp, err := cryptoocsp.ParseResponseForCert(respBytes, leaf, issuer)
	if err != nil {
		oc.noteUnusableResponse(respBytes, leaf, issuer)
		return 0, time.Time{}, fmt.Errorf("ocsp parse response: %w", err)
	}
	now := time.Now()
	if err := responderAuthorized(ocspResp, issuer, now); err != nil {
		oc.unauthorizedTotal.Add(1)
		return 0, time.Time{}, err
	}
	if !responseFresh(ocspResp, now) {
		oc.staleTotal.Add(1)
		return 0, time.Time{}, fmt.Errorf("ocsp: response for %s is outside its validity window", leaf.SerialNumber.Text(16))
	}
	return ocspResp.Status, responseValidUntil(ocspResp, issuer), nil
}

// errUnauthorizedResponder is returned for a response whose signer is not an
// RFC 6960 §4.2.2.2 authorized responder for this issuer.
var errUnauthorizedResponder = errors.New("ocsp: response signer is not an authorized responder")

// responderAuthorized enforces RFC 6960 §4.2.2.2 on the party that signed the
// response. It is the other half of binding a response to a certificate, and
// without it the binding buys nothing.
//
// x/crypto verifies an embedded responder certificate by asking only whether
// the ISSUER signed it — never whether it carries id-kp-OCSPSigning. The peer's
// own leaf is, by definition, a certificate the issuer signed, and the peer
// holds its private key. So a peer could sign a fresh "good" response about its
// OWN serial, embed its own leaf as the responder, serve it from the responder
// URL in its own AIA, and have a REVOKED certificate accepted — needing no
// response from anyone else at all. That is strictly easier than the borrowed-
// response vector CHAOS-65 closed, and it survived it (Codex review, PR #1369).
//
// Two signers are authorized and nothing else is: the issuer itself (the
// library has already verified that signature), and a delegate the issuer
// signed that carries the OCSP-signing EKU and is inside its own validity
// window. Delegated responders are ordinary, so refusing every embedded
// certificate is not an option — pinned by
// TestChaos65_Control_AuthorizedDelegateIsStillAccepted.
//
// The delegate's own revocation status is deliberately NOT checked: that is the
// infinite regress RFC 6960 §4.2.2.2.1 answers with id-pkix-ocsp-nocheck, and
// the validity window is the part that is both cheap and sound.
func responderAuthorized(resp *cryptoocsp.Response, issuer *x509.Certificate, now time.Time) error {
	if resp.Certificate == nil || resp.Certificate.Equal(issuer) {
		return nil // signed by the issuer itself
	}
	if !slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		// ExtKeyUsageAny is deliberately NOT accepted: RFC 6960 asks for
		// id-kp-OCSPSigning specifically, and honouring "any" would re-admit
		// every ordinary leaf the issuer ever signed.
		return fmt.Errorf("%w: no id-kp-OCSPSigning extended key usage", errUnauthorizedResponder)
	}
	if now.Before(resp.Certificate.NotBefore.Add(-responseClockSkew)) ||
		now.After(resp.Certificate.NotAfter.Add(responseClockSkew)) {
		return fmt.Errorf("%w: delegate outside its validity window", errUnauthorizedResponder)
	}
	return nil
}

// noteUnusableResponse attributes a response that would not parse for this
// certificate, distinguishing a broken responder from a hostile one.
//
// `not_for_certificate` is an ACCUSATION — its metric help and the admin
// panel's red banner both read it as evidence that something is answering with
// borrowed responses — so it is charged only when that is demonstrably what
// happened: the response parses, its signature verifies against the issuer, and
// the serial it carries belongs to someone else. Everything else (an HTML error
// page, truncated DER, a bad signature) is a broken responder and counts as
// malformed. Charging every parse failure to the accusation meant an ordinary
// 502 raised a standing claim of attack, on a surface whose whole job is to be
// believed (Codex review, PR #1369).
//
// The re-parse runs only on the failure path, and it is deliberately the only
// way to tell the two apart: the library checks the serial BEFORE it verifies
// any signature, so its serial-mismatch error on its own proves nothing about
// who signed. A response carrying multiple statuses cannot be re-parsed this
// way and is counted as malformed — an undercount of the accusation, which is
// the only direction it may err in.
func (oc *Checker) noteUnusableResponse(body []byte, leaf, issuer *x509.Certificate) {
	if resp, err := cryptoocsp.ParseResponseForCert(body, nil, issuer); err == nil &&
		resp.SerialNumber != nil && resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		oc.notForCertTotal.Add(1)
		return
	}
	oc.malformedTotal.Add(1)
}

// responseValidUntil is the instant past which this response would no longer be
// accepted if it were parsed again — the EARLIER of what the assertion claims
// and what the signer's own authority permits.
//
// Both terms are needed because both checks run at PARSE time while a verdict
// outlives its parse inside the cache. responseFresh bounds the assertion;
// responderAuthorized bounds the signer. Taking only the first meant a delegate
// expiring in two minutes could sign a "good" whose NextUpdate was days out: the
// handshake that parsed it cached the verdict, and later handshakes kept
// admitting the certificate for the rest of the cache TTL even though a re-parse
// would have refused the identical bytes as an unauthorized responder (Codex
// review, PR #1369).
//
// That is the same shape as the NextUpdate finding this function was added for —
// a rule enforced on the wire and dropped one layer down — so the cap is
// expressed as "when would responderAuthorized start refusing", and MIRRORS its
// branch structure exactly rather than approximating it. A response signed by
// the issuer itself takes no signer deadline, because responderAuthorized
// applies no window check there: capping on the issuer's own NotAfter would make
// the cache refuse verdicts the parser still accepts, which costs responder
// queries and buys nothing (an expired issuer fails the chain long before this).
func responseValidUntil(resp *cryptoocsp.Response, issuer *x509.Certificate) time.Time {
	until := resp.ThisUpdate.Add(maxResponseAge)
	if !resp.NextUpdate.IsZero() {
		until = resp.NextUpdate.Add(responseClockSkew)
	}
	if resp.Certificate != nil && !resp.Certificate.Equal(issuer) {
		// Same skew allowance responderAuthorized grants, so the cache expires
		// at precisely the instant a re-parse would begin rejecting.
		if signerUntil := resp.Certificate.NotAfter.Add(responseClockSkew); signerUntil.Before(until) {
			until = signerUntil
		}
	}
	return until
}

// responseFresh reports whether resp is currently authoritative.
//
// OCSP requests here carry no nonce and the exchange rides plaintext HTTP, so
// ThisUpdate/NextUpdate are the only replay defence there is: without this
// check a "good" response captured before the certificate was revoked stays
// valid forever. The skew is tolerated in both directions — a clock rollback on
// either end is a fault, not an attack, and must not take revocation checking
// down — but an unbounded future ThisUpdate is refused.
func responseFresh(resp *cryptoocsp.Response, now time.Time) bool {
	if resp.ThisUpdate.IsZero() {
		return false
	}
	if resp.ThisUpdate.After(now.Add(responseClockSkew)) {
		return false // produced in the future
	}
	if !resp.NextUpdate.IsZero() {
		return now.Before(resp.NextUpdate.Add(responseClockSkew))
	}
	// No NextUpdate: RFC 6960 §2.4 reads that as "newer information is always
	// available", which without a ceiling is an unbounded replay window.
	return now.Sub(resp.ThisUpdate) <= maxResponseAge
}

// CleanupCache evicts expired entries from the OCSP cache.
func (oc *Checker) CleanupCache() {
	oc.mu.Lock()
	now := time.Now()
	for k, e := range oc.cache {
		if now.After(e.expiresAt) {
			delete(oc.cache, k)
		}
	}
	oc.mu.Unlock()
}
