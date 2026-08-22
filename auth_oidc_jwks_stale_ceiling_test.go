package main

// auth_oidc_jwks_stale_ceiling_test.go — security-regression gates for the HARD
// ceiling on stale-JWKS trust (SEC-JWKS-1).
//
// Background. CHAOS-49 (PR #1117) correctly stopped a non-200 / keyless JWKS
// response from WIPING the cached key set, because wiping it also destroys
// getKey's "return the stale key rather than failing" fallback and produces a
// silent fleet-wide SSO outage. What it did not add was a bound on how long that
// fallback may keep authenticating: after the fix, a cache that can never be
// refreshed keeps validating ID tokens with the same keys FOREVER.
//
// That inverts the security meaning of an IdP key revocation. Removing a
// compromised signing key from the JWKS document is the IdP's only revocation
// lever for already-minted tokens; a relying party that keeps the withdrawn key
// indefinitely has silently opted out of it. The window closes only when a
// refresh succeeds — and the refresh is exactly what is broken in this scenario.
//
// The gates below pin the resulting contract:
//
//	SEC-JWKS-1a  inside the ceiling, a stale key still authenticates (the
//	             CHAOS-49 availability win is preserved — blips, rate-limiter
//	             bodies and multi-hour outages must not cause an SSO outage)
//	SEC-JWKS-1b  past the ceiling, a stale key is REFUSED (fail closed)
//	SEC-JWKS-1c  a successful refresh re-arms the full window (recovery is on
//	             OBSERVED evidence — a fetch that actually returned keys — never
//	             on elapsed time)
//	SEC-JWKS-1d  the ceiling never applies to a FRESH key set, whatever the
//	             refresh cadence
//	SEC-JWKS-1e  the constants stay ordered so the ceiling cannot be narrower
//	             than the ordinary TTL

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// jwksBrokenAfterFirst serves one good key set and then fails every subsequent
// refresh with a 503 — the shape of an IdP whose JWKS endpoint has gone away
// (DNS, egress policy, edge stub, expired origin cert) after a key rotation.
func jwksBrokenAfterFirst(t *testing.T, kid string, key *rsa.PublicKey) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var broken atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if broken.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(jwksBodyFor(t, kid, key)))
	}))
	t.Cleanup(srv.Close)
	return srv, &broken
}

// ageCache rewinds the cache's last SUCCESSFUL fetch by age and clears the
// negative window so the next lookup genuinely attempts a refresh.
func ageCache(j *jwksCache, age time.Duration) {
	j.mu.Lock()
	j.fetchedAt = time.Now().Add(-age)
	j.lastAttempt = time.Time{}
	j.mu.Unlock()
}

// ── SEC-JWKS-1a: inside the ceiling, stale still serves ─────────────────────

// The CHAOS-49 availability contract. A JWKS endpoint that has been down for
// hours must not take admin SSO and the captive portal down with it.
func TestJWKS_StaleKeyStillServedInsideCeiling(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	srv, broken := jwksBrokenAfterFirst(t, "kid-1", &key.PublicKey)

	j := jwksCacheAgainst(t, srv)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("initial getKey: %v", err)
	}

	broken.Store(true)
	// Well past the ordinary TTL, comfortably inside the ceiling.
	ageCache(j, jwksStaleMaxAge/2)

	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("a stale key inside the trust ceiling was refused — this is the "+
			"CHAOS-49 SSO-outage regression: %v", err)
	}
}

// ── SEC-JWKS-1b: past the ceiling, stale is refused ─────────────────────────

// The security half. Once refreshes have been failing for longer than the
// ceiling, the cached key set is no longer evidence of anything the IdP still
// vouches for: a key withdrawn from the JWKS document (the revocation lever for
// an already-minted token) would keep validating tokens indefinitely. Fail
// closed instead.
func TestJWKS_StaleKeyRefusedPastCeiling(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	srv, broken := jwksBrokenAfterFirst(t, "kid-1", &key.PublicKey)

	j := jwksCacheAgainst(t, srv)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("initial getKey: %v", err)
	}

	broken.Store(true)
	ageCache(j, jwksStaleMaxAge+time.Hour)

	if _, err := j.getKey("kid-1"); err == nil {
		t.Fatal("a key set that has been unrefreshable for longer than the trust " +
			"ceiling still authenticated a token — an IdP key revocation cannot " +
			"take effect on this node (fail-open on revocation)")
	}
}

// The refusal must hold for the THROTTLED path too. Past the ceiling, a lookup
// that is suppressed by the negative window must still fail closed rather than
// fall through to the stale key: the throttle is a rate control, never a licence
// to extend the trust window.
func TestJWKS_StaleKeyRefusedPastCeilingWhenThrottled(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	srv, broken := jwksBrokenAfterFirst(t, "kid-1", &key.PublicKey)

	j := jwksCacheAgainst(t, srv)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("initial getKey: %v", err)
	}

	broken.Store(true)
	j.mu.Lock()
	j.fetchedAt = time.Now().Add(-(jwksStaleMaxAge + time.Hour))
	j.lastAttempt = time.Now() // inside the negative window ⇒ refreshOnce throttles
	j.mu.Unlock()

	if _, err := j.getKey("kid-1"); err == nil {
		t.Fatal("a throttled lookup past the trust ceiling served the stale key — " +
			"the refresh rate limiter must not widen the trust window")
	}
}

// ── SEC-JWKS-1c: recovery is on observed evidence ───────────────────────────

// A successful refresh — one that actually returned usable keys — is the only
// thing that re-arms the window. This mirrors the recovery discipline used by
// storage_health.go and the identity_backend contract row: never on elapsed
// time, always on observed evidence.
func TestJWKS_SuccessfulRefreshReArmsTrustWindow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	srv, broken := jwksBrokenAfterFirst(t, "kid-1", &key.PublicKey)

	j := jwksCacheAgainst(t, srv)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("initial getKey: %v", err)
	}

	// Past the ceiling with a broken endpoint: refused.
	broken.Store(true)
	ageCache(j, jwksStaleMaxAge+time.Hour)
	if _, err := j.getKey("kid-1"); err == nil {
		t.Fatal("expected a refusal past the ceiling")
	}

	// The IdP comes back. The next lookup must succeed AND reset the window.
	broken.Store(false)
	j.mu.Lock()
	j.lastAttempt = time.Time{} // clear the negative window so a refresh is attempted
	j.mu.Unlock()
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("a recovered JWKS endpoint did not re-arm the trust window: %v", err)
	}

	// Break it again but stay inside the ceiling measured from the NEW fetch:
	// the key must serve again, proving fetchedAt was actually advanced.
	broken.Store(true)
	ageCache(j, jwksStaleMaxAge/2)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("the window was not re-armed by the successful refresh: %v", err)
	}
}

// ── SEC-JWKS-1d: a fresh key set is never subject to the ceiling ────────────

func TestJWKS_FreshKeySetNeverRefused(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	srv, _ := jwksBrokenAfterFirst(t, "kid-1", &key.PublicKey)

	j := jwksCacheAgainst(t, srv)
	for i := 0; i < 3; i++ {
		if _, err := j.getKey("kid-1"); err != nil {
			t.Fatalf("fresh lookup %d refused: %v", i, err)
		}
	}
}

// ── SEC-JWKS-1e: constant ordering ──────────────────────────────────────────

// The ceiling must sit strictly above the ordinary TTL, and the refresh floor
// strictly below it, or the cache would either fail closed on every ordinary
// refresh cycle or never retry inside its own trust window.
func TestJWKS_TrustWindowConstantsAreOrdered(t *testing.T) {
	if jwksMinRefreshInterval >= jwksCacheTTL {
		t.Fatalf("jwksMinRefreshInterval (%s) must stay well under jwksCacheTTL (%s) "+
			"or a genuine key rotation is never picked up", jwksMinRefreshInterval, jwksCacheTTL)
	}
	if jwksCacheTTL >= jwksStaleMaxAge {
		t.Fatalf("jwksStaleMaxAge (%s) must exceed jwksCacheTTL (%s) or an ordinary "+
			"refresh cycle would fail closed", jwksStaleMaxAge, jwksCacheTTL)
	}
}

// ── SEC-JWKS-1f: the ceiling breach is observable, not just logged ──────────

// The stale-trust ceiling was previously visible only via a rate-limited log
// line — an admin without log/Grafana access had no way to discover that ID-
// token validation for a provider had started failing closed. staleCeilingStatus
// is the operator-facing signal (consumed by checkOIDCJWKSTrust in
// diagnostics.go); it must flip true exactly when getKey starts refusing and
// flip back false the moment a refresh actually recovers — never on elapsed
// time alone.
func TestJWKS_StaleCeilingStatusReflectsRefusalAndRecovery(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	srv, broken := jwksBrokenAfterFirst(t, "kid-1", &key.PublicKey)

	j := jwksCacheAgainst(t, srv)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("initial getKey: %v", err)
	}
	if breached, _, _ := j.staleCeilingStatus(); breached {
		t.Fatal("a freshly-fetched cache reported the stale ceiling as breached")
	}

	// Inside the ceiling: still degraded-but-serving, not yet a breach.
	broken.Store(true)
	ageCache(j, jwksStaleMaxAge/2)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("unexpected refusal inside the ceiling: %v", err)
	}
	if breached, _, _ := j.staleCeilingStatus(); breached {
		t.Fatal("staleCeilingStatus reported a breach while still inside the trust window")
	}

	// Past the ceiling: getKey refuses, and the status must say so.
	ageCache(j, jwksStaleMaxAge+time.Hour)
	if _, err := j.getKey("kid-1"); err == nil {
		t.Fatal("expected a refusal past the ceiling")
	}
	breached, since, uri := j.staleCeilingStatus()
	if !breached {
		t.Fatal("getKey refused past the ceiling but staleCeilingStatus did not report a breach")
	}
	if since < jwksStaleMaxAge {
		t.Fatalf("staleCeilingStatus reported since=%s, want >= the %s ceiling", since, jwksStaleMaxAge)
	}
	if uri == "" {
		t.Fatal("staleCeilingStatus did not report the JWKS URI")
	}

	// Recovery is on OBSERVED evidence only: a successful refresh must clear it.
	broken.Store(false)
	j.mu.Lock()
	j.lastAttempt = time.Time{}
	j.mu.Unlock()
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("recovered endpoint still refused: %v", err)
	}
	if breached, _, _ := j.staleCeilingStatus(); breached {
		t.Fatal("staleCeilingStatus still reported a breach after a successful refresh")
	}
}
