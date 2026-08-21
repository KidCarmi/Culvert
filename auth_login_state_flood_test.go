package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/authstate"
)

// auth_login_state_flood_test.go — regression gates for the unauthenticated
// login-state eviction defect.
//
// Culvert mints OIDC PKCE / SAML AuthnRequest state SPECULATIVELY, while
// resolving a captive-portal login URL for a client that has not authenticated
// yet. Both stores are hard-capped, and both used to evict "one arbitrary
// entry" — a single-key map range, i.e. a uniformly random LIVE entry.
//
// That made an anonymous request a weapon against other users' logins: flood
// the no-credentials path, and every insertion past the cap destroyed some
// other browser's in-flight state, so real callbacks came back "invalid or
// expired state". Failure was closed (no bypass), but SSO was remotely
// deniable by anyone who could reach the gateway.
//
// These gates pin the fixed property end to end, through the real request
// path, not just at the store's unit boundary.

// floodClientRequest is one unauthenticated proxied request from addr, shaped
// the way the Default no-credentials arm requires to reach the captive-portal
// redirect (non-CONNECT + a Mozilla User-Agent — browserRedirectEligibleLegacy).
func floodClientRequest(t *testing.T, addr string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://intranet.example/page", http.NoBody)
	r.RemoteAddr = addr
	r.Header.Set("User-Agent", "Mozilla/5.0 (flood)")
	return r
}

// TestLoginState_UnauthenticatedFloodCannotEvictAnotherClient is the headline
// gate: one source hammering the login path must not be able to destroy a
// different client's in-flight PKCE state.
//
// It drives globalPKCEStore exactly as CaptiveLoginURL does — same store, same
// client attribution helper — and floods it by two full store capacities,
// which under the previous arbitrary-eviction policy left the victim's
// survival probability below one in a million.
func TestLoginState_UnauthenticatedFloodCannotEvictAnotherClient(t *testing.T) {
	orig := globalPKCEStore
	globalPKCEStore = newPKCEStore()
	t.Cleanup(func() { globalPKCEStore = orig })

	victim := floodClientRequest(t, "10.20.30.40:51000")
	globalPKCEStore.Set("victim-state", authStateClientKey(victim), &pkceEntry{
		verifier:   "victim-verifier",
		nonce:      "victim-nonce",
		relayURL:   "http://intranet.example/page",
		providerID: "corp-oidc",
	})

	attacker := floodClientRequest(t, "198.51.100.7:40000")
	attackerKey := authStateClientKey(attacker)
	for i := range 2 * pkceStoreMax {
		globalPKCEStore.Set(fmt.Sprintf("flood-%d", i), attackerKey, &pkceEntry{providerID: "corp-oidc"})
	}

	entry, ok := globalPKCEStore.Peek("victim-state")
	if !ok {
		t.Fatal("an unauthenticated flood from one source evicted another client's in-flight login state — SSO is remotely deniable")
	}
	if entry.verifier != "victim-verifier" || entry.nonce != "victim-nonce" {
		t.Fatalf("victim entry corrupted: %+v", entry)
	}
	if globalPKCEStore.Len() > pkceStoreMax {
		t.Errorf("store exceeded its cap: %d > %d", globalPKCEStore.Len(), pkceStoreMax)
	}
	if globalPKCEStore.Evictions() == 0 {
		t.Error("expected the flood to have been absorbed by evictions of its own entries")
	}
}

// TestLoginState_SAMLFloodCannotEvictAnotherClient is the same property on the
// SAML half. The two stores are separate instances of the same engine, and a
// fix that only reached one of them would leave a SAML deployment exposed.
func TestLoginState_SAMLFloodCannotEvictAnotherClient(t *testing.T) {
	orig := globalSAMLStateStore
	globalSAMLStateStore = newSAMLStateStore()
	t.Cleanup(func() { globalSAMLStateStore = orig })

	victim := floodClientRequest(t, "10.20.30.40:51000")
	globalSAMLStateStore.Set("victim-relay", authStateClientKey(victim), &samlStateEntry{
		requestID:  "victim-request",
		relayURL:   "http://intranet.example/page",
		providerID: "corp-saml",
	})

	attackerKey := authStateClientKey(floodClientRequest(t, "198.51.100.7:40000"))
	for i := range 2 * samlStateStoreMax {
		globalSAMLStateStore.Set(fmt.Sprintf("flood-%d", i), attackerKey, &samlStateEntry{providerID: "corp-saml"})
	}

	entry, ok := globalSAMLStateStore.Peek("victim-relay")
	if !ok {
		t.Fatal("an unauthenticated flood from one source evicted another client's in-flight SAML state")
	}
	if entry.requestID != "victim-request" {
		t.Fatalf("victim entry corrupted: %+v", entry)
	}
}

// TestLoginState_IPv6FloodCollapsesToItsPrefix closes the obvious escape: a
// host with a /64 owns 2^64 addresses, so keying fairness on the full IPv6
// address would hand one machine an unlimited supply of buckets. The whole /64
// must count as one client.
func TestLoginState_IPv6FloodCollapsesToItsPrefix(t *testing.T) {
	orig := globalPKCEStore
	globalPKCEStore = newPKCEStore()
	t.Cleanup(func() { globalPKCEStore = orig })

	victim := floodClientRequest(t, "[2001:db8:1::5]:51000")
	globalPKCEStore.Set("victim-state", authStateClientKey(victim), &pkceEntry{providerID: "corp-oidc"})

	for i := range 2 * pkceStoreMax {
		r := floodClientRequest(t, fmt.Sprintf("[2001:db8:beef::%x]:40000", i+1))
		globalPKCEStore.Set(fmt.Sprintf("flood-%d", i), authStateClientKey(r), &pkceEntry{providerID: "corp-oidc"})
	}

	if _, ok := globalPKCEStore.Peek("victim-state"); !ok {
		t.Fatal("a flood rotating addresses inside one /64 evicted an unrelated client — the IPv6 prefix collapse is not in effect")
	}
	if n := globalPKCEStore.Clients(); n != 2 {
		t.Errorf("Clients = %d, want 2 (victim + one collapsed /64)", n)
	}
}

// TestLoginState_SpoofedForwardedHeaderDoesNotForkTheClientKey is the other
// escape: if the fairness key honoured X-Forwarded-For from an untrusted peer,
// a flooder could mint a fresh bucket per request and defeat fair share
// outright. realClientIP ignores XFF unless the peer is a configured trusted
// proxy — this pins that the login-state key inherits that gate.
func TestLoginState_SpoofedForwardedHeaderDoesNotForkTheClientKey(t *testing.T) {
	if err := SetTrustedProxyCIDRs(nil); err != nil {
		t.Fatalf("clear trusted proxies: %v", err)
	}
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(nil) })

	base := authStateClientKey(floodClientRequest(t, "198.51.100.7:40000"))
	if base != "198.51.100.7" {
		t.Fatalf("client key = %q, want the peer address", base)
	}
	for i := range 32 {
		r := floodClientRequest(t, "198.51.100.7:40000")
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.1.2.%d", i))
		if got := authStateClientKey(r); got != base {
			t.Fatalf("spoofed X-Forwarded-For %q forked the fairness key to %q", r.Header.Get("X-Forwarded-For"), got)
		}
	}
}

// TestLoginState_TrustedProxyForwardedHeaderIsHonoured is the positive half:
// behind a configured trusted proxy every client presents the proxy's peer
// address, so WITHOUT honouring X-Forwarded-For the whole population would
// collapse into one bucket and evict each other.
func TestLoginState_TrustedProxyForwardedHeaderIsHonoured(t *testing.T) {
	if err := SetTrustedProxyCIDRs([]string{"192.0.2.10/32"}); err != nil {
		t.Fatalf("set trusted proxies: %v", err)
	}
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(nil) })

	seen := make(map[string]bool)
	for i := range 8 {
		r := floodClientRequest(t, "192.0.2.10:40000")
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.1.2.%d", i))
		seen[authStateClientKey(r)] = true
	}
	if len(seen) != 8 {
		t.Fatalf("distinct client keys = %d, want 8 behind a trusted proxy: %v", len(seen), seen)
	}
}

// TestAuthStateClientKey_MalformedAddresses covers the degenerate inputs. An
// unresolvable address must yield a usable (empty) bucket key rather than
// panicking or leaking a port into the key space.
func TestAuthStateClientKey_MalformedAddresses(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{"ipv4 with port", "203.0.113.9:1234", "203.0.113.9"},
		{"ipv4 without port", "203.0.113.9", "203.0.113.9"},
		{"ipv6 with port", "[2001:db8:1:2:3:4:5:6]:443", "2001:db8:1:2::/64"},
		{"ipv4-mapped ipv6 canonicalises", "[::ffff:203.0.113.9]:443", "203.0.113.9"},
		{"garbage", "not-an-address", ""},
		{"empty", "", ""},
		{"port only", ":8080", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://x/", http.NoBody)
			r.RemoteAddr = c.addr
			if got := authStateClientKey(r); got != c.want {
				t.Errorf("authStateClientKey(%q) = %q, want %q", c.addr, got, c.want)
			}
		})
	}
	if got := authStateClientKey(nil); got != "" {
		t.Errorf("authStateClientKey(nil) = %q, want empty", got)
	}
}

// TestLoginState_ExpiredEntriesStillFailClosed guards the half that must NOT
// change: fairness is about who gets evicted, never about admitting state that
// should be rejected. An expired entry stays unusable.
func TestLoginState_ExpiredEntriesStillFailClosed(t *testing.T) {
	clock := time.Now().Add(-(pkceEntryTTL + time.Second))
	s := authstate.NewWithClock[*pkceEntry](pkceEntryTTL, pkceStoreMax, func() time.Time { return clock })
	s.Set("stale", "203.0.113.5", &pkceEntry{verifier: "v", providerID: "corp-oidc"})
	clock = time.Now()

	if _, ok := s.Peek("stale"); ok {
		t.Error("an expired PKCE entry must not be readable")
	}
	if _, ok := s.Pop("stale"); ok {
		t.Error("an expired PKCE entry must not be redeemable")
	}
}

// TestLoginState_MetricsExposeEvictionPressure pins the operator-facing signal.
// Silent eviction is what made the original defect invisible: logins failed
// with "invalid or expired state" and nothing counted it.
func TestLoginState_MetricsExposeEvictionPressure(t *testing.T) {
	orig := globalPKCEStore
	globalPKCEStore = newPKCEStore()
	t.Cleanup(func() { globalPKCEStore = orig })

	key := authStateClientKey(floodClientRequest(t, "198.51.100.7:40000"))
	for i := range pkceStoreMax + 25 {
		globalPKCEStore.Set(fmt.Sprintf("k%d", i), key, &pkceEntry{providerID: "corp-oidc"})
	}

	var buf strings.Builder
	liveFeedWritePrometheus(&buf)
	body := buf.String()

	for _, want := range []string{
		"culvert_login_state_entries{store=\"oidc_pkce\"}",
		"culvert_login_state_clients{store=\"oidc_pkce\"}",
		"culvert_login_state_evictions_total{store=\"oidc_pkce\"}",
		"culvert_login_state_evictions_total{store=\"saml\"}",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	if strings.Contains(body, "culvert_login_state_evictions_total{store=\"oidc_pkce\"} 0\n") {
		t.Error("eviction counter stayed at zero after overflowing the store")
	}
}

// TestLoginState_ConcurrentMintAndRedeem exercises the real call shape under
// contention: many clients minting state while others redeem theirs. Each
// redemption must return that client's own entry, exactly once.
func TestLoginState_ConcurrentMintAndRedeem(t *testing.T) {
	orig := globalPKCEStore
	globalPKCEStore = newPKCEStore()
	t.Cleanup(func() { globalPKCEStore = orig })

	const workers = 12
	done := make(chan error, workers)
	for w := range workers {
		go func(w int) {
			for i := range 100 {
				state := fmt.Sprintf("w%d-s%d", w, i)
				r := floodClientRequest(t, net.JoinHostPort(fmt.Sprintf("10.0.%d.%d", w, i%250+1), "5000"))
				globalPKCEStore.Set(state, authStateClientKey(r), &pkceEntry{verifier: state, providerID: "corp-oidc"})
				got, ok := globalPKCEStore.Pop(state)
				if !ok {
					done <- fmt.Errorf("worker %d: state %q vanished between mint and redeem", w, state)
					return
				}
				if got.verifier != state {
					done <- fmt.Errorf("worker %d: redeemed %q, want %q", w, got.verifier, state)
					return
				}
				if _, again := globalPKCEStore.Pop(state); again {
					done <- fmt.Errorf("worker %d: state %q was redeemable twice", w, state)
					return
				}
			}
			done <- nil
		}(w)
	}
	for range workers {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
