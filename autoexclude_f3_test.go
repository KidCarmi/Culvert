package main

import (
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// TestMaybeFailOpenClient_LearnOnlyPinningUnderFailOpen closes the F3 coverage
// hole: maybeFailOpenClient (the client-leg pinning learn entry point) was 0%
// covered, so a regression that made it learn on a non-pinning error, or ignore
// the fail-open gate, would have shipped green — a wrongful-bypass (exfil) class.
//
// It pins three contracts: (1) a specific pinning cert-alert under a fail-open
// rule learns (learn-only — the client already aborted, so there is no session to
// rescue); (2) a non-pinning client error never learns; (3) a fail-close rule
// never learns even on a genuine pinning alert (the never-consult control).
func TestMaybeFailOpenClient_LearnOnlyPinningUnderFailOpen(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	fo, scope := bindFailOpenProfile(t, "fo", "fail-open")
	id := ProxyIdentity{ClientIP: "203.0.113.9", Identity: "u1"}

	// (1) Pinning rejection under fail-open → learns (confirmN=1 promotes at once).
	maybeFailOpenClient("pinned.example", fo, id, errors.New("remote error: tls: bad certificate"))
	if _, ok := autoExclude().Contains(scope, "pinned.example"); !ok {
		t.Fatal("client pinning rejection under fail-open must learn (learn-only)")
	}

	// (2) A non-pinning client error must NOT learn.
	maybeFailOpenClient("noise.example", fo, id, errors.New("read tcp: connection reset by peer"))
	if _, ok := autoExclude().Contains(scope, "noise.example"); ok {
		t.Fatal("non-pinning client error must not populate the cache")
	}

	// (3) A fail-close rule never learns even on a genuine pinning alert.
	fc, fcScope := bindFailOpenProfile(t, "fc", "fail-close")
	maybeFailOpenClient("pinned.example", fc, id, errors.New("remote error: tls: bad certificate"))
	if _, ok := autoExclude().Contains(fcScope, "pinned.example"); ok {
		t.Fatal("fail-close rule must never learn a pinning rejection (never-consult control)")
	}
}
