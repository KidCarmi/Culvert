package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// CHAOS-68 round 3 — the two logout findings.
//
// The sweep's whole premise is that a Culvert cookie is self-contained, so the
// revocation list is the ONLY way to withdraw a live session's authority. Two
// defects sat directly on that claim and are pinned here.

// logoutTestSession mints a genuine, signed proxy session cookie and returns
// the cookie value together with the b64 payload the revocation list keys on
// (everything before the final dot — the split Decode itself performs).
func logoutTestSession(t *testing.T, sub string) (value, key string) {
	t.Helper()
	if !session.HasSigningKey() {
		initSessionSecret()
	}
	// The Jti MUST be unique per call, and this is the one line in the file
	// worth reading twice. `Exp` has second granularity and every other field
	// here is fixed, so a deterministic Jti makes the whole payload
	// byte-identical between two mints in the same wall-clock second — which
	// under `-count=2` means the second "freshly minted" cookie is exactly the
	// one the first run just revoked, and the precondition fails with
	// "session: revoked".
	//
	// That is the C5.1 defect reproduced inside the test written to check
	// revocation: `Session.Jti`'s own doc comment records that it was added
	// because "without Jti the (Sub, Role, Exp-in-seconds) tuple yielded a
	// byte-identical payload, identical b64, identical HMAC, and an
	// effectively-revoked cookie if any prior login of that tuple had been
	// revoked". A fixture that hard-codes the uniqueness field defeats the
	// mechanism it exists to provide (caught by CI's determinism lane, which
	// runs -count=2; a plain -shuffle=on run passes).
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		t.Fatalf("rand: %v", err)
	}
	raw, err := encodeSession(&Session{
		Sub: sub,
		Exp: time.Now().Add(time.Hour).Unix(),
		Jti: hex.EncodeToString(jti),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	dot := strings.LastIndex(raw, ".")
	if dot < 0 {
		t.Fatalf("encoded session has no signature separator: %q", raw)
	}
	return raw, raw[:dot]
}

func logoutRequestWithCookie(name, value string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/logout", http.NoBody)
	// Only Name=Value serializes on an inbound cookie; the rest satisfies gosec G124.
	req.AddCookie(&http.Cookie{
		Name: name, Value: value,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return req
}

// TestChaos68_ProxyLogoutRevokesTheSessionToken is the Codex P1 defect gate.
//
// authLogout used to call clearSessionCookie and nothing else. Clearing a
// cookie is a request to the browser, not a withdrawal of authority: the token
// stayed valid until its natural expiry, so a retained or stolen copy replayed
// against this node or any other. This is the PROXY session, which proxy.go's
// identity arm reads for identity- and group-scoped policy, so the window was
// an enforcement gap on the data plane.
//
// Verified FAILING against the pre-fix body (clear-only): the session still
// decodes after logout.
func TestChaos68_ProxyLogoutRevokesTheSessionToken(t *testing.T) {
	value, key := logoutTestSession(t, "chaos68-proxy-logout")

	if _, err := decodeSession(value); err != nil {
		t.Fatalf("precondition: freshly minted session must decode, got %v", err)
	}

	authLogout(httptest.NewRecorder(), logoutRequestWithCookie(sessionCookieName, value))

	if !sessionRevoked.IsRevoked(key) {
		t.Error("proxy logout did not revoke the session token: the cookie stays replayable until it expires")
	}
	if _, err := decodeSession(value); err == nil {
		t.Error("the logged-out proxy cookie still decodes, so it still carries authority")
	}
}

// TestChaos68_ForgedLogoutCookieCreatesNoRevocation pins the hardening that
// makes the fix above safe to apply.
//
// revokeSessionCookie used to read the expiry with a bare base64+JSON decode
// and revoke whatever it found, verifying nothing — while BOTH its call sites
// are logout handlers on the public allowlist. The revocation map is uncapped
// and each entry expires at a time taken FROM THE COOKIE, and every call
// marshals the whole list to disk and gossips it fleet-wide, so one
// unauthenticated caller could mint arbitrarily many effectively permanent
// entries across the fleet (CHAOS-63's write-amplification shape, aimed at the
// control that withdraws session authority).
//
// Verified FAILING against the pre-fix body: the forged payload is revoked.
func TestChaos68_ForgedLogoutCookieCreatesNoRevocation(t *testing.T) {
	if !session.HasSigningKey() {
		initSessionSecret()
	}
	// A well-formed payload with a far-future expiry and a signature that is
	// simply wrong — exactly what an unauthenticated caller can send.
	forgedPayload := "eyJzdWIiOiJjaGFvczY4LWZvcmdlZCIsImV4cCI6NDEwMjQ0NDgwMH0"
	forged := forgedPayload + ".not-a-valid-signature"

	if _, err := decodeSession(forged); err == nil {
		t.Fatal("precondition: the forged cookie must not verify")
	}

	authLogout(httptest.NewRecorder(), logoutRequestWithCookie(sessionCookieName, forged))
	apiAuthLogout(httptest.NewRecorder(), func() *http.Request {
		req := logoutRequestWithCookie(uiSessionCookieName, forged)
		req.Method = http.MethodPost
		return req
	}())

	if sessionRevoked.IsRevoked(forgedPayload) {
		t.Error("an unverified cookie was added to the revocation list: a public endpoint can now grow it without bound, on disk and across the fleet")
	}
}

// TestChaos68_AdminLogoutStillRevokes is the CONTROL.
//
// The cheapest way to pass the forged-cookie gate is to stop revoking at all,
// which would silently delete the logout half of the whole plane. Both logout
// paths must still revoke a GENUINE session.
func TestChaos68_AdminLogoutStillRevokes(t *testing.T) {
	value, key := logoutTestSession(t, "chaos68-admin-logout")

	req := logoutRequestWithCookie(uiSessionCookieName, value)
	req.Method = http.MethodPost
	apiAuthLogout(httptest.NewRecorder(), req)

	if !sessionRevoked.IsRevoked(key) {
		t.Error("admin logout stopped revoking: the hardening removed the behaviour it was meant to protect")
	}
}

// TestChaos68_UnwritablePathIsNotReportedDurable is the Codex P2 defect gate.
//
// LoadRevocations treated os.IsNotExist as a clean first run and returned,
// while Configured was already true — so revocationsAreDurable() claimed a
// revocation would survive a restart even though the parent directory did not
// exist and the first save was guaranteed to fail. The cluster API, the
// diagnostics row and the metric all stayed green until some later logout
// happened to be the first write.
//
// Verified FAILING against the pre-fix body (bare `return nil`): durable reads
// true on an unwritable path.
func TestChaos68_UnwritablePathIsNotReportedDurable(t *testing.T) {
	resetSessionRevocationHealthForTest()
	t.Cleanup(resetSessionRevocationHealthForTest)

	// A path whose PARENT does not exist: the file is absent (the first-run
	// branch) and no write to it can ever succeed.
	bad := t.TempDir() + "/no-such-dir/revocations.json"
	prev := session.RevocationsPath()
	session.SetRevocationsPath(bad)
	t.Cleanup(func() { session.SetRevocationsPath(prev) })

	noteRevocationPersistenceConfigured(bad)
	if err := sessionRevoked.LoadRevocations(); err != nil {
		t.Fatalf("an absent file must not be a load error: %v", err)
	}

	if revocationsAreDurable() {
		t.Error("an unwritable revocations path was reported durable: the operator sees green until the first logout discovers the path is bad")
	}
}

// TestChaos68_WritablePathIsStillDurable is the CONTROL for the gate above.
//
// The cheapest way to pass it is to report every node non-durable, which would
// make the signal useless and page every correctly configured appliance. A good
// path must still read durable — and the probe must have actually created the
// file, which is what proves the claim was earned rather than assumed.
func TestChaos68_WritablePathIsStillDurable(t *testing.T) {
	resetSessionRevocationHealthForTest()
	t.Cleanup(resetSessionRevocationHealthForTest)

	good := t.TempDir() + "/revocations.json"
	prev := session.RevocationsPath()
	session.SetRevocationsPath(good)
	t.Cleanup(func() { session.SetRevocationsPath(prev) })

	noteRevocationPersistenceConfigured(good)
	if err := sessionRevoked.LoadRevocations(); err != nil {
		t.Fatalf("LoadRevocations on a good path: %v", err)
	}

	if !revocationsAreDurable() {
		t.Error("a writable revocations path was reported non-durable")
	}
	if _, err := os.Stat(good); err != nil {
		t.Errorf("the boot probe did not create the revocations file, so durability was assumed rather than proven: %v", err)
	}
}
