package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ── Phase C5.1 — Session Jti tests ────────────────────────────────────────
//
// Pins the C5.1 contract:
//
//   • Every newly issued Session carries a 128-bit random Jti
//     (hex-encoded; 32 chars). Two same-second logins for the same
//     user produce DIFFERENT cookie values.
//   • Encode/decode round-trip preserves Jti.
//   • Legacy cookies (no jti field) decode cleanly with Jti="" and
//     remain revocable via the existing b64 token map.
//   • Identity() does NOT carry Jti — Jti is a session identifier,
//     not an identity attribute.
//   • Jti is bound by the HMAC envelope; tampering with it without
//     resigning fails the signature check.

// TestSession_Jti_GenerateUnique — direct entropy assertion on the
// helper. Two calls in a tight loop must produce different values.
// Probability of collision in N=2 calls over a 2^128 space is
// 2^-128, so a flake here means the random source is broken.
func TestSession_Jti_GenerateUnique(t *testing.T) {
	a := newSessionJti()
	b := newSessionJti()
	if a == b {
		t.Errorf("newSessionJti returned the same value twice: %q", a)
	}
	if want := 32; len(a) != want {
		t.Errorf("jti length = %d, want %d (16 bytes hex)", len(a), want)
	}
	// Must be lowercase hex.
	for _, c := range a {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("jti contains non-hex char %q in %q", c, a)
			break
		}
	}
}

// TestSession_Jti_UniqueAcrossEncodes confirms the same-second
// regression case at the encodeSession layer: two encodes of the same
// (Sub, Role, Exp) tuple produce DIFFERENT cookie values because Jti
// differs. This is the primary defect C5.1 fixes.
func TestSession_Jti_UniqueAcrossEncodes(t *testing.T) {
	withFreshSessionSecret(t)

	exp := time.Now().Add(time.Hour).Unix()
	makeCookie := func() string {
		s := &Session{Sub: "alice", Provider: "local", Role: "viewer", Exp: exp, Jti: newSessionJti()}
		v, err := encodeSession(s)
		if err != nil {
			t.Fatalf("encodeSession: %v", err)
		}
		return v
	}
	a := makeCookie()
	b := makeCookie()
	if a == b {
		t.Errorf("two encodes for the same (sub, role, exp) tuple produced identical cookies — Jti not in payload?\n  got: %q", a)
	}
	// Sanity: both must decode and verify.
	if _, err := decodeSession(a); err != nil {
		t.Errorf("decodeSession(a): %v", err)
	}
	if _, err := decodeSession(b); err != nil {
		t.Errorf("decodeSession(b): %v", err)
	}
}

// TestSession_Jti_RoundTrip — encode preserves the Jti exactly across
// decode. Confirms the field is in the JSON payload, not lost in
// serialization.
func TestSession_Jti_RoundTrip(t *testing.T) {
	withFreshSessionSecret(t)

	want := newSessionJti()
	s := &Session{Sub: "bob", Provider: "local", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Jti: want}
	cookie, err := encodeSession(s)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	got, err := decodeSession(cookie)
	if err != nil {
		t.Fatalf("decodeSession: %v", err)
	}
	if got.Jti != want {
		t.Errorf("round-trip Jti = %q, want %q", got.Jti, want)
	}
}

// TestSession_Jti_BackwardCompat_LegacyDecodes — a cookie minted
// before C5.1 (no jti field in the JSON) MUST still decode. The
// omitempty tag on Jti means absent-on-the-wire decodes to "". This
// is the rolling-upgrade and rollback compatibility guarantee.
func TestSession_Jti_BackwardCompat_LegacyDecodes(t *testing.T) {
	withFreshSessionSecret(t)

	cookie := craftLegacyCookie(t, "carol", "viewer", time.Now().Add(time.Hour).Unix())
	s, err := decodeSession(cookie)
	if err != nil {
		t.Fatalf("decodeSession(legacy cookie): %v", err)
	}
	if s.Jti != "" {
		t.Errorf("legacy cookie decoded with Jti = %q, want \"\" (field absent on wire)", s.Jti)
	}
	if s.Sub != "carol" || s.Role != "viewer" {
		t.Errorf("legacy cookie payload mismatch: %+v", s)
	}
}

// TestSession_Jti_BackwardCompat_LegacyRevoke — revocation must still
// work for cookies that lack a Jti. Revocation is keyed on the b64
// payload, not on Jti, so this should be unchanged. Pins the
// invariant explicitly.
func TestSession_Jti_BackwardCompat_LegacyRevoke(t *testing.T) {
	withFreshSessionSecret(t)
	withFreshRevocationList(t)

	cookie := craftLegacyCookie(t, "dan", "viewer", time.Now().Add(time.Hour).Unix())
	// Sanity: it decodes before revocation.
	if _, err := decodeSession(cookie); err != nil {
		t.Fatalf("pre-revoke decode: %v", err)
	}

	b64 := cookie[:strings.LastIndex(cookie, ".")]
	sessionRevoked.Revoke(b64, time.Now().Add(time.Hour))

	if _, err := decodeSession(cookie); err == nil {
		t.Errorf("post-revoke decode succeeded; expected \"session: revoked\"")
	} else if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("post-revoke error = %v, want contain \"revoked\"", err)
	}
}

// TestSession_LoginLogoutLogin_NoRevocationCollision is the regression
// test for the C5a finding. Encode → revoke → encode AGAIN with the
// same (Sub, Role, Exp-second). Without C5.1 the second encode would
// produce the same b64 and decodeSession would return "session:
// revoked". With C5.1 the second cookie is unique because of Jti and
// decodes cleanly.
func TestSession_LoginLogoutLogin_NoRevocationCollision(t *testing.T) {
	withFreshSessionSecret(t)
	withFreshRevocationList(t)

	exp := time.Now().Add(time.Hour).Unix()
	first := &Session{Sub: "eve", Provider: "local", Role: "viewer", Exp: exp, Jti: newSessionJti()}
	firstCookie, err := encodeSession(first)
	if err != nil {
		t.Fatalf("encodeSession first: %v", err)
	}
	// Logout-style revocation of the first cookie's b64.
	firstB64 := firstCookie[:strings.LastIndex(firstCookie, ".")]
	sessionRevoked.Revoke(firstB64, time.Unix(exp, 0))

	// Second login in the same second — Jti must be different.
	second := &Session{Sub: "eve", Provider: "local", Role: "viewer", Exp: exp, Jti: newSessionJti()}
	if second.Jti == first.Jti {
		t.Fatalf("two newSessionJti calls returned the same value: %q", first.Jti)
	}
	secondCookie, err := encodeSession(second)
	if err != nil {
		t.Fatalf("encodeSession second: %v", err)
	}
	if secondCookie == firstCookie {
		t.Fatalf("second cookie equals revoked first cookie; C5.1 fix did not take effect")
	}
	if _, err := decodeSession(secondCookie); err != nil {
		t.Errorf("second cookie decode: %v (must NOT be \"session: revoked\")", err)
	}
}

// TestSession_Jti_NotInIdentity — Jti is a session-scope value, not an
// identity attribute. Identity() must not surface it (no field on
// Identity exists for it, and no copy path should sneak it in via a
// future refactor).
func TestSession_Jti_NotInIdentity(t *testing.T) {
	s := &Session{Sub: "frank", Email: "f@example.com", Provider: "local", Jti: newSessionJti()}
	id := s.Identity()
	// Identity has no Jti field; this test guards against a future
	// addition that bridges them. We assert by JSON-marshaling the
	// identity and ensuring the Jti string never appears in it.
	idJSON, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("marshal Identity: %v", err)
	}
	if strings.Contains(string(idJSON), s.Jti) {
		t.Errorf("Identity JSON %q contains Jti %q — Jti must stay session-scoped", string(idJSON), s.Jti)
	}
}

// TestSession_Jti_TamperingFailsMAC — confirms Jti is inside the HMAC
// envelope. Encode a session, mutate its Jti in the JSON payload, and
// keep the original signature → decodeSession must reject for
// invalid signature.
func TestSession_Jti_TamperingFailsMAC(t *testing.T) {
	withFreshSessionSecret(t)

	s := &Session{Sub: "grace", Provider: "local", Role: "viewer", Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti()}
	cookie, err := encodeSession(s)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	dot := strings.LastIndex(cookie, ".")
	b64, mac := cookie[:dot], cookie[dot+1:]

	// Decode the b64 payload, mutate Jti to a different valid value,
	// re-encode without recomputing the MAC.
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var mut Session
	if err := json.Unmarshal(payload, &mut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mut.Jti = newSessionJti() // attacker-controlled new Jti
	mutPayload, err := json.Marshal(&mut)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tampered := base64.RawURLEncoding.EncodeToString(mutPayload) + "." + mac

	if _, err := decodeSession(tampered); err == nil {
		t.Errorf("tampered cookie decoded successfully; Jti not bound by MAC")
	} else if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("tampered cookie error = %v, want \"invalid signature\"", err)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────

// withFreshSessionSecret installs a deterministic 32-byte secret for
// the duration of t and restores the previous value on cleanup.
// Required because other tests may have left sessionSecret in any
// state, and the encode/decode round trips depend on a stable key.
func withFreshSessionSecret(t *testing.T) {
	t.Helper()
	prev := sessionSecret
	sessionSecret = make([]byte, 32)
	for i := range sessionSecret {
		sessionSecret[i] = byte(i + 1) // deterministic, non-zero
	}
	t.Cleanup(func() { sessionSecret = prev })
}

// withFreshRevocationList swaps the global revocation list out for an
// empty one for the duration of t. Mirrors the snapshot/restore
// pattern documented in CLAUDE.md for tests that touch shared
// revocation state.
func withFreshRevocationList(t *testing.T) {
	t.Helper()
	sessionRevoked.mu.Lock()
	prevTokens := sessionRevoked.tokens
	prevUsers := sessionRevoked.users
	sessionRevoked.tokens = map[string]time.Time{}
	sessionRevoked.users = map[string]time.Time{}
	sessionRevoked.mu.Unlock()
	t.Cleanup(func() {
		sessionRevoked.mu.Lock()
		sessionRevoked.tokens = prevTokens
		sessionRevoked.users = prevUsers
		sessionRevoked.mu.Unlock()
	})
}

// craftLegacyCookie builds a session cookie that lacks the jti field
// entirely (mimicking pre-C5.1 cookies). Bypasses encodeSession to
// avoid the omitempty/empty-string ambiguity — we want the field
// SHAPE to differ, i.e. the JSON to literally lack a "jti" key.
func craftLegacyCookie(t *testing.T, sub, role string, exp int64) string {
	t.Helper()
	// legacySession mirrors the pre-C5.1 Session shape — no Jti
	// field at all. JSON-marshaling this struct produces output
	// indistinguishable from a Session minted before C5.1.
	type legacySession struct {
		Sub      string   `json:"sub"`
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		Groups   []string `json:"grp,omitempty"`
		Provider string   `json:"pvd"`
		Role     string   `json:"role,omitempty"`
		Exp      int64    `json:"exp"`
	}
	payload, err := json.Marshal(&legacySession{Sub: sub, Provider: "local", Role: role, Exp: exp})
	if err != nil {
		t.Fatalf("marshal legacy session: %v", err)
	}
	if strings.Contains(string(payload), `"jti"`) {
		t.Fatalf("legacy payload unexpectedly contains jti: %s", string(payload))
	}
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	return b64 + "." + sessionMAC(b64)
}
