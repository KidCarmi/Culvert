package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// SEC-REVOKE-1 — an unsigned cookie must not reach the revocation list.
//
// apiAuthLogout discarded decodeSession's error (`sess, _ :=`) and then called
// revokeSessionCookie unconditionally. That function does its own base64+JSON
// decode with NO signature check, on the stated premise that the "HMAC [was]
// already verified by decodeSession" — false on this path, because the error
// was thrown away. /api/auth/logout is on the PUBLIC allowlist, so an
// UNAUTHENTICATED POST carrying `base64({"sub":"…","exp":9999999999}).garbage`
// inserted an attacker-chosen key into session.RevocationList.tokens with an
// attacker-chosen expiry.
//
// That map is unbounded and evicts only lazily on expiry, so a far-future exp
// means the entry is permanent. SaveRevocations then rewrites the whole
// revocations file on every request (O(n) per insert over a set the caller is
// growing), and the cluster revocation sync gossips the entries to every node,
// which merges and persists them too.

// revocationProbeEnv isolates the process-wide revocation list.
func revocationProbeEnv(t *testing.T) {
	t.Helper()
	withSessionKey(t)
	configuredCfg(t)
	t.Cleanup(session.Revoked.SwapForTest())
}

// forgedCookieValue builds a well-formed-looking cookie whose signature is
// nonsense: valid base64url payload, valid JSON, bogus MAC.
func forgedCookieValue(sub string, exp int64) string {
	payload := fmt.Sprintf(`{"sub":%q,"exp":%d}`, sub, exp)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".not-a-valid-signature"
}

func postLogout(t *testing.T, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/logout", http.NoBody)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: cookie}) // #nosec G124 -- request-side test cookie
	}
	rec := httptest.NewRecorder()
	apiAuthLogout(rec, req)
	return rec
}

// TestSECREVOKE1_UnsignedCookieIsNotRevoked is the DEFECT GATE. Pre-fix each
// iteration added a permanent, attacker-sized entry.
func TestSECREVOKE1_UnsignedCookieIsNotRevoked(t *testing.T) {
	revocationProbeEnv(t)
	before := sessionRevoked.Count()

	const iterations = 25
	for i := 0; i < iterations; i++ {
		// A long subject, as an attacker growing the table would send: the
		// retained key is the cookie VALUE, bounded only by MaxHeaderBytes
		// (the 1 MiB MaxBytesReader bounds the BODY, not the Cookie header).
		sub := strings.Repeat("A", 2000) + fmt.Sprint(i)
		rec := postLogout(t, forgedCookieValue(sub, 9999999999))
		// The answer must stay 200: a logout that reported why it refused would
		// be an oracle, and a browser holding a junk cookie must still clear it.
		if rec.Code != http.StatusOK {
			t.Errorf("iteration %d: status = %d, want 200", i, rec.Code)
		}
		if !strings.Contains(strings.Join(rec.Header().Values("Set-Cookie"), " "), uiSessionCookieName) {
			t.Errorf("iteration %d: logout did not clear the cookie", i)
		}
	}

	if after := sessionRevoked.Count(); after != before {
		t.Errorf("DEFECT: %d unsigned, attacker-chosen revocation entries accepted from an unauthenticated caller (%d -> %d)",
			after-before, before, after)
	}
}

// TestSECREVOKE1_ForgedPayloadNeverBecomesRevoked checks the effect rather than
// the count: a prefix an attacker planted must not be reported as revoked, or
// they could pre-revoke a payload shape before it is ever minted.
func TestSECREVOKE1_ForgedPayloadNeverBecomesRevoked(t *testing.T) {
	revocationProbeEnv(t)
	payload := `{"sub":"victim","exp":9999999999}`
	b64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	postLogout(t, b64+".not-a-valid-signature")

	if sessionRevoked.IsRevoked(b64) {
		t.Error("DEFECT: an attacker-chosen payload prefix is now in the revocation set")
	}
}

// TestSECREVOKE1_MalformedCookiesAreAbsorbed covers the boundary shapes the
// decoder must not choke on, and pins that none of them writes an entry.
func TestSECREVOKE1_MalformedCookiesAreAbsorbed(t *testing.T) {
	revocationProbeEnv(t)
	before := sessionRevoked.Count()

	for _, value := range []string{
		"",                     // empty cookie value
		"no-dot-at-all",        // no separator
		".",                    // separator only
		".sig",                 // empty payload
		"payload.",             // empty signature
		"!!!not-base64!!!.sig", // undecodable payload
		base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig",
		base64.RawURLEncoding.EncodeToString([]byte(`{"exp":"soon"}`)) + ".sig",
		strings.Repeat("A", 4096) + ".sig",
	} {
		rec := postLogout(t, value)
		if rec.Code != http.StatusOK {
			t.Errorf("value %q: status = %d, want 200", value, rec.Code)
		}
	}
	// And with no cookie at all.
	if rec := postLogout(t, ""); rec.Code != http.StatusOK {
		t.Errorf("no cookie: status = %d, want 200", rec.Code)
	}

	if after := sessionRevoked.Count(); after != before {
		t.Errorf("DEFECT: malformed cookies added %d revocation entries", after-before)
	}
}

// TestSECREVOKE1_GenuineLogoutStillRevokes is the not-vacuous control: the fix
// must not turn logout into a no-op. A real admin session must still be
// revoked, and its cookie must stop decoding afterwards.
func TestSECREVOKE1_GenuineLogoutStillRevokes(t *testing.T) {
	revocationProbeEnv(t)

	value, err := encodeSession(&Session{
		Sub: "bob", Provider: uiSessionProvider, Role: string(RoleViewer),
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	// Precondition: the cookie is currently good.
	if _, derr := decodeSession(value); derr != nil {
		t.Fatalf("precondition: fresh session should decode, got %v", derr)
	}

	before := sessionRevoked.Count()
	if rec := postLogout(t, value); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if after := sessionRevoked.Count(); after != before+1 {
		t.Errorf("a genuine logout did not revoke: count %d -> %d", before, after)
	}
	if _, derr := decodeSession(value); derr == nil {
		t.Error("the logged-out session cookie still decodes — it was not revoked")
	} else if !strings.Contains(derr.Error(), "revoked") {
		t.Errorf("session rejected for the wrong reason: %v", derr)
	}
}

// TestSECREVOKE1_AnySignedTokenIsRevocable is the BOUNDARY on the other side of
// the gate, and it pins a decision that was made the other way first.
//
// The first version of this fix routed logout through a full admissibility test
// (audience + roster), and this test asserted that a replayed portal token must
// NOT revoke. Reconciling with SEC-UISESS-1 on main showed that to be the wrong
// line: admissibility also refuses a DELETED user's session and one naming an
// unenrolled role, and declining to revoke those is strictly worse security —
// they are exactly the tokens most worth revoking, and they are real tokens
// this appliance signed.
//
// So verification alone is the gate. What the defect allowed was the insertion
// of a key NOBODY signed, with an attacker-chosen expiry; a signed token can
// only revoke itself, and whoever holds it could already use it. Revoking a
// token minted for the proxy plane is therefore permitted here, and this test
// says so out loud rather than leaving the looser gate looking like an
// oversight.
func TestSECREVOKE1_AnySignedTokenIsRevocable(t *testing.T) {
	revocationProbeEnv(t)

	for _, tc := range []struct {
		name string
		sess *Session
	}{
		{
			name: "a token minted for the proxy plane",
			sess: &Session{Sub: "mallory@corp.example", Provider: "oidc-profile-01"},
		},
		{
			name: "an admin token naming no roster account",
			sess: &Session{Sub: "deleted-admin", Provider: uiSessionProvider, Role: string(RoleAdmin)},
		},
		{
			name: "an admin token naming an unenrolled role",
			sess: &Session{Sub: "bob", Provider: uiSessionProvider, Role: "superuser"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.sess.Exp = time.Now().Add(time.Hour).Unix()
			tc.sess.Jti = newSessionJti()
			value, err := encodeSession(tc.sess)
			if err != nil {
				t.Fatalf("encodeSession: %v", err)
			}
			if _, derr := decodeSession(value); derr != nil {
				t.Fatalf("precondition: the token should verify, got %v", derr)
			}

			before := sessionRevoked.Count()
			if rec := postLogout(t, value); rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if after := sessionRevoked.Count(); after != before+1 {
				t.Errorf("a signed token must be revocable: count %d -> %d", before, after)
			}
			if _, derr := decodeSession(value); derr == nil {
				t.Error("the token still decodes after logout — it was not revoked")
			}
		})
	}
}
