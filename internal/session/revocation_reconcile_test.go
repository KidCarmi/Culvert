package session

// revocation_reconcile_test.go — CHAOS-73, review round.
//
// A logout that finds the token already present must still reconcile it with
// the SIGNED expiry, not report "already known" and write nothing.
//
// The two expiries are independent. The token is the cookie payload, which
// seals its own Exp; the revocation entry carries a separate Expiry FIELD,
// and the gossip wire is raw JSON, so a peer chooses that field freely. A
// peer can therefore register this very session's token and name it short.
// With an unconditional no-op on the existing key, the genuine logout can no
// longer correct it: the sweep evicts on the untrusted expiry while Decode
// still honours the cookie, and the logged-out session authenticates again
// for the rest of its real life (Codex P2, PR #1591).
//
// The pre-CHAOS-73 logout wrote the signed expiry unconditionally, so this is
// a regression the no-change-no-write path introduced — which is why it needs
// a permanent gate rather than a comment.

import (
	"testing"
	"time"
)

// expiryOf and isVerified read the list directly: this is a white-box test
// beside its owner, so it needs no production accessor.
func expiryOf(r *RevocationList, token string) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tokens[token]
}

func isVerified(r *RevocationList, token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.verified[token]
	return ok
}

// signedCookieFor mints a real cookie and returns it with its payload half,
// which is the revocation key.
func signedCookieFor(t *testing.T, sub string, life time.Duration) (cookie, token string, exp time.Time) {
	t.Helper()
	exp = time.Now().Add(life).Truncate(time.Second)
	s := Session{Sub: sub, Provider: "local", Exp: exp.Unix()}
	cookie, err := Encode(&s)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	dot := -1
	for i := len(cookie) - 1; i >= 0; i-- {
		if cookie[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		t.Fatalf("encoded cookie has no MAC separator: %q", cookie)
	}
	return cookie, cookie[:dot], exp
}

func TestRevokeVerified_ShortImportedExpiryCannotSurviveAGenuineLogout(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)
	ResetRefusalCountersForTest()

	cookie, token, signed := signedCookieFor(t, "victim", time.Hour)

	// A peer registers THIS session's token, but names it short. Nothing
	// about the entry is malformed: only the Expiry field is the peer's.
	short := time.Now().Add(time.Minute).Truncate(time.Second)
	if added := Revoked.MergeRevocations([]RevocationEntry{{Token: token, Expiry: short.Unix()}}); added != 1 {
		t.Fatalf("setup: peer entry not admitted (added=%d); this gate would prove nothing", added)
	}

	// The user now logs out for real, with the cookie this appliance signed.
	ok, reason := Revoked.RevokeVerified(cookie)

	if got := expiryOf(Revoked, token); !got.Equal(signed) {
		t.Errorf("after a genuine logout the entry expires at %v, but the signed cookie "+
			"runs to %v: the sweep drops the revocation while Decode still honours the "+
			"cookie, so the logged-out session authenticates again (reason=%v)",
			got.UTC(), signed.UTC(), reason)
	}
	if !ok {
		t.Errorf("RevokeVerified reported no change (reason=%v) though it corrected the "+
			"expiry; the caller then persists nothing and a restart reloads the short "+
			"value", reason)
	}
	if !isVerified(Revoked, token) {
		t.Error("the reconciled entry is not marked verified, so exportPersisted writes " +
			"it without provenance and the reload puts this appliance's own revocation " +
			"back under the untrusted bounds")
	}
}

// CONTROL: a true replay — the entry is already present at the signed expiry
// AND already verified — must still report no change, so no write happens.
// This is CHAOS-70's rule, and the fix above must not trade it away.
func TestRevokeVerified_TrueReplayStillReportsNoChange(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)
	ResetRefusalCountersForTest()

	cookie, token, signed := signedCookieFor(t, "repeat", time.Hour)

	if ok, reason := Revoked.RevokeVerified(cookie); !ok {
		t.Fatalf("setup: first logout refused (reason=%v)", reason)
	}
	ok, reason := Revoked.RevokeVerified(cookie)
	if ok || reason != RevokeAlreadyKnown {
		t.Errorf("a replayed identical logout reported ok=%v reason=%v; it changes "+
			"nothing and must therefore write nothing", ok, reason)
	}
	if got := expiryOf(Revoked, token); !got.Equal(signed) {
		t.Errorf("the replay moved the expiry to %v, want %v", got.UTC(), signed.UTC())
	}
}

// CONTROL: a LATER imported expiry is not shortened by a logout. Retaining
// longer than the cookie lives is safe; cutting it short is the failure.
func TestRevokeVerified_DoesNotShortenALongerExistingExpiry(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)
	ResetRefusalCountersForTest()

	cookie, token, signed := signedCookieFor(t, "longer", time.Hour)
	longer := signed.Add(2 * time.Hour)
	if added := Revoked.MergeRevocations([]RevocationEntry{{Token: token, Expiry: longer.Unix()}}); added != 1 {
		t.Fatalf("setup: peer entry not admitted (added=%d)", added)
	}

	Revoked.RevokeVerified(cookie)

	if got := expiryOf(Revoked, token); !got.Equal(longer) {
		t.Errorf("the logout moved the expiry to %v, shortening the existing %v; "+
			"retaining a revocation longer than its cookie lives costs one map entry, "+
			"dropping it early resurrects the session", got.UTC(), longer.UTC())
	}
}
