package session

// Correctness contract for the single-acquisition revocation read path
// (StatusFor, and Decode's use of it). The performance contract is in
// revocation_readpath_benchgate_test.go; this file runs in the normal suite.
//
// What changed is the NUMBER OF LOCK ACQUISITIONS per authenticated request,
// not the decision taken under them. These tests pin that: StatusFor must agree
// with the two single-question methods it replaces on every input, including
// the expiry boundary and the lazy eviction those methods perform; and Decode's
// rejection order must be exactly what it was, because that order is the one
// thing moving the revocation check past the payload decode could have
// disturbed.

import (
	"strings"
	"testing"
	"time"
)

// TestStatusFor_AgreesWithTheSingleQuestionMethods runs the same matrix through
// both entry points — on separate lists, so the eviction one performs cannot
// change what the other sees — and requires the same answer AND the same
// resulting map membership. The eviction is observable through Tracked, Count
// and the persisted export, so "same answer, different state" is not agreement.
func TestStatusFor_AgreesWithTheSingleQuestionMethods(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		exp   time.Time
		store bool
	}{
		{name: "absent", store: false},
		{name: "live/hour", exp: now.Add(time.Hour), store: true},
		{name: "live/second", exp: now.Add(time.Second), store: true},
		{name: "boundary/now", exp: now, store: true},
		{name: "expired/second", exp: now.Add(-time.Second), store: true},
		{name: "expired/hour", exp: now.Add(-time.Hour), store: true},
		{name: "expired/far", exp: now.Add(-100 * 24 * time.Hour), store: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const tok, user = "payload-under-test", "bob@example.com"
			seed := func() *RevocationList {
				r := NewRevocationList()
				if tc.store {
					r.mu.Lock()
					r.tokens[tok] = tc.exp
					r.verified[tok] = struct{}{}
					r.users[user] = tc.exp
					r.mu.Unlock()
				}
				return r
			}
			combined, separate := seed(), seed()

			gotTok, gotUser := combined.StatusFor(tok, user)
			wantTok := separate.IsRevoked(tok)
			wantUser := separate.IsUserRevoked(user)

			if gotTok != wantTok {
				t.Errorf("StatusFor token = %v, IsRevoked = %v", gotTok, wantTok)
			}
			if gotUser != wantUser {
				t.Errorf("StatusFor user = %v, IsUserRevoked = %v", gotUser, wantUser)
			}

			state := func(r *RevocationList) (tok1, prov, usr bool) {
				r.mu.Lock()
				defer r.mu.Unlock()
				_, tok1 = r.tokens[tok]
				_, prov = r.verified[tok]
				_, usr = r.users[user]
				return tok1, prov, usr
			}
			cTok, cProv, cUsr := state(combined)
			sTok, sProv, sUsr := state(separate)
			if cTok != sTok {
				t.Errorf("token retained = %v, single-question form retained = %v — the eviction decision diverged", cTok, sTok)
			}
			if cProv != sProv {
				t.Errorf("provenance marker retained = %v, single-question form = %v — `verified` fell out of step with `tokens`", cProv, sProv)
			}
			if cUsr != sUsr {
				t.Errorf("user entry retained = %v, single-question form retained = %v", cUsr, sUsr)
			}
		})
	}
}

// TestStatusFor_EmptySubjectSkipsTheUserLookup pins the guard Decode's call
// site used to apply itself. An empty subject is not a username, and looking it
// up would make a revocation recorded under the empty key — which no public
// mutator can create, but a merged peer entry could — gate every cookie that
// carries no subject.
func TestStatusFor_EmptySubjectSkipsTheUserLookup(t *testing.T) {
	r := NewRevocationList()
	r.mu.Lock()
	r.users[""] = time.Now().Add(time.Hour)
	r.mu.Unlock()

	if _, userRevoked := r.StatusFor("absent-token", ""); userRevoked {
		t.Error("StatusFor consulted the user map for an empty subject")
	}
	// The guard is about the EMPTY key only: a real subject still resolves.
	r.RevokeUser("real@example.com")
	if _, userRevoked := r.StatusFor("absent-token", "real@example.com"); !userRevoked {
		t.Error("StatusFor missed a live account revocation for a non-empty subject")
	}
}

// TestDecode_RejectionOrderIsUnchanged pins the error precedence Decode applies,
// which is the contract the single-acquisition rewrite had to preserve: the
// revocation check moved past the base64 and JSON decode, so a reordering would
// show up here as a different message for one of these cookies.
//
// The order is: invalid signature, then revoked, then expired, then user
// revoked. Each case below is constructed to satisfy every earlier test and
// fail exactly one.
func TestDecode_RejectionOrderIsUnchanged(t *testing.T) {
	SetSigningKey(testKey("decode rejection order"))

	// Each subtest swaps in a fresh list, so the order they run in cannot
	// decide what they see — the repository's rule for tests that touch shared
	// revocation state, and what -shuffle enforces.
	payloadOf := func(t *testing.T, s *Session) (raw, b64 string) {
		t.Helper()
		raw, err := Encode(s)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		return raw, raw[:strings.LastIndex(raw, ".")]
	}

	t.Run("invalid signature beats everything", func(t *testing.T) {
		t.Cleanup(Revoked.SwapForTest())
		raw, b64 := payloadOf(t, &Session{Sub: "a@example.com", Exp: time.Now().Add(time.Hour).Unix()})
		Revoked.Revoke(b64, time.Now().Add(time.Hour))
		if _, err := Decode(raw + "x"); err == nil || !strings.Contains(err.Error(), "invalid signature") {
			t.Errorf("err = %v, want invalid signature", err)
		}
	})

	t.Run("revoked beats expired", func(t *testing.T) {
		t.Cleanup(Revoked.SwapForTest())
		// Expired AND revoked: the revocation must be reported.
		raw, b64 := payloadOf(t, &Session{Sub: "b@example.com", Exp: time.Now().Add(-time.Hour).Unix()})
		Revoked.Revoke(b64, time.Now().Add(time.Hour))
		if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Errorf("err = %v, want revoked (not expired)", err)
		} else if strings.Contains(err.Error(), "user revoked") {
			t.Errorf("err = %v, want the token revocation, not the user one", err)
		}
	})

	t.Run("expired beats user revoked", func(t *testing.T) {
		t.Cleanup(Revoked.SwapForTest())
		// Expired AND the account is revoked: the expiry must be reported.
		raw, _ := payloadOf(t, &Session{Sub: "c@example.com", Exp: time.Now().Add(-time.Hour).Unix()})
		Revoked.RevokeUser("c@example.com")
		if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Errorf("err = %v, want expired (not user revoked)", err)
		}
	})

	t.Run("user revoked is reported on its own", func(t *testing.T) {
		t.Cleanup(Revoked.SwapForTest())
		raw, _ := payloadOf(t, &Session{Sub: "d@example.com", Exp: time.Now().Add(time.Hour).Unix()})
		Revoked.RevokeUser("d@example.com")
		if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), "user revoked") {
			t.Errorf("err = %v, want user revoked", err)
		}
	})

	t.Run("a clean cookie still decodes", func(t *testing.T) {
		t.Cleanup(Revoked.SwapForTest())
		raw, _ := payloadOf(t, &Session{Sub: "e@example.com", Exp: time.Now().Add(time.Hour).Unix()})
		s, err := Decode(raw)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if s.Sub != "e@example.com" {
			t.Errorf("Sub = %q, want e@example.com", s.Sub)
		}
	})
}

// TestDecode_StillRefusesEveryRevokedShape is the security backstop behind the
// reordering: whatever message Decode chooses, a revoked cookie and a revoked
// account must both be REFUSED. The precedence test above is about which error;
// this one is about the outcome, which is the part that matters.
func TestDecode_StillRefusesEveryRevokedShape(t *testing.T) {
	SetSigningKey(testKey("decode refuses revoked"))

	t.Run("logged-out cookie", func(t *testing.T) {
		t.Cleanup(Revoked.SwapForTest())
		raw, err := Encode(&Session{Sub: "f@example.com", Exp: time.Now().Add(time.Hour).Unix()})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if _, err := Decode(raw); err != nil {
			t.Fatalf("pre-revoke Decode: %v", err)
		}
		if changed, reason := Revoked.RevokeVerified(raw); !changed {
			t.Fatalf("RevokeVerified = (false, %q)", reason)
		}
		if _, err := Decode(raw); err == nil {
			t.Error("Decode accepted a cookie after RevokeVerified")
		}
	})

	t.Run("deleted account", func(t *testing.T) {
		t.Cleanup(Revoked.SwapForTest())
		raw, err := Encode(&Session{Sub: "g@example.com", Exp: time.Now().Add(time.Hour).Unix()})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		Revoked.RevokeUser("g@example.com")
		if _, err := Decode(raw); err == nil {
			t.Error("Decode accepted a cookie for a revoked account")
		}
	})
}
