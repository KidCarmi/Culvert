package session

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// revocation_bounds_expiry_test.go — the CHAOS-73 entry points (RevokeVerified,
// the shared sweep, and the provenance-trusted reload) answer "has this
// revocation's lifetime ended?" with SEC-REVEXP-1's one oracle.
//
// SEC-REVEXP-1 moved every eviction site that existed on main to
// revocationExpired, Decode's acceptance test transposed. CHAOS-73 added three
// more decision points of its own, each written against the older predicate
// (`now.After(exp)` / `!now.Before(exp)`), which disagrees with Decode for the
// whole wall-clock second numbered s.Exp. Each gate below is that second,
// observed inside one settled second, and each fails against the older
// predicate at its site.

// A logout in the final second of a session's life must revoke it. Decode
// still accepts the cookie for that whole second, so refusing it as
// RevokeExpired would leave the logged-out cookie authenticating until the
// second ends.
func TestRevocationExpiry_VerifiedLogoutInFinalSecondRevokes(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)

	observeWithinSecond(t, func(sec int64) string {
		Revoked.SwapForTest()
		cookie, err := Encode(&Session{Sub: "final-second", Exp: sec})
		if err != nil {
			return "encode: " + err.Error()
		}
		if _, err := Decode(cookie); err != nil {
			return "control: Decode rejected a cookie in its final second: " + err.Error()
		}
		changed, reason := Revoked.RevokeVerified(cookie)
		if !changed || reason != RevokeAccepted {
			return "a logout in the cookie's final second was refused as " + string(reason)
		}
		if _, err := Decode(cookie); err == nil {
			return "the logged-out cookie still decoded inside its final second"
		}
		return ""
	})
}

// The shared sweep is the ONLY eviction step in front of ExportRevocations
// (the gossip wire) and exportPersisted (the revocations file), and it also
// runs amortized on insert. It must keep both lists' final-second entries.
func TestRevocationExpiry_SweepKeepsFinalSecondEntries(t *testing.T) {
	rl := NewRevocationList()

	observeWithinSecond(t, func(sec int64) string {
		rl.mu.Lock()
		rl.tokens["inside"] = time.Unix(sec, 0)
		rl.tokens["past"] = time.Unix(sec-60, 0)
		rl.users["inside-user"] = time.Unix(sec, 0)
		rl.sweepLocked(time.Now())
		_, tokKept := rl.tokens["inside"]
		_, pastKept := rl.tokens["past"]
		_, userKept := rl.users["inside-user"]
		rl.mu.Unlock()

		switch {
		case !tokKept:
			return "the sweep evicted a token revocation inside its final second"
		case !userKept:
			return "the sweep evicted a user revocation inside its final second"
		case pastKept:
			return "the sweep kept a token revocation a minute past its expiry"
		}
		return ""
	})
}

// A provenance-verified entry reloaded from the revocations file in its
// final second must come back: dropping it on reload resurrects the session
// for that second on a node that restarted.
func TestRevocationExpiry_VerifiedReloadKeepsFinalSecondEntry(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)
	path := withRevocationsFile(t)
	// A token over the untrusted key bound, so only the provenance branch can
	// admit it: the gossip-path oracle check cannot mask this one.
	tok := strings.Repeat("v", MaxRevocationTokenLen+1)

	observeWithinSecond(t, func(sec int64) string {
		Revoked.SwapForTest()
		data, err := json.Marshal([]RevocationEntry{{Token: tok, Expiry: sec, Prov: provenanceMAC(tok, sec)}})
		if err != nil {
			return "marshal: " + err.Error()
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return "write: " + err.Error()
		}
		if err := Revoked.LoadRevocations(); err != nil {
			return "load: " + err.Error()
		}
		if !Revoked.IsRevoked(tok) {
			return "a verified revocation in its final second was dropped on reload"
		}
		return ""
	})
}
