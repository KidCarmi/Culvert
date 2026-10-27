package session

// revocation_expiry.go — SEC-REVEXP-1. The ONE expiry oracle shared by the
// revocation list and the cookie verifier.
//
// # THE DEFECT
//
// Two predicates decided "has this session's lifetime ended?" and they did not
// agree, in the fail-OPEN direction.
//
//	Decode (session.go)          accepts while  time.Now().Unix() <= s.Exp
//	IsRevoked / IsUserRevoked /
//	ExportRevocations /
//	MergeRevocations             retained while !time.Now().After(exp)
//
// Every production revocation expiry is a WHOLE SECOND — `revokeSessionCookie`
// stores `time.Unix(s.Exp, 0)` and `MergeRevocations` stores
// `time.Unix(e.Expiry, 0)` — while `time.Now()` carries a sub-second
// remainder. So for the whole of the wall-clock second numbered `s.Exp`:
//
//	now.After(exp)   == true   → the revocation is EVICTED (and deleted)
//	now.Unix() > Exp == false  → Decode ACCEPTS the cookie
//
// A session cookie that was explicitly logged out — or whose account was
// deleted — therefore authenticated again for up to one second at the end of
// its lifetime, with the revocation record destroyed rather than merely
// ignored. `ExportRevocations` deleted it on the same test, so the one-second
// hole also propagated: the entry vanished from the on-disk file and from the
// next cluster gossip export.
//
// Measured against the real Decode before the fix: a session with
// `Exp == time.Now().Unix()`, revoked at `time.Unix(s.Exp, 0)`, reported
// `IsRevoked=false` and `Decode err=<nil>` — the cookie was honoured after
// logout. `TestRevocationExpiry_EvictionNeverPrecedesDecode` is that
// measurement, inverted into a gate.
//
// # THE FIX, AND WHY IT IS THE SAFE DIRECTION
//
// There is now one predicate and the revocation list is the side that moved,
// because a revocation must OUTLIVE the session it revokes — never the
// reverse. `revocationLive` mirrors Decode's acceptance test exactly, so an
// entry is retained for precisely as long as some cookie could still be
// accepted, and not one tick less.
//
// The change can only RETAIN an entry longer (by under one second), never
// drop one sooner, so it cannot resurrect a session, cannot refuse a
// legitimate logout, and cannot unbound the list: retention is still capped by
// the session TTL that set the expiry in the first place.
//
// # WHY NOT MOVE Decode INSTEAD
//
// Tightening Decode to reject during the final second would shorten every
// session by up to a second and change the meaning of the `exp` claim this
// appliance signs and ships in a cookie — a wire-contract change to fix an
// internal disagreement. Retaining a revocation marginally longer changes no
// contract and is strictly fail-closed.

import "time"

// revocationLive reports whether a revocation recorded with expiry exp must
// still be honoured at now.
//
// It is Decode's acceptance test, transposed: Decode admits a session while
// `now.Unix() <= s.Exp`, so a revocation naming that session stays live under
// exactly the same comparison. Both sides are reduced to whole seconds, which
// is the resolution the `exp` claim is signed at — comparing a second-truncated
// expiry against a sub-second `now` is the mismatch this function exists to
// remove.
func revocationLive(now, exp time.Time) bool {
	return now.Unix() <= exp.Unix()
}

// revocationExpired is revocationLive's negation, named for the eviction call
// sites so they read as what they do.
func revocationExpired(now, exp time.Time) bool {
	return !revocationLive(now, exp)
}

// RevocationLiveAt is the EXPORTED face of the same oracle, for the cluster
// surfaces in package main that carry a RevocationEntry's wire expiry (an int64
// Unix second) and cannot reach the unexported predicate.
//
// It exists so those surfaces do not hand-roll the comparison. A second
// spelling of "has this revocation's lifetime ended?" outside this file is how
// SEC-REVEXP-1 reopened twice: once in a counting path (AU-60), once in the
// user-export loop beside an already-fixed token loop (AU-62). Both were a raw
// `now.After(exp)` — or its transposition `exp.Before(now)` — standing in for
// this function.
//
// Callers ask whether the revocation must still be HONOURED, which is the
// question every persistence, gossip and aggregation surface actually has.
func RevocationLiveAt(now time.Time, expiry int64) bool {
	return revocationLive(now, time.Unix(expiry, 0))
}
