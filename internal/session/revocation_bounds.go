package session

// revocation_bounds.go — CHAOS-73. The admission rules for the session
// revocation list.
//
// The list is written from THREE places and only one of them is trusted:
//
//   1. the local logout path (session.go `revokeSessionCookie` → RevokeVerified)
//   2. cluster gossip      (controlplane_client.go → MergeRevocations)
//   3. the persistence file (session_startup.go → LoadRevocations)
//
// Before this file, none of the three authenticated or bounded anything.
// `/api/auth/logout` is deliberately on uiAuthMiddleware's PUBLIC allowlist —
// it has to be, or an expired session could never be cleared — and the logout
// handler base64-decoded whatever cookie it was handed and inserted the
// payload as a revocation key. The HMAC was never checked on that path: the
// call site's comment said "HMAC already verified by decodeSession", which is
// true of Decode and false of logout, because the handler calls
// revokeSessionCookie unconditionally and not only when readUISessionCookie
// returned a session.
//
// So an UNAUTHENTICATED caller chose the key bytes, the key LENGTH and the
// EXPIRY. Measured against the real handler behind a real net/http server: a
// 524,389-byte forged cookie answered 200 and was retained with a 100-year
// expiry, which the lazy evictor can never reclaim; and because the handler
// rewrites the whole file after every insert, 200 requests carrying 16 KiB
// each (3.2 MB in) wrote 441 MB to disk — amplification 17x → 34x → 68x →
// 135x as the request count doubled, i.e. QUADRATIC, not linear. In a cluster
// the same entry is exported to the Control Plane every 3 s, merged by every
// other node and persisted there too, so one unauthenticated request to one
// node's admin port is durable fleet-wide state.
//
// Two rules close it, and they are deliberately NOT the same rule:
//
//   (1) THE LOCAL PATH AUTHENTICATES INSTEAD OF BOUNDING. A revocation key is
//       the payload half of a cookie THIS appliance signed, so a cookie whose
//       HMAC does not verify cannot name a session of ours and there is
//       nothing for it to revoke. Refusing it therefore loses nothing — unlike
//       CHAOS-63's login bound, which had to keep over-long CONFIGURED
//       usernames working, there is no legitimate caller on the far side of
//       this check. Verification also costs no availability for the case the
//       public route exists to serve: Decode checks the MAC BEFORE the expiry,
//       so an EXPIRED cookie still verifies and still logs out.
//
//   (2) THE UNTRUSTED-ORIGIN PATHS ARE BOUNDED, AND THE LOCAL ONE IS EXEMPT.
//       A peer node and an on-disk file are lower-trust tiers than our own
//       signing key, and neither is reachable by (1): a peer sends whatever
//       bytes it likes, and the file may have been written by a build that
//       predates this one. They get a key-size bound and an entry cap; the
//       MAC-verified local path gets NEITHER, so a real session is always
//       revocable however large its cookie grew. That asymmetry is the same
//       shape as CHAOS-63's `cfg.LoginNameConfigured` exemption and exists for
//       the same reason: a bound must never refuse the real thing.
//
// WHY THERE IS NO CAP ON THE LOCAL PATH. Evicting a revocation entry
// resurrects a revoked session — a fail-OPEN failure of a security control, so
// a cap here is not free the way a cap on a cache is. With (1) in place the
// local entry count is bounded by REAL logins inside one session TTL (max 7d),
// and each of those already costs a credential verification governed by
// internal/authcost. That is the bound; it is a consequence of
// authentication, not an extra mechanism. The remote path has no such
// backstop, so it gets the explicit cap — and refusing there is COUNTED,
// because a refused remote entry means cluster-wide revocation is incomplete
// on this node (the same thing culvert_audit_cluster_push_drops_total says
// about the audit trail, and it is surfaced the same way rather than inventing
// a second dialect).

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"
)

// MaxRevocationTokenLen bounds a revocation key arriving from an UNTRUSTED
// origin (cluster gossip, the persistence file). It is never applied to a
// locally MAC-verified revocation.
//
// The bound is DERIVED, not guessed: a key is base64url(json(Session)) and
// must have travelled as a cookie value, and the de-facto browser limit is
// 4096 bytes for the whole cookie. 8192 is double that, so every cookie this
// appliance can issue AND a browser can carry is admitted with margin to
// spare. TestRevocationBounds_ExceedsAnythingEncodeCanProduce re-measures that
// against the live Encode rather than trusting this paragraph.
const MaxRevocationTokenLen = 8192

// MaxRevocationEntries caps how many entries an untrusted origin may add. A
// local, MAC-verified revocation is admitted past it (see the header: refusing
// one would resurrect a session an operator deliberately killed).
const MaxRevocationEntries = 65536

// revocationSweepEvery amortizes the expired-entry sweep over insertions.
// Before CHAOS-73 eviction was lazy-on-read ONLY, which never fires for the
// one key guaranteed never to be presented again — the cookie that just logged
// out — so a standalone (non-clustered) appliance had no evictor at all and
// the list, and its file, grew monotonically for the life of the deployment.
const revocationSweepEvery = 256

// RevokeReason is the BOUNDED classification of a refused or accepted
// revocation. It reaches a metric label and a log line, so it is a closed set
// and never carries caller-supplied bytes (WK-12/RS-5).
type RevokeReason string

const (
	// RevokeAccepted — the cookie verified and the entry was recorded.
	RevokeAccepted RevokeReason = "accepted"
	// RevokeAlreadyKnown — verified, but already on the list. No write needed.
	RevokeAlreadyKnown RevokeReason = "already_known"
	// RevokeUnsigned — the HMAC did not verify. Cannot name a session of ours.
	RevokeUnsigned RevokeReason = "unsigned"
	// RevokeMalformed — no separator, or the payload is not a Session.
	RevokeMalformed RevokeReason = "malformed"
	// RevokeExpired — verified, but already past its own expiry. Decode
	// rejects it anyway, so recording it would buy nothing and cost a write.
	RevokeExpired RevokeReason = "expired"
	// RevokeOversize — untrusted origin only: key longer than a cookie this
	// appliance could have issued.
	RevokeOversize RevokeReason = "oversize"
	// RevokeCapacity — untrusted origin only: the entry cap is full.
	RevokeCapacity RevokeReason = "capacity"
)

// refusal counters, by reason. Read through Refused.
var revokeRefusals struct {
	unsigned  atomic.Int64
	malformed atomic.Int64
	expired   atomic.Int64
	oversize  atomic.Int64
	capacity  atomic.Int64
}

func noteRefusal(reason RevokeReason) {
	switch reason {
	case RevokeUnsigned:
		revokeRefusals.unsigned.Add(1)
	case RevokeMalformed:
		revokeRefusals.malformed.Add(1)
	case RevokeExpired:
		revokeRefusals.expired.Add(1)
	case RevokeOversize:
		revokeRefusals.oversize.Add(1)
	case RevokeCapacity:
		revokeRefusals.capacity.Add(1)
	}
}

// Refused returns the cumulative count of revocation attempts refused for the
// given reason. An unknown reason reports 0 rather than panicking — this feeds
// a metrics surface, which must never be the thing that takes the process down.
func Refused(reason RevokeReason) int64 {
	switch reason {
	case RevokeUnsigned:
		return revokeRefusals.unsigned.Load()
	case RevokeMalformed:
		return revokeRefusals.malformed.Load()
	case RevokeExpired:
		return revokeRefusals.expired.Load()
	case RevokeOversize:
		return revokeRefusals.oversize.Load()
	case RevokeCapacity:
		return revokeRefusals.capacity.Load()
	}
	return 0
}

// ResetRefusalCountersForTest zeroes the process-wide refusal counters.
func ResetRefusalCountersForTest() {
	revokeRefusals.unsigned.Store(0)
	revokeRefusals.malformed.Store(0)
	revokeRefusals.expired.Store(0)
	revokeRefusals.oversize.Store(0)
	revokeRefusals.capacity.Store(0)
}

// RevokeVerified records a revocation for a cookie value this appliance
// signed, and refuses everything else. It reports whether the caller must
// persist (true only when the list actually changed) and the bounded reason.
//
// The MAC check is the whole security property and it is FIRST: the key is
// derived from caller-supplied bytes, so nothing may be retained, parsed into
// a map or written to disk before we know the appliance issued it. The
// comparison is constant-time, like Decode's.
//
// The expiry is read from the payload only AFTER the MAC verifies, so it is
// a value we signed rather than one the caller chose — which is what stops a
// forged entry pinning itself in the map with a far-future expiry the sweeper
// can never reclaim.
func (r *RevocationList) RevokeVerified(cookieValue string) (changed bool, reason RevokeReason) {
	dot := strings.LastIndex(cookieValue, ".")
	if dot < 0 {
		noteRefusal(RevokeMalformed)
		return false, RevokeMalformed
	}
	b64, sig := cookieValue[:dot], cookieValue[dot+1:]

	if !hmac.Equal([]byte(sig), []byte(mac(b64))) {
		noteRefusal(RevokeUnsigned)
		return false, RevokeUnsigned
	}

	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		noteRefusal(RevokeMalformed)
		return false, RevokeMalformed
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		noteRefusal(RevokeMalformed)
		return false, RevokeMalformed
	}

	exp := time.Unix(s.Exp, 0)
	if !time.Now().Before(exp) {
		// Already dead by its own terms; Decode rejects it on expiry alone.
		noteRefusal(RevokeExpired)
		return false, RevokeExpired
	}

	// Deliberately NOT bounded by MaxRevocationTokenLen or MaxRevocationEntries:
	// this key is provably a session this appliance issued, and refusing to
	// revoke a real session is the one failure this control may not have.
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tokens[b64]; exists {
		return false, RevokeAlreadyKnown
	}
	r.tokens[b64] = exp
	r.sweepIfDueLocked(time.Now())
	return true, RevokeAccepted
}

// sweepIfDueLocked drops expired entries once every revocationSweepEvery
// insertions. Amortized O(1) per insert. Caller must hold r.mu.
func (r *RevocationList) sweepIfDueLocked(now time.Time) {
	r.sinceSweep++
	if r.sinceSweep < revocationSweepEvery {
		return
	}
	r.sweepLocked(now)
}

// sweepLocked drops every entry whose own expiry has passed. Caller holds r.mu.
func (r *RevocationList) sweepLocked(now time.Time) {
	r.sinceSweep = 0
	for tok, exp := range r.tokens {
		if now.After(exp) {
			delete(r.tokens, tok)
		}
	}
	for user, exp := range r.users {
		if now.After(exp) {
			delete(r.users, user)
		}
	}
}

// admitUntrustedLocked decides whether an entry from an untrusted origin
// (cluster gossip, the persistence file) may be recorded. Caller holds r.mu
// and must have swept first, so the cap is measured against LIVE entries.
func (r *RevocationList) admitUntrustedLocked(e RevocationEntry, now time.Time) bool {
	if len(e.Token) > MaxRevocationTokenLen {
		noteRefusal(RevokeOversize)
		return false
	}
	if !now.Before(time.Unix(e.Expiry, 0)) {
		return false // already expired; not a refusal worth counting
	}
	if _, exists := r.tokens[e.Token]; exists {
		return false
	}
	if len(r.tokens) >= MaxRevocationEntries {
		noteRefusal(RevokeCapacity)
		return false
	}
	return true
}

// Tracked returns the number of revocation entries currently held.
func (r *RevocationList) Tracked() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tokens)
}

// Sweep drops expired entries now. Exported for the startup path, which wants
// a load from disk not to carry forward entries that died while we were down.
func (r *RevocationList) Sweep() {
	r.mu.Lock()
	r.sweepLocked(time.Now())
	r.mu.Unlock()
}
