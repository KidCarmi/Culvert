package main

import (
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// CHAOS-71 — a session is an identity only while the provider that minted it
// is still an identity source this appliance honours.
//
// A `ps_session` cookie is minted in exactly two places, both interactive IdP
// callbacks (`authOIDCCallback`, `authSAMLCallback` → `setSessionCookie`), and
// it carries the asserting profile's id in `pvd` plus the GROUPS that provider
// asserted. `resolveRequestAuth`'s arm 1 read all three straight out of the
// cookie and consulted NOTHING about the provider, so deleting or disabling an
// IdP — the one lever an operator has for "cut this federation off" — revoked
// nothing already minted: every browser holding such a cookie kept its subject
// AND its groups for the rest of the session TTL (default 8 h, max 7 d), and
// those groups go straight into `policyStore.Evaluate`, so group-scoped allow
// rules kept matching for a federation the operator had just removed.
//
// The asymmetry is INSIDE ONE FUNCTION: arm 2 (Proxy-Authorization Basic)
// iterates `idpRegistry.EnabledCredentialProviders()` on every request, so a
// deleted provider stops authenticating credentials immediately — and
// `TestResolveRequestAuthRejectsEnabledOIDCWithoutLiveBackend` already pins
// that posture. Arm 1 consulted the live set never. One revocation action, two
// postures, decided only by which arm the client happens to be on.
//
// THE FIX IS DERIVED STATE, NOT A REVOCATION EVENT, and that choice is the
// load-bearing part. A `RevocationList.RevokeProvider` entry (the obvious
// shape, mirroring the existing `RevokeUser`) would have to be persisted, be
// gossiped, and be emitted by every writer of the registry — and the admin
// DELETE handler is only ONE of those writers. `IdPRegistry.ReplaceAll` is
// also reached from config import, config-version rollback and the CP→DP
// `syncSnapshotIdPProfiles` path, none of which run that handler. Probing the
// live set instead is correct for all of them at once, needs no persistence
// (the registry file already is), needs no gossip (`ConfigSnapshot.IdPProfiles`
// already carries it fleet-wide), cannot be evicted, and cannot go stale:
// freshness is EVALUATED on every request rather than latched at the moment of
// an admin action — the `ca_health.go` / CHAOS-61 discipline. A second
// mechanism answering the same question is the defect this repo keeps
// recording, so `RevokeProvider` is deliberately NOT added.
//
// `RevokeUser` (register row AU-19) is a DIFFERENT dimension and is NOT closed
// here: the `users` map is still neither persisted nor gossiped while the
// sibling `tokens` map in the same struct is both. It is bounded for the admin
// UI by `uiAuthMiddleware`'s roster backstop and is unreachable from the proxy
// cookie (which no local login ever mints), so it is recorded, not fixed.
// ---------------------------------------------------------------------------

// sessionProviderLocal is the `pvd` value `setUISessionCookie` stamps on an
// admin-UI session. It names no registry profile; the admin UI owns its own
// backstop (`uiAuthMiddleware`'s `cfg.UIUserExists` check).
const sessionProviderLocal = "local"

// sessionProviderLive reports whether the provider named by a VERIFIED session
// cookie is still a live identity source.
//
// It admits exactly three shapes, and each exclusion is the reason the
// predicate can be fail-closed without being an availability regression:
//
//   - "" — EXACTLY the empty string, a cookie minted before the `pvd` field
//     existed. Refusing these would log out every pre-upgrade session on the
//     deploy that adds this check, for no security gain: such a cookie names
//     no federation, so there is no federation to have been cut off.
//
//     THE EMPTINESS TEST IS ON THE RAW STRING AND MUST STAY THERE. Trimming
//     first makes a whitespace-only `pvd` indistinguishable from unset — the
//     exact mistake `initSessionSecret` (session.go) documents at length and
//     deliberately avoids — and here it is also a DIVERGENCE, which is the
//     worse half: `identityAuthSource` tests `id.Provider != ""` on the raw
//     value, so a `pvd` of "  " would be treated as "no federation" by this
//     predicate while still being stamped into `authenticatedSource` and
//     carried into the policy decision as a federation name. Two layers
//     disagreeing about which values mean "no provider" is the defect; the
//     rule is that this predicate asks the SAME question `identityAuthSource`
//     asks, never a re-derived one, and `TestChaos71_ProviderEmptinessAgreesWithIdentityAuthSource`
//     pins the agreement from both sides. Caught by this sweep's own
//     `ControlPrefixAloneIsNotAProvider` gate, which is why that control
//     enumerates whitespace.
//
//   - "local" — the admin-UI cookie. Not a registry id.
//
//   - a profile id that is currently ENABLED AND COMPILED (`r.live`). Delete,
//     disable and a failed compile all remove it from that map, and in all
//     three the operator's intent is that this federation authenticates nobody.
//
// BOTH the bare id and the prefixed `Name()` form are probed, and that is not
// defensive clutter: this codebase carries two representations of one provider
// identity on purpose — the interactive providers stamp the BARE profile id
// into `Identity.Provider` (`auth_oidc_flow.go` `ExchangeCode`,
// `auth_saml.go` `extractSAMLIdentity`) while `Name()` returns `oidc:<id>` /
// `saml:<id>`, which is why `stripIdPPrefix` exists at all. A fail-closed
// bound applied to the wrong representation is a customer-visible outage, not
// a tightening (CHAOS-69's round-1 IDN regression, learned the expensive way),
// and probing both cannot WIDEN anything: each form must still resolve to a
// live provider.
func sessionProviderLive(provider string) bool {
	// Raw, untrimmed — see the emptiness note above. A whitespace-only value
	// is a provider name that resolves to nothing, not an absent field.
	if provider == "" || provider == sessionProviderLocal {
		return true
	}
	if _, ok := idpRegistry.LiveProvider(provider); ok {
		return true
	}
	if bare := stripIdPPrefix(provider); bare != provider {
		if _, ok := idpRegistry.LiveProvider(bare); ok {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Visibility. A refusal is otherwise indistinguishable from a user who simply
// has no cookie: the request falls through to the no-credential dispatch and
// is challenged exactly as an anonymous one would be, which is the point of
// the fix and also the reason it needs its own counter.
// ---------------------------------------------------------------------------

var (
	// sessionProviderRevokedTotal counts REQUESTS whose verified session named
	// a provider that is no longer live — not distinct sessions. A browser
	// keeps re-sending a dead cookie until it is re-challenged and logs in
	// again, so the rate is set by traffic; the name says "requests" in the
	// metric help and the runbook for exactly that reason.
	//
	// Emitted UNCONDITIONALLY, unlike the gauges elsewhere in this tree: there
	// is no configuration to gate it on, so a flat zero means "no request has
	// carried a session from a removed provider" and can never mean "the
	// feature is off" (the inverse of the socks5/cluster_ca emission rule, for
	// the same one-reading-per-series reason).
	sessionProviderRevokedTotal atomic.Int64

	// sessionProviderLogGate is the CAS-claimed rate gate for the log line.
	// Claimed, not read-compare-store: concurrent requests on a flood would
	// all observe the same expired stamp and all emit, which would make a
	// mitigation for a log-volume problem into one (CHAOS-70 round 1 P2). The
	// cumulative count rides every line, so the magnitude is never suppressed.
	sessionProviderLogGate atomic.Int64
)

// sessionProviderLogInterval bounds the refusal log to one line per minute.
const sessionProviderLogInterval = time.Minute

// sessionProviderRevokedCount returns the cumulative refusal count for the
// admin/metrics surfaces.
func sessionProviderRevokedCount() int64 { return sessionProviderRevokedTotal.Load() }

// noteSessionProviderRevoked charges the refusal and, at most once per
// interval, names it in the process log.
//
// The ACCOUNTING LANDS FIRST, before anything observable: a reader — or a gate
// — acting on the refusal must never be able to observe the counter unmoved
// (CHAOS-69 round 3, where exactly one of four entry points had the accounting
// and the reply in the wrong order because the sequence was hand-written
// inline instead of going through the shared helper).
func noteSessionProviderRevoked(provider, subject, clientIP string) {
	total := sessionProviderRevokedTotal.Add(1)

	now := timeNowSessionProvider()
	last := sessionProviderLogGate.Load()
	// A clock rollback (last in the future) re-arms rather than silencing the
	// line until wall-clock catches up — CHAOS-61's verdict that a negative
	// age is STALE, not fresh.
	if last != 0 && now.Sub(time.Unix(0, last)) < sessionProviderLogInterval &&
		!time.Unix(0, last).After(now) {
		return
	}
	if !sessionProviderLogGate.CompareAndSwap(last, now.UnixNano()) {
		return // another request claimed this window
	}
	logger.Printf("AUTH_SESSION_PROVIDER_REVOKED client=%s provider=%q identity=%q total=%d: "+
		"the session was signed by this appliance but its identity provider is no longer enabled; "+
		"the request is treated as unauthenticated and re-challenged",
		sanitizeLog(clientIP), sanitizeLog(provider), sanitizeLog(subject), total)
}

// timeNowSessionProvider is the clock seam. A health/rate surface must be a
// pure function of recorded state and an INJECTED clock — mixing a real clock
// into a gate whose tests drive synthetic stamps is what made CHAOS-66's
// determinism gate fail on a loaded runner and nowhere else.
var timeNowSessionProvider = time.Now

// resetSessionProviderBoundsForTest clears the process-global counter and rate
// gate. A leaked gate suppresses the line for every later test in the package.
func resetSessionProviderBoundsForTest() {
	sessionProviderRevokedTotal.Store(0)
	sessionProviderLogGate.Store(0)
}
