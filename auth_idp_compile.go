package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"sync/atomic"
	"time"
)

// CHAOS-66 — what compiling an IdP profile actually DOES.
//
// Register row AU-11 scored this path "✓ compile", on the evidence that the
// staging is isolated: ReplaceAll builds every provider before it swaps the
// live registry, so a bad control-plane IdP update cannot break a Data Plane's
// working providers. That is true, and it answers a different question from
// the one that matters. The row asked how the compile is STAGED and never
// asked what the compile PERFORMS — and compileIdPProfile performs blocking
// outbound HTTP to an operator-named third party: fetchSAMLMetadata (15 s) for
// a SAML profile carrying metadata_url, fetchOIDCDiscovery (10 s) for every
// OIDC profile. Only the LDAP arm is network-free. Same shape as CA-6 before
// §35: the row's own evidence column named the property that makes the
// findings reachable, and the verdict looked past it.
//
// Two defects followed from it, both measured against the real binary.
//
// (1) THE REGISTRY WRITE LOCK WAS HELD ACROSS THAT FETCH. Upsert took
// r.mu.Lock() and then called compileIdPProfile under it. Go's sync.RWMutex is
// writer-preferring, so a blocked writer also blocks every subsequent RLock —
// and resolveRequestAuth (proxy.go) calls idpRegistry.HasEnabledInteractiveProvider()
// on EVERY proxied request. Measured against an origin that completes the TCP
// handshake and then goes silent — the ordinary wedged-IdP-web-tier fault, and
// the same fault CHAOS-58 bounded one subsystem over: the per-request probe was
// still blocked after 3 s and Upsert ran the full 10 s discovery timeout. So
// one admin saving one IdP profile stalled the entire data plane for ten
// seconds (fifteen for SAML), with no error, no counter and no health movement
// — the admin plane taking the data plane down, which is the posture §33 exists
// to forbid. r.persist was under the same lock, so an AtomicWrite (temp +
// fsync + rename) on a wedged or full volume reached the same stall by a
// second route.
//
// (2) EVERY SNAPSHOT APPLY REBUILT EVERY PROVIDER FROM SCRATCH, including
// profiles that had not changed. Measured: five byte-identical ReplaceAll
// calls rebuilt the live provider five times. A Data Plane polls the control
// plane every 30 s (dp_enrollment.go) and any config mutation anywhere in the
// fleet advances the snapshot version, so editing ONE policy rule made every
// node re-fetch every SAML metadata document and every OIDC discovery document
// — N nodes × M profiles of outbound traffic at the IdP, caused by a change
// that has nothing to do with identity.
//
// The consequence of (2) is the one an SRE cares about, because the compile's
// failure is not contained to identity. On the Data Plane poll path
// (fetchAndApply, controlplane_client.go) syncSnapshotIdPProfiles runs BEFORE
// applyConfigSnapshot and a failure returns: no blocklist, no policy rules, no
// rate limits, no IP filter, no session HMAC, no last-good persist, and
// lastVersion is not advanced — so the next poll re-downloads the same snapshot
// and re-attempts the same fetch, every 30 s, forever. An IdP's metadata
// endpoint being unreachable therefore FREEZES THE FLEET'S SECURITY CONFIG:
// a block rule pushed in response to an incident silently never arrives, while
// the proxy keeps serving on stale policy and the log says only "IdP profile
// sync rejected". The same fault reaches three callers with three different
// amounts of applied state (fetchAndApply applies nothing; applyConfigSnapshot
// has already applied policy and the blocklist; the delta path has applied
// everything but the extended state) — one fault, three postures.
//
// THE FIX IS TO REMOVE THE CAUSE, NOT TO RELITIGATE THE ABORT POSTURE. Whether
// a failed IdP compile should abort unrelated config is a real question and a
// real owner decision (recorded as IDP-3); it is not this change's to make,
// because partial application has its own hazard — a policy rule scoped to an
// authSource whose profile did not compile under-matches. What this change does
// is make the compile stop happening when nothing asked for it.
//
// Three rules now hold.
//
//   - **No third-party I/O runs under the registry lock, and none runs under
//     the persist either.** Registry mutations serialise on writeMu (the
//     enrollment.go importMu shape); r.mu is taken only to publish an
//     already-built candidate, so its hold time is a map swap.
//
//   - **A profile whose compile-relevant configuration is unchanged reuses its
//     live provider** on the ReplaceAll (control-plane snapshot) path. The
//     fingerprint covers the profile as marshalled, MINUS the OIDC endpoint
//     fields that the compile itself writes back (they are outputs, not
//     inputs), PLUS the ambient inputs the compile reads — today
//     proxyBaseURL(nil), which NewSAMLProvider turns into the SP EntityID and
//     ACS URL. A snapshot that changes the proxy base URL and nothing else must
//     still recompile, and applyExternalAuthSnapshotSettings deliberately sets
//     that value immediately before the IdP sync for exactly this reason.
//     Anything unrecognised — a nil profile, a marshal failure, a field added
//     later — yields a fingerprint that cannot match, so the fallback is
//     RECOMPILE, i.e. the pre-change behaviour. Never worse.
//
//   - **Upsert deliberately does NOT reuse.** An admin saving a profile is an
//     explicit operator action on one profile, and re-saving it unchanged is
//     the documented remedy for AU-6 (SAML metadata and OIDC discovery are
//     fetched once and never refreshed, so an IdP signing-certificate rollover
//     breaks assertion validation until the profile is re-saved or the process
//     restarts). Reusing there would delete the only recovery path this
//     appliance has for a rotated IdP certificate. The snapshot path carries no
//     per-profile operator intent — its trigger is someone editing a policy
//     rule — which is precisely why reuse belongs there and not here.
//
// The compile is also bounded by ONE envelope rather than a per-profile
// allowance (the CHAOS-58 / CHAOS-65 rule): idpCompileBudget is deliberately
// the old per-fetch SAML timeout, so a single-profile deployment is unchanged
// and only the worst case — N profiles serialising into N × 15 s on the poll
// goroutine and on the boot path — shrinks.

// idpCompileBudget bounds ALL third-party work performed by one registry
// operation, not each fetch within it. Deliberately the value fetchSAMLMetadata
// already spent on a single metadata document: the ordinary one-profile
// deployment is byte-identical and only the fan-out changes.
const idpCompileBudget = 15 * time.Second

// idpFingerprintScheme tags the fingerprint's construction. Bumping it
// invalidates every stored fingerprint, which costs one recompile per enabled
// profile and can never cause a stale provider to be reused.
const idpFingerprintScheme = "idpfp/v1"

// liveIdP is a compiled provider together with the fingerprint of the profile
// it was compiled FROM. They travel as one value so the two can never disagree
// — a separate parallel map would be a second source of truth for "is this
// provider still the right one", which is the question a reuse decision asks.
type liveIdP struct {
	provider    IdentityProvider
	fingerprint string
}

// compileIdPProfileFn is the compile seam. Production is compileIdPProfileCtx;
// tests substitute a compile whose cost and outcome they control, so the gates
// that pin the locking and reuse contracts are deterministic and need no
// network, no DNS and no timing assumptions.
var compileIdPProfileFn = compileIdPProfileCtx

// idpCompileContext returns the bounded context one registry operation's
// compiles share, plus its cancel func.
func idpCompileContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), idpCompileBudget)
}

// idpFetchContext derives the context one third-party fetch runs under. It
// inherits the caller's envelope when there is one, so N profiles share a
// single budget rather than taking a fresh allowance each; a caller with no
// deadline (a direct constructor call outside a registry mutation) gets the
// envelope's own value so no path is left unbounded.
func idpFetchContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		return context.WithTimeout(context.Background(), idpCompileBudget)
	}
	if _, ok := parent.Deadline(); ok {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, idpCompileBudget)
}

// idpCompileFingerprint identifies the inputs a compile consumes. Equal
// fingerprints mean compiling again would produce a provider equivalent to the
// one already live, so the existing one may be reused and the third-party fetch
// skipped.
//
// It returns "" for anything it cannot characterise. "" is never equal to a
// stored fingerprint (those are hex SHA-256), and reuse additionally requires a
// non-empty value, so an uncharacterisable profile always recompiles.
func idpCompileFingerprint(p *IdPProfile) string {
	if p == nil {
		return ""
	}
	c := *p
	if c.OIDC != nil {
		o := *c.OIDC
		// Written back by NewOIDCFlowProvider from the discovery document, so
		// they are OUTPUTS of a compile. Including them would make the
		// fingerprint of a freshly-compiled profile differ from the fingerprint
		// of the identical admin input and defeat every reuse.
		o.AuthorizationEndpoint = ""
		o.TokenEndpoint = ""
		o.IntrospectionEndpoint = ""
		o.UserinfoEndpoint = ""
		o.JWKsURI = ""
		c.OIDC = &o
	}
	b, err := json.Marshal(&c)
	if err != nil {
		return ""
	}
	h := sha256.New()
	idpFPWrite(h, []byte(idpFingerprintScheme))
	idpFPWrite(h, b)
	// Ambient compile inputs. NewSAMLProvider reads proxyBaseURL(nil) and turns
	// it into the SP EntityID and the ACS URL, so a snapshot that changes only
	// the proxy base URL changes what a compile would produce even though the
	// profile bytes are identical. Anything else a constructor comes to read
	// from outside the profile belongs here too.
	idpFPWrite(h, []byte(proxyBaseURL(nil)))
	return hex.EncodeToString(h.Sum(nil))
}

// idpFPWrite length-frames one field into the digest so that concatenation can
// never make two different field sets hash alike (the CHAOS-57 cacheKey rule).
func idpFPWrite(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	h.Write(n[:]) //nolint:errcheck // hash.Hash.Write never returns an error
	h.Write(b)    //nolint:errcheck // hash.Hash.Write never returns an error
}

// ---------------------------------------------------------------------------
// Observability
//
// Counters only, and no new operator-contract row or alert. The state an
// operator must act on — "this node is not applying new policy/auth config" —
// already has exactly one name (the dp_config_snapshot_apply check,
// diagnostics.go, fed by configSnapshotApplyFailing), and a second name for one
// root cause is two pages for one action. What was missing is the magnitude and
// the cause: how much third-party work the registry is doing, how much of it
// the reuse rule removed, and whether compiles are failing.
// ---------------------------------------------------------------------------

var (
	idpCompileTotal       atomic.Int64
	idpCompileFailures    atomic.Int64
	idpCompileReusedTotal atomic.Int64
)

func noteIdPCompiled()       { idpCompileTotal.Add(1) }
func noteIdPCompileFailure() { idpCompileFailures.Add(1) }
func noteIdPCompileReused()  { idpCompileReusedTotal.Add(1) }

// idpCompileCounters reports the three counters for the metrics exposition.
func idpCompileCounters() (compiled, failed, reused int64) {
	return idpCompileTotal.Load(), idpCompileFailures.Load(), idpCompileReusedTotal.Load()
}

// resetIdPCompileCountersForTest isolates the process-global counters.
func resetIdPCompileCountersForTest() {
	idpCompileTotal.Store(0)
	idpCompileFailures.Store(0)
	idpCompileReusedTotal.Store(0)
}
