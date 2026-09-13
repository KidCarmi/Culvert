# Security regression review — Canary read-first classification, OCSP revocation, rate-limit exempt view

**Date:** 2026-09-12
**Scope:** every change merged to `main` on 2026-09-12 — `574d265..2833db3`, i.e. the nine
pull requests #1362, #1363, #1364, #1365, #1366, #1367, #1368, #1369, #1370. 77 commits,
95 files, +12 179 / −406.
**Branch:** `claude/epic-bardeen-8qpw0p`
**Predecessor:** `2026-09-05-mcp-canary-physical-effect-window.md`.
**Method:** read every production diff hunk in the window (tests and docs read for the claims
they pin, not audited); trace each candidate finding to the consuming call site before calling
it a finding; verify the library behaviour a claim rests on against the module source rather
than the comment asserting it; and mutation-verify every new guard by reverting the fix and
requiring the guard to fail.

---

## 1. Executive summary

Three of the nine PRs are documentation or test-only (#1363, #1364, #1366 — see §6). The
other six are, in the main, **posture-strengthening work**, and two of them close real holes
in always-on code:

- **#1369 (OCSP, CHAOS-65)** rewrote upstream revocation checking and closed a complete
  revocation bypass by the party being checked, in seven distinct shapes across four review
  rounds — response-to-certificate binding, signer-to-authority binding, freshness, cache TTL
  capping against both the assertion and the signer, CertID-keyed caching, an SSRF-guarded
  responder client, and "revoked wins over good".
- **#1367** closed the second half of SEC-SOCKS5-LOG-1: unauthenticated SOCKS5 destination
  bytes still reached the process log unsanitised *indirectly*, through `plugin.Decide` →
  `obs.Printf`.
- **#1368** is a cost-only change to two per-request IP gates, and the exempt-list read path
  it rewrote preserves its previous verdict byte for byte — including the IPv4-mapped miss it
  deliberately did **not** "fix", because fixing it would widen a rate-limit exemption.
- **#1362** and **#1370** are the First Controlled Canary: #1362 adds a strictly narrower
  fail-closed activation gate, and #1370 adds a narrow, authoritative read-first tool
  classification plus a pre-send authority re-ask that closes a real TOCTOU between the
  boundary guards and the physical send.

**Two security-relevant regressions were found in #1370 and are fixed in this PR.** Both are
in the MCP subsystem, which composes nothing in a stock build.

| ID | Severity | Reachable in a stock build? | State |
|---|---|---|---|
| SEC-MCP-BAND-1 | **Low** (latent; see §2.4) | No — Gateway Canary must be armed, and the ambiguous-identity input is currently unreachable | **Fixed** — 1 runtime guard, 4 runtime gates + 2 policy-engine gates |
| SEC-MCP-PRESEND-1 | **Low** (correctness + data race) | No — same precondition | **Fixed** — refusal carried in the error, 3 gates |
| OCSP-11 | Informational | Yes (when OCSP is enabled) | **Recorded, not fixed** — see §4 |
| OBS-YARA-1 | Informational | Yes | **Recorded** — see §5 |

Nothing else in the window regressed. §6 records what was reviewed and why the current
implementation is sound.

---

## 2. SEC-MCP-BAND-1 — the read-first class promotion carries a `tools/call` out of the MCP-ID-005 identity hard override

**CWE-863 (Incorrect Authorization) · OWASP A01:2021 Broken Access Control · Low (latent).**

### 2.1 What changed

Before #1370, `runtime/policy.go`'s `policyOperation` classified **every** Gateway method
other than `tools/list` as `policy.OpWrite`:

```go
default: // tools/call
    // Conservative default: a tool call is a write unless a later slice supplies a
    // finer class. Destructive is NEVER assumed.
    op.Class = policy.OpWrite
```

#1370 adds the authoritative narrow exception the First Canary needs. When a Gateway canary
activation is armed and its immutable reviewed record binds this exact
`(tenant, server, tool)` at this exact fingerprint, fingerprint format and pinned server
identity to a four-eyes-reviewed read-only class, `classifyReadFirstToolCall` promotes the
call to `policy.OpRead`.

The promotion is written into `op.Class`, which `buildPolicyInput` then assigns to
`in.Operation` — the decision tuple the policy engine evaluates. That is deliberate and the
file says why: one classification, so the policy engine, the Canary activation gate and the
live side-effect gate cannot disagree about the class.

### 2.2 The consequence that was not stated

`op.Class` has more readers than the read-first gate, and one of them is a **hard override**
no rule can undo — MCP-ID-005, in `policy/engine.go`'s `subjectOverride`:

```go
// 4. Missing/ambiguous identity on a write/high-risk operation (MCP-ID-005).
if writeOrHigher(in.Operation.Class) && in.Principal.Assurance == AssuranceUnknown {
    return hard(ActionDeny, ReasonIdentityAmbiguous, RemediationIncreaseAssurance, in, snap), true
}
```

`writeOrHigher` is `OpWrite || OpDestructive || OpControl`. Because every `tools/call` was
`OpWrite`, this override denied **every tool invocation from a principal carrying no
assurance at all**, unconditionally and ahead of rule matching. A promotion to `OpRead` leaves
the band, so the override stops firing — and the promotion, not a policy decision, becomes the
reason an identity control no longer applies.

That is a different proposition from the one the review answered. A reviewer determined the
**tool** does not mutate state. Nobody determined that invoking it without knowing who is
asking is acceptable, and a non-mutating tool still returns upstream data to whoever called
it. The ordering was confirmed structurally, not inferred: `buildPolicyInput` sets
`Principal` first, calls `attachGatewayRefs` (which promotes) second, assigns
`in.Operation = op` third, and `dispatchPolicy` evaluates the engine fourth, so the promoted
class is exactly what `subjectOverride` reads.

### 2.3 Attack scenario

*Preconditions:* the Gateway capability in a live rollout mode with an armed activation
(`beginCanaryActivation`, reached from `mcp_rollout.go`'s commit path behind the activation
preflight); the target tool in the activation's reviewed set, matching on fingerprint, format,
tenant and pinned identity; a four-eyes `live_execution` approval; a policy rule that matches
the promoted read; and a request whose resolved assurance is `AssuranceUnknown`.

*Scenario:* the request is not hard-denied by MCP-ID-005 as it would have been before the
seam existed, and proceeds to rule matching. Everything downstream still applies — tenant
isolation, quarantine overrides, default-deny, the live-execution approval, the budget, the
class-in-force check — so the impact is bounded to the loss of **this one control**: an
unidentified principal reaching a real upstream tool invocation, where the gateway previously
refused it outright. A read-only tool still discloses upstream data.

### 2.4 Why the severity is Low, and why it is still worth fixing

`AssuranceUnknown` **is not reachable on the live MCP path today**, and that is a property of
a different package. `runtime/auth.go`'s `buildAuthRequest` asserts `AssuranceHigh` for every
request, and `authn.effectiveAssurance` **clamps** it to what the verified sender constraint
justifies — `AssuranceHigh` for DPoP/mTLS, `AssuranceLow` for a bearer token. The clamp is a
ceiling, never a floor, so the resolved value is always Low or High. Measured on the package's
own fixture: `assurance=low`. MCP-ID-005 is therefore currently unreachable for a Gateway
`tools/call` with or without this window's change.

So this is a **latent coupling**, not a live bypass, and the report says so rather than
inflating it. It is still worth closing now for one reason: the control is held up by an
invariant asserted nowhere, and `authn`'s own comment invites exactly the change that ends it —

> Extending this: a future caller with INDEPENDENT verified assurance evidence for a human (a
> checked `amr`/`acr` claim, a verified step-up assertion) must add that evidence as a new
> derivation branch here, where it can be checked […]

The first such branch that can yield Unknown makes the override reachable again, and at that
moment a reviewed tool is silently exempt from it. A three-line fail-closed guard bought now
costs nothing; discovered later it is a hole with a changelog entry in front of it.

### 2.5 Fix

`internal/mcp/runtime/policy.go` — decline the promotion when the principal's assurance is
unknown. The request keeps `OpWrite`, MCP-ID-005 denies it exactly as it did before the
classifier existed, and nothing about a properly identified principal changes:

```go
func (p *pipeline) classifyReadFirstToolCall(op *policy.Operation, serverID, toolName string, assurance policy.Assurance) {
    if p.capability != protocol.Gateway {
        return
    }
    if assurance == policy.AssuranceUnknown {
        return // never promote out of the MCP-ID-005 band
    }
    if p.deps.canaryReviewedReadFirst(p.capability.String(), serverID, toolName) {
        op.Class = policy.OpRead
    }
}
```

Three properties make this the safe shape:

- **It only ever subtracts.** Declining to promote can make a request more restricted, never
  less, so it cannot itself become a second way to promote (gated by
  `TestReadFirstRuntime_KnownIdentityDoesNotPromoteWithoutAReviewedRead`).
- **It is the same shape as every other branch in the function** — an uncertainty leaves
  `OpWrite` in place. "We cannot tell who is asking" joins "no armed activation", "no reviewed
  entry", "a drifted fingerprint".
- **The line is the hard override, not rule matching.** Moving a reviewed read-only tool
  between ordinary rules is what the reviewed class is *for*, and that is deliberately left
  alone. Only the fail-closed override that no rule can undo is protected.

The alternative considered and rejected was widening MCP-ID-005 to cover every Gateway tool
invocation regardless of class. It is the more architecturally honest statement of the
control, but it changes a shared policy engine for a case that is currently unreachable, with
a far larger blast radius on an engine carrying extensive existing tests. It is recorded here
as the deeper option for the owners; if it is taken, the runtime-side guard should be removed
in the same change rather than left as a second authority on the same question — and
`policy.TestIdentityBand_ReadIsOutsideTheBandSoAPromotionEscapesIt` fails when it is, which is
the intended signal.

### 2.6 Required tests — all present, all mutation-verified

`internal/mcp/runtime/read_first_identity_band_test.go`:

| Gate | Proves |
|---|---|
| `TestReadFirstRuntime_AmbiguousIdentityIsNeverPromoted` | the guard — verified **failing** against the pre-fix shape |
| `TestReadFirstRuntime_AmbiguousIdentityNeverReachesTheClassifier` | the seam is not even consulted — verified **failing** against the pre-fix shape |
| `TestReadFirstRuntime_KnownIdentityStillGetsThePromotion` | **control**: Low/Medium/High still promote, so the gate above is not satisfied by deleting the feature |
| `TestReadFirstRuntime_KnownIdentityDoesNotPromoteWithoutAReviewedRead` | the guard is not a second promotion path |

`internal/mcp/policy/identity_band_class_test.go` pins the engine-side fact the guard exists
for, from the engine's own side, so the coupling is visible in both directions:

| Gate | Proves |
|---|---|
| `TestIdentityBand_AmbiguousIdentityIsDeniedForEveryWriteOrHigherClass` | the band is `OpWrite`/`OpDestructive`/`OpControl` and the denial is a hard override |
| `TestIdentityBand_ReadIsOutsideTheBandSoAPromotionEscapesIt` | `OpRead` is outside it — i.e. a promotion alone is enough to escape |

The runtime gates call `classifyReadFirstToolCall` directly rather than driving `Process` end
to end. That is deliberate and documented in the file: the live path cannot produce
`AssuranceUnknown` today, so an end-to-end gate could only assert the coincidence that keeps
the override unreachable, not the rule that must hold when it becomes reachable.

---

## 3. SEC-MCP-PRESEND-1 — the pre-send refusal travelled in a captured variable, not in the error

**CWE-362 (Race Condition) · Low (correctness + data race).**

### 3.1 What changed

#1370 closes a real TOCTOU: `runExecute`'s comment used to say nothing blocking sits between
the final kill re-read and `Upstream.Call`, which was true of that function and false of the
one it calls — `Client.Call` blocks in `pool.acquire` until another request finishes, and then
in DNS, connect and the TLS handshake. A kill, a demotion, a scope withdrawal or an approval
revocation could land, return success, and the waiting request would send anyway.

The fix hands the client a `PreSend` predicate re-asked at two sites: in `roundTrip` before
`client.Do`, and in `pinnedDialTLS` after the TLS handshake with the connection established
and nothing written. This is good work and the two sites genuinely bracket different phases.

### 3.2 The defect

`internal/mcp/upstreamclient/transport.go` is explicit about why the dialer's verdict must not
be shared through a variable:

> A captured variable would have been simpler and wrong: net/http may dial on its own
> goroutine, so reading a value the dialer wrote after `Do` returns is a data race the
> detector would (rightly) flag. Carrying the fact IN THE ERROR needs no synchronisation at
> all.

`internal/mcp/execution/run.go` then did precisely that, one layer up:

```go
var preSendErr error
var preSendDrift bool
preSend := func() error {
    perr, drift := e.preCallGuard(in, admKillGen, revalidate)
    if perr != nil {
        preSendErr, preSendDrift = perr, drift
    }
    return perr
}
… Upstream.Call(…, CallOptions{… PreSend: preSend})
if preSendErr != nil { applyBoundaryRefusal(preSendErr, preSendDrift) }
```

Two consequences:

1. **A data race.** `getConn` selects on `w.ready` against `ctx.Done()`. When the request
   context ends while a dial is finishing, `Do` returns while the dial goroutine is still
   running; a handshake that completed in that instant still runs the predicate and writes
   these variables, concurrently with the read above and with no happens-before edge. A torn
   read of an `error` interface is undefined behaviour, and the required `-race` CI gate would
   flag it whenever the interleaving is hit.
2. **A mis-attribution, which is deterministic and needs no race at all.** An abandoned dial's
   refusal is discarded along with its connection, because the leg already failed for an
   unrelated reason — but the variable still holds "a refusal happened somewhere". The request
   is then diagnosed as a withdrawn-authority refusal when what actually failed was the
   transport. Both facts reach `bf.gateReason`, i.e. the outcome reason and the block
   telemetry an operator reads during an incident. That is the same class of defect #1370
   itself fixed twice in this window (the `not_for_certificate` and `responder_blocked`
   accusation counters in §6.1): **a surface an operator is told to act on must be charged
   only from evidence that supports the specific claim it makes.**

Fail-closed behaviour is *not* affected: the refusal still propagates as the error `Call`
returns, so the request is refused either way. What is lost or falsified is the diagnosis.

### 3.3 Fix

Carry both facts in the error, exactly as the client already does for its own marker:

```go
type preSendGuardErr struct {
    err     error
    drifted bool
}
func (e *preSendGuardErr) Error() string { return e.err.Error() }
func (e *preSendGuardErr) Unwrap() error { return e.err }
```

`preSend` returns `&preSendGuardErr{…}`; `runExecute` recovers it with
`errors.As(err, &preSendRefusal)`. `Unwrap` exposes the guard error, so
`classifyBoundaryError`'s `errors.Is` chain, `withdrawnReasonOf`, and the client's own
never-sent marking behave identically to a refusal raised by the pre-call guard directly. A
pre-send refusal is never retryable (it is marked never-sent, so `retryable()`'s pre-response
requirement fails), so the error `Call` returns is always the refusal itself when one
happened — the classification is complete, not merely usually complete.

### 3.4 Required tests — all present

`internal/mcp/execution/presend_refusal_carrier_test.go`:

| Gate | Proves |
|---|---|
| `TestPreSendRefusal_FromAnotherGoroutineIsStillClassified` | a refusal raised on another goroutine still surfaces the gate's own bounded reason, sends nothing, and releases the slot |
| `TestPreSendRefusal_AnAbandonedDialsRefusalIsNotAttributedToTheRequest` | the deterministic defect gate — verified **failing** against the captured-variable shape, with no timing dependence |
| `TestPreSendRefusal_PermittingPredicateStillSends` | **control**: a permitting predicate leaves the executing path untouched |

The fake upstream models net/http's dial goroutine (`opts.PreSend()` on its own goroutine).
Note honestly what the first gate does *not* prove: because the fake joins that goroutine, it
creates a happens-before edge, so it passes under `-race` against the pre-fix shape too. The
race is real but its interleaving cannot be scheduled deterministically from a test, which is
why the defect gate targets the **mis-attribution** half — the same reasoning
`shutdown_chaos_test.go` records for the escalation tie, and the repo's standing preference
for a deterministic gate over one that can flake.

---

## 4. OCSP-11 — the response's CertID issuer binding is not verified (recorded, not fixed)

**CWE-295 (Improper Certificate Validation) · Informational · reachable when OCSP is
enabled, but not exploitable in the mainstream threat model.**

#1369's central finding is that `cryptoocsp.ParseResponse` never compares the serial, so a
genuine CA-signed `good` about any other certificate of the same issuer answered for this one.
The fix — `ParseResponseForCert(respBytes, leaf, issuer)` — is correct and was verified against
the module source (`x/crypto@v0.56.0/ocsp/ocsp.go`). So was the `responderAuthorized` premise:
the library verifies the embedded delegate is issuer-signed and the response delegate-signed,
but never checks `id-kp-OCSPSigning`, which is exactly the hole round 1b closed.

What the library matches, however, is the **serial alone**:

```go
for _, resp := range basicResp.TBSResponseData.Responses {
    if cert.SerialNumber.Cmp(resp.CertID.SerialNumber) == 0 { … }
}
```

RFC 6960's CertID also carries `issuerNameHash` and `issuerKeyHash`, and neither is compared —
here or in the library. A serial is unique only *within* an issuer, which is the reasoning
this window already applied, correctly, to the verdict **cache** (`certKey` hashes the issuer
subject and SPKI alongside the serial, on the recorded grounds that sequential serials make
cross-CA collision ordinary rather than exotic). The same reasoning has not been carried to
the response **binding**.

**Why it is Informational and not a finding.** The response must still verify against this
issuer or an issuer-signed OCSP-EKU delegate inside its validity window. To exploit the gap an
attacker needs a signature from that authority over a CertID naming a *different* issuer and
the victim's serial — which a conforming responder never produces, and which a subscriber
cannot obtain, since CAs do not issue OCSP-signing delegates to subscribers. The reachable
shapes require a cross-signed delegated responder plus a serial collision across two CAs the
same node trusts.

**Recommended remediation, when it is taken.** `cryptoocsp.Response` exposes `IssuerHash` (the
algorithm) but not the CertID's `NameHash`/`IssuerKeyHash` values, so the check cannot be
written against the current API: it needs either an upstream addition or a local CertID parse
compared against the one `CreateRequest(leaf, issuer, nil)` built. That is its own change with
its own tests, and it should carry a gate proving a response whose CertID names another issuer
is refused. Recorded as a register row rather than patched inside a review of somebody else's
window.

**This is the fourth instance in one sweep of the pattern #1369's own header names** — a
validity rule enforced at one layer and not carried to the next (response→subject,
signer→authority, assertion→cache, signer→cache). Issuer→CertID is the fifth edge of the same
shape, and the standing rule the window records applies to it unchanged.

---

## 5. OBS-YARA-1 — the YARA rule set now lives on a writable volume (recorded)

#1366 corrects stale documentation: the effective rules directory has been `/data/yara` (the
compose file has passed `-yara-rules-dir /data/yara` for some time) while the comments and the
commented-out example mount still named the image path `/app/yara`. The change is a **fix**,
not a regression — an operator following the old comment would mount their rules over
`/app/yara`, where nothing reads them, and lose detection silently.

Worth recording for completeness: the effective path is on the writable `proxy-data` volume
rather than the read-only image, so YARA rule integrity now depends on `/data` integrity, and
`POST /api/security-scan/yara/reload` will load whatever is there. The marginal exposure is
small — anything with arbitrary write to `/data` can already rewrite `admin_settings.json` and
the policy store, which is a strictly larger win — and `seedYARARules` correctly refuses to
overwrite a non-empty directory, so operator rules are never clobbered. The documented
override mount is `:ro`.

---

## 6. Reviewed and found sound

### 6.1 #1369 — OCSP revocation checking (`internal/ocsp`, +585/−70)

Read in full against the library source. The engine is materially stronger than what it
replaced, and the four review rounds each closed a genuine hole. Verified specifically:

- `ParseResponseForCert` with a non-nil leaf at the one call site; `ParseResponse` appears
  nowhere in the package.
- `responderAuthorized` admits exactly two signers, refuses `ExtKeyUsageAny`, and checks the
  delegate's window — and the library's issuer-signature verification the function relies on
  is real (confirmed in `ocsp.go`, both the embedded-certificate and no-certificate branches).
- `responseValidUntil` mirrors `responderAuthorized`'s branch structure, so the cache expires
  at the instant a re-parse would begin refusing; the issuer-signed branch correctly takes no
  signer cap because that branch applies no window check.
- `cacheResult` does not cache a verdict already at or past its deadline (`ttl <= 0` returns).
- Only `Revoked` short-circuits `checkResponders`; a `Good` is remembered with the earliest
  deadline among the Good answers and the loop continues, so the peer's AIA **order** cannot
  decide the verdict.
- `certKey` hashes issuer subject + issuer SPKI + serial.
- The SSRF guard is inline at the call site per repo convention, `CheckRedirect` refuses
  outright, and `blockedTotal` is charged only on `errors.Is(err, ssrf.ErrBlocked)` at both
  the pre-flight and dial layers.
- `resolve` re-checks the cache inside `flightMu` before opening a flight, and the leader
  publishes on every exit path including a panic, with fail-closed flight defaults.
- Cache eviction at capacity is not a security concern here: an evicted verdict causes a
  re-query, never an admission (unlike the credential cache, where CHAOS-57 had to make
  eviction fair).

`ocsp_coverage.go` is honest disclosure of register row OCSP-8 — the callbacks are not on the
inspected-HTTPS path — with a structural gate pinning the agreement between the claim and the
code. Not wiring them is the correct call and the file states why.

### 6.2 #1369 — `ssrf.ErrBlocked` now wraps the pre-flight refusal

This widens a shared security sentinel, so every consumer was checked. There are three:
`internal/ocsp` (the intended new consumer, at both layers), and `errSSRFBlocked` in
`security.go`, whose only reader is `shouldRecordConnectFailure`. That function receives a
**dial** error from the `ssrfControl` dialer; the pre-flight `isPrivateHost` error returns 403
earlier in `handleTunnelInspect` and never reaches it, so the widening cannot move that
decision. No caller string-matches the messages (checked). The resolution-failure branch is
deliberately **not** wrapped, which is what makes the accusation counter honest.

### 6.3 #1368 — `prefixSet` extraction and the rate-limit exempt view

The extraction is faithful: `buildPrefixSet` is the previous `publishView` body verbatim and
`prefixSet.contains` the previous tail. `prefixFromIPNet` — the function whose family
normalisation is easy to get wrong in the fail-open direction — is now shared rather than
copied, which is the right call for the same reason the badger recovery engine moved to
`internal/storeguard`.

The new `IsExempt` preserves the previous verdict exactly: zoned addresses are rejected to
match `net.ParseIP`, `Unmap()` keeps a 4-in-6 probe matching v4 CIDRs and not v6 ones, and the
single-IP set is deliberately **not** canonicalised, because canonicalising would make a
mapped probe *hit* an exemption it does not hit today — widening a rate-limit bypass. All four
mutators (`AddExemption`, `AddExemptions`, `RemoveExemption`, `ReplaceExemptions`) publish; no
other writer of `exemptNets`/`exemptIPs` exists (checked). The published view never aliases
`exemptNets`, which matters because `RemoveExemption` compacts it in place. `AddExemptions` is
the bulk primitive and both list-restoring callers use it; the two call-site changes preserve
the previous silent-skip of invalid entries, including the deliberate decision not to add them
to the import response's `warnings`.

### 6.4 #1367 — log-injection round 2

Correct and in the right direction throughout. The finding it closes is the right one: walling
one *call shape* does not wall the *path*, and `plugin.Decide` → `obs.Printf` was reached from
an unauthenticated SOCKS5 request with a client-chosen destination. The remaining
`obs.ReportPanic("plugin:"+p.Name(), …)` passes an unsanitised component, but the production
sink renders it under `%q` (which escapes control characters) and as a JSON audit field, and
plugin names are compile-time in-tree — not a finding.

### 6.5 #1370 — the upstream client's `DialTLSContext` swap

Replacing `TLSClientConfig` + `TLSHandshakeTimeout` with `DialTLSContext` is the right way to
get a re-ask point after the handshake, and the two regressions it could have caused were both
handled: SNI is preserved explicitly (`cfg.ServerName = canon.Host` when empty — the pinned
branch of `tlsConfig` sets no ServerName, and net/http would have supplied it), and the
handshake stays bounded by `TLSTimeout()` on a context derived from the dial context. HTTP/2
negotiation is unchanged (neither shape sets `ForceAttemptHTTP2` or `NextProtos`, so both are
HTTP/1.1). `VerifyConnection` still runs under `InsecureSkipVerify` in the pinned branch.

### 6.6 #1370 / #1362 — the Canary gates themselves

- `canary.ReviewedTargetSet.Compare`/`OperationClassFor`/`ReviewedReadFirst` are pure, ignore
  `cur.OperationClass` as an input, and yield `(OpUnset, false)` for every verdict but an exact
  match — so a moved fingerprint, format, identity or tenant inherits no classification.
- `CanonicalizeReviewedTargets` refuses an unset or non-reviewable class, so an activation
  cannot arm carrying a target it cannot classify; the restore path re-validates through the
  same function.
- `canaryScopeInForce` and `canaryClassInForce` both fail closed on an empty/absent value.
- `Deps.canaryReviewedReadFirst` collapses the seam's two-value answer into one predicate, so
  no call site can read `ok` apart from the class.
- #1362 adds `ScopeExactFirstCanary` as a **new** activation-level readiness row that defaults
  false — a strict narrowing, evaluated from the signed scope in the authoritative preflight.

### 6.7 The small ones

- **#1365** adds `loginOversizeRejected` to `/api/stats` (viewer role, confirmed in
  `uiRoutes`). A count, no attacker-supplied content — the CHAOS-63 signal was otherwise
  visible only to a metrics scraper.
- **#1364** is documentation plus two `config.example.yaml` comments, including an explicit
  `trust_forwarded_headers: false` showing the safe default. No default changed.
- **#1363** adds a governance review document only.

---

## 7. Residual risk

- **OCSP-11** (§4) — the CertID issuer binding is unverified. Low exploitability; needs an
  API-level change to fix properly.
- **OCSP-8** — revocation is still not checked on the inspected-HTTPS path, which is the one
  path where this appliance validates an origin certificate for a client. Deliberate,
  disclosed on four surfaces by #1369, and correctly deferred: attaching the callbacks would
  make every inspected HTTPS request fail closed on reaching an external responder.
- **OCSP-9 / OCSP-10** — no stapling (`tls.ConnectionState.OCSPResponse` is never requested)
  and no CRL fallback; a certificate with no AIA responder is accepted unchecked.
- **SEC-MCP-BAND-1's deeper form** (§2.5) — MCP-ID-005 is still keyed on the operation class
  rather than on "is this a tool invocation", so any *future* promotion path into a
  non-`writeOrHigher` class needs the same guard. The two engine-side gates in
  `identity_band_class_test.go` are what make that visible.
- **AU-17, PX-1/5/6/7/8, WK-3c** and the rest of the standing register are unchanged by this
  window.

---

## 8. Files changed by this PR

| File | Change |
|---|---|
| `internal/mcp/runtime/policy.go` | SEC-MCP-BAND-1 — decline the read-first promotion for an unidentified principal |
| `internal/mcp/runtime/read_first_identity_band_test.go` | new — 4 gates (2 mutation-verified, 2 controls) |
| `internal/mcp/policy/identity_band_class_test.go` | new — 2 gates pinning the MCP-ID-005 band from the engine side |
| `internal/mcp/execution/run.go` | SEC-MCP-PRESEND-1 — carry the pre-send refusal in the error, not in captured variables |
| `internal/mcp/execution/presend_refusal_carrier_test.go` | new — 3 gates (1 mutation-verified, 1 control) |
| `docs/engineering/security-reviews/2026-09-12-canary-read-first-and-ocsp-window.md` | this review |
