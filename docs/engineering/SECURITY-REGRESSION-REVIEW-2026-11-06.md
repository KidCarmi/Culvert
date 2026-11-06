# Security Regression Review — 2026-11-06

**Scope.** `ee0f2ab…b05d649` (`origin/main`) — the 24 h since the 2026-11-05
review, 7 merged pull requests (#1807 #1808 #1809 #1810 #1811 #1812 #1813), 93
files, +13,668/−119. Of that, ~11,900 lines are a newly vendored third-party
SAML library. Production code changed in six places: `third_party/saml/`
(vendored fork + patches), `internal/admission/engine.go`,
`cluster_ratelimit_budget.go` (new), `controlplane.go`, `internal/ca/ca.go`, and
`diagnostics_blocklist_feed.go` (new).

| PR | Change | Security surface |
|---|---|---|
| **#1813** | `fix(saml): patch GO-2026-6909 in the vendored crewjam/saml fork` | **SAML assertion validation** — authentication bypass, identity spoofing, supply chain |
| **#1807–#1812** | `CHAOS-111: bound the hot-IP gossip plane` | **cluster rate-limit enforcement**, control-plane authz, memory exhaustion, disclosure |
| **#1808** | `perf(ca): take the manager lock off the leaf-cert cache hit path` | **intercepting-CA leaf cache** — MITM-class wrong-certificate risk, CA rotation, remote memory exhaustion |
| **#1809** | `diag: warn when a remote blocklist feed's latest sync failed` | threat-feed staleness visibility, SSRF, log injection |
| **#1810** | `fix(maint-install): read one-line triple-quoted TOML literals` | maintenance-agent install parsing |
| **#1811** | the 2026-11-05 review's own fixes (DPI saturation indicator) | already reviewed |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against
`ee0f2ab`, not against an ideal. One finding is measured against `b05d649`
itself, because this window *introduced* the code that carries it.

**Method.** This window's risk is concentrated and asymmetric. The SAML fork is
~11,900 lines of freshly vendored authentication code with three hand-written
security patches and no upstream fix to compare against; it was reviewed as a
supply-chain artifact first (is it what it claims to be?) and as a security
patch second (does it close the class it claims to close?). The CHAOS-111 and
CA changes were each given a bounded, hypothesis-driven pass against their
pre-range behavior. Every claim below that matters was executed, not reasoned
about: the three patch claims were tested against the real upstream release, and
the one finding that changes an authentication decision was demonstrated end to
end through Culvert's own SAML callback before and after the fix.

**Five findings. Three fixed here, one reported and pinned, one documentation
correction. Thirteen hypotheses were tested: ten disproved outright, and three
wrong in a way that became a finding.**

---

## Executive Summary

The SAML fork is genuinely what it says it is — verified byte for byte against
the signed upstream release — and its three patches are correct. But its
namespace qualification stopped at the fields that carry *identity* and left
the fields that carry *validity* on their original namespace-blind tags. Under
the fork's own stated precondition, that leaves **every check
`validateAssertion` makes defeatable except the signature, the issuer and a 90-
second issue delay**: audience restriction, ACS recipient binding,
`InResponseTo` binding and both expiry windows all fall. Measured end to end, an
assertion the IdP minted for a *different* service provider, audience-restricted
to it and expired 30 minutes earlier, authenticated to Culvert as that
assertion's subject. That is cross-SP assertion reuse — an authentication
bypass — and it is a completeness gap in a security fix this window shipped,
under exactly the precondition the window itself judged worth fixing. It is
fixed here with the same six-line mechanism, plus the one fail-closed check that
the fix makes necessary.

The CHAOS-111 gossip bound and the CA lock-free cache both hold. Neither
introduced an exploitable regression; the CHAOS-111 work is, on net, strongly
fail-closed relative to `ee0f2ab`, where the flood it exists to survive took the
whole cluster's rate limiting offline. Each left one low-severity gap, both
addressed: the CA change made a hand-maintained counter the sole input to a
remote-triggerable memory bound while removing the only test that checked that
counter against reality, and the gossip cache introduced a sub-second window in
which one address loses remote enforcement on one node.

No regression was found in authorization, CSRF, XSS, SSRF, open redirect,
header injection, request smuggling, path traversal, command injection, log
injection, secret exposure, audit coverage, TLS or certificate validation,
persistence or wire compatibility.

---

## Security Findings

### S-1 (fixed) — the SAML fork's namespace fix stopped short of every check that decides whether an assertion is *for this SP* and *still valid*

**Affected contract.** `third_party/saml/schema.go`,
`(*ServiceProvider).validateAssertion` and `validateAudienceRestriction` in
`third_party/saml/service_provider.go`; Culvert's only consumer is
`SAMLProvider.ExchangeAssertion` (`auth_saml.go:208`), which does **no
independent audience or recipient check** — it trusts the library's verdict
entirely.

**Defect.** Patch (b) of the fork namespace-qualified `Subject.NameID` and the
`AttributeStatement`/`Attribute`/`AttributeValue` chain, because
`encoding/xml` matches a bare-tagged or untagged field against an element of
that local name in *any* namespace. The fields that gate validity kept their
original tags. `encoding/xml` treats two shapes differently, and both are
exploitable:

| Shape | Second same-local-name match | Fields left unqualified |
|---|---|---|
| pointer / value struct | **overwrites** the existing struct's attributes | `Assertion.Conditions`, `SubjectConfirmation.SubjectConfirmationData`, `AudienceRestriction.Audience` |
| slice | **appends** | `Subject.SubjectConfirmations`, `Conditions.AudienceRestrictions` |

`validateAudienceRestriction` accepts when **any** entry matches
(`service_provider.go`, `audienceRestrictionsValid`), so one appended
foreign-namespace `<x:AudienceRestriction>` is sufficient. Note that the
fork's own `PATCHES.md` described this as "would replace it (last match wins)" —
that is the pointer behaviour; for the two slice fields the mechanism is
*append*, which is why the audience restriction falls even though the IdP's own
entry survives.

**Attack scenario.** Preconditions, in full: (1) an IdP that Culvert trusts
signs an assertion that contains foreign-namespace sibling elements — the
fork's stated precondition for (b) and (c), and the advisory's own; (2) the
attacker can present that assertion to Culvert's ACS within `MaxIssueDelay`
(90 s, `service_provider.go:168`), from a login flow they initiated themselves,
so the `RelayState` and stored request ID are theirs.

Given that, with patches (a)+(b)+(c) only:

```
<saml:Assertion …>                                  ← signed, unmodified
  <saml:Subject>
    <saml:NameID>admin@example.com</saml:NameID>    ← bound correctly by (b)
    <saml:SubjectConfirmation>
      <saml:SubjectConfirmationData                  ← the IdP's real values
          Recipient="https://other-sp/acs"
          InResponseTo="id-another-sps-request"
          NotOnOrAfter="11:00"/>
      <x:SubjectConfirmationData                     ← overwrites all three
          Recipient="https://culvert/auth/saml/callback"
          InResponseTo="id-attackers-own-request"
          NotOnOrAfter="2099-01-01"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotOnOrAfter="11:30">             ← the IdP's real window
    <saml:AudienceRestriction>
      <saml:Audience>https://other-sp/metadata</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <x:Conditions NotOnOrAfter="2099-01-01">           ← overwrites the window
    <x:AudienceRestriction>                          ← APPENDED; one match passes
      <x:Audience>https://culvert/</x:Audience>
    </x:AudienceRestriction>
  </x:Conditions>
</saml:Assertion>
```

Every remaining check falls. Measured against the as-merged fork at 12:00, with
`AllowIDPInitiated: false` (Culvert's setting, `auth_saml.go:109`, so
`InResponseTo` *is* checked):

```
Conditions.NotOnOrAfter  = 2099-01-01   (the IdP signed 11:30)
AudienceRestrictions     = 2 entries    [other-sp, culvert]  → passes
SCD.Recipient            = culvert ACS  (the IdP signed other-sp's ACS)
SCD.InResponseTo         = attacker's   (the IdP signed another SP's request)
SCD.NotOnOrAfter         = 2099-01-01   (the IdP signed 11:00)
→ validateAssertion: ACCEPTED
```

and end to end through `SAMLProvider.ExchangeAssertion`, against the as-merged
fork, the callback returned a full identity:

```
authenticated as &{Sub:alice@example.com Email:alice@example.com
                   Name:Alice Example Groups:[engineering admins] Provider:corp-saml}
```

for an assertion audience-restricted to `other-sp.example`, bound to
`other-sp.example`'s ACS, and expired in the year 2000.

**Exploitability and likelihood.** Exploitability given the precondition is
high: the whole attack is attribute values on sibling elements, no
cryptographic work, and the groups it carries feed Culvert's policy. Likelihood
is **low**, because the precondition requires the IdP to emit foreign-namespace
elements inside the region it signs — a relay cannot add them, since exclusive
canonicalization covers the namespace declaration of every visibly-utilized
prefix inside the signed assertion. The realistic sources are a compromised or
malicious IdP, a multi-tenant IdP whose assertion XML a tenant can influence, or
an IdP proxy that re-signs. The reason to fix it anyway is consistency: this
window already paid the compatibility cost of namespace-qualifying `NameID` and
the attribute chain under *this same precondition*, and a precondition worth
closing for identity spoofing is worth closing for authentication bypass.

**Impact / affected assets.** Authentication on every Culvert surface that
accepts SAML, including the admin control plane; the identity and group claims
that feed policy decisions; cross-tenant and cross-SP trust boundaries.

**Fix.** Namespace-qualify the six fields `validateAssertion` and
`validateAudienceRestriction` read, with the same
`urn:oasis:names:tc:SAML:2.0:assertion <local>` mechanism and the same
`Culvert fork (GO-2026-6909)` comment convention as (b). Scoped deliberately to
the fields that gate the authentication decision; the fields nothing reads are
left alone and recorded (see Residual Risk).

**Severity.** High impact, low likelihood → **Medium**, raised in priority
because it is an incomplete security fix shipped in this window rather than an
inherited defect.

**CWE.** CWE-287 Improper Authentication; CWE-290 Authentication Bypass by
Spoofing; CWE-294 Authentication Bypass by Capture-replay; CWE-91 XML Injection.
**OWASP.** A07:2021 Identification and Authentication Failures.
**Regression risk of the fix.** Low — see Regression Analysis.

### S-2 (fixed) — `validateAssertion` accepted an assertion with no `SubjectConfirmation` at all, skipping `Recipient` and `InResponseTo`

**Defect.** The loop
`for _, subjectConfirmation := range assertion.Subject.SubjectConfirmations` is
the **only** place `Recipient` and `InResponseTo` are checked. An empty slice
runs the body zero times, so both checks are silently skipped and the assertion
is accepted on the signature, issuer, issue delay and `Conditions` alone.
Measured against the as-merged fork:

```
FAIL-OPEN: assertion with no SubjectConfirmation accepted;
           Recipient and InResponseTo never checked
```

This is pre-existing in upstream v0.5.1 and is **not** a regression. It is
reported and fixed here for two reasons. First, it is precisely the fail-open
that patch (a) — "reject, never dereference, missing elements" — set out to
close, and (a) closed the nil-pointer cases while leaving the empty-slice case.
Second, and decisively, S-1's fix makes closing it mandatory: once
`SubjectConfirmations` binds only to the assertion namespace, an assertion whose
*only* confirmation is foreign-namespace leaves the slice empty, and S-1's fix
would otherwise have converted a hostile confirmation into **no confirmation
checks at all** — a strictly worse outcome than the bug it fixes.

**Fix.** `len(assertion.Subject.SubjectConfirmations) == 0` →
`assertion Subject has no SubjectConfirmation`. The Web Browser SSO profile
requires at least one bearer `<saml:SubjectConfirmation>`
(saml-profiles-2.0-os §4.1.4.2), so this rejects only schema-invalid input.

**Severity.** **Medium** standalone (it needs the same IdP-side precondition);
**required** as part of S-1.
**CWE.** CWE-287; CWE-294. **OWASP.** A07:2021.

### S-3 (fixed, test only) — the leaf-cert cache's memory bound lost its only independent oracle in the same change that made it counter-driven

**Affected contract.** `internal/ca/ca.go`, `storeLeaf` / `certCacheMaxSize`
(10,000 entries, evict oldest 10%).

**Defect.** `b80a415` replaced the `map` behind the leaf cache with a
`sync.Map`. `sync.Map` has no `len()`, so `certCacheMaxSize` is now enforced
against `cm.cacheLen`, a hand-maintained `atomic.Int64`
(`if cm.cacheLen.Load() > certCacheMaxSize`). A forward proxy's client chooses
the SNI, so it chooses this cache's keys — `certCacheMaxSize` is a
**remote-memory-exhaustion bound**. In the same change,
`TestGetCert_CacheOrderDoesNotGrowOnRefresh` had its
`entries := len(cm.cache)` rewritten to `entries := cm.CertCacheLen()`, which
was the only assertion in the package that compared the cache's size against
the map itself. The new `TestCertCache_LenDrivesEviction` compares `cacheLen`
against `cacheOrder`, but the same two statement pairs in `storeLeaf` maintain
both, so it is not an independent oracle.

The bookkeeping is correct **today** — every `cacheLen` write sits under `mu`
beside the map mutation it describes, and the invariant
`cacheLen == live entries == len(cacheOrder)` was verified to hold across 2,500
bound-crossing inserts with a `Range`-counted ground truth. This is a test gap,
not a live vulnerability.

**Failure scenario.** A later change that stores into or deletes from
`cm.cache` outside `storeLeaf`/`resetLeafCacheLocked` — a per-host invalidation
endpoint, a negative-cache entry, a TTL sweeper — without moving `cacheLen`.
The counter then under-counts, the eviction branch stops firing, and the cache
grows without bound on attacker-chosen hostnames. **Proven by mutation**:
injecting one untracked sibling `cm.cache.Store` into `storeLeaf` leaves
`TestCertCache_LenDrivesEviction`, `TestCertCache_ResetClearsTheLenCounter` and
`TestGetCert_CacheOrderDoesNotGrowOnRefresh` all **green** while the map holds
twice the entries the bound allows. Only the new oracle catches it.

**Fix.** `TestCertCache_LenAgreesWithTheMapItCounts` — a `Range`-counted count
of what the `sync.Map` actually holds, asserted against both `cacheLen` and
`cacheOrder` at every stage of the lifecycle (empty, distinct inserts, a refresh
of an already-cached host, seeded to the bound, the insert that crosses it, and
`ClearCache`). No production code changed.

**Severity.** **Low** (test coverage of a remote-triggerable bound).
**CWE.** CWE-770 Allocation of Resources Without Limits or Throttling (the
guard, not a live defect); CWE-1121 excessive reliance on derived state.
**OWASP.** A04:2021 Insecure Design.

### S-4 (reported, not fixed; bound pinned) — the cached gossip generation narrows remote rate-limit enforcement for up to one second

**Affected contract.** `controlplane.go`,
`(*rateLimitAggregator).ClusterTotalsExcluding` pass 1 and `Update`.

**Defect.** `Update` deliberately does **not** invalidate the cached
generation for a node it already knows ("that is the steady state the cache
exists for"). Pass 1 skips any IP the generation does not track
(`if !tracked { continue }`). So a peer's count that lands after
`gen.builtAt` is invisible to the reply for the rest of `rlTotalsCacheTTL`
(1 s), and for an address the generation does not track at all, pass 2 cannot
supply it either: `FreshCount` reads the missing IP as zero and that one address
is enforced **locally-only on that one node** until the requester's next round.
`ee0f2ab`'s `ClusterTotalsExcluding` summed `a.perNode` live inside the RPC, so
it *did* include such a count. This is therefore a regression in the strict
sense.

**Why it is not fixed.** The exposure widens from the pre-existing ≤5 s gossip
cadence (`rlGossipInterval`) to ≤6 s, against a freshness window of the whole
rate-limit window — `clusterRemoteCountMaxAge(window)`, and every production
`RateLimiter.Configure` call site passes a hardcoded `time.Minute` (only the
*limit* is operator-configurable; verified across all eight call sites). It is
bounded to one address on one node for one round, the local half of the limit
never stops applying, and it is not attacker-steerable: `builtAt` is re-rolled
every ≤1 s and the alignment depends on independent staggered 5 s tickers. Both
available fixes are worse than the defect — falling back to the live per-node
slots costs O(nodes) per untracked address (up to 4,096 × nodes per RPC), and
invalidating on any untracked IP means a flood invalidates every generation,
each reintroducing the O(nodes² × hot IPs) collapse CHAOS-111 exists to
eliminate.

**What was done instead.** The pass-1 comment asserted that "absent from the
reply is exactly what the pre-fix code produced for an IP no OTHER node
reported". That is inaccurate in the one case that matters, and a maintainer
reading it would conclude pass 1 loses nothing. It now states the real bound and
names the gate. `TestCHAOS111_PassOneStalenessStaysInsideTheGossipRound` pins
the constant relations that keep the window negligible
(`rlTotalsCacheTTL` < `rlGossipInterval`, ≤ a tenth of the rate-limit window,
≪ `rlNodeStaleAfter`) and demonstrates the window itself, including that it
closes on the next rebuild rather than persisting. Verified by mutation: raising
`rlTotalsCacheTTL` to 10 s fails the gate.

**Severity.** **Low**. **CWE.** CWE-770. **OWASP.** A04:2021.

### S-5 (corrected) — two inaccuracies in the fork's own patch record

`third_party/saml/PATCHES.md` is the document a future maintainer will use to
tell an introduced failure from a pre-existing one, and to decide when the fork
can be deleted. Two statements in it were wrong.

1. Its Verification section claimed the full upstream suite produces "one
   failure that is pre-existing and unrelated
   (`TestSPCanProduceSignedRequestRedirectBinding`, a DEFLATE output golden that
   differs under the current Go toolchain)". That test **passes** on clean
   v0.5.1 at the pinned toolchain (go1.27.3), across all eight of its
   RSA/ECDSA × SHA-1/256/384/512 subtests. It is not a baseline failure, and
   recording it as one would mask a real one later.
2. The "Known remaining issues" entry described the unqualified fields as
   something a foreign element "would replace … (last match wins)". That is
   true of the pointer and value fields and false of the two slice fields,
   where the mechanism is *append* — which is exactly why the audience
   restriction was defeatable while the IdP's own entry survived.

Both are corrected, the verification note now records the measured three-arm
differential, and patch (d) is documented.

---

## Risk Rating

| ID | Finding | Impact | Likelihood | Severity | Regression? | Status |
|---|---|---|---|---|---|---|
| S-1 | SAML validity fields namespace-blind → cross-SP assertion reuse | High | Low | **Medium** | Incomplete fix shipped in-window | **Fixed** |
| S-2 | Empty `SubjectConfirmations` skips Recipient + InResponseTo | High | Low | **Medium** | No (upstream v0.5.1) | **Fixed** (required by S-1) |
| S-3 | Leaf-cache memory bound lost its independent oracle | Medium | — (test gap) | **Low** | Yes (in-window) | **Fixed** (test only) |
| S-4 | Cached gossip generation narrows remote enforcement ≤1 s | Low | Low | **Low** | Yes (in-window) | **Reported + pinned** |
| S-5 | Patch-record inaccuracies | — | — | **Informational** | Yes (in-window) | **Corrected** |

---

## Regression Analysis

**Does S-1/S-2's fix break conforming SAML?** This is the only question in this
review that could cause an outage, and it was answered by execution rather than
by argument.

The fork drops every upstream test that loads key material, so the vendored
tree's own suite cannot answer it. The complete v0.5.1 release — including
`service_provider_test.go`, `identity_provider_test.go`, and the `samlsp` and
`samlidp` suites — was therefore run as a **three-arm differential** against a
scratch copy of the release with only the patched production files overlaid:

| Arm | Failures |
|---|---|
| clean v0.5.1 | *none* |
| fork as merged (`b05d649`) | `TestAttributeXMLRoundTrip`, `TestParseXMLArtifactResponse` |
| fork with S-1/S-2 fixed | **the same two — no new failures** |

Both are `xml.Marshal` golden-string comparisons, pre-existing from patch (b):
the qualified structs emit additional redundant
`xmlns="urn:oasis:names:tc:SAML:2.0:assertion"` declarations and the parsed
content is identical. `xml.Marshal` is not on a production path for any of these
types — the library builds its outbound XML with `Element()`, and the only
production `xml.Marshal`/`MarshalIndent` calls marshal *metadata*
(`identity_provider.go:203`, `samlsp/middleware.go:71`, Culvert's
`ui_auth.go:1152`), which contains none of the six changed types. So **no byte
Culvert emits changes.**

The behavioural direction was also pinned positively, not inferred: the three
spellings a real IdP uses — a declared `saml:` prefix, a default `xmlns` on the
assertion, and the prefix redeclared on every individual element — all still
bind and still validate, and that control passes on **both** arms. A
foreign-namespace element at any of the six sites is now *ignored* rather than
fatal: an otherwise-valid response carrying one still authenticates. The
residual compatibility cost is an IdP that qualifies `<saml:Assertion>` but not
its children, which is schema-invalid SAML, and is the same cost patch (b)
already accepted for `NameID`.

**Supply chain.** The fork's provenance claim was verified rather than trusted.
`github.com/crewjam/saml@v0.5.1` was downloaded through the module proxy with
sumdb verification; its hashes match `PATCHES.md` exactly
(`h1:g+mfp0CrLuLRZCK793PgJcZeg5dS/0CDwoeAX2zcwNI=`,
go.mod `h1:r0fDkmFe5URDgPrmtH0IYokva6fac3AUdstiPhyEolQ=`). A full recursive diff
against the vendored tree shows **only** `schema.go`, `schema_test.go` and
`service_provider.go` differing, with `PATCHES.md` and `go_2026_6909_test.go`
added and the dropped files exactly as documented (tests, `testdata/`, the
go-fuzz harness, `example/`, CI metadata). Nothing was altered in `xmlenc/`,
`identity_provider.go`, `metadata.go` or anywhere else — in particular, no
signature-verification or decryption path was touched beyond the three
documented patches.

**CHAOS-111 and CA.** Both were checked against `ee0f2ab` across rate-limit
bypass, cache staleness, control-plane authorization, disclosure, memory/DoS and
log injection (CHAOS-111) and key correctness, CA rotation, expiry, bounds, data
race and the owner's concurrency contract (CA). `SyncRateLimits` still begins
with `verifyNode` at byte-identical position; `apiClusterRateLimits` still
carries `requireRole(RoleViewer)` and its new keys are integers only — no IP
addresses on any new API, metric or UI surface; the one new log line uses
`logger.Printf` with `sanitizeLog(node)` and `%q`. All four CA-install paths
still reset the leaf cache under `mu`, the TTL and leaf-expiry checks on the
fast path are byte-identical to `ee0f2ab`, and the cache key is the bare host
in both versions with the leaf's SANs derived from that same string. The
CHAOS-111 work is a large **net fail-closed** improvement: at `ee0f2ab` the
50-node × 50,000-hot-IP flood blew the RPC deadline, so `ApplyRemoteCounts` was
never called and *every* address on *every* node degraded to local-only
limiting.

---

## Attack Scenarios

1. **Cross-SP SAML assertion reuse (S-1).** An IdP-signed assertion carrying
   foreign-namespace siblings, minted for another service provider and already
   expired, is replayed into Culvert's ACS within 90 s from a login flow the
   attacker initiated. Audience, ACS recipient, `InResponseTo` and both expiry
   windows are all supplied by the attacker's elements. Result: authentication
   as the assertion's subject, with its group claims feeding policy.
   **Demonstrated end to end; now rejected.**
2. **Hostile confirmation becomes no confirmation (S-2, interaction).** Had S-1
   been fixed without S-2, an assertion whose only `<SubjectConfirmation>` is
   foreign-namespace would have left the slice empty and skipped the `Recipient`
   and `InResponseTo` checks entirely — a worse outcome than the original bug.
   **Closed in the same change; pinned by a dedicated subtest.**
3. **Unbounded leaf-cache growth on attacker-chosen SNI (S-3, future).** A
   later cache writer that misses the counter silently disables eviction; a
   client that controls the SNI then grows the cache without limit while every
   test in the package passes. **Mutation-proven; now caught.**
4. **Per-address remote-enforcement gap (S-4).** An address crossing the hot
   threshold on a peer inside a ≤1 s slice contributes no remote count to one
   node's next round, roughly doubling that node's permissiveness for that one
   address for one round. Not attacker-steerable; **documented and bounded.**

---

## Hypotheses tested and disproved

A disproof is worth as much as a finding: it is what makes the absence of a
regression a measurement rather than an impression.

| Hypothesis | Disproving evidence |
|---|---|
| The vendored fork differs from upstream v0.5.1 somewhere undocumented — a weakened signature check, a changed `xmlenc` decryption path, a quietly dropped guard | `go mod download` of `v0.5.1` through the proxy with sumdb verification: hashes match `PATCHES.md` exactly. Recursive `diff -rq` against the vendored tree: **only** `schema.go`, `schema_test.go`, `service_provider.go` differ; additions are `PATCHES.md` + `go_2026_6909_test.go`; dropped files exactly as documented. `xmlenc/`, `identity_provider.go`, `metadata.go`, `samlsp/`, `samlidp/` byte-identical |
| The fix for S-1 breaks conforming SAML from a real IdP | Three-arm differential of the **complete** v0.5.1 suite (including the key-dependent `service_provider`/`identity_provider`/`samlsp`/`samlidp` tests the fork drops): clean = all pass, fork-before = 2 marshal-golden failures, fork-after = **the same 2, none new** |
| The fix changes bytes Culvert emits on the wire | All six changed types have `Element()` methods and the library builds outbound XML with those. The only production `xml.Marshal`/`MarshalIndent` calls marshal *metadata* (`identity_provider.go:203`, `samlsp/middleware.go:71`, `ui_auth.go:1152`), which contains none of them |
| Namespace-qualifying `Subject.SubjectConfirmations` is safe on its own | **Disproved — this became S-2.** The validation loop is the only place `Recipient`/`InResponseTo` are checked, so a foreign-namespace-only confirmation would leave the slice empty and skip both. The qualification is only safe together with the empty-slice rejection |
| A foreign `<x:Conditions>` *replaces* `AudienceRestrictions`, clearing them | **Premise wrong.** `encoding/xml` appends to slice fields rather than replacing; the IdP's own entry survives. The actual defeat is appending one *matching* entry, because `validateAudienceRestriction` accepts when any entry matches. `PATCHES.md` corrected (S-5) |
| An *empty* foreign `<x:Conditions>` is enough to defeat the expiry check | Zero-value `NotOnOrAfter` makes `NotOnOrAfter.Add(MaxClockSkew).Before(now)` true → `"assertion Conditions is expired"`. That direction fails **closed**; the attacker must supply an explicit future window |
| `TestSPCanProduceSignedRequestRedirectBinding` is a pre-existing upstream baseline failure, as the patch record claims | Passes on clean v0.5.1 at the pinned go1.27.3, all eight RSA/ECDSA × SHA-1/256/384/512 subtests. **Became S-5** |
| A control-plane route became reachable without authentication, or a role gate was dropped | `SyncRateLimits` is byte-identical at its head with `verifyNode` in the same position; `controlplane_tls.go`, `controlplane_codec.go`, `ui_rbac.go` and `store.go` are **unchanged in the entire range**; `apiClusterRateLimits` still opens with method check + `requireRole(RoleViewer)`, byte-identical |
| Client IPs or per-IP counts are newly exposed on a weaker-gated surface | Every new key on the viewer-gated API is an integer — two compile-time bounds and four atomic counters. No IP label on any new metric series. UI and OpenAPI render the same integers |
| The lock-free CA cache lost key specificity, so host A can be served host B's leaf, or an expired leaf can be served | Key is the bare `host` in both versions and the leaf's SANs derive from that same string; the TTL and `Leaf.NotAfter` checks on the fast path are byte-identical to `ee0f2ab`; all four CA-install paths still reset the cache under `mu`; `sync.Map.Clear` is a single `root.Store`, so no half-emptied cache is observable |
| `cacheLen` already drifts from the map it counts, so the memory bound is live-broken | Holds today: a `Range`-counted ground truth agreed with `cacheLen` and `cacheOrder` across 2,500 bound-crossing inserts and after `ClearCache`. The defect is the missing *oracle*, not the bookkeeping — hence S-3 is test-only |
| The cached gossip generation over-subtracts the requester's own counts, silently under-counting the fleet (the worse fail-open) | The reply subtracts `gen.perNode[excludeNode]` — the slot the generation **summed** — not the live slot, so `gen.totals − own` is self-consistent even after the requester's slot is replaced. The residual is the ≤1 s lag in the other direction, which is S-4 |
| Peer-supplied strings reach a log line unsanitized | The one new log site uses `logger.Printf` with `sanitizeLog(node)` and `%q`, rate-limited to one line per minute. No IP is logged anywhere in the new code |

## Files

**Production (security-behaviour change):**

- `third_party/saml/schema.go` — six fields namespace-qualified
  (`Subject.SubjectConfirmations`, `SubjectConfirmation.NameID`,
  `SubjectConfirmation.SubjectConfirmationData`, `Assertion.Conditions`,
  `Conditions.AudienceRestrictions`, `AudienceRestriction.Audience`).
- `third_party/saml/service_provider.go` — empty-`SubjectConfirmations`
  rejection in `validateAssertion`.

**Production (comment only):**

- `controlplane.go` — pass-1 staleness comment corrected (S-4).

**Documentation:**

- `third_party/saml/PATCHES.md` — patch (d) documented; verification record and
  the remaining-issues list corrected (S-5).
- `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-11-06.md` — this review.

**Tests:**

- `third_party/saml/go_2026_6909_test.go`
- `auth_saml_go_2026_6909_test.go`
- `internal/ca/certcache_lockfree_test.go`
- `cluster_ratelimit_budget_chaos111_test.go`

---

## Required Tests

Every test below fails against the as-merged fork and passes with the fix,
except where marked as a control (which must pass on **both** arms) or as a
bound gate (which has no pre-fix arm because the code it bounds is new).

**Negative / attack (S-1, S-2)** — `third_party/saml/go_2026_6909_test.go`:

- `TestGO20266909ValidationElementsRequireAssertionNamespace` — 5 cases, one per
  injection site plus all of them at once, asserting at parse level that the
  IdP's own `Conditions` window, audience, recipient, `InResponseTo` and SCD
  expiry all survive.
- `TestGO20266909ValidateAssertionRejectsForeignNamespaceValidationElements` —
  the full chained bypass must be rejected, **with the IdP's own signed values
  as the negative control**: the same document validates against a service
  provider configured for the values the IdP actually signed, which proves the
  rejection is the namespace binding and not an unrelated parse failure.
- `TestGO20266909ValidateAssertionRequiresSubjectConfirmation` — `none at all`
  and `foreign-namespace only`.

**Positive / boundary control (must pass on both arms):**

- `TestGO20266909ValidationElementsAcceptEverySAMLNamespaceSpelling` — declared
  prefix, default `xmlns`, per-element redeclared prefix.

**End-to-end through Culvert's real callback** —
`auth_saml_go_2026_6909_test.go`, via `SAMLProvider.ExchangeAssertion` with a
valid IdP signature over the edited assertion:

- `TestSAMLGO20266909ForeignNamespaceValidationElementsDoNotAuthenticate` — the
  retargeted assertion must not authenticate, with "retargeted, no foreign
  copies" as the control.
- `TestSAMLGO20266909ForeignNamespaceValidationElementsAreIgnoredNotFatal` — a
  valid assertion carrying ignorable foreign elements still authenticates, so
  the fix is "bind correctly", not "reject anything unusual".

**Malformed input / panic containment:** covered by the window's existing
`TestSAMLGO20266909MalformedSignedAssertionRejectedWithoutPanic` and
`TestGO20266909ValidateAssertionRejectsMissingElementsWithoutPanic`, both still
passing; every new helper routes through `go6909Validate`/`exchangeGO6909`,
which turn a panic into a failure rather than aborting the binary.

**Bound / bookkeeping gates:**

- `internal/ca/certcache_lockfree_test.go:TestCertCache_LenAgreesWithTheMapItCounts`
  (S-3) — mutation-verified independent oracle.
- `cluster_ratelimit_budget_chaos111_test.go:TestCHAOS111_PassOneStalenessStaysInsideTheGossipRound`
  (S-4) — mutation-verified bound gate.

**Concurrency.** The SAML change is a parse-path struct-tag change with no
shared mutable state, so there is no meaningful concurrency assertion to add;
it is covered by `-race` across the fork module (`-count=2`) and the root suite
rather than by a fabricated concurrency test. The two bound gates run inside
packages whose existing race/shuffle lanes were re-run (see Verification).

---

## Verification

Tested revision: `b05d649` plus the changes in this review. Toolchain
`go1.27.3` (`go env GOVERSION`), matching the `go.mod` `toolchain` pin;
`GOTOOLCHAIN=auto`, no workflow override.

| Check | Result |
|---|---|
| `go vet ./...` | pass |
| `go mod tidy -diff` | no drift |
| `CGO_ENABLED=0 go build -ldflags="-s -w" -o culvert .` | pass |
| `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /dev/null .` | pass |
| `go vet ./...` + `go test -race -count=2 ./...` in `third_party/saml` | pass |
| `go test -race -count=1 -run 'SAML|Saml|TestAuth' .` | pass |
| `go test -race -shuffle=on -count=2 ./internal/ca` | pass |
| `go test -race -shuffle=on -count=2 ./internal/admission` | pass |
| `go test -race -count=1 -run 'TestCHAOS111_\|TestAdmissionMigration_\|TestDistributedAdmission_ProductionWiring' .` | pass |
| `python3 docs/agent-context/check.py` | pass |
| `TEST_SEED=20260421 go test -race -count=1 -timeout=40m ./...` | see PR |
| full upstream v0.5.1 suite, three-arm differential | no new failures |
| mutation tests (S-3 oracle, S-4 bound gate, S-1/S-2 pre-fix arms) | all catch their mutant |

`third_party/saml` is a **separate module** reached through a directory
`replace`, so root `go test ./...` does not cover it; its suite must be run from
that directory.

**Not run, and why.** `golangci-lint` at the gate's pinned v2.15.0 is not
installed in this environment and the container's own binary is older than this
module's language version (see `conventions.md`); the `benchgate` wall-clock
lanes (a single-tenant container cannot produce comparable ratios); the frontend
`npm run verify` tree (untouched); `make api-verify` (no route, schema or
handler change); CodeQL. A passing local selection is not aggregate CI
approval — the required verdicts are `✅ Fast PR Gate — APPROVED` and
`✅ Deep PR Gate — APPROVED` for the PR's own revision.

---

## Residual Risk

1. **The SAML fork is outside `go.sum` and outside vulnerability scanning.**
   A directory `replace` removes `github.com/crewjam/saml` from root `go.sum`
   entirely (verified: no entry), so the module hash is no longer verified at
   build time, and `govulncheck`/Dependabot can no longer match it to a module
   version. That is the intended effect for GO-2026-6909, but it also means
   **any future crewjam/saml advisory will be invisible** to this repository's
   automated scanning for as long as the fork lives. `PATCHES.md` has a removal
   plan but no tracking mechanism. Recommend a periodic manual check of
   `pkg.go.dev/vuln` for the module as part of the fork's removal plan; out of
   scope for this review, which does not add process.
2. **Unqualified fields deliberately left alone.**
   `Assertion.AuthnStatements`, `AttributeValue.NameID`,
   `Conditions.OneTimeUse`, `Conditions.ProxyRestriction` and
   `LogoutRequest.NameID` keep bare or untyped tags. None is read by
   `validateAssertion`, `validateAudienceRestriction` or Culvert's
   `extractSAMLIdentity` — `AuthnStatement`, `SessionIndex` and SAML
   `LogoutRequest` appear nowhere in Culvert outside the fork — so a
   foreign-namespace element at those sites changes no decision this deployment
   makes. They must be qualified if a caller ever starts reading one.
3. **An empty `AudienceRestrictions` still passes the audience check
   vacuously** (`len(...) == 0` ⇒ valid). That is upstream's deliberate reading
   of an optional element and is unchanged here. It is not a bypass of a
   restriction the IdP *did* sign, because the IdP's own
   `<saml:AudienceRestriction>` now always survives in the slice; it only means
   an IdP that omits the element entirely is trusted to have meant to.
4. **`MaxIssueDelay` is the last line for assertion replay.** With S-1 fixed,
   `IssueInstant + MaxIssueDelay` (90 s) and the `Conditions`/SCD windows all
   apply again, but Culvert keeps no used-assertion-ID cache, so within those
   windows the same assertion can be presented more than once. This is upstream-
   standard behaviour and pre-dates this window; worth a separate look.
5. **S-4's ≤1 s remote-enforcement window** is accepted, documented and gated,
   not removed.
6. **The hot-IP export bound is not operator-tunable.** `MaxExportedHotIPs` is
   a compile-time 4,096. A deployment with a very tight configured limit and
   more than 4,096 distinct clients per window will have its coldest clients
   narrowed to local-only limiting in *normal* operation. This is surfaced on a
   metric, a counter, the API and a UI banner, and the direction is fail-open.
   Pre-existing to this review's changes and the window's documented tradeoff.
7. **`RateLimitDelta.IP` has no length validation** on either side of the
   gossip wire, so a *compromised enrolled node* can spend its 16 MiB inbound
   budget on very long keys that the control plane retains and reflects into
   broadcasts. `ee0f2ab` had no entry-count bound at all, so this window
   strictly improves it; flagged as a pre-existing hardening gap, gated behind
   cluster-member compromise, for a future change.
8. **Not measured:** whether `ClusterTotalsExcluding`'s grown branch count stays
   inside the repository's `cyclop` threshold of 15 and the `funlen`/`gocognit`
   declaration-line baselines. Per `conventions.md` this needs a full-tree lint
   pass compared against the same measurement on the base, with the gate's own
   pinned linter version — which was not available here.
