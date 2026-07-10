# M0-PR2 — Served-Catalog Verification — Detailed Engineering Design

**Milestone:** M0 (Foundation & Safety), **PR 2 of 5.** **Epic:** E1 (served-verify
interlock). **Branch base:** `main` (rebased onto `main` after PR1 #628 merges —
PR2 is independent of PR1; see dependency note). **Canonical parent:**
`CULVERT-RELEASE-PLATFORM-MASTER-DESIGN.md`, `M0-DETAILED-DESIGN.md` §4.3.

## Single objective

> **Prove that catalog bytes served over HTTP are validated through the real
> production verification path before promotion.**

Everything in this PR serves that one objective. Anything not required by it is
explicitly deferred (§6).

## Dependency (explicit)

PR2 **does not depend on PR1** — it touches `release_catalog_http_test.go` (+ a new
served-verify test file), with **no file or functional overlap** with PR1
(`release_spec.go`/`release_gen_test.go`/`ci.yml`). **Prefer waiting for PR1 (#628)
to merge, then build/rebase PR2 from the latest `main`.** Design + planning review
proceed now; **implementation starts only after PR1 merges.** No stacked branch is
needed (zero overlap). PR1 follow-up fixes never land here.

## 1. Scope (the served-verification contract)

Prove, with executable tests, that bytes fetched over HTTP from an origin are run
through the **real, unmodified production verification path** and **fail closed**
unless every check passes:

1. **Transport → verify:** `HTTPCatalogProvider.Stage` (two-phase: signature over
   raw index BEFORE manifest enumeration) → `LoadVerifiedCatalog` (re-verify +
   per-manifest SHA-256).
2. **Freshness + rollback:** the holder-level gate
   (`checkCatalogFreshness` + `checkCatalogRollback`, driven explicitly with an
   injected clock + a `statePath` floor — these are NOT run by `Stage`/
   `LoadVerifiedCatalog`, per the M0 planning review).
3. **Baked-root served gate:** an env-gated variant that constructs the trust store
   from the **real baked Sigstore root + pinned `ci.yml` identity**
   (`newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity())`
   + `NewTrustStoreWithSigstore(nil, VerifyEnforce, sv)`) and drives the real
   provider against an external served URL — the variant the dormant R2 promote
   (PR3) invokes to satisfy M0 must-prove #8. Skipped locally (no served URL).

The contract's essence: **served bytes are untrusted; only bytes that pass the real
path are eligible for promotion.** PR2 delivers the reusable proof; PR3 wires it
into the dormant stage→verify→promote job.

## 2. Non-goals (this PR)

No R2 job, no promote step (PR3). No new production code path — this PR is
test-only plus, if needed, a tiny exported test seam. No client refresher (M1). No
changes to the verifier, trust roots, freshness, or `HTTPCatalogProvider`
behavior — PR2 exercises them, it does not modify them.

## 3. Repository findings (evidence)

- `release_catalog_http_test.go` already has `fakeCatalogServer` (httptest) driving
  the **real** `HTTPCatalogProvider` + `LoadVerifiedCatalog`, with negatives: bad
  index signature → zero manifest fetches; tampered manifest → caught on load;
  truncated body; timeout; SSRF dial guard; redirect guard; 304.
- **Gap for the contract:** `Stage`/`LoadVerifiedCatalog` do **not** run freshness
  or rollback (those are `checkCatalogFreshness`/`checkCatalogRollback`, holder-
  level). So "served + expired ⇒ reject" and "served + lower-version ⇒ reject" are
  **not** currently proven on the served path.
- **Gap for must-prove #8:** every served test uses the virtual signer
  (`ca.NewVirtualSigstore`), which verifies only bytes it signed itself — it cannot
  stand in for the **baked-root** verification of real Fulcio-signed production
  bytes. `TestReleaseCatalogKeylessVerify` uses the baked root but loads a **local
  dir**, never HTTP.
- The provider supports `p.guard = nil` (whitebox) for loopback httptest hosts.

## 4. Design — tests to add

**Reuse, don't duplicate:** extend the existing `fakeCatalogServer` harness; do not
add a second origin fake.

1. **`TestServedVerify_Contract` (virtual signer — plumbing + freshness/rollback):**
   serve a valid signed catalog; drive `Stage → LoadVerifiedCatalog →
   checkCatalogFreshness(injected now) → checkCatalogRollback(statePath floor)`;
   assert PASS. Then the contract negatives, each asserting the served bytes are
   **rejected before they could be promoted**:
   - tampered index (signature fails; zero manifest fetches — already partly
     covered, assert here as the contract entry point);
   - stripped/garbage sidecar (artifact-owns-outcome ⇒ reject, no downgrade);
   - **expired** (freshness, injected `now` past `expires_at` + skew) — NEW;
   - **rollback / lower `catalog_version`** than the persisted floor — NEW;
   - malformed index JSON (fail-closed parse).
   Freshness/rollback negatives use the injected-clock + `statePath` pattern
   (`release_catalog_freshness_test.go`), never `time.Now()`.
2. **`TestServedVerify_BakedRootGate` (env-gated, `CULVERT_RELEASE_SERVED_URL`):**
   the baked-root + pinned-identity served variant (must-prove #8). Skipped when
   the env is unset (local). This is the exact routine PR3's dormant job calls
   against the staged URL.

## 5. Test strategy

- Extend `fakeCatalogServer`/`signedCatalogFiles` minimally for the freshness/
  rollback fixtures (control `expires_at`/`catalog_version`).
- Injected clock + temp `statePath` for freshness/rollback (no wall-clock; no rot).
- `p.guard = nil` for loopback.
- `go test ./...`, `-race` on the catalog surface, `go vet`, `-count=2 -shuffle=on`.
- No audit-ring assertions (CLAUDE.md caveat N/A).

## 6. Deferred — general HTTP-provider hardening (separate future PR, NOT this one)

Per the single-objective rule, these are transport robustness, **not** the
served-verification-before-promotion contract, and are explicitly deferred:
- **weak-ETag / `304` conditional-GET** validator-matching (the reliability review
  flagged a plain `http.FileServer` emits no ETag / never Cloudflare's `W/"…"`
  form) — refresh-loop transport hardening; lands with the M1 refresher or a
  dedicated hardening PR.
- **redirect-guard variants** (multi-hop, cross-host) beyond the existing single
  case.
- **oversized-body bound** stress (`catalogMaxReadBytes+1`) — transport DoS guard,
  already partly covered by the truncated case.
- **retry/backoff** behavior.

These do not affect whether served bytes are *verified before promotion*; adding
them here would violate the single-scope rule.

## 7. Failure / rollback behavior

Test-only (plus at most a tiny exported test seam). Every negative asserts
fail-closed. Rollback = revert the commit; no production behavior changes.

## 8. Acceptance criteria

M0 must-prove #8 (served bytes checked by the real in-binary verifier) demonstrated
by `TestServedVerify_BakedRootGate` (baked root) + `TestServedVerify_Contract`
(plumbing + freshness/rollback). The served-verification contract is proven
fail-closed for tamper/strip/expired/rollback/malformed. No change to production
verification behavior.

## 9. Owner prerequisites

None for the tests. The baked-root gate's `CULVERT_RELEASE_SERVED_URL` is set by
PR3's dormant job (owner enables that later); locally it skips.

## 10. Definition of Done

§8 met; contract negatives green; `-race`/`vet`/`-count=2 -shuffle=on` clean;
no production code path changed; deferred hardening (§6) recorded; PR is
single-scope (served-verification contract only); rebased on `main` after PR1
merges.
