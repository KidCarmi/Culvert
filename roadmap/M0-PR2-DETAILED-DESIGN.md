# M0-PR2 — Served-Catalog Verification — Detailed Engineering Design (v2, post planning-review)

**Milestone:** M0 (Foundation & Safety), **PR 2 of 5.** **Epic:** E1 (served-verify
interlock). **Branch base:** `main` (rebased onto `main` after PR1 #628 merges;
PR2 is independent of PR1). **Canonical parent:**
`CULVERT-RELEASE-PLATFORM-MASTER-DESIGN.md`, `M0-DETAILED-DESIGN.md` §4.3.

**v2 changelog:** revised after three independent planning reviews
(architecture/correctness, security, reliability+testability), which converged on
one central improvement: **drive the real production orchestrator `autoSeedCatalog`
over real HTTP** instead of hand-assembling the verify sequence. Findings +
resolutions in §11.

## Single objective

> **Prove that catalog bytes served over HTTP are validated through the real
> production verification path before promotion.**

## Dependency (explicit)

PR2 **does not depend on PR1** — distinct files (`release_catalog_http_test.go` +
a new served-verify test file; PR1 touched `release_spec.go`/`release_gen_test.go`/
`ci.yml`), zero overlap. **Prefer waiting for PR1 (#628) to merge, then build/rebase
PR2 from latest `main`.** Design + planning review are complete now; **implementation
starts only after PR1 merges.** No stacked branch needed. PR1 fixes never land here.

## 1. The real production path (what PR2 must exercise)

The one production function that does "served bytes → verify → before promotion"
is **`autoSeedCatalog`** (`release_autoseed.go:49-93`):

```
stager.Stage(ctx)            → fetch+stage over the transport (HTTPCatalogProvider)
LoadVerifiedCatalog(...)     → verify-before-parse (two-phase sig + per-manifest sha256)
checkCatalogFreshness(now)   → expires_at / skew / future-dating   (injected clock)
readVersionFloor(statePath)  → the PERSISTED rollback floor
checkCatalogRollback(floor)  → version ≥ floor
swapCatalogDir(...)          → atomic promote (the swap IS the promotion)
```

`autoSeedCatalog` takes a `catalogStager` interface (`release_autoseed.go:30`) that
`HTTPCatalogProvider.Stage` (`release_catalog_http.go:179`) satisfies. So PR2 wires
the **real** `HTTPCatalogProvider` (served by `httptest`) **into** `autoSeedCatalog`
— exercising the real ordering, the real persisted-floor read, and the real
swap-gating, with **no new production seam**.

**Why not hand-roll the sequence:** re-implementing `Stage → LoadVerifiedCatalog →
freshness → rollback` in the test re-creates the fetch↔promote drift the objective
warns against — a regression *inside* `autoSeedCatalog` (reordered checks, dropped
rollback, swap-before-verify, or bypassing the persisted floor) would pass a
hand-rolled test yet break prod. Driving `autoSeedCatalog` closes that.

## 2. Scope — the transport delta only

`release_autoseed_test.go` **already** proves the verify/freshness/rollback/no-clobber
negatives via a **fake** stager (`fakeStager` → a pre-built local dir):
`TestAutoSeed_FailClosedMatrix` (forged/expired/missing-expires_at/missing-version),
`TestAutoSeed_RollbackRefused` (persisted floor), `TestAutoSeed_FailedSeedPreservesExisting`
(no-clobber). The **one** dimension none cover is **bytes that actually traversed
HTTP**. PR2's unique contribution is exactly: *the same promote contract, but with a
real `HTTPCatalogProvider.Stage` over `httptest`.* We do not re-litigate the leaf
negatives — we assert the transport-driven path reaches the same outcomes.

## 3. Non-goals (this PR)

No R2 job / promote-to-R2 (PR3). **No new production code and no exported test seam**
— every symbol needed is `package main` whitebox-reachable (`autoSeedCatalog`,
`HTTPCatalogProvider`, `NewTrustStoreWithSigstore`, `newSigstoreVerifier`,
`officialSigstoreIdentity`, `bakedSigstoreTrustedRootJSON`, `checkCatalogFreshness/
Rollback`). No refresher (M1). No change to the verifier/roots/freshness/provider.

## 4. Repository findings (corrected)

- **`fakeCatalogServer`** (`release_catalog_http_test.go`) drives the real
  `HTTPCatalogProvider` and covers: happy path, bad-signature→zero-manifest-fetch,
  tampered-manifest-on-load, partial/truncate, timeout, **304/ETag**
  (`TestHTTPProvider_UnchangedCatalog304`). **Correction (was imprecise in v1):**
  the SSRF **dial guard** and **redirect guard** tests
  (`TestHTTPProvider_DialGuardRejectsPrivate`, `…RedirectGuard`) do **not** use
  `fakeCatalogServer` — they build a production-guard provider and call
  `safeDialContext`/`checkRedirect` directly. So PR2 must not re-test guard logic.
- **Gap:** `Stage`/`LoadVerifiedCatalog` do **not** run freshness/rollback (those
  live in `autoSeedCatalog`/holder). So "served + expired/rollback ⇒ reject" is
  **unproven on the transport** today — the delta PR2 fills.
- **Fixtures already exist:** `signedCatalogFiles(t, priv, freshValidSource(exp, ver))`
  / `buildCatalogSourceFull` (`release_catalog_test.go`) emit controllable
  `expires_at`/`catalog_version` — **no edit to `fakeCatalogServer`/`signedCatalogFiles`.**
- **Baked-root construction** is `NewTrustStoreWithSigstore(nil, VerifyEnforce,
  newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity()))`
  (as used at `release_identity_test.go:73`). A **virtual** signer
  (`ca.NewVirtualSigstore`) cannot chain to the real baked root — so it proves
  plumbing, not baked-root acceptance.
- **`swapCatalogDir`** does `os.Rename(stage, dst)` → **EXDEV** across filesystems;
  the test must `provider.SetStageBase(<same temp root as catalogDir>)`.

## 5. Design — tests to add

**T1 — `TestServedVerify_Contract` (drive the real orchestrator over HTTP).**
Call `autoSeedCatalog(ctx, provider, cfg)` where `provider` is a real
`HTTPCatalogProvider` (`p.guard=nil` for the loopback httptest host,
`SetStageBase(tmp)`) pointed at `fakeCatalogServer`, `cfg.now` injected,
`cfg.statePath`/`cfg.catalogDir` in one temp root, `cfg.trust` = the virtual-signer
store.
- **Positive:** a valid served catalog ⇒ swap happened (dest catalog installed).
- **Negatives** (each asserts `autoSeedCatalog` errors **and the dest is untouched**):
  tampered index, expired (injected `now` past `expires_at`+skew), rollback
  (served version < persisted `statePath` floor — proving the **persisted** floor
  read, not a hand-passed int), malformed index JSON.
  Fixtures via `signedCatalogFiles(t, priv, freshValidSource(exp, ver))`.

**T2 — `TestServedVerify_BakedRootFailClosed` (baked-root consulted on the served
path; LOCAL, no owner setup).** `cfg.trust = NewTrustStoreWithSigstore(nil,
VerifyEnforce, newSigstoreVerifier(bakedSigstoreTrustedRootJSON,
officialSigstoreIdentity()))`; serve a virtual-signed (or unsigned) catalog; assert
`autoSeedCatalog` **rejects** with **no swap**. This proves the real baked-root
store is actually consulted over HTTP and fails closed — the locally-provable half
of must-prove #8.

**T3 — `TestServedVerify_ArtifactOwnsOutcome` (anti-downgrade over HTTP).** Serve a
`.sigstore` sidecar alongside `.sig` with a **dual** trust store (ed25519 key + a
virtual sigstore verifier); strip/corrupt the `.sigstore` and assert the served
path **rejects** (no fall-through to ed25519) — proving artifact-owns-outcome
through the **transport**, not just the existing unit-level `memDualSource` case.

**T4 — `TestServedVerify_BakedRootGate` (baked-root POSITIVE; env-gated, PR3).**
The real-Fulcio-bytes positive requires CI keyless signing, so it is
`CULVERT_RELEASE_SERVED_URL`-gated and **explicitly deferred to PR3** (owner sets
the URL against a freshly-staged published catalog). It must use the **production
guard** (`isPrivateHost`, i.e. NOT `p.guard=nil`) and the full `autoSeedCatalog`
path. Named here; not an executable assertion in PR2.

## 6. Deferred — general HTTP-provider hardening (separate PR, NOT this one)

Confirmed by the security + reliability reviews as **not** verification-bypass gaps
(the guards already exist in code and are tested): **oversized-body** stress
(`readAllBounded` already caps every fetch), **weak-ETag/304** validator matching
(a spoofed 304 → `errCatalogUnchanged`, no dir, bounded by use-time expiry —
not a bypass), **multi-hop redirect** variants (`safeDialContext`+`checkRedirect`
already guard + tested), **retry/backoff** (refresh-loop / M1). The PR2 contract
asserts these guards remain intact; it does not extend them.

## 7. Test strategy

Injected clock + temp `statePath` (rot-proof; pattern exists at
`release_catalog_freshness_test.go:92-94,164-170`). `SetStageBase` to a shared temp
root (EXDEV). `p.guard=nil` only for the loopback contract tests; the PR3 baked-root
positive keeps the production guard. `go test ./...`, `-race` on the catalog surface,
`go vet`, `-count=2 -shuffle=on`. Offline sigstore fixtures (`ca.NewVirtualSigstore`)
— no network flake.

## 8. Acceptance criteria (claim only what runs locally in PR2)

- **T1** proves the real `autoSeedCatalog` promote path over HTTP: valid installs;
  tamper/expired/rollback/malformed reject with no swap (transport delta of the
  already-proven autoseed negatives).
- **T2** proves the baked-root store is consulted on the served path and **fails
  closed** (the locally-provable half of must-prove #8).
- **T3** proves artifact-owns-outcome over HTTP.
- **Must-prove #8 POSITIVE (real Fulcio bytes over HTTP) is explicitly PR3** (T4,
  needs CI signing) — §8 does not claim it as demonstrated in PR2.
- No production verification behavior changed.

## 9. Owner prerequisites

None for T1–T3. T4's `CULVERT_RELEASE_SERVED_URL` is set by PR3/owner; skipped locally.

## 10. Definition of Done

§8 met; T1–T3 green (incl. dest-untouched-on-failure assertions);
`-race`/`vet`/`-count=2 -shuffle=on` clean; no production code or seam changed;
deferred hardening (§6) recorded; single-scope (served-verification contract only);
rebased on `main` after PR1 merges.

## 11. Planning-review findings & resolutions (traceability)

| Finding | Sev | Resolution in v2 |
|---|---|---|
| CORR/REL — hand-rolled verify sequence instead of the real orchestrator | **HIGH** | §1/§5 T1 — drive `autoSeedCatalog` over real HTTP; fixes the `checkCatalogRollback(statePath)` wording (persisted floor is read by `autoSeedCatalog`, not a hand-passed int). |
| REL — must-prove #8 claimed-but-not-locally-provable | **HIGH** | §5 T2 (baked-root fail-closed, local) + §8 rewording; positive deferred to PR3 (T4). |
| SEC F1 — baked-root gate must run full freshness+rollback + keep prod guard | MED | §5 — T1 runs the full path; T4 (PR3 positive) uses the production guard. |
| SEC F2 / CORR LOW — anti-downgrade only unit-level | MED | §5 T3 — serve `.sigstore` + dual store, strip one, reject over HTTP. |
| REL — no seam needed; drop "if needed" hedge | MED | §3 — no exported seam; test-only claim strengthened. |
| REL — freshness fixture overstated | MED | §4 — reuse `signedCatalogFiles(…, freshValidSource(exp, ver))`; no harness edit. |
| REL — EXDEV swap flake | MED | §4/§7 — `SetStageBase` to a shared temp root. |
| SEC F3 — no-refetch TOCTOU for PR3 | LOW | §1 — `autoSeedCatalog` promotes the SAME staged dir it verified; PR3 reuses it. |
| REL LOW — §3 coverage enumeration imprecise | LOW | §4 — corrected (SSRF/redirect tests don't use `fakeCatalogServer`). |
| SEC F5 / REL — §6 deferrals confirmed not security gaps | INFO | §6 — retained with the confirmation. |

**Disposition:** all HIGH/MEDIUM resolved in design. Implementation begins after
PR1 (#628) merges, on a branch (re)built from `main`.
