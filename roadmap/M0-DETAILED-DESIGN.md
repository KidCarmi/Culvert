# M0 — Foundation & Safety — Detailed Engineering Design

**Milestone:** M0 (first). **Canonical parent:** `CULVERT-RELEASE-PLATFORM-MASTER-DESIGN.md`.
**Branch base:** `main` @ `9b30c81`. **Epics:** E1 (publishing pipeline & correctness
core), E2 (version authority), E5 (legacy retirement), E4-staging (guardrails
without owner creds).

This document is **self-contained** — it restates the master-design decisions M0
implements so it can be reviewed and executed without other docs.

---

## 1. Scope

M0 makes the release-catalog **generation and publish contract correct, deterministic,
idempotent, and single-writer**, adds the **served-catalog verification interlock**,
lands a **dormant** R2 publish workflow, retires the **legacy unauthenticated GitHub
tag** discovery, and lands **IaC guardrails + activation docs** — all **without owner
credentials** and **without changing any live customer behavior**.

M0 must prove (master design "M0 must prove"):
1. Catalog generation is deterministic.
2. Re-running the same release is idempotent.
3. The weekly re-sign path does **not** allocate a new `catalog_version`.
4. Two publishers cannot create conflicting content at the same version.
5. Staged catalog bytes are verified **before** live promotion.
6. Verification failure cannot mutate the live pointer.
7. The R2 publishing job has **no** `id-token: write`.
8. Served bytes are checked by the **actual in-binary verifier**.
9. Missing Cloudflare credentials cause an explicit **safe skip / gated failure**, never partial production behavior.
10. Legacy unauthenticated GitHub tag discovery is retired/safely disabled.
11. Existing GitHub Pages behavior is **unchanged**.

## 2. Non-goals (explicitly deferred)

- No live R2 publishing (job is dormant; no owner creds used).
- No rings, no atomic CAS version-counter, no graduation tooling (single-ring ⇒ not needed).
- No revoke workflow, no re-sign **cron** (M1/E8) — but the re-sign **no-allocate contract** is coded + unit-proven now.
- No client refresher (M1/E3). No repo-private flip (M2). No Pages changes (M3).
- No `id-token`/OIDC use in the new job. No telemetry/console (M4).

## 3. Repository findings (evidence)

- **RB-2 (non-determinism):** `ci.yml:440-443` builds the spec with
  `NOW=$(date -u …)` / `EXP=$(date -u -d '+90 days' …)` for `generated_at`,
  `expires_at`, **and** `created_at`. Re-running the same tag ⇒ different bytes ⇒
  different `manifest_sha256` ⇒ non-idempotent publish. `generateReleaseCatalog`
  itself is deterministic (`release_gen.go:11-15`); the **non-determinism is in the
  spec's timestamps**, upstream in CI shell.
- **RB-1 (version race):** `catalog_version = (count of v* tags)+1`
  (`ci.yml:443`) is computed under `concurrency: group: ci-${{ github.ref }}`
  (`ci.yml:20`). Two different tags run under **different** groups → allocation is
  **not serialized** → two tags created close together can both count the same
  history and collide at the same `catalog_version`. Appliances accept
  `version == floor` (`release_catalog_freshness.go:106-114`), so a collision is
  silently accepted.
- **Served verify gap:** the CI gate (`TestReleaseCatalogGate`) verifies the
  **generated** bytes on disk, never the **served** bytes; `TestReleaseCatalogServedVerify`
  does not exist (`grep`: no match).
- **E5:** `update.go` `checkGitHubLatestTag` (~`:309`) GETs
  `https://api.github.com/repos/KidCarmi/Culvert/tags` **unauthenticated** →
  404 on a private repo → legacy checker silently reports "no update."
- **Pages:** `publish-catalog-pages.yml` is untouched by all M0 changes.

## 4. Design — the correctness core

### 4.1 Deterministic spec construction (E1 / fixes RB-2)

Move spec **timestamp + version derivation out of wall-clock shell into a pure,
tested Go function.** New `release_spec.go`:

```
type SpecInputs struct {
    Version      string   // "1.4.3" (from tag/version_bare)
    Repo         string   // "ghcr.io/kidcarmi/culvert"
    ListDigest   string   // "sha256:<64hex>" (pushed digest)
    Platforms    []string
    GeneratedAt  string   // RFC3339 UTC — DETERMINISTIC input (tagged-commit date)
    ExpiresAt    string   // RFC3339 UTC — DETERMINISTIC (GeneratedAt + expiryDays)
    CreatedAt    string   // RFC3339 UTC — DETERMINISTIC (== GeneratedAt for a tag build)
    CatalogVersion int    // DETERMINISTIC input (see 4.2)
    Channels     []Channel
}
func buildReleaseSpec(in SpecInputs) (releaseCatalogSpec, error)   // pure, validates, no clock, no git
```

- **Timestamps are inputs, not `date -u`.** CI derives `GeneratedAt` from the
  **tagged commit's committer date** (`git log -1 --format=%cI "$GITHUB_REF_NAME"`),
  which is fixed for a tag → re-running the same tag yields identical timestamps.
- **`ExpiresAt = GeneratedAt + expiryDays`** computed in Go (deterministic), with
  **`expiryDays = 180`** (master design D9) — raised from 90.
- `buildReleaseSpec` reuses the existing validators; it does **not** duplicate
  `generateReleaseCatalog` — it only assembles a validated `releaseCatalogSpec`
  that the existing generator consumes.

**CI wiring:** the `spec` step computes the three deterministic facts
(`COMMIT_ISO`, `CATVER`, `VERSION`+`DIGEST`) in shell (pure git reads, no clock),
then runs a **small env-driven Go entrypoint** that calls `buildReleaseSpec` and
writes `spec.json` to `CULVERT_RELEASE_GEN_SPEC`. The heredoc `date -u` is deleted.
The entrypoint is an **env-gated test** `TestWriteReleaseSpec` (mirrors the existing
`TestReleaseCatalogGate` env pattern: reads `CULVERT_RELEASE_SPEC_*` inputs, writes
the file) — so **all timestamp/version/shape logic lives in tested Go**, shell only
gathers immutable git facts.

### 4.2 Version authority (E2 / fixes RB-1 / master design D4)

Invariant: **`catalog_version` is monotonic; the tag build is the sole allocator;
re-sign and revoke never invent a fresh one out of a race.**

- **Deterministic allocation for a tag:** `CatalogVersion` is passed as an
  **explicit input** to `buildReleaseSpec` (never computed inside it). For the tag
  build CI computes `CATVER = (count of v* tags)+1` — deterministic for a given
  tag history.
- **Serialize the allocator (removes the RB-1 race):** the catalog-publishing work
  runs under a **dedicated, constant** concurrency group
  `concurrency: { group: catalog-version-allocator, cancel-in-progress: false }`
  (NOT per-ref), so two tag builds (and any future re-sign/revoke) **queue** for
  allocation + history write instead of interleaving. The per-ref `ci-${{ github.ref }}`
  group stays for build isolation; the allocator group is added to the
  **catalog-pipeline job** only. *(M0 has only the tag allocator; the group is the
  guardrail future writers MUST join — enforced by a workflow-lint test, 4.6.)*
- **Re-sign never allocates (contract, unit-proven now):** `buildReleaseSpec` takes
  the version as an input, so a future re-sign passes the **existing** version. A
  unit test proves `resign`-shaped inputs (same version) produce a byte-identical
  index **except** for the freshness timestamps, and the **same** `catalog_version`.
- **Create-only history (contract):** the (dormant) publish job writes
  `history/<ring>/v<N>/` with create-only semantics so two publishes can never land
  different content at the same version. Enforced in the workflow (4.4) + asserted
  by a test that the workflow uses the create-only flag.

### 4.3 Served-catalog verification interlock (E1 / master design D6, RB-4)

New `TestReleaseCatalogServedVerify` (`release_catalog_served_test.go`):
- Generate a signed bundle (Sigstore virtual signer, offline) into a temp dir.
- Serve it over a Go `httptest.Server` (an HTTP file server = the "origin/edge").
- Drive the **real** `HTTPCatalogProvider` + `LoadVerifiedCatalog` +
  freshness/rollback against the served URL — proving **what is served** verifies,
  not just what was generated.
- Negatives (fail-closed): tampered index, stripped/garbage sidecar (artifact-owns-
  outcome ⇒ reject, no downgrade), expired, rollback (lower version), malformed
  JSON, oversized body — each must reject and (for the promote model) leave a prior
  "live" copy untouched.

This test is reusable by CI's dormant R2 job (PR3) pointed at the staged URL.

### 4.4 Dormant R2 stage→verify→promote workflow (E1 / D6, D7)

New `.github/workflows/` job `publish-catalog-r2` (or a job in `ci.yml`; decided in
PR3 review):
- **Permissions `contents: read` only — NO `id-token: write`** (D7; it only
  verifies an already-signed bundle).
- **Dormant/gated:** guarded by `if: ${{ secrets.R2_ACCOUNT_ID != '' }}` (or an
  explicit `vars.R2_PUBLISH_ENABLED == 'true'`) so with no owner creds it **safe-
  skips**; it never runs partially. Tag-path only.
- **stage → verify → promote → purge → confirm** (master design §Release Platform):
  upload manifests to live (immutable, safe-early) → stage full bundle to
  `history/<ring>/v<N>/` **create-only** → download-back verify the **staged** URL
  with `TestReleaseCatalogServedVerify` → promote index+sidecars to live only on
  success → purge → cache-busting confirm.
- Fails closed at every step; verify-fail ⇒ no promote ⇒ live pointer untouched.

### 4.5 Legacy retirement (E5)

`update.go::checkGitHubLatestTag`: gate the GitHub-tags fallback **off by default**
behind an explicit opt-in (env/config, e.g. `CULVERT_LEGACY_GH_TAG_CHECK=1`), read
once. Default path makes **no** unauthenticated GitHub call (so a private repo never
404-bricks the checker); a loud one-line log states it's disabled. Code retained
(not deleted) for the compatibility window; a unit test asserts the default build
performs no GitHub-tags request. The `updater` sidecar stays until cutover (M2/M3).

### 4.6 IaC guardrails + activation docs (E4-staging)

- `deploy/terraform/` skeleton (Cloudflare + GitHub providers) declaring the
  **guardrails** (R2 bucket/policy, custom domain, cache rules, `release` env
  protections, `v*` ruleset) — **not applied by CI**, checked-in as the source of
  truth; `terraform validate`-clean; no secrets.
- `docs/operator/catalog-hosting-r2-activation.md`: the exact owner activation
  steps (create bucket/domain, add the 5 secrets, enable the dormant job).
- A **workflow-lint test** (Go, parses the workflow YAML) asserting: the R2 job has
  no `id-token: write`; it is secret-gated; catalog-publishing shares the allocator
  concurrency group; history writes are create-only. This is the machine-checkable
  encoding of invariants 4/6/7.

## 5. State transitions & trust boundaries

- **Spec build:** git facts (immutable) → `buildReleaseSpec` (pure) → validated spec → existing generator → deterministic bytes. No clock, no network.
- **Publish (dormant):** untrusted staging (`history/v<N>/`) → **in-binary verify (trust boundary)** → promote to live. The live pointer crosses from old→new only through a passed verify.
- **Verify:** unchanged in-binary, offline, fail-closed; R2/httptest origin is untrusted.

## 6. Failure behavior

| Failure | Behavior |
|---|---|
| Spec inputs missing/invalid | `buildReleaseSpec` returns error; CI step fails closed; nothing published. |
| Non-deterministic drift (bug) | `TestBuildReleaseSpec_Deterministic` / determinism gate fails in CI. |
| Version collision (bug/removed serialization) | concurrency test + create-only history test fail; workflow-lint fails if the group is dropped. |
| Served bytes don't verify | `TestReleaseCatalogServedVerify` fails; dormant job (when live) does not promote. |
| Missing CF creds | dormant job **safe-skips** (gated `if`); no partial writes. |
| Private repo (legacy path) | default build makes no GitHub-tags call; no 404 brick. |

## 7. Rollback behavior

Every M0 change is additive and CI/local-only:
- Spec refactor: revert the commit; the old shell heredoc returns. No customer impact.
- Served-verify test: pure addition.
- Dormant R2 job: gated off; deleting it changes nothing live (Pages remains authoritative).
- Legacy gate: default-off flag; flip the env to restore old behavior.
- IaC/docs: inert.

## 8. Test strategy

- `TestBuildReleaseSpec_Deterministic` (same inputs → identical spec twice) + `_Idempotent` (full generate → identical index bytes twice).
- `TestBuildReleaseSpec_ResignNoAllocate` (resign inputs preserve `catalog_version`; only timestamps differ).
- `TestReleaseCatalogServedVerify` (+ negatives, §4.3).
- `TestVersionAllocation_MonotonicNoSplit` (pure allocation function: same tag history → same version; growing history → strictly increasing; two concurrent computations over the same committed history agree).
- `TestWorkflowInvariants` (parse YAML: R2 job has no `id-token`, is secret-gated, uses the allocator group, create-only history).
- `TestLegacyGhTagCheck_DisabledByDefault` (no outbound GitHub-tags request in the default build).
- Regression: existing `TestGenerateReleaseCatalog_Deterministic`, `TestReleaseCatalogGate`, keyless/verify suites stay green. Run `go test ./...`, `-race` on the catalog surface, `go vet`.

## 9. Acceptance criteria (M0 done)

All 11 "must prove" items (§1) demonstrated by the tests above **and** by the
dormant-job workflow shape; existing Pages + release behavior unchanged; no owner
credential used; all required CI gates green on each M0 PR.

## 10. Owner prerequisites (do NOT block M0; needed to ACTIVATE later)

Cloudflare account/bucket/domain, R2 S3 creds, cache-purge token, zone ID, cache
rules, Smart Tiered Cache, disabled `r2.dev`; GitHub secrets, protected `release`
env + reviewers, `v*` ruleset. Documented in `catalog-hosting-r2-activation.md`.

## 11. Risks

| Risk | Mitigation |
|---|---|
| Committer-date timestamps unexpected (e.g. rebased tag) | Document the derivation; it only needs to be *stable per tag*, not "now". A re-tag is a new release. |
| Env-gated Go spec writer complicates CI | Mirror the proven `TestReleaseCatalogGate` env pattern; keep it tiny. |
| Allocator concurrency group starves parallel tag builds | `cancel-in-progress:false` queues, doesn't drop; tag builds are infrequent. |
| Dormant job accidentally runs | Double-gate: secret presence `if` + tag-path `if`; workflow-lint asserts the gate. |
| Legacy flag missed by an operator relying on it | Loud log + activation doc; code retained. |

## 12. PR split (rollback/review boundaries)

| PR | Scope | Why separate |
|---|---|---|
| **M0-PR1** | `release_spec.go` + deterministic CI spec + version-authority (allocator group, resign-no-allocate contract) + tests | The correctness core; smallest revertable unit that fixes RB-1/RB-2. |
| **M0-PR2** | `TestReleaseCatalogServedVerify` + local httptest origin harness | Pure test addition; independent of CI publish. |
| **M0-PR3** | Dormant `publish-catalog-r2` workflow + workflow-lint test | Isolated CI surface; must be reviewable for the no-`id-token`/gated/create-only invariants alone. |
| **M0-PR4** | Legacy `checkGitHubLatestTag` default-off + test | Isolated runtime-client change; clean revert. |
| **M0-PR5** | Terraform guardrails skeleton + activation docs | Inert infra/docs; owner-facing. |

## 13. Definition of Done

- §9 acceptance met; §8 tests green (incl. `-race` on the catalog surface, `go vet`).
- No `date -u`/wall-clock/hardcoded digests/versions/domains in the spec path.
- The dormant R2 job carries `contents: read` only and safe-skips without creds.
- Pages + existing release flow byte-unchanged.
- Execution tracker updated; each PR merged (by the owner) with required gates green.
