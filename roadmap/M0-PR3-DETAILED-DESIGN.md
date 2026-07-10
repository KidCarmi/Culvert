# M0-PR3 — Dormant R2 stage→verify→promote publisher — Detailed Design (v1)

**Milestone:** M0 (Foundation & Safety) — PR 3 of 5.
**Single objective:** add a **dormant** `publish-catalog-r2` workflow that, when an
owner later flips `vars.R2_PUBLISH_ENABLED=true`, stages the already-signed release
catalog to R2, **verifies the STAGED bytes over HTTP through the real in-binary
baked-root path**, and only then server-side-copies them to the live pointer —
fail-closed at every step. Until the var is set it is a **clean skip** (green,
neutral, zero writes). Plus a YAML-parsing `TestWorkflowInvariants` that pins the
security invariants so the workflow can't silently drift into an unsafe shape.

Authority: `roadmap/CULVERT-RELEASE-PLATFORM-MASTER-DESIGN.md` and
`roadmap/M0-DETAILED-DESIGN.md` §4.4 / §4.6 / §8 / §12. This PR is the isolated CI
surface of M0; it is **independent of PR4 (legacy retirement) and PR5 (IaC +
activation docs)** and must not include their work.

---

## 1. Scope (this PR only)

| In scope | Out of scope (later PR) |
|---|---|
| `.github/workflows/publish-catalog-r2.yml` — new **dormant** publisher | `deploy/terraform/**` IaC skeleton (**PR5**) |
| `TestWorkflowInvariants` — YAML-parsing workflow-lint (Go, goccy/go-yaml) | `docs/operator/catalog-hosting-r2-activation.md` (**PR5**) |
| Wire the env-gated served gate (`TestServedVerify_BakedRootGate`, shipped in PR2) as the workflow's verify step | `checkGitHubLatestTag` default-off (**PR4**) |
| Tracker row update | Any owner credential / secret creation; `vars` flip; repo-private |

**No production behavior changes.** The job never runs until an owner sets
`vars.R2_PUBLISH_ENABLED=true` **and** provisions the five R2/Cloudflare secrets.
GitHub Pages remains the authoritative catalog host for all of M0 (Pages retirement
is M3). `publish-catalog-pages.yml` and `ci.yml` are **untouched**.

## 2. Must-prove items addressed (from M0 §1 evidence map)

| # | Item | Evidence in this PR |
|---|---|---|
| 6 | R2 publish is stage→verify→promote (never promote-before-verify) | workflow structure + `TestWorkflowInvariants` intent assertion |
| 7 | R2 job has **no `id-token: write`** | `TestWorkflowInvariants` (parses `permissions:`) |
| 8 | Served bytes verified through the **real baked-root** path before promotion | verify step runs `TestServedVerify_BakedRootGate` against the STAGED URL |
| — | Dormant gate uses `vars`, never `secrets.*` in `if:` | `TestWorkflowInvariants` (scans every `if:`) |
| 11 | Existing Pages behavior unchanged | no diff to `publish-catalog-pages.yml` / `ci.yml` |

## 3. Repository evidence (grounding)

- **Signed bundle already exists.** `ci.yml` `catalog-pipeline` (tag path) runs
  `cosign sign-blob → index.json.sigstore`, proves it end-to-end
  (`TestReleaseCatalogKeylessVerify`), then attaches
  `culvert-release-catalog-<tag>.tar.gz` (`index.json` + `index.json.sigstore` +
  `manifests/`) to the GitHub Release (`ci.yml:516-546`). The R2 publisher consumes
  the **same** artifact — it does not re-sign or re-generate.
- **Pages publisher is the shape to mirror.** `publish-catalog-pages.yml` triggers on
  `workflow_run: ["CI"] completed`, resolves the tag, `gh release download`s the
  bundle, refuses an unsigned bundle (`test -s …/index.json.sigstore`), stages, and
  deploys. The R2 publisher copies this structure with a different sink and an added
  **verify-staged-before-promote** interlock.
- **The verify gate already exists (PR2).** `TestServedVerify_BakedRootGate`
  (`release_catalog_served_test.go`) is `t.Skip` unless `CULVERT_RELEASE_SERVED_URL`
  is set; when set it builds the trust store from
  `newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity())` +
  `NewTrustStoreWithSigstore(nil, VerifyEnforce, sv)`, keeps the production SSRF guard
  (`NewHTTPCatalogProvider`'s default `isPrivateHost`), and drives the real
  `autoSeedCatalog` against the served URL. This PR **wires** that gate as the
  workflow's verify step against the staged prefix.
- **`vars` vs `secrets` in `if:`.** `secrets.*` is unavailable in `if:` conditions
  (GitHub Actions). The dormant gate therefore keys on `vars.R2_PUBLISH_ENABLED`;
  the R2/Cloudflare **secrets** are referenced only inside step `run:`/`env:`, which
  never execute while the job is skipped.
- **YAML parser present.** `goccy/go-yaml` is already a dependency (config.go), so
  `TestWorkflowInvariants` needs no new module.

## 4. Design

### 4.1 Placement — a new standalone workflow file

`publish-catalog-r2.yml`, **not** a job inside `ci.yml`. Rationale:
- Isolation & reviewability: the entire dormant R2 surface is one file, diffable and
  lintable for the security invariants alone (M0 §12).
- Permission hygiene: `ci.yml`'s `catalog-pipeline`/`docker` jobs legitimately hold
  `id-token: write`; adding an id-token-free R2 job into that file invites accidental
  permission bleed. A separate file with a top-level `permissions: { contents: read }`
  is unambiguous and mirrors how `publish-catalog-pages.yml` is isolated.
- Trigger parity: like Pages, it runs **after** CI has attached the signed bundle, via
  `workflow_run: ["CI"]`.

### 4.2 Trigger & dormant gate

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
  workflow_dispatch:
    inputs:
      tag: { description: "Release tag (e.g. v1.0.0)", required: false, type: string }

permissions:
  contents: read            # download the release bundle via gh; NO id-token
concurrency:
  group: r2-publish
  cancel-in-progress: false # never cancel an in-flight promote
```

Job-level gate (both conditions required; `vars`, never `secrets`):

```yaml
if: >-
  ${{ vars.R2_PUBLISH_ENABLED == 'true' && (
       github.event_name == 'workflow_dispatch' ||
       (github.event.workflow_run.conclusion == 'success' &&
        github.event.workflow_run.event == 'push' &&
        startsWith(github.event.workflow_run.head_branch, 'v'))) }}
```

Absent/!= 'true' var ⇒ the job is skipped → the workflow completes **green and
neutral**, no partial run, no secret referenced.

### 4.3 Steps — stage → verify → promote → purge → confirm (fail-closed)

All external input (tag, ref names) passes through `env:` and is validated to a
`vX.Y.Z` shape before use (never interpolated into `run:` text) — the same
injection-safe pattern as the Pages publisher. `set -euo pipefail` throughout.

1. **Resolve tag & version** — from dispatch input or `workflow_run.head_branch`;
   validate `v[0-9]*`; `N = <catalog_version>` is NOT recomputed here — staging is
   keyed by the **tag** (`history/stable/<TAG>/`), which is unique per release
   (create-only backstop below). (The catalog's internal `catalog_version` remains
   the monotonic-floor authority inside the signed bytes; the object prefix only needs
   per-publish uniqueness.)
2. **Download + integrity-precheck the signed bundle** — `gh release download "$TAG"
   --pattern 'culvert-release-catalog-*.tar.gz'`; `tar xzf`; **refuse** if
   `index.json` / `index.json.sigstore` / `manifests/` are missing (byte-for-byte the
   Pages guard). This is a structural precheck, not the trust decision — the trust
   decision is step 4, against the STAGED URL.
3. **Stage to R2, create-only** — upload `index.json`, `index.json.sigstore`,
   `manifests/**` to `s3://$R2_BUCKET/history/stable/$TAG/…` using **conditional
   create** (`aws s3api put-object --if-none-match '*'`, which R2 honors) so a
   re-publish of an existing tag can never overwrite immutable history. Manifests may
   be uploaded first (their keys embed `release_id = culvert-<version>`, unique per
   release — `release_gen.go:92`), but staging the index create-only is the ordering
   guarantee. Endpoint/credentials from `secrets.R2_*` (see §6).
4. **Verify the STAGED URL through the real baked-root path** — set
   `CULVERT_RELEASE_SERVED_URL="$R2_PUBLIC_BASE/history/stable/$TAG"` and run
   `go test -run TestServedVerify_BakedRootGate -count=1 -v .`. This fetches the staged
   index+sidecars over HTTPS and drives `autoSeedCatalog` with the baked-root,
   pinned-`ci.yml`-identity, enforce-mode trust store. **verify-fail ⇒ hard stop ⇒ no
   promote** ⇒ the live pointer is never touched. (A virtual signer cannot verify real
   Fulcio-signed production bytes — this is why the gate uses the baked root, M0 §4.3
   role 2.)
5. **Promote by server-side copy** — only on step-4 success, `aws s3api copy-object`
   the **already-verified staged objects** into the live prefix
   (`release-catalog/{index.json,index.json.sigstore,manifests/**}`). We copy the
   verified staged bytes, never re-upload the local artifact (SEC-M3: the promoted
   bytes are provably the ones that passed verification).
6. **Purge + confirm** — Cloudflare cache-purge the live `index.json` + sidecars
   (`secrets.CF_CACHE_PURGE_TOKEN`, `secrets.CF_ZONE_ID`); re-fetch the live index with
   a cache-bust and assert it matches the promoted digest.

Every step exits non-zero on failure; `set -e` + explicit `test`/guard checks make a
partial promote impossible (verify precedes the only write to the live pointer).

### 4.4 `TestWorkflowInvariants` (load-bearing, parses the YAML)

New Go test (whitebox, `package main`) that reads `.github/workflows/
publish-catalog-r2.yml` via `goccy/go-yaml` and asserts:

- **No `id-token` anywhere** — neither top-level `permissions` nor any job
  `permissions` grants `id-token` (must-prove #7). Fail if present at any level.
- **`contents` is at most `read`** at top level.
- **Dormant gate uses `vars`, not `secrets`** — every `if:` string in the file
  contains no `secrets.` token; the job gate references `vars.R2_PUBLISH_ENABLED`.
- **Create-only history flag present (intent)** — the staging step's `run:` contains
  the `--if-none-match` conditional-create marker. Labeled an **intent** assertion
  (it pins the documented mechanism, not runtime behavior — M0 §4.6 / TEST-M5).
- **Verify-before-promote ordering (intent)** — the step that sets
  `CULVERT_RELEASE_SERVED_URL` / runs `TestServedVerify_BakedRootGate` appears
  **before** any `copy-object`/promote step in job step order.

The test is pure/offline (reads a file in-repo), deterministic, and runs in the
normal `-race`/`-count=2 -shuffle=on` suite. It must not depend on network or on the
workflow ever having run.

## 5. State transitions & trust boundary

```
GitHub Release (signed bundle, from ci.yml) ── gh download ──▶ runner tmp (untrusted)
   └─ create-only upload ─▶ R2 history/stable/<TAG>/ (untrusted staging)
        └─ HTTPS fetch ─▶ in-binary baked-root verify  ◀── TRUST BOUNDARY
             └─ (only on pass) server-side copy ─▶ R2 live release-catalog/ (served)
                  └─ cache purge + cache-bust confirm
```

The trust boundary is the in-binary baked-root verification of the **staged** bytes.
R2 (staging and live) is untrusted transport, exactly like Pages.

## 6. Owner prerequisites (activate later; do NOT block this PR)

Referenced by the workflow but intentionally absent today (documented here; full
runbook is **PR5**):
- `vars.R2_PUBLISH_ENABLED` (the dormant switch)
- `secrets.R2_S3_ACCESS_KEY_ID`, `secrets.R2_S3_SECRET_ACCESS_KEY`,
  `secrets.R2_S3_ENDPOINT` (R2 bucket write)
- `secrets.CF_CACHE_PURGE_TOKEN`, `secrets.CF_ZONE_ID` (cache purge)
- `vars.R2_PUBLIC_BASE` (e.g. `https://catalog.culvertlabs.com`) — the served base for
  the verify step

Until the owner provisions these AND flips the var, the job skips. No secret is read
on the skip path.

## 7. Failure behavior

| Failure | Behavior |
|---|---|
| `vars.R2_PUBLISH_ENABLED` unset / not `true` | job skipped → green, neutral, zero writes |
| CI run wasn't a successful tag push | job skipped (workflow_run guard) |
| Release bundle missing / unsigned | download step fails closed (no stage) |
| Staged tag already exists | create-only upload fails closed (immutable history preserved) |
| **Staged bytes don't verify** | verify step fails → **no promote** → live pointer untouched |
| Cache purge fails | job fails after promote; live bytes are already the verified ones; re-run purges (idempotent) |

## 8. Test & validation strategy

- `TestWorkflowInvariants` — the assertions in §4.4.
- `go build ./...`, `go vet .`, `gofmt -l`.
- `go test -race -count=2 -shuffle=on -run 'TestWorkflowInvariants|TestServedVerify' .`
- Regression: `TestServedVerify_*`, keyless/verify suites, `TestReleaseCatalogGate`,
  `TestGenerateReleaseCatalog_Deterministic` stay green (this PR adds a workflow file
  + one test; no production Go changes).
- **`actionlint`** the new workflow if available in the Deep gate; otherwise the
  YAML-parse test is the structural backstop. (The Deep gate's workflow lint, if any,
  is authoritative; `TestWorkflowInvariants` pins the *security* invariants a generic
  linter would not.)

## 9. Definition of Done

Dormant workflow present with `contents: read` only and the `vars`-gate; verify step
wired to the baked-root served gate against the staged prefix, ordered before any
promote; `TestWorkflowInvariants` green and pinning #7 + the vars-gate + create-only
+ verify-before-promote; no diff to `ci.yml` / `publish-catalog-pages.yml`; no owner
credential used; both required CI gates green.

## 10. Rollback

Deleting `publish-catalog-r2.yml` changes nothing live (Pages remains authoritative;
the job never ran). `TestWorkflowInvariants` is a pure addition. Fully additive.

## 11. Open questions for planning review

1. **Placement** — standalone `publish-catalog-r2.yml` (this design) vs a gated job in
   `ci.yml`. Recommendation: standalone, for permission isolation.
2. **Object layout** — `history/stable/<TAG>/` staging + `release-catalog/` live vs a
   flat live prefix. Does the create-only immutability belong on the staging prefix,
   the live prefix, or both?
3. **Verify granularity** — is `TestServedVerify_BakedRootGate` (index+sidecars+one
   `autoSeedCatalog`) sufficient, or should the workflow also assert a promoted-vs-
   staged digest equality after the server-side copy (defense against a copy that
   silently diverges)?
4. **Cache-purge failure semantics** — fail the job (surface it) vs warn-and-continue
   (bytes already promoted). This design fails the job; is that the right call given
   the live pointer is already correct?
5. **actionlint** — is there an existing workflow-lint lane this file must satisfy, and
   should `TestWorkflowInvariants` overlap or stay strictly security-invariant-only?
