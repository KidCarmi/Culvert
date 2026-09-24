# CI/CD Redesign — Lane Architecture & Retirement Checklist

## 0. Current status (authoritative)

As of 2026-09-24, main `6ec745d` (#1487) plus the toolchain-consistency
change (§20); before it, main `75dbb8b` (#1486: targeted report dispatches skip the
trend) plus the first natural-run measurements (§18.3–§18.5) and the
conformance-fixture change (§19). This table
is the one place that says where the plan stands. The sections below it are
the record of how each stage was built and measured; where their present
tense disagrees with this table, this table wins.

| Stage | Implemented | Operationally verified | Awaiting natural samples | Remaining backlog |
|---|---|---|---|---|
| Lane architecture, retirement steps 2–7 (§1–§3) | Yes | Yes: Fast/Deep gates carry every PR; QA/Security are pass-through on PRs | — | Step 1 (branch protection names Fast/Deep only; admin) and step 8 (traffic-smoke promotion, then retire `proxy-pr-gate.yml`) |
| Release publication gating (§5a) | Yes: one predicate over `.github/release-evidence.txt` via `require-release-evidence.sh`; `docker` pushes candidate tags only; `promote-image` moves `latest`/`main`/semver onto the tested digest; every asset is staged as a draft | Yes: on `3febe59` main QA failed, so `Auto-Tag Release` and `Promote moving channels (main)` both refused at their evidence step and nothing was promoted (CI run 35905503220) | — | Main-to-tag build-once promotion: a tag still rebuilds the image the main push already built and tested |
| Stage 1: QA scheduling (§8) | Yes | Yes | — | — |
| Stages 2A/2B: coverage from the race run, race ownership by event (§9–§10) | Yes | Yes | — | — |
| Stage 3: native cross-compilation in the production image (§11) | Yes: `FROM --platform=$BUILDPLATFORM`, `-trimpath -buildvcs=false` | Yes (byte-identical binaries, measured) | — | — |
| Toolchain consistency (§20) | Yes: the root `go.mod` `toolchain go1.26.8` line drives CI, release binaries and every builder image (`golang:1.26.8-alpine` pinned by digest); walled with negative controls | Locally (both arches reproducible, both binaries record `go1.26.8`); CI qualification on this change's PR | Performance samples before this change ran Go 1.26.6 (§20) | Moving to Go 1.27 needs a lint-tool upgrade first (§20); the installer's operator-side source-build fallback stays unpinned |
| Stage 4: E2E image dependency discipline and recipe parity (§12) | Yes | Yes | — | — |
| Stages 5A–5C: sharded race + coverage in QA and in the Fast PR Gate (§13–§15) | Yes: 4 root shards + a non-root lane on one engine | Yes | — | The non-root lane is now the Fast gate's critical path (§18.5); root-state/package isolation (`internal/mcp/execution` is 72 % of the lane) |
| Stage 6A: small restore fixtures by default (§16) | Yes | Yes | — | — |
| Stage 6B: reporting + weekly equivalence audit (§17, §18) | Yes | Schema v2 verified live: 28 on-demand PR reports read their evidence from artifacts and named a verified cohort; a metadata-only report stays `unknown`/unverified. The first automatic v2 report on main failed closed (HTTP 403, rate limit suspected) and its re-run verified it (§18.3.1) | Scheduler: the first audit (Sunday 2026-09-27 06:23 UTC) and its 09:43 backstop have not fired — **pending**. Verified cohorts: **1**. Successful executions: Fast `race` 16, Fast `race+frontend+mcp` 8, main QA 1. The PR samples all come from one 12-hour window, so every baseline stays provisional (§18.4) | — (the dispatch fix is confirmed live: a targeted dispatch skipped the trend, an empty one ran it; §18.3.1) |

Remaining backlog, in the order the measurements support (§18.5):

1. **The non-root lane** — it bounds the Fast race path in 23 of 24
   successful code-PR runs (median 752 s against 454 s for the slowest
   shard); `internal/mcp/execution` is the last package to finish in every
   inspected lane. A saving here is a hypothesis until a bounded comparison
   measures it (§18.5): PR time-to-both-green is bounded by the Deep gate's
   determinism job in 25 of 28 runs.
2. **Determinism** — the longest job on both QA (≈860 s) and the Deep PR
   gate (median 897 s). First slice done: repeated OpenAPI fixture
   preparation in the conformance tests (§19).
3. **Root-state/package isolation** — packages whose tests share process or
   on-disk state cannot be split or reordered safely; this bounds items 1–2.
4. **Repeated static-contract work** — many walls re-read and re-parse the
   same workflow and source files independently.
5. **Main-to-tag build-once promotion** — a tag still rebuilds the image the
   main push already built and tested.
6. ~~**Toolchain consistency**~~ — done (§20): one pinned compiler, Go
   1.26.8. Follow-up: adopting Go 1.27 needs the pinned golangci-lint
   upgraded first.

None is implemented by the closeout. Unrelated test investigations stay
outside this plan.

Historical status (2026-07-03; superseded by the table above): **retirement steps 2–4, §3.9 docker-skip, AND steps 5–7 in
PASS-THROUGH MODE applied** (2026-07-03). The heavy installer/maint e2e
workflows are nightly + path-filtered on PRs; catalog-e2e and CodeQL are
PR-path-scoped; the QEMU image build no longer runs on PRs. Steps 5–7 were
executed **required-check-safe**: `qa-gate.yml` and
`security-release-gate.yml` keep their `pull_request` triggers and aggregate
check names (`✅ QA Gate — APPROVED`, `✅ Security Gate — APPROVED`), but on
PRs every heavy job skips and the aggregates (now `if: always()` +
skipped-as-pass) report success with a "superseded by Fast/Deep PR Gate"
summary — full behavior is unchanged on main pushes, tags, and the new
weekly scan cron. `code-review.yml`'s coverage-delta and build jobs are
deleted (tidy check moved into the Fast Gate's hygiene job).

REMAINING (repo-admin only): **step 1** — in Settings → Branches, require
`✅ Fast PR Gate — APPROVED` and `✅ Deep PR Gate — APPROVED`; once no rule
requires the QA/Security aggregate names, the two pass-through workflows'
`pull_request` triggers (and eventually the files' PR paths) can be dropped
in a trivial follow-up. **Step 8** — promote traffic-smoke after its
two-week flake-free window, then retire `proxy-pr-gate.yml`. This document
is the authority for what supersedes what. **CI-review fix pass applied (2026-07-03,
five-perspective agent review)**: P0s — qa-logic pipefail (main/tag QA gate
could green on failing tests), docs-only classifier carve-out for the
load-bearing SAML reference doc, auto-tag now waits for BOTH gate approvals
on the SHA before tagging (mechanical release gating; tag-echo re-runs
dropped from qa-gate/catalog/installer/maint workflows). Supply chain —
top-level permissions on all workflows, Dependency-Obituary SHA-pinned,
ref_name env-indirection, installer-script tag-pinned, dependabot covers
cmd/culvert-maint + docker. Filters — admin-plane (ui_*.go), upstream*.go,
update/backup/restore/geoip/events, .trivyignore, trust material
(trusted_root.json, release_identity.env), deep-gate self-validation.
Cost — ci.yml test/smoke PR-skip, proxy-pr-gate.yml deleted (triple
duplicate), buildx cache main-scope fallback, fuzz Mon/Wed/Fri, conditional
cancel-in-progress on ci.yml, nightly concurrency groups isolated.
Reliability — deep-gate trivy DB mirror, TEST_SEED everywhere, determinism
failure DX (seed + artifact), timeout-minutes on every job. **Hygiene batch applied
(2026-07-03)**: `.github/actions/needs-verdict` is now THE skipped-as-pass
aggregate (all four gate aggregates use it); `.github/scripts/
coverage-floor.sh` is THE coverage contract (Fast Gate + qa-gate share one
floors table); every job uses the `setup-go-cache` composite (31 direct
call sites migrated, GO_VERSION envs removed); playwright browsers cached.
STILL DEFERRED: classify-diff consolidation (the fast/deep filter sets are
intentionally different — reciprocal sync comments added instead, incl.
deep-gate↔codeql), release-matrix consolidation (release machinery, ~10
min/release payoff only).

## 1. Lane architecture

| Lane | Workflow | Trigger | Role |
|------|----------|---------|------|
| A — Fast PR Gate | `pr-fast-gate.yml` | every PR | **The** required merge check: fmt/vet/build (+arm64 compile, static-binary assert), golangci-lint, ONE full `-race` run owning both coverage contracts (global 55% + per-file floors), benchgate (allocs/op), govulncheck+gosec (pinned), gitleaks (runs even on docs-only PRs), maint-agent module (path-gated), traffic smoke (advisory) |
| B — Deep PR Gate | `pr-deep-gate.yml` | every PR, jobs path-gated | Required-if-run supplementary depth: build-image-once → trivy image + compose validation, hadolint, staticcheck, determinism (`-count=2 -shuffle`, triggered by any `*_test.go`), go-licenses on `go.mod/go.sum`, packaging (shellcheck/visudo/systemd) |
| C — Nightly/weekly | `proxy-nightly-e2e.yml`, `proxy-weekly-stress.yml`, `fuzz-nightly.yml`, `proxy-ui-e2e.yml`, `auth-idp-interop.yml` | schedule | Load, stress, leak, restart-under-traffic, benchmarks, coverage-guided fuzzing, UI e2e, IdP interop |
| D — Security assurance | Lane A fast trio + `codeql.yml` + `security-release-gate.yml` (until retired) | PR + schedule | SAST/deps/secrets/SBOM/SARIF |
| E — Release | `ci.yml` docker/catalog-pipeline/release/provenance path + `security-release-gate.yml` on tags | tags `v*`, main push | Multi-arch build, SBOM, cosign, SLSA, catalog gate, evidence |
| F — Installer/OVA | `install-lifecycle-e2e.yml`, `maint-agent-*-e2e.yml` + Lane B packaging job | PR (to be path-filtered), release | install/migrate/upgrade/rollback, agent lifecycle, appliance assertions |

Docs-only PR handling: neither PR gate uses workflow-level `paths:` filters —
a required check whose workflow never runs sits at "Expected" and blocks merge
forever. Instead a `changes` job classifies the diff (dependency-free
`git diff HEAD^1 HEAD` on the merge ref), jobs self-gate with `if:`, and the
always-running `*-approved` aggregates treat skipped as passing.

## 2. Duplication being removed (why the parallel phase exists)

Pre-redesign, every PR ran: **3×** the full `-race` suite (qa-logic ran it
twice internally + security-gate tests-race), 2 more full non-race runs
(determinism ×2 counts), 2 `-short` runs (coverage-delta), **~13** docker
image builds, four 35-minute installer/maint e2e jobs, multi-arch
arm64-via-QEMU builds that were never pushed, and CodeQL — with no path
filters anywhere except proxy-ui-e2e.

## 3. Retirement checklist (follow-up PR, after ≥1 green parallel cycle)

Time-box the parallel phase to **one week** — it costs roughly +50% CI spend.
Execute in this order; each ✂ step pairs a workflow change with a
branch-protection edit **in the same sitting**:

1. **Add `Fast PR Gate / ✅ Fast PR Gate — APPROVED` and
   `Deep PR Gate / ✅ Deep PR Gate — APPROVED` to required checks** once each
   has one green cycle. Do NOT remove any existing required check yet.
2. **Move the heavy e2e off the PR path first** (they dominate cost):
   - `install-lifecycle-e2e.yml` → `schedule` (nightly) + `push: tags v*` +
     PR `paths: [scripts/**, packaging/**, docker-compose*.yml, Dockerfile*]`
   - `maint-agent-backup-upgrade-e2e.yml` → same treatment
   - `maint-agent-update-e2e.yml` stays as the PR representative but gains
     the same `paths:` filter (it is advisory-by-paths, not required, so a
     workflow-level filter is safe here).
3. **Path-filter `catalog-e2e.yml`** (do not delete — it is the behavioral
   coverage for the release trust chain):
   `paths: [release_*.go, internal/**, test/e2e/**, Dockerfile, go.mod, go.sum, .github/workflows/catalog-e2e.yml]`
4. **Move `codeql.yml` off every-PR**: keep the weekly schedule + main push;
   add PR `paths:` for the security surface (same globs as Lane B's
   `security` filter) if PR-time CodeQL is still wanted.
5. ✂ **Retire `qa-gate.yml`** — superseded map:
   qa-logic/qa-coverage → Lane A `test-race`; qa-determinism → Lane B
   `determinism`; qa-infra-compose → Lane B `compose-validate`; qa-os →
   Lane A `hygiene` (static assert); qa-contract → covered by `./...` in
   Lane A; qa-agent → Lane A `agent` + Lane B `packaging`; qa-bench →
   Lane A `benchgate`. **Remove `qa-gate-approved` from required checks in
   the same change** — a deleted workflow's required check hard-blocks all
   merges at "Expected".
6. ✂ **Slim `security-release-gate.yml`** to tags/main-push/schedule only
   (it remains the release-time evidence gate): PR-time gosec/govulncheck/
   gitleaks now live in Lane A; trivy-image/hadolint/go-licenses in Lane B.
   Keep trivy-fs, SBOM, SARIF uploads, and the aggregate on the
   non-PR triggers. Update required checks if `release-approved` was required
   on PRs.
7. ✂ **Slim `code-review.yml`**: `lint` is superseded by Lane A (keep the
   reviewdog inline-comment variant only if the team wants inline comments);
   `coverage-delta` (two extra test runs) is superseded by Lane A's floors —
   delete or keep as advisory; `build` superseded by Lane A `hygiene`.
8. **`proxy-pr-gate.yml`** retires once Lane A's `traffic-smoke` is promoted
   (see §4).
9. **`ci.yml` constraints — do not violate:**
   - The workflow **name `CI` must not change** and the workflow must not be
     split in a way that changes its name: `publish-catalog-r2.yml`
     triggers on `workflow_run: workflows: ["CI"]`. Renaming it silently
     kills signed-catalog publication to the R2 origin (the
     `CULVERT_RELEASE_CATALOG_URL` auto-seed origin, and since the Pages
     retirement the ONLY one). If it is ever renamed, update
     `publish-catalog-r2.yml` in the same PR.
   - The `docker` job on main-push/tags is **release machinery** (next-version
     compute, push/retag, cosign, `proxy_digest`/`version_bare` outputs
     consumed by `catalog-pipeline`, transitively gating `release`). The
     PR-only `_build-image.yml` reusable must never replace it.
   - Optional PR-cost win that IS safe: make the `docker` job build
     amd64-only (`push: false` already) on `pull_request` events, or skip it
     on PRs entirely now that Lane B builds+scans the image; verify
     `catalog-pipeline`'s `needs: [docker]` if-chain first.
   - Before restructuring the tag path at all, verify how tag-triggered runs
     fire today: `auto-tag` pushes tags with `GITHUB_TOKEN`, which does
     **not** trigger workflows — confirm the actual release trigger chain
     (manual tags / PAT) before assuming `tags: v*` reproduces it.

## 4. Traffic-smoke promotion criterion

`pr-fast-gate.yml`'s `traffic-smoke` job is `continue-on-error: true` and
excluded from the aggregate's `needs`. Promote it (drop `continue-on-error`,
add to `needs`) after **two weeks of flake-free runs** across the nightly
proxy lane and the advisory PR runs — the workflow file itself says the
traffic-plane suite must prove stability first. Then retire
`proxy-pr-gate.yml` (step 8).

## 5. Required branch-protection checks (end state)

- `Fast PR Gate / ✅ Fast PR Gate — APPROVED`
- `Deep PR Gate / ✅ Deep PR Gate — APPROVED`
- (optional) `CodeQL / analyze` if PR-time CodeQL is retained on security paths

Everything else — nightly stress/load/fuzz, weekly IdP interop, UI e2e,
benchmarks, heavy installer e2e — is scheduled/advisory, and release-blocking
only via the tag-path gates.

### 5a. Release-gate integrity (PANW audit item 1 — REQUIRED admin step)

Every release-publishing job gates on ONE predicate over ONE manifest:
`.github/scripts/require-release-evidence.sh` reads
`.github/release-evidence.txt` and resolves each row through
`.github/scripts/require-gate.sh`, which binds the verdict to the workflow
**file** path and to a main-push run of the exact commit (a spoofed check-run
*name* or a tag-triggered re-run of the same SHA cannot self-approve). A
`mandatory` row refuses on failed, cancelled, pending, skipped, neutral or
absent. This is the in-repo backstop.

It is a BACKSTOP, not the primary control. On the tag path `require-gate.sh`
is checked out from the **tagged tree**, so anyone able to push an arbitrary
`v*` tag can also strip the guard. The primary control is a **repo ruleset
that restricts `v*` tag creation to the `github-actions[bot]`** (i.e. only
`auto-tag` may mint release tags; humans cannot push `v*` at all):

> Settings → Rules → Rulesets → New tag ruleset → Target `v*` →
> Restrict creations → Bypass list: `github-actions[bot]` only.

Until that ruleset exists, a maintainer with push access can still hand-push a
tag on a *reviewed, green* commit (the in-repo guard allows exactly that and
refuses a non-green commit). Set the ruleset to close the arbitrary-tree class.

**Closed (was deferred, Phase 2).** A *main* push used to publish and
cosign-sign `ghcr:latest` in parallel with the gate, so a commit that later
failed the gate had already shipped a signed `latest` (run 35507615339
published 29 minutes before the QA/Security verdict existed). Now `docker`
pushes only non-channel candidate tags (`candidate-<run_id>`, `sha-<short>`),
and the evidence-gated `promote-image` job moves `latest`/`main`/semver onto
that exact tested digest; every release asset is staged as a draft and only
`publish-release` turns it public. Runbook:
`docs/operator/release-publication-gating.md`.

### 5b. Egress control on the signing jobs (PANW audit item 2)

The OIDC-token-bearing jobs (`docker`, `catalog-pipeline`, `release`, plus the
`_build-image` reusable, and `pr-fast-gate/test-race`)
run `go build`/`go test`/`docker build` over the full dependency graph while
holding the cosign signing identity. A compromised transitive dep could
exfiltrate that token. **Phase 2a (applied):** `step-security/harden-runner`
runs in `egress-policy: audit` as the first step of each — non-breaking egress
monitoring + a baseline for the block flip. golangci-lint is now installed via
checksum-verified `go install` (was `curl | sh` off a mutable tag ref).

### 5d. SBOM + reproducibility (PANW audit item 4)

The Dockerfile no longer runs `go mod tidy` at image-build time — the image
builds from the exact reviewed `go.mod`/`go.sum` (tidiness is enforced in CI by
the Fast Gate's `go mod tidy -diff`, not re-resolved in the image layer). All
Go builds (image, `test`, and the `release` matrix) now pass `-trimpath` as
reproducibility groundwork. **Caveat:** `-trimpath` is a build-input change, so
the first tagged release carrying it produces different binary hashes (and
therefore different SLSA subject digests) than prior releases — expected, not
tampering; note it in that release's changelog.

**Reproducible-build determinism (verifiable-provenance groundwork).** The two
release builds (`ci.yml`, proxy + `culvert-maint`) now also pass `-buildvcs=false`.
This was **required, not cosmetic**: `culvert-maint` is a separate module with no
own `.git`, it reads the ROOT repo status, and the proxy binary written by the
earlier matrix step is an untracked, non-gitignored sibling — so the default
`auto` stamped `vcs.modified=true` and made the maint SLSA subject
**order-dependent** (a clean-tree rebuild would hash-mismatch). With `false`, both
binaries are byte-reproducible independent of tree state (the commit is already
carried by the tag + provenance, so the VCS stamp is redundant); the first release
after this again changes the hashes (expected). A Deep-gate **build-determinism**
step (two identical-flag builds must be byte-identical, to `RUNNER_TEMP`) now
guards this on every Go-touching PR — for **both** release modules (proxy AND
`culvert-maint`, the module that carried the bug), so a future maint-specific
non-determinism regression is caught too.

**F1 — verifiable provenance (DONE).** A tag-path `verify-reproducible` matrix
job (`ci.yml`, `needs: [aggregate-subjects]`) independently rebuilds every
released binary at the tag (fresh checkout, fresh runner) and asserts each
rebuilt `sha256` EQUALS the signed SLSA subject decoded from
`aggregate-subjects.outputs.hashes` — the exact bytes `provenance` signs. Any
mismatch (or a missing subject / drifted filename) fails the leg **closed**, and
`provenance` is gated on it (`needs: [aggregate-subjects, verify-reproducible]`),
so a reproducibility break on ANY leg withholds the SLSA attestation and reds the
release. The build is a **shared composite** (`.github/actions/build-release-binaries`)
that BOTH the `release` job and `verify-reproducible` call, so the independent
rebuild can never drift from the real build (a two-copy build command would make
the check tautological or falsely-red). Honest scope: this is **same-image,
same-pinned-toolchain** reproduction (`setup-go-cache` reads `go-version-file:
go.mod` for both; Go 1.26.6 today),
not an independent-environment rebuild — SLSA's trusted builder covers build
integrity; F1 verifies *determinism* (catches dep/toolchain-drift/tampering
nondeterrminism between hashing and signing). The verify job is `contents: read`
only (signs nothing — deliberately no `id-token`). **Guardrail:** never add
`always()`/`success()`/a status function to `provenance`'s `if:`, or the gate
silently opens. **Image binary (closed).** The production `Dockerfile` used to
build with the default `-buildvcs=auto`; its `.dockerignore` strips tracked
files while keeping `.git`, so the image binary shipped `vcs.modified=true`.
Both Go stages now build with `-trimpath -buildvcs=false` (§11), so the image
binary is tree-state reproducible too.

**F2 — runtime version stamp (DONE).** Prompted by the first LIVE
authoritative MCP Observe Acceptance (v1.0.202), which failed its required
`artifact.version` criterion: `main.version` was stamped correctly by the
release build (`-X main.version=${REF_NAME}`), but the live `/healthz`
handler omitted the `version` field entirely, so the release's runtime
version stamp was unverifiable. Two fail-closed gates now guard this, both
wired from `.github/scripts/` (deliberately called a "version stamp", not a
"release identity" — that term is reserved for the cosign/Sigstore
signer-trust identity verified separately in this same pipeline):
- **`assert-release-ref.sh`** runs on the `release` job (before
  `Build release binaries`) AND on `verify-reproducible` (before
  `Rebuild release binaries`) — it refuses to build/sign when `REF_NAME` is
  empty or not a `vX.Y.Z` tag, so an official signed binary can never be
  stamped with an empty/dev/latest/SHA version.
- **`assert-runtime-version.sh`** runs only on the native `linux/amd64` leg
  of `release` (a foreign-platform binary can't execute on the runner): it
  boots the exact just-built bytes-under-signature with `-ui-no-tls`, polls
  `GET /healthz` on the admin listener, and asserts the reported `version`
  field equals the release tag. This is the check that would have caught
  v1.0.202 — it proves the signed binary surfaces its version stamp at
  runtime, not just that the linker flag was set.

`api/openapi/openapi.yaml`'s `HealthStatus.version` documents the field
these gates enforce. See `TestHealthz_ReportsRuntimeVersion` (handler) and
the `release_version_identity` test family (guard behavior) for the pinned
contract.

Every GitHub Release now carries **per-module CycloneDX SBOMs** for its binaries
(`culvert.sbom.cdx.json` + `culvert-maint.sbom.cdx.json`), generated once on the
linux/amd64 leg (syft reads the embedded Go build-info, identical across
GOOS/GOARCH). This replaces the prior state where the source-tree SBOM was a
90-day artifact falsely documented as "attached to every release" and the 7
released binaries had no SBOM at all. The SBOMs are Release *assets*, a channel
disjoint from the SLSA subjects, so the `aggregate-subjects` `==7` invariant is
untouched. The image already ships a BuildKit CycloneDX SBOM attestation
(`sbom: true`), so it is out of scope here.

**cosign 2.x→3.x bundle migration (DONE).** The pinned `cosign-installer@v4.1.2`
installs cosign **3.0.6**, which removed `sign-blob`/`attest-blob`'s detached
`--output-certificate`/`--output-signature` — so the binary/SBOM signing steps
were latently broken on the next tag (corroborated: release v1.0.0 shipped zero
binary/SBOM assets). Migrated to the cosign-3.x **new-format Sigstore bundle**
(`--bundle *.sigstore.json`, matching the catalog step) on all three paths:
- **Binaries** now ship a single `<binary>.sigstore.json` bundle instead of
  `.sig`/`.pem`.
- **SBOMs** are signed **standalone** with `cosign sign-blob --bundle`
  (`<sbom>.sigstore.json`, new-format Sigstore bundle). Deliberately NOT
  `attest-blob` with a binary subject: the SBOMs are per-**module** and shared by
  every arch binary, so binding one to a single binary's digest (e.g.
  linux/amd64) would make `verify-blob-attestation` fail the subject check for
  the arm64/darwin/windows binaries. A standalone signed SBOM verifies for
  consumers of any released binary.
- The cosign binary is explicitly pinned (`cosign-release: 'v3.0.6'`) on all
  Install-cosign steps so a future installer bump can't silently reintroduce the
  flag drift.
- **Operator impact:** `packaging/culvert-maint/install.sh` now verifies with
  `cosign verify-blob --bundle`, the verifier container default is bumped to
  `ghcr.io/sigstore/cosign/cosign:v3.0.6` (the correct GHCR path — the prior
  `ghcr.io/sigstore/cosign:*` reference was never a pullable image), and the
  local-binary override is `CULVERT_MAINT_BUNDLE` (was `CULVERT_MAINT_SIG`/`_PEM`).
  **Operators who pinned a cosign v2.x digest via `CULVERT_MAINT_COSIGN_IMAGE`
  MUST re-pin to v3.0.6** — a v2.x verifier cannot parse a v3 new-format bundle.
- No CI lane runs a real keyless verify (needs OIDC), so
  `cosign_bundle_migration_test.go` string-pins the bundle wiring on both the
  producer (`ci.yml`) and consumer (`install.sh`) as the regression guard.

**Follow-ups:** a single consolidated evidence-bundle tarball (SBOMs + provenance
+ scan reports + gate summaries per tag) is optional (those artifacts already
exist individually).

### 5c. DAST — attack the running product (PANW audit item 3)

`dast-nightly.yml` (scheduled) boots the real proxy and points scanners at it:
`testssl.sh` against the admin UI TLS (**gated** on legacy protocols / weak
cipher families — not on severity, since a self-signed cert is a legitimate
HIGH PKI finding), an **authenticated** OWASP ZAP baseline (see below), and a
gosec run with **G401 (weak crypto) + G402 (InsecureSkipVerify) re-included**
(report-only discovery of the surface the blocking gates' blanket exclusion
hides).

**Authenticated ZAP (DONE).** The ZAP job scans the **configured** proxy so the
auth/session/CSRF/RBAC stack is live — not a first-run open server where it is
inert. It provisions an admin via `POST /api/setup/complete`, proves auth now
bites (a protected route returns **401** unauthenticated), logs in, and injects
the `ps_ui_session` cookie on **every** ZAP request via the Replacer add-on
(`matchtype=REQ_HEADER` adds the header when absent), with a positive
authenticated-**200** reach-check bracketing the anon-401 smoke so a cookie-name
regression can't silently un-authenticate the scan. The admin UI is a **SPA**
whose protected `/api/*` routes are fetched from JavaScript, so the job also runs
the **AJAX (JS-aware) spider** (`-j`, duration-capped) — a headless browser that
executes the SPA's JS so ZAP actually reaches the post-login API surface, not
just the static shell. `/api/auth/logout` is globally excluded so a stray hit
can't drop the session mid-scan. The
provision/gate checks are a deterministic (non-advisory) guard; ZAP findings
stay advisory (`-I` + `|| true`).

The forged-leaf TLS posture of the **inspected path** — the product's core
function — is asserted deterministically + hermetically by
`TestMITM_ForgedLeafTLSPosture` (Go, default suite): TLS ≥ 1.2, AEAD cipher,
ECDSA P-256 leaf, and a TLS 1.1 client refused. An external scanner through the
CONNECT path is infeasible in CI (the shipped binary has no runtime
loopback-SSRF relax — that is test-only). `proxy.go`'s client-facing
`tls.Config` now pins `MinVersion: tls.VersionTLS12` explicitly (was relying on
the Go default) so the floor is contractual.

**G401/G402 now ENFORCED (DONE).** The blocking gosec (Fast Gate root +
cmd/culvert-maint, the release/QA gates, and `.golangci.yml`) no longer
blanket-excludes G401 (weak crypto) / G402 (InsecureSkipVerify). The discovery
delta was exactly three G402 sites, all already config-gated operator opt-ins
(`auth_oidc.go`, `auth_oidc_flow.go`, `auth_ldap.go` — `cfg.TLSSkipVerify`); each
now carries an at-site `// #nosec G402 -- <reason>` (the form standalone gosec
honors, vs the prior `//nolint:gosec` which it ignored — that mismatch was the
sole reason for the blanket exclude). Zero G401 findings. Net: no product
behavior change; any NEW ungated `InsecureSkipVerify` or weak hash now fails CI.
The nightly DAST J4 lane is retained as a report-only view of the *remaining*
excluded classes (G703/G704, SSRF/forward-proxy-by-design).

**HSTS — evaluated and dropped.** Admin-UI HSTS was implemented and reviewed but
**cancelled**: HSTS is host-scoped (not port-scoped, RFC 6797 §8.3), so a header
from the HTTPS UI (:9090) would force-upgrade the same host's **always-HTTP**
proxy/PAC/health port (:8080) to HTTPS in an admin's browser, breaking PAC
auto-config in Culvert's default same-host topology. Only revisit as an **opt-in**
(default off) for operators who run the UI on a dedicated host.

**Follow-ups:** a client-side cipher **allowlist** on the inspect `tls.Config`
(MinVersion is pinned; the suite set still inherits Go defaults); optionally
promote the ZAP/testssl findings from advisory to blocking after a stable
baseline.

**Phase 2b (TODO — flip to block after one real tagged release):** harden-runner
`block` is NOT applied yet because the Actions runtime/OIDC/cache use
per-region FQDNs under `*.actions.githubusercontent.com` that block can't
reliably match without an empirical baseline, and a wrong allowlist mid-pipeline
yields a *partial* release (images already signed to ghcr, release aborted).
Procedure: run one real `v*` release with audit on, read harden-runner's
reported endpoints, then set `egress-policy: block` + `allowed-endpoints` pinned
to those exact FQDNs. Known-required hosts (starting list, confirm against the
report): `github.com:443`, `api.github.com:443`, `uploads.github.com:443`,
`release-assets.githubusercontent.com:443`, `objects.githubusercontent.com:443`,
`codeload.github.com:443`, the reported `*.actions.githubusercontent.com` +
`*.blob.core.windows.net` FQDNs (Actions/OIDC/artifacts/gha-cache),
`ghcr.io:443`, `pkg-containers.githubusercontent.com:443`,
`proxy.golang.org:443`, `sum.golang.org:443`, `storage.googleapis.com:443`,
`fulcio.sigstore.dev:443`, `rekor.sigstore.dev:443`,
`tuf-repo-cdn.sigstore.dev:443`, `registry-1.docker.io:443`,
`auth.docker.io:443`, `production.cloudflare.docker.com:443`. Note: the
`docker` job's in-container build egress (apk, `go mod download` inside
buildkit) bypasses harden-runner — block there protects only the host-side
cosign step. The `provenance` job is an SLSA reusable workflow (`@v2.1.0`,
tag-pinned by design) — harden-runner cannot be injected into it; accepted gap.

## 6. Pinning policy

GitHub Actions: full commit SHA + version comment (enforced convention).
Go-installed tools: exact versions (gosec v2.27.1, govulncheck v1.5.0,
go-licenses v1.6.0, staticcheck 2025.1, golangci-lint v2.5.0). Exception:
`benchstat@latest` — `golang.org/x/perf` publishes no tagged releases and it
only feeds the informational weekly diff. Known remaining unpinned ref:
`KidCarmi/Dependency-Obituary@main` (first-party, advisory,
continue-on-error).

## 7. Expected PR wall-time

| Scenario | Before | After retirement |
|----------|--------|------------------|
| Docs-only PR | ~40–60 min of jobs | gitleaks + aggregates (~2 min) |
| Typical Go PR | ~40–60 min | ~10–15 min (bounded by the single `-race` run) |
| Proxy/security/deps PR | ~40–60 min | ~20–30 min (Lane A ∥ Lane B, image built once) |
| Release tag | ~60+ min | unchanged by design (full evidence) |

## 8. Stage 1 — QA scheduling (shipped)

Six QA Gate jobs — `qa-determinism`, `qa-coverage`, `qa-infra-compose`,
`qa-os`, `qa-contract`, `qa-bench` — carried `needs: qa-logic` while consuming
no output and no artifact from it. The edge bought nothing and serialised the
longest job in the workflow (a full `-race` suite, ~25 min observed) in front of
every one of them on main pushes and manual dispatches. Stage 1 removes the six
edges, leaving all eight substantive jobs independent and joined only by the
`✅ QA Gate — APPROVED` aggregate.

The PR-time skip those jobs used to inherit by CASCADE from `qa-logic`'s own
`if:` is now stated on each job explicitly
(`if: github.event_name != 'pull_request'`). Dropping the edge without restoring
the condition would have started running the whole QA suite on every pull
request — the opposite of retirement step 5. `always()` is deliberately NOT used:
it would also run the jobs on PRs and after a cancellation.

Unchanged by design: workflow name, job ids, required-check names, the trigger
matrix (push→main, pull_request→main, workflow_dispatch; no schedule, no tag
push), every command, flag, seed, coverage floor, timeout, permission,
concurrency group, artifact and cleanup step, the aggregate's `always()`, the
shared `needs-verdict` action, and `qa-gate.yml`'s `mandatory` row in
`.github/release-evidence.txt`.

Behaviour change, intended: a `qa-logic` failure no longer suppresses its former
dependents — they run and report their own verdict. The aggregate still refuses,
because it still needs all eight.

Wall: `qa_gate_scheduling_test.go` (5 tests / 22 sub-cases). It parses the real
workflow and drives the REAL `needs-verdict` composite action's shell rather
than a re-implementation of its jq. Every assertion was verified failing against
the pre-change tree or against an injected defect (re-added edge, dropped `if:`,
`always()` substitution, a job dropped from the aggregate, a restored tag
trigger, and a `needs-verdict` that stops refusing `cancelled`).

### Follow-up (NOT in stage 1): `needs-verdict` accepts `skipped` on every event

`.github/actions/needs-verdict` treats a `skipped` need as a pass unless the
caller passes `require-success`. The event is not part of its input, so it
cannot distinguish a legitimate PR skip from an all-skipped main push. No gate
aggregate in this repository passes `require-success` today, so an all-skipped
main-push QA run would report APPROVED. This is PRE-EXISTING and shared by the
Fast/Deep PR and Security aggregates; it is not made better or worse by stage 1,
and tightening it is a policy change to a shared action that belongs in its own
reviewed diff (the likely shape: pass `require-success` with the substantive job
ids on non-PR events).

Two consequences to carry until it is closed:

* Validating a QA scheduling change on a non-PR event means confirming that all
  eight substantive jobs **executed** successfully, not merely that the
  aggregate went green.
* `TestQAGateVerdict_RealActionBehaviour` pins the behaviour as it IS, including
  this gap, so closing it is a visible diff rather than a silent one.

## 9. Stage 2A — QA coverage from the race run (shipped)

QA executed the whole `./...` suite TWICE on every main push. `qa-logic` ran it
under `-race`; `qa-coverage` ran it again under `-coverprofile`, with the same
`TEST_SEED` and the same package scope, purely to instrument what the first run
had already executed.

Stage 2A adds `-coverprofile=coverage.out` to the race invocation and turns
`qa-coverage` into a VERIFIER: it downloads the profile `qa-logic` publishes and
runs the existing `.github/scripts/coverage-floor.sh` on it. One execution, same
evidence.

`qa-coverage` therefore gets a `needs: qa-logic` edge back — the one stage 1
removed from it. That is not a reversal: stage 1 removed six edges that carried
**no data**, and this one carries an artifact, so the job genuinely cannot start
earlier. The invariant the wall pins is that distinction (`qaAllowedJobEdges`),
not a blanket "no edges" rule.

Unchanged: the eight substantive jobs and the aggregate; the other five jobs stay
independent; the global 55% floor, every per-file floor and the script's
arithmetic; the `qa-coverage` artifact name, its `coverage.out` path and its
30-day retention; the shuffled determinism suite, the maintenance-agent module
checks and the benchgate tests; the PR pass-through.

### The shape is not new here — Security already runs it

`security-release-gate.yml`'s `tests-race` job has been running
`go test -v -race -count=1 -timeout=40m -coverprofile=coverage.out ./...` —
the same combined command, on the same suite, under the same 50m/40m budgets —
on every non-PR event. Stage 2A makes QA match a shape this repository already
relies on, rather than introducing one.

It also supplies a CONTROLLED measurement of the instrumentation cost, on the
same commit `35169ba` and the same runner class:

| Job | Command | Duration |
|---|---|---|
| `qa-gate` / `qa-logic` | `-race`, no coverage | **1969 s** |
| `security-release-gate` / `tests-race` | `-race` **+ `-coverprofile`** | **1950 s** |

Race+coverage measured 19 s FASTER than race-only — i.e. the overhead is below
this suite's run-to-run variance, not that instrumentation is free. Do not quote
that as a speedup; quote it as "no measurable cost".

So a main push ran the full suite **three** times before 2A (QA race, QA
coverage, Security race+coverage), runs it **twice** after, and would run it
**once** after 2B.

### Why the coverage numbers do not move

`-race` forces `-covermode=atomic`, so the profile's `mode:` line changes and its
counters carry real counts instead of 0/1. `go tool cover` treats any count > 0
as covered, so the PERCENTAGES the floors are computed from are unaffected.
Measured on the packages hosting four of the nine floor files, `go tool cover
-func` output is **byte-identical** between the two arms — same statement-block
set (348 blocks), same total, same per-file floor arithmetic. Only the `mode:`
line differs.

### The failure modes the edge introduces, and where each is refused

Moving evidence across a job boundary adds ways to be green without it. A floor
enforced against nothing is indistinguishable from a floor that passed, so each
is refused explicitly:

| Failure | Refused by |
|---|---|
| Profile missing/empty/malformed at the producer | `qa-logic`'s guard step, before upload |
| Profile never published | `if-no-files-found: error` on the upload |
| Producer failed or was cancelled | `needs: qa-logic` — `qa-coverage` never runs, and qa-logic's own result fails the aggregate |
| Download empty or truncated | `qa-coverage`'s guard step, before the floor script |
| Floor genuinely breached | `coverage-floor.sh`, unchanged |
| A profile from some OTHER run | `download-artifact` is passed no `run-id`/`github-token`, so it is scoped to this run |

Note the third row: a failed `qa-logic` SKIPS `qa-coverage`, and `needs-verdict`
reads a skip as a pass. The gate is still correct **only** because qa-logic's own
`failure` is in the same `needs` set. Never drop qa-logic from the aggregate.
Pinned by `TestQAGateCoverage_VerdictRefusesMissingCoverageEvidence`.

Wall: `qa_gate_coverage_test.go`, which drives the REAL shipped shell — both
guard steps and `coverage-floor.sh` itself — rather than re-implementing them,
and builds a genuinely valid profile by compiling a throwaway module instead of
hand-writing profile lines that `go tool cover` cannot resolve.

### Not done here — stage 2B

The duplicate main-push race execution ACROSS workflows is untouched:
`qa-gate.yml`'s `qa-logic` and `security-release-gate.yml` both run the full
`-race` suite on a main push. Consolidating them is stage 2B and is not a
scheduling change — see §10.

## 10. Stage 2B — cross-workflow race ownership (shipped)

On a main push the full `-race ./...` suite ran TWICE, in two workflows:
`qa-gate.yml`'s `qa-logic` (which since stage 2A also produces the authoritative
coverage profile) and `security-release-gate.yml`'s `tests-race`, with the same
`TEST_SEED` and the same package scope, for one verdict.

It could not be fixed by deleting a job, because **the two workflows do not run
on the same events**:

| Event | qa-gate.yml | security-release-gate.yml |
|---|---|---|
| push → main | yes | yes |
| pull_request → main | jobs skip (pass-through) | pass-through |
| tag `v*` | **no trigger at all** | yes |
| schedule (weekly) | no | yes |
| workflow_dispatch | yes (any ref) | yes |

Deleting `tests-race` would have left version tags, the weekly cron and
Security-only dispatches with **no race evidence at all**.

### What shipped: ownership by event

`tests-race` is now scoped by EVENT and REF together:

```
pull_request           → skip  (pass-through, unchanged)
push → refs/heads/main → SKIP  — owned by qa-gate.yml's qa-logic
push → refs/tags/v*    → RUN   — qa-gate.yml has no tag trigger
schedule (weekly)      → RUN   — ref is main, but QA has no schedule
workflow_dispatch      → RUN   — including on main
```

**Keying on the branch alone is the trap.** The scheduled and manual runs also
have `refs/heads/main` as their ref, so a `github.ref != 'refs/heads/main'`
condition would silently suppress exactly the events on which nothing else runs
the suite. The condition must test the event too.

### One skip is intentional; every other one is a hole

`needs-verdict` reads a skipped need as a pass — which is what makes the
intentional main-push skip acceptable, and would equally swallow a `tests-race`
that failed to start on a tag. So on every event where Security still OWNS the
suite, the aggregate passes `require-success: tests-race`, which demands
exactly `success` and refuses a skip. On a main push (and on PRs) the input is
empty and the skip is accepted.

That predicate is written TWICE — the job's `if:` and the aggregate's
`require-success` — because a job-level `if:` cannot read `env`, so it cannot be
factored out in YAML. `TestSecurityRace_OwnershipPredicateIsSingleSourced` pins
the two copies equal. Drift is silent in one direction (a suite that runs
unrequired) and wedging in the other (a gate demanding a job that never starts).

### The release verdict did not change, and that is the point

`.github/release-evidence.txt` already required BOTH workflows as `mandatory`,
and `require-release-evidence.sh` binds each row to the workflow FILE PATH, the
exact head SHA, `event=push` and `head_branch == main`. Stage 2B moves the
main-push race run from one side of that conjunction to the other; it does not
move it out. Nothing was added to the predicate, no cross-workflow polling job
was introduced, and no reusable workflow was called twice (which would not have
removed an execution anyway).

Consequently a green Security run on main means **this workflow's required scans
passed** — not that QA passed. The banner and step summary say so explicitly,
and the summary renders the race row as "owned by qa-gate.yml — not evaluated
here" on a main push rather than a tick it did not earn.

### Artifact ownership

| Artifact | Producer | Scope |
|---|---|---|
| `qa-coverage` | `qa-gate.yml` / `qa-logic` | **Authoritative** main-push profile; the floors are enforced against it |
| `coverage-report` | `security-release-gate.yml` / `tests-race` | This workflow's standalone runs only — tags, schedule, dispatch |

`coverage-report` is therefore absent on main pushes from 2B onward. That is
safe because **nothing consumes it**: it has no reader in any workflow, script or
test (audited, and pinned by `TestSecurityRace_CoverageArtifactOwnership`). No
stand-in was fabricated for it; on main, read `qa-coverage`.

### Expected saving, and what is not yet measured

A main push ran the suite three times before 2A, twice after 2A, and **once**
after 2B — removing roughly one `qa-logic`-equivalent (~2000 s, ~33
runner-minutes) per main push. **Actual main-push behaviour and savings require
post-merge observation**: a branch `workflow_dispatch` deliberately RUNS
`tests-race` (dispatch is an event Security owns), so the dispatch used to
validate this change cannot demonstrate the main-push skip. Report
runner-minutes and wall-clock separately when it lands.

Walls: `security_race_ownership_test.go` (7 tests) plus the STAGE 2B section of
`.github/scripts/test/release-gating-cases.sh`, which drives the REAL predicate
with Security green and QA absent / failed / cancelled / timed-out / stale /
skipped / neutral / pending / wrong-SHA / tag-ref / dispatch-event, each
refusing, with a both-green control that approves.

### Rollback

Revert the commit. `tests-race` returns to `if: github.event_name != 'pull_request'`
and the aggregate stops passing `require-success`; the main push simply runs the
suite twice again. Nothing else depends on the change: the release predicate,
the evidence manifest, every publication barrier and both check identities are
untouched, and `coverage-report` reappears on main pushes.

## 11. Stage 3 — native cross-compilation in the production image (shipped)

The production multi-platform build (`ci.yml` `docker` job, `linux/amd64,linux/arm64`)
ran the **whole Go compiler under QEMU** for arm64. Neither Go stage pinned a
platform, so each pulled the TARGET-arch `golang` image, and on an amd64 runner
the arm64 compile of both the proxy and the bundled maintenance agent was
emulated instruction by instruction.

### What shipped

Both Go stages — `builder` (proxy) and `maintbuilder` (the separately
versioned agent) — now run `FROM --platform=$BUILDPLATFORM` and cross-compile
with `GOOS=${TARGETOS} GOARCH=${TARGETARCH}`. `CGO_ENABLED=0` is unchanged, so
the output is the static pure-Go binary a native build produces. Everything
else in the recipe is untouched: version resolution and normalization, the
proxy `buildCommit`, the agent's `server.Version` symbol, `-trimpath` and
`-buildvcs=false`, every binary path, the `/app/deploy` bundle, the runtime
user, permissions, entrypoint, HEALTHCHECK and `/data` volume.

The **runtime stage stays on the TARGET platform** — an arm64 image must carry
an arm64 userland — so QEMU is still required for its Alpine package and user
setup, and `setup-qemu-action` stays in `ci.yml`. Only the compilation moved.

`ARG TARGETOS`/`ARG TARGETARCH` are declared inside each stage **after**
`go mod download` and `COPY`. A build ARG joins the cache key of every later
RUN, so declaring it late keeps the architecture-independent layers (git,
module download, source copy) shared: BuildKit runs them ONCE for both targets
and forks only the final `go build`, visible in its own step labels as
`[linux/amd64 builder 7/7]` and `[linux/amd64->arm64 builder 7/7]`.

The CI cache configuration (`cache-from: type=gha`, `cache-to: mode=max`) was
deliberately NOT changed, so this change's effect is measurable on its own.
Adding a Go build-cache mount is a separate step that must first prove correct
invalidation across source, module graph, toolchain and target architecture.

### The defect this makes possible, and the wall against it

On the build platform, a `go build` that does not take GOARCH from the target
compiles for the **host**. The image still builds, the manifest still says
arm64, every amd64 check stays green — and the binary is amd64. It fails only
when an arm64 host executes it, and for the agent that host is the operator's:
`scripts/install.sh` extracts `/app/deploy/bin/culvert-maint` from the image and
checks only that it is executable (`[[ -x ]]`) before installing it as the
host-root agent.

The sharp case is `GOARCH=${TARGETARCH}` with no `ARG TARGETARCH` in the same
stage. The automatic platform ARGs exist in global scope but must be
re-declared per stage, so the expansion is EMPTY — and an empty GOARCH means
host. A grep for the assignment passes that defect.

`dockerfile_crossbuild_test.go` therefore models the Dockerfile rather than
matching text: it splits stages, tracks the ARGs in scope at each RUN, reads the
GOOS/GOARCH each `go build` actually receives, and requires them to come from
in-scope TARGETOS/TARGETARCH. It also requires every Go-compiling stage to be on
`$BUILDPLATFORM` (otherwise compilation is emulated again), keeps the final
stage OFF it, and fails when either expected build stops being visible. It
derives 11 defects from the REAL Dockerfile — each anchor must match exactly
once, so a stale mutation cannot silently test the unmodified file — and
requires every one to be rejected, plus a global-scope-ARG control and an
equivalent-spelling control. It was verified failing on both stages of the
pre-change Dockerfile.

### Evidence (local; see the PR for logs)

Existing PR checks cannot show this: the Deep PR gate builds an amd64 image
only, and the Fast gate's arm64 compile covers the proxy but not the bundled
agent. So real final images were built for both platforms and inspected.

* **Architecture.** Both binaries were extracted from each final image and read
  with `readelf`/`file`/`go version -m`. In the arm64 image, `/app/culvert` and
  `/app/deploy/bin/culvert-maint` are both `AArch64`, statically linked (no
  program interpreter, no dynamic section), `GOARCH=arm64`, `CGO_ENABLED=0`; the
  amd64 image carries `x86-64` equivalents.
* **Byte identity.** All four binaries (proxy + agent × amd64 + arm64) are
  **byte-identical** to the ones the pre-change, QEMU-emulated build produced
  (same sha256, same size). The change alters how the binaries are produced,
  not what ships.
* **Runtime.** The same built images (not rebuilt) were run for each platform
  with an isolated data volume: `/health` 200, `/ready` 200 reporting version
  `1.0.235`, Docker HEALTHCHECK `healthy`, and the bundled
  `culvert-maint --version` printing `v1.0.235` — the arm64 image under an
  `aarch64` userland as user `proxy`.
* **Single-platform builds.** Plain `docker build` (QA's path) and
  `docker compose -f docker-compose.yml -f docker-compose.ci.yml build proxy`
  (the smoke job's path, also with `--no-cache`) both build, produce host-arch
  static binaries, and the compose stack comes up `healthy`.

### Measurement

Same machine for every run (4 vCPU / 15 GB — the shape of a GitHub
`ubuntu-latest` runner), same source tree, same Go 1.27.1 toolchain, same
base-image digests, one BuildKit `docker-container` builder, multi-platform
`linux/amd64,linux/arm64`, pushed to a local registry. **Cold** = builder cache
pruned and `--no-cache`. **Warm** = cache primed by the cold run, then a
one-line source change in BOTH modules, so module layers are cached and both
compilers re-run (the shape of an ordinary main push).

Compiler-stage durations (BuildKit `DONE` times). Stages run concurrently, so
these are NOT additive:

| Stage | Baseline cold | Candidate cold | Baseline warm | Candidate warm |
|---|---|---|---|---|
| proxy `go build`, arm64 | 871.6s (QEMU) | **78.6s** (amd64→arm64) | 598.3s | **82.5s** |
| agent `go build`, arm64 | 500.2s (QEMU) | **32.9s** | 289.6s | **38.2s** |
| proxy `go build`, amd64 | 120.0s | 79.3s | 106.9s | 80.7s |
| agent `go build`, amd64 | 44.3s | 35.7s | 41.6s | 39.0s |
| arm64 `go mod download` | 56.8s (QEMU) | shared with amd64 (7.0s) | cached | cached |

The amd64 stages got faster only because they no longer share 4 cores with an
emulated compiler — amd64 compilation itself is unchanged.

Whole multi-platform build (wall-clock; a build runs on one runner, so its
runner-time equals its wall time):

| | Baseline | Candidate | Change |
|---|---|---|---|
| Cold | 938.6s (15.6 min) | 90.8s / 91.2s (n=2) | ~10x |
| Warm | 601.3s (10.0 min) | 85.3s / 85.7s (n=2) | ~7x |

Baseline is n=1 per cell (each baseline cold run costs ~16 minutes); the
effect is an order of magnitude larger than run-to-run variance.

**Scope of these numbers.** They are the image BUILD step on local hardware of
the same shape as a CI runner. They are not a claim about the `docker` job's
total duration or about main-push wall-clock: the job also logs in, pushes
through the GHA cache and signs, and its position on the release critical path
is not measured here. Like stage 2B, the real effect requires **post-merge
observation** of the `docker` job on main. A branch `workflow_dispatch` is not a
substitute: it pushes and signs a candidate image in the public registry.

**Validation environment, disclosed.** This sandbox's egress policy denies the
Alpine package CDN (`dl-cdn.alpinelinux.org`, 403) and re-terminates TLS. So
every build — baseline AND candidate — used a validation copy of the Dockerfile
that differs from the real one in exactly three `apk` lines, made non-fatal,
plus base images carrying the sandbox's CA. It was verified that
`diff(baseline, candidate)` of the two measured files equals the PR's diff
exactly. Consequences: no `git` in the builder (so `buildCommit` is empty in
BOTH), and the runtime stage's `apk` setup is near-instant here, where in CI it
runs under QEMU. Neither touches the compiler stages this change moves; CI
exercises the real `apk` lines.

### Behavior change: the legacy builder is no longer supported

`FROM --platform=$BUILDPLATFORM` requires BuildKit. The deprecated legacy
builder (`DOCKER_BUILDKIT=0`) never sets `$BUILDPLATFORM` and now stops at the
first FROM with `failed to parse platform : ""` — verified: the pre-change
Dockerfile builds under it, the new one does not. No default preserves it: the
legacy builder does not expose the host platform at all, so any hardcoded value
breaks the other architecture. Every supported path already uses BuildKit — it
is Docker's default since Engine 23.0, Compose v2 uses nothing else, every CI
path uses buildx, and `scripts/install.sh` installs current Docker + Compose v2
— and the Dockerfile now says so at the line the error points to. An owner who
still needs the legacy builder should revert this stage.

### Supply chain: what changes and what does not

`ci.yml` is not modified. Cosign signing, the SBOM attestation (scans the final
image, whose binaries are byte-identical), catalog digest binding
(`list_digest` == pushed digest), `promote-image`'s own-run digest check, the
`org.opencontainers.image.revision` binding and every publication barrier are
untouched. SLSA release subjects and `verify-reproducible` are built by the
`build-release-binaries` composite, not this Dockerfile.

One recorded, intended difference: the arm64 image's BuildKit **provenance**
now lists `golang@1.27-alpine?platform=linux/amd64` as a material (previously
`linux/arm64`), because that is the toolchain that compiled it. The runtime
`alpine` material stays `linux/arm64`. Nothing in the repository reads
provenance materials; an external policy that pins the toolchain material to the
image's platform would need updating.

### Next original-plan follow-up (done in stage 4, §12)

At the time of this stage, `test/e2e/maint-agent/Dockerfile.e2e` — used by the
maint-agent update, backup-upgrade, install-lifecycle and
appliance-catalog-update E2E workflows — had drifted from production: `golang:1.26-alpine` (production 1.27),
`alpine:3.22` (production 3.24), a build-time `go mod tidy` (the divergent-recipe
step production removed), and no `-trimpath`/`-buildvcs=false`. Stage 4
aligned it (§12).

### Rollback

Revert the commit. Both Go stages go back to the target platform, compilation
under QEMU resumes, and the regression wall is removed with it. Nothing else
depends on the change: the produced binaries are byte-identical, `ci.yml`, the
cache configuration and every release/publication gate are untouched. A revert
also restores legacy-builder support.

## 12. Stage 4 — E2E image dependency discipline and recipe parity (shipped)

`test/e2e/maint-agent/Dockerfile.e2e` is the proxy image four workflows use to
drive real installs, upgrades, backups and rollbacks: `install-lifecycle-e2e`
(three jobs), `maint-agent-update-e2e`, `maint-agent-backup-upgrade-e2e` and
`appliance-catalog-update-e2e`. It had drifted from production in two ways.

### 1. It repaired the module graph it was supposed to test

The build ran `go mod tidy` inside the image. A committed `go.mod`/`go.sum` that
could not build was silently fixed in the layer, and the E2E went green on a
module graph nobody committed. Reproduced locally against a real worktree:

| Committed-graph defect | Old recipe (`go mod tidy`) | New recipe |
|---|---|---|
| `go.sum` missing the hash of a compiled module (`goccy/go-yaml`) | tidy restores it, build **passes** | build **fails**: `missing go.sum entry for module providing package github.com/goccy/go-yaml` |
| `go.mod` missing a requirement | tidy restores it, build **passes** | build **fails**: `cannot find module providing package … import lookup disabled by -mod=readonly` |

The image now builds only from the committed graph:

* no `go mod tidy` (or any other module-graph mutator) at build time;
* `go build -mod=readonly` — already Go's default without a vendor directory,
  now explicit so a future `GOFLAGS` or vendor tree cannot change it silently;
* `go.mod` and `go.sum` are proven unchanged across **both** the download and
  the compile by `test/e2e/maint-agent/depfiles-guard.sh`, which prints a unified
  diff and the fix (`go mod tidy` in the repo, commit both files) on failure.

**The download check has to be in the SAME `RUN` as `go mod download`.** The
next instruction, `COPY . .`, overwrites both files with the committed copies,
so a download-induced change checked any later is already gone. A test
(`TestE2EImage_LateCheckIsConcealedByCopy`) demonstrates exactly that, and the
wall requires the ordering structurally. Tidiness itself stays enforced where it
belongs, in the Fast Gate's `go mod tidy -diff`, which this stage does not touch.

### 2. It had drifted from production's recipe

It used `golang:1.26-alpine` and `alpine:3.22` against production's
`golang:1.27-alpine` and `alpine:3.24`, and compiled without `-trimpath` and
`-buildvcs=false`. The builder now uses production's image and production's
compile: `$BUILDPLATFORM` with `GOOS/GOARCH` from in-stage `TARGETOS/TARGETARCH`
(§11), `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, `-ldflags="-s -w …"`,
and the runtime uses production's alpine. It prints `go version` so every CI log
records the compiler that built the image. The companion rollback image
`test/e2e/catalog-update/Dockerfile.badhealth` moved to the same alpine.

The root `go.mod` (`go 1.26.6`) and `cmd/culvert-maint/go.mod` (`go 1.25`) are
unchanged; a 1.27 toolchain satisfies both. The host-side agent toolchain is
unchanged too, including `scripts/install.sh`'s `CULVERT_GO_IMAGE` default of
`golang:1.25` for building the agent from source — recorded, deliberately out
of scope.

### Intentional differences from production — kept, and pinned

* **No GeoIP stage** (db-ip.com is often blocked on runners; irrelevant here).
* **`BUILD_VARIANT`** reaches the binary (`-X main.version=e2e-<v>`),
  `/app/VERSION` and a final `LABEL`, so v1 and v2 are genuinely different
  images with different registry digests — the agent compares REAL digests.
* **No `/app/deploy` bundle and no `maintbuilder` stage.** Without the bundled
  agent, `scripts/install.sh` takes its source/release fallback, which the
  installer-lifecycle job exists to exercise. Adding the bundle to make this
  image "look like production" would silently stop testing it.

### The wall: `e2e_image_recipe_test.go`

Every parity expectation is **derived from the production Dockerfile at test
time** — builder image, runtime image, builder platform, compile flags,
non-symbol `-ldflags`, `CGO_ENABLED`/`GOOS`/`GOARCH` — so the test holds no
third copy of the version list. A production bump that is not mirrored fails
the build; a deliberate bump needs no test edit. It also checks the dependency
discipline (no mutators, `-mod=readonly`, both guards in the same `RUN` as the
step they guard, guard before `COPY . .`), reuses §11's in-scope-`TARGETARCH`
checker, and pins the intentional differences. It derives 14 regressions from
the real files — image anchors taken from production, never literals — and
requires each to be rejected. It executes the REAL `depfiles-guard.sh` against
real `go.mod`/`go.sum` mutations. Against the pre-change files it reports every
problem this section lists.

### Reproducibility: what is and is not pinned

Matching tags do not make the image reproducible. Still mutable: the
`golang:1.27-alpine` and `alpine:3.24` tags (each resolves to whatever digest
is current), the runtime `apk upgrade`/`apk add` against the live Alpine
repositories, and the module proxy (bounded by `go.sum`, which now cannot
change during the build). CI logs record the digests and `go version` each run
actually resolved. Pinning base images by digest is a production-wide decision
and is not taken here. *(Superseded for the Go builder image by §20: it is now
pinned by digest. `alpine:3.24` and the runtime `apk` steps remain mutable.)*

### Measurement

Local, same machine, both recipes built as the workflows build them (plain
`docker build`, v1 with a pruned cache, then v2): old cold 52.9s / warm 46.1s;
new cold 53.4s / warm 38.7s. The compile step is 41.1s cold / 35.8s warm
against the old tidy+build step's 43.1s / 43.2s. This stage is about
correctness; it is roughly time-neutral. The sandbox blocks the Alpine package
CDN, so both local recipes had their `apk` lines made non-fatal and used base
images carrying the sandbox CA — that is NOT qualification. Qualification is
the six E2E jobs running the unchanged recipe on GitHub runners (see the PR).

### Rollback

Revert the commit. The E2E image returns to the old base images, build-time
`go mod tidy` and the previous flags; the four workflows are unchanged, so
nothing else needs to move.

## 13. Stage 5A — root-suite sharding pilot (evidence only)

> Superseded in operation by §14 (stage 5B): the pilot workflow is now
> `qa-race-shards.yml`, it runs on every QA execution, and the `verdict`/
> `compare` commands take the additional flags shown in §14's "Reproduce".
> This section is kept as the record of the 5A evidence.

The root package's race+coverage suite is ONE process inside `qa-logic`: ~6,300
top-level entries in ~25–33 minutes, the longest item on every main push. Stage
5A asks one question — can it run as several isolated processes **without
silently losing a test, a coverage block or a failure** — and answers it with a
working, opt-in pilot and measured evidence. Adopting it in a required gate is
stage 5B; nothing here changes what any gate requires.

### Shape

`cmd/rootshard` + `.github/workflows/qa-root-shard-pilot.yml` (reusable, no
trigger of its own), called from `qa-gate.yml` only when a manual dispatch sets
`root_shard_pilot: true` (default false):

| Job | What it does |
|---|---|
| `pilot-build` | `go test -c -race -cover .` **once**; inventory from the binary's own `-test.list .*` (source-regex counts are not authoritative: the root has 6,421 `func Test…` in source, many behind build tags such as `benchgate`, against 6,325 runnable Test/Fuzz/Example entries + 136 benchmarks in the default-tag CI binary); times an empty run (process start + TestMain + coverage write); partitions by measured duration |
| `pilot-shard` ×4 | runs its selections against THAT binary from the same checkout path; refuses another binary, commit, toolchain or working directory; first proves the binary's own `-test.list` selects exactly the planned entries; then runs with the reference's per-binary flags (`-test.paniconexit0 -test.gocoverdir -test.timeout=40m -test.count=1 -test.coverprofile`), test2json events streamed to evidence |
| `pilot-lane` | every package `go list ./...` returns EXCEPT the exact root import path, as whole packages, `-race -count=1 -timeout=40m -coverprofile -json` |
| `pilot-verdict` | `if: always()`; rejects failed/cancelled/missing shards, identity mismatches, inventory mismatches (every planned entry exactly one result; nothing unselected ran), unusable or incompatible profiles; merges all profiles by block; runs the UNCHANGED `coverage-floor.sh` |
| `qa-root-shard-pilot-compare` (in `qa-gate.yml`) | compares with the SAME run's unsharded `qa-logic` (no extra full-suite run): discovered vs executed inventory, pass/skip per entry, subtest inventory, package set, block universe, covered-block union, per-file coverage, and the floors verdict of both profiles |

### Why each choice

* **Build once, run the binary.** Compiling per shard would give four binaries
  whose equality is assumed, not checked; one binary with a sha256 in the
  manifest makes "every shard ran the same code" a verified fact.
* **Same checkout path, no `-trimpath`.** `pkgSourceDir()` uses
  `runtime.Caller`; tests read source, docs, frontend assets and fixtures and
  invoke Go. Each shard checks out the same commit at the path the binary was
  compiled in and has the same toolchain; the tool refuses otherwise.
* **Evidence outside the checkout.** Several tests walk the repository, so the
  binary and evidence live in `RUNNER_TEMP` — the shards test exactly the tree
  the reference tests.
* **Partition = longest-processing-time-first over measured durations**, total
  order (estimate desc, name asc; ties to the lowest shard), so the same inputs
  give the same plan. Estimates are floored at the 10 ms resolution of `go test
  -v` (most root tests print `0.00s`; zero weights piled 5,053 of 6,319 entries
  onto one shard in the first seeded plan) and a new test takes the MEAN
  measured cost (the median is 0). New tests therefore enter the partition
  automatically.
* **Selections are anchored, escaped and verified twice.**
  `^(?:QuoteMeta(a)|QuoteMeta(b)…)$` — the group keeps testing's splitter from
  seeing a top-level `|`/`/`; every chunk regex is evaluated against the whole
  inventory with the same regexp engine `testing` uses (it must select exactly
  its names, nothing else, no benchmark), an empty selection is refused
  (`-test.run ''` runs everything), and on the runner the binary's own
  `-test.list <regex>` must return exactly the planned names.
* **Argument size.** Linux caps one argv string at 128 KiB; the inventory is
  ~268 KB of names. Selections are chunked at 96 KiB (one process each); four
  shards need one chunk each today, and the tool handles more.
* **Merge by block.** Key = source path + block coordinates; statement counts
  must agree (else: different builds, refused); counters sum (atomic), a
  zero-covered block is counted once. Root profiles must share an identical
  block universe (same binary); the lane profile must contain no root block.
  Percentages are never averaged and duplicate root blocks never concatenated.
* **Coverage differences are reported, not fatal.** The block universe must be
  identical; covered-block differences are listed by location, and the floors
  decide pass/fail exactly as today — race/timing-dependent branches differ
  between any two runs.
* **Failures are never retried.** `fail-fast: false`, every shard runs to
  completion, evidence uploads `if: always()`.

### Reproduce

The pilot is opt-in and runs only on a manual dispatch of the QA gate from the
branch under test (PR/main behaviour, required job names and the aggregate's
`needs` are unchanged — pinned by `qa_root_shard_pilot_test.go`,
`qa_gate_scheduling_test.go` and `security_race_ownership_test.go`):

```bash
gh workflow run qa-gate.yml --ref <branch> -f root_shard_pilot=true
```

Locally, the same steps the jobs run (any writable directory outside the
checkout for `$OUT`):

```bash
C=$(git rev-parse HEAD); go build -o "$OUT/rootshard" ./cmd/rootshard
"$OUT/rootshard" build -out-dir "$OUT/build" -commit "$C"     # compile once, list, time an empty run
"$OUT/rootshard" plan -list "$OUT/build/list.txt" -timings .github/qa-root-shard-timings.json \
  -pkg "$(go list .)" -shards 4 -out "$OUT/build/plan.json"
for i in 0 1 2 3; do
  "$OUT/rootshard" run-shard -plan "$OUT/build/plan.json" -manifest "$OUT/build/manifest.json" \
    -binary "$OUT/build/root.test" -shard $i -out-dir "$OUT/shards/shard-$i" -commit "$C" -timeout 40m
done
"$OUT/rootshard" run-lane -out-dir "$OUT/lane" -commit "$C" -timeout 40m
"$OUT/rootshard" verdict -build-dir "$OUT/build" -shards-dir "$OUT/shards" -lane-dir "$OUT/lane" -out-dir "$OUT/verdict"
.github/scripts/coverage-floor.sh "$OUT/verdict/merged.cover.out"
# against an unsharded `go test -race -coverprofile=coverage.out -v ./... > logic.log` of the same commit:
"$OUT/rootshard" compare -ref-log logic.log -ref-profile coverage.out \
  -pilot-results "$OUT/verdict/results.json" -pilot-profile "$OUT/verdict/merged.cover.out" \
  -list "$OUT/build/list.txt" -pkg "$(go list .)" -out "$OUT/comparison.json"
```

`go test ./cmd/rootshard` runs the tool's own gates, including an end-to-end
test that builds a fixture module (TestMain, subtests, a skip, a Fuzz seed, an
Example, a benchmark, a helper that re-execs the test binary and `os.Exit`s,
a second package) and requires ZERO lost coverage blocks against a real
unsharded `go test -race -coverprofile -v ./...` of it, plus the failure paths:
a failing test, a crashing test (panic mid-chunk), a missing shard, a shard
from another binary, and an unusable profile — each must turn the verdict red
and name the cause.

### Measurements (GitHub-hosted `ubuntu-latest`, 4 vCPU, warm module cache)

Three dispatches on the branch; each run's reference is the SAME run's
unsharded `qa-logic`, so both sides share runner class, cache state and time
of day.

| | Run 1 `35786256715` | Run 2 `35789916458` | Run 3 `35793263705` |
|---|---|---|---|
| Plan | bootstrap (local timings, fallback-heavy) | local measured timings, 5 ms floor | **CI-measured timings** (run 2's reference) |
| Build job (compile+list+empty run) | — | 108 s (81 s) | 95 s (72 s) |
| Empty run = process start + TestMain + coverage write | — | 1.95 s | ≈2 s |
| Binary / artifact | — | 112 MB / 55 MB, ~4 s up, 2–4 s down | same |
| Shard test time (s) | 414 / 324 / 504 / 296 | 424 / 440 / 405 / 434 | **379 / 421 / 420 / 411** (plan 392 each) |
| Shard job (s) | — | 452 / 466 / 435 / 468 | 415 / 456 / 453 / 436 |
| Non-root lane job (s) | 719 | 468 | 668 |
| … of which `internal/mcp/execution` | 521 s | 311 s | 465 s |
| **Pilot critical path** (first queued → verdict) | 769 s | **614 s** | **723 s** |
| build+shards done / lane done | — | +583 s / +471 s | +578 s / +691 s |
| **Reference critical path** (`qa-logic` job) | 1987 s | 1710 s | 1929 s |
| Speed-up | 2.6× | 2.8× | 2.7× |
| Pilot runner time (build+4 shards+lane+verdict) | 42.2 min | 40.4 min | 42.5 min |
| Reference runner time (`qa-logic` + `qa-coverage`) | 33.1 min | 28.8 min | 32.7 min |
| Verdict | **red, correctly** (5 problems) | green | green |

Costs the spec asked to separate: queue delay 2–23 s per job (the lane and
build queue longest because they start with the rest of the gate); setup-go
10–19 s per job; artifact transfer ≤ 5 s per job; repeated TestMain ≈ 2 s per
shard (8 s total — negligible against ~410 s shards). Compilation is paid ONCE
(72–81 s) instead of once per shard. The extra runner time (~+10 min, +30–40%)
is five extra setups, one extra compile, and the lane re-running what
`qa-logic` already runs in the reference; it buys a ~2.7× shorter critical
path.

**The critical path is now bounded by two things, not by the root suite.**
Build + the slowest shard finish at ~+580 s in both measured runs; the lane
finishes anywhere from +471 s to +691 s, driven almost entirely by
`internal/mcp/execution` (311–521 s across three runs; 428–505 s in the
reference). In run 3 the lane, not the shards, was the critical path.

### Equivalence (run 3 — the fix-complete run)

| Check | Reference | Pilot |
|---|---|---|
| Root entries discovered (binary `-test.list`) | 6,325 | 6,325 |
| Root entries executed, each exactly once | 6,325 | 6,325 |
| Skipped (all environmental: `/data` not writable, opt-in CI-only gates, no root for a bind mount, interop env unset) | 51 | the same 51, each with its skip reason |
| Subtests | 3,819 | 3,819 (0 missing, 0 extra) |
| Packages | 112 | 112 |
| Block universe (root + all other packages) | 46,223 | 46,223 — identical |
| Covered blocks | 35,043 | 35,038 |
| Statement coverage | 78.8% (56,029/71,092) | 78.8% (56,021/71,092) |
| `coverage-floor.sh` | exit 0 | exit 0, byte-identical per-file table |

**Failure path, demonstrated for real (run 1).** Run 1 carried a deliberately
unmeasured timing seed that one of the pilot's own wall tests rejects. The
shard containing that test exited 1, its evidence still uploaded, the other
shards ran to completion, and the verdict listed the failure by name alongside
the other problems — nothing was retried or masked. The same run's lane
`-race` found a real data race in the tool itself (two writers on one
buffer), fixed in the next commit.

**Lost coverage — found, fixed, and the remainder explained.**

* *Found and fixed:* run 2 lost 14 blocks in `main.go`/`upstream_downgrade.go`.
  Those are reached by helper tests that re-exec the test binary and leave via
  `os.Exit`; the child's counters are written to `GOCOVERDIR` and merged by the
  parent. `go test` sets `GOCOVERDIR` in the environment AND passes
  `-test.gocoverdir`; the pilot passed only the flag, so every child's
  coverage was silently dropped. Now reproduced by the fixture's re-exec test
  (which fails without the fix) and gone in run 3.
* *Remaining (run 3): 14 blocks covered only by the reference, 9 only by the
  pilot*, all in the root package. 11 of the 14 recur in run 2 under a
  different plan, so they are NOT noise. They are **test-order coupling**:
  branches reached only when an EARLIER test in the same process left global
  state behind (a loaded root/cluster CA, a recorded CA-load failure or GeoIP
  load error, a populated request log, a once-resolved value). Proven for
  `ui_frontend_v2.go:110` (`ensureFrontendV2`'s cached return, a
  process-lifetime `atomic.Pointer` no test resets):
  `TestNewAdminUIServer_ReturnsConfiguredServer` alone → 0,
  `TestAdminUIServer_ShutdownReturnsBeforeDeadline` alone → 0, both in one
  process → 1. The unsharded reference covers it only because file order puts
  both in one process; the pilot's plan puts them on different shards. The 9
  gained blocks are the same mechanism in the other direction. No TEST is
  lost — each still runs once and passes — only an incidental path through
  shared state. Net effect 8 statements (0.01 pp), inside every floor.

### Recommendation for stage 5B

1. **Adopt 4 shards; do not go to 6.** The shards land within −3%/+8% of
   the plan (379–421 s against 392 s), and build + slowest shard already finish at ~580 s — below the
   lane in run 3. Six shards would cut ~140 s of shard time only while the
   lane is not the bound, at two more setups (~2 runner-minutes) per run.
2. **Split the lane, and put `internal/mcp/execution` on its own job.** It is
   the single biggest variance on the critical path (311–521 s); alone it
   bounds the pilot at roughly build-time + 470 s either way. With it split
   out, the expected critical path is max(build + shard, mcp/execution) ≈
   580 s, i.e. ~3× today.
3. **Refresh timings from CI, not by hand.** The compare job prints a fresh
   `qa-root-shard-timings.json` derived from the same run's reference;
   committing it periodically (or deriving it in the gate from the last main
   run) keeps the balance. New tests already enter automatically at the mean.
4. **Keep the equivalence check as the adoption gate**, not a one-off: the
   compare job (inventory, per-entry results, block universe) should stay red
   on any missing execution when 5B moves the race+coverage contract onto the
   shards; coverage differences stay reported, floors stay the judge.
5. **Cost.** Expect ~+30–40% runner-minutes for ~2.7× critical path. If that
   is too much, run the shards only where the critical path matters (the PR
   Fast Gate) and keep the single process on main.
6. **Test-order coupling is now visible**, which it never was in one process.
   The 11 recurring blocks are candidates for making those tests set up their
   own state; that is test hygiene for a separate change, not a blocker.

Rollback: delete the `root_shard_pilot` input and its two jobs from
`qa-gate.yml`, `qa-root-shard-pilot.yml`, `cmd/rootshard` and the timing file.
Nothing else depends on them.

## 14. Stage 5B — sharded race + coverage adopted in QA

Stage 5A showed the root suite can run as isolated processes without losing a
test. It left three gaps. 5B closes them, then moves QA's race + coverage
execution onto the shards. The Fast PR Gate is **not** migrated here; that is
the next reviewed step (§14.7).

### 14.1 What changed in QA

| Before (5A) | After (5B) |
|---|---|
| `qa-logic` = build + vet + the whole unsharded `go test -race -coverprofile ./...` (~25–33 min) | `qa-logic` = whole-module build + `go vet` only |
| `qa-coverage` needs `qa-logic`, reads its `qa-coverage` artifact | `qa-coverage` needs `qa-race`; `qa-race`'s verdict publishes the same `qa-coverage` artifact (same name, same `coverage.out`, same retention); the floors are unchanged |
| the pilot ran only on `root_shard_pilot: true` and never counted | `qa-race` (`qa-race-shards.yml`, 4 shards) runs on **every** QA execution and is in the aggregate's `needs` |
| — | `unsharded_audit: true` (manual dispatch, default false) also runs the pre-5B unsharded command and compares the two on the same SHA |

These stay the same:
- the aggregate check name (`✅ QA Gate — APPROVED`);
- the determinism lane (whole suite, shuffled, `-count=2`);
- bench, OS, compose, contracts and maintenance-agent;
- PR pass-through behaviour;
- the Security gate's use of QA's race run. `security_race_ownership_test.go` now pins `qa-race` as the only main-push race owner.

### 14.2 Coverage equivalence: losses now fail

In 5A, `compare` *reported* a block the reference covered and the shards did
not, but did not fail on it. Unchanged rounded coverage and passing floors do
not establish equivalence, so 5B makes such a loss **fail** the comparison.
There is one way out: an exact entry in
`.github/qa-root-shard-coverage-exceptions.json`. Each entry must have:
- one block key;
- a reason and evidence;
- a block that is still in the universe (stale entries fail, and so do duplicates).

The file is **pinned empty** by `qa_race_shards_test.go`. A future exception
therefore needs a reviewed test change, not only a JSON edit. Blocks gained by
the shards are still reported and never fail.

Each block that runs 2–4 of 5A lost (40 blocks across the three runs) was
investigated individually rather than blamed on the single `ui_frontend_v2`
reproducer:

| Group | Blocks | Cause | Resolution |
|---|---|---|---|
| `main.go`, `upstream_downgrade.go` | 14 | Re-exec'd child coverage dropped (no `GOCOVERDIR` in env) | Fixed in 5A. The fixture's re-exec test fails without it |
| CA / security / TLS / frontend state (`ui_frontend_v2.go`, root and cluster CA, GeoIP load error, rate-limit restore, server TLS pool) | see `coverage_isolation_security_test.go` | Global state left behind by an earlier test in the same process | Isolated `TestCovIsoSec_*` fixtures that set up their own state |
| Policy / config / store (stale-version and in-lock 409s, log ring, import arms, top-hosts raced insert, catalog comparator arg order, `WaitOp` cancel, crash collector) | 27 (25 + the `connLimiter.Enable` import arm found by qualification round 1 + the `otlpRuleMetrics` rule loop found by round 3, §14.7) | Earlier test state, or a race / map-order interleaving | `TestCovIsoPolicy_*` (`coverage_isolation_policy_test.go`). Interleavings are forced deterministically, e.g. the existing `policyWriteStateDecisionHook` seam, a lock held while a named frame is parked, or a context cancelled inside the round trip, rather than hoped for |
| Non-root packages (`internal/authcost`, `mcp/catalog`, `mcp/upstreamclient`, `policylearn`, `saasfeed`, `scanner`, `urlcat`) | see files | Timing and ordering of the package's own tests, or Go's randomized map iteration (`scanner` `BypassHosts`) | `TestIsolation_*` in each package's `coverage_isolation_test.go` |

Every fixture was verified by running it **alone** (its own covered binary,
`-test.run '^Name$'`, its own profile) with a non-zero hit count on its
block(s), and under `-race` and `-shuffle=on`. No production code changed.

### 14.3 The verdict is complete on its own

An ordinary QA run has no unsharded reference; not having one is the point of
sharding. So every expectation the verdict judges against now comes from a
source other than the evidence being judged:

| Evidence | Expected from | Refused when |
|---|---|---|
| Root tests | The binary's own `-test.list` (5A) | An entry is missing, reported twice, or unplanned |
| Root blocks | `build` keeps the binary's **empty-run profile** (`root-universe.cover.out`, sha256 in the manifest) | The merged root profile's block set or statement counts differ from it, e.g. every shard truncated identically |
| Lane packages | `go list ./...` minus the root (5A) | The set differs, or the evidence comes from another commit, toolchain or OS/arch |
| Lane tests | `inventory.go`: a source enumerator that mirrors cmd/go's rules (`isTest`/`isTestFunc`, TestMain excluded, examples only with an `Output:` comment, test and x_test files under the lane's `-race` build config). On every verdict it is **cross-checked against the root binary's `-test.list`**; if it cannot reproduce that list exactly, its lane expectations are rejected | A declared test has no result (never ran, or its events were lost); a result has no declaration (foreign); an entry reports twice; any failure |
| Lane blocks | The `race-universe` job runs the lane's exact command with `-run=^$` (a different job from the lane) | The lane profile's block set differs, it is empty, or it is truncated |

Legitimate edge packages are **listed** in the verdict rather than tolerated:
- `packagesWithoutTests`;
- `packagesWithoutStatements`;
- `emptyPackages` (neither).

`go test -cover` reports an empty package as *skipped*. That skip is accepted
for exactly those packages and for no other.

Retained from 5A:
- exact root partitioning;
- Test/Example/Fuzz coverage;
- child-process coverage via `GOCOVERDIR`;
- zero-covered blocks counted once;
- identity checks;
- a failing, cancelled or missing producer fails the verdict. The job also has an explicit "every producer succeeded" step.

The negative tests in `cmd/rootshard/completeness_test.go` each cause a real
verdict to fail **with no reference run present**:
- a lane profile with no blocks, or truncated;
- lost events for one test;
- an event stream cut mid-line;
- a ghost entry;
- a missing universe;
- lane evidence passed off as the universe;
- a universe from another commit;
- every root profile truncated identically;
- a test added to the source after the build;
- a replaced root universe.

### 14.4 Determinism failure: `TestBenchGate_IPFilterBulkLoadIsLinear` (8.28× vs 8×)

This was **measurement instability, not a regression**, and the fix was kept
separately reviewable as PR #1472 (merged; this branch carries it via main). It was diagnosed by measurement, not by
replaying a seed, and the numbers are in that PR:
- **Idle:** median 4.25×, 0/60 runs over 8×.
- **Under CPU contention:** median 4.44×, 16/60 over 8×, worst 13.66×. A GC cycle triggered by the preceding allocation-heavy phase lands inside one of the two timed windows.
- **With a `runtime.GC()` settle before each timed window** (what `testing.B` does): worst 4.98× under the same load, 0/60. The sibling rate-limit-exempt gate goes from 7/30 failures (worst 11.84×) to 0/30.

The negative control still catches the defect it was written for: reintroducing a per-entry publish in `AddAll` gives 18×. The threshold, inputs and retry policy are unchanged. Enlarging the inputs was measured and rejected, because it moved the idle median to 6.3×.

### 14.5 Operating model

- **New tests and packages enter automatically.**
  - Root entries come from the compiled binary's `-test.list`.
  - Lane packages come from `go list ./...`.
  - Lane tests come from the source enumerator, which is itself verified against the binary.
  - Block sets come from the build.
  - No list is maintained by hand. A new root test with no timing is placed at the mean measured cost.
- **Timing data only balances.** `.github/qa-root-shard-timings.json` decides which shard runs an entry, never whether it runs.
  - Refresh it from an audit run: the audit-compare job prints a timings file derived from the same run's unsharded reference. Commit it as-is.
  - A stale file costs balance (a longer slowest shard), never correctness.
- **Ownership of comparison failures.**
  - A red verdict on an ordinary run is owned by the author of the change that turned it red. It names the missing test, block or producer. Read the producer job first.
  - A red audit comparison is owned by the author of the coupled test or code. Pin the block with an isolated test. An exception requires a reviewed change to the pinned-empty exceptions file and its wall test.
  - "Flake" is not an accepted classification, per the repo's CI rules.
- **Reverting without weakening checks.** Revert the 5B commit.
  - `qa-logic` gets its whole-suite race + coverage run back.
  - `qa-coverage` reads the same artifact name from it.
  - The walls revert with it.
  - Do **not** revert by dropping `qa-race` from the aggregate's `needs`, or by pointing `qa-coverage` at a partial profile. Either would leave QA with no race run or incomplete coverage evidence.

### 14.6 Reproduce

```bash
C=$(git rev-parse HEAD); go build -o "$OUT/rootshard" ./cmd/rootshard
"$OUT/rootshard" build -out-dir "$OUT/build" -commit "$C"
"$OUT/rootshard" plan -list "$OUT/build/list.txt" -timings .github/qa-root-shard-timings.json \
  -pkg "$(go list .)" -shards 4 -out "$OUT/build/plan.json"
for i in 0 1 2 3; do
  "$OUT/rootshard" run-shard -plan "$OUT/build/plan.json" -manifest "$OUT/build/manifest.json" \
    -binary "$OUT/build/root.test" -shard $i -out-dir "$OUT/shards/shard-$i" -commit "$C" -timeout 40m
done
"$OUT/rootshard" run-lane -out-dir "$OUT/lane" -commit "$C" -timeout 40m
"$OUT/rootshard" universe -out-dir "$OUT/universe" -commit "$C" -timeout 40m
"$OUT/rootshard" verdict -build-dir "$OUT/build" -shards-dir "$OUT/shards" -lane-dir "$OUT/lane" \
  -universe-dir "$OUT/universe" -commit "$C" -out-dir "$OUT/verdict"
.github/scripts/coverage-floor.sh "$OUT/verdict/merged.cover.out"
# audit mode, against `go test -race -count=1 -timeout=40m -coverprofile=coverage.out -v ./... > logic.log`:
"$OUT/rootshard" compare -ref-log logic.log -ref-profile coverage.out \
  -pilot-results "$OUT/verdict/results.json" -pilot-profile "$OUT/verdict/merged.cover.out" \
  -list "$OUT/build/list.txt" -pkg "$(go list .)" \
  -coverage-exceptions .github/qa-root-shard-coverage-exceptions.json -out "$OUT/comparison.json"
```

In CI: `gh workflow run qa-gate.yml --ref <branch> -f unsharded_audit=true`.

### 14.7 Qualification (actual CI evidence)

Every number below comes from a GitHub-hosted `ubuntu-latest` run. The before
figures are the two most recent main-push QA runs under the pre-5B layout.

**Rounds.**

| Round | Run | Commit | Mode | Outcome |
|---|---|---|---|---|
| 1 | `35834009198` | `21bfd7d` | audit (sharded + unsharded, same commit) | Inventory identical; **1** reference-only covered block, so the comparison failed, as designed. Pinned by `TestCovIsoPolicy_ImportEnablesConnLimit` |
| 2 | `35837869936` | `59a555e` | ordinary (no reference) | Race path fully green. The determinism lane failed on `internal/yara` `TestRegexRunner_ConcurrentScans` (see below) |
| 3 | `35839915521` | `d78d942` | audit | Inventory identical (6,361). **2 lost, 2 gained**, all new. Lost: `internal/scanner` `BypassHosts` sort swap (map-order coin flip) and `otlpRuleMetrics`' loop (needed an earlier test's registered rule). Pinned by `TestIsolation_BypassHostsSortsAnUnorderedMap` and `TestCovIsoPolicy_OTLPRuleMetricsReportsRegisteredRules`. Gained: two empty-state branches |
| 4 | `35844201068` | `76f8cb5` | audit | Inventory identical (6,362 / 3,847 / 112 / 50). Round 3's blocks are gone. **2 lost, 1 gained**, all new. Both lost blocks are in `internal/policylearn`, i.e. in the **lane, which runs the reference's exact command**: the captured-window admission path, reached only when one of 200 racing goroutines beats a `StopSession`. Pinned by `TestIsolation_CapturedCurrentWindowIsAdmitted`. Gained: `AdminSettingsOverriddenSurfaces`' non-nil branch |
| 5 | `35846673968` | `b0078ec` | audit | Inventory identical (6,362 / 3,847 / 112 / 50); covered blocks equal (35,234 each). Round 4's blocks are gone. **1 lost, 1 gained**. Lost: `internal/mcp/catalog` `DisableServer`'s skip `continue`, again in the lane, reached only when `TestConcurrentIngestAndDisable`'s two goroutines line up two disables back to back. Pinned by `TestIsolation_DisableServerSkipsOtherAndAlreadyDisabled`. Gained: the same `AdminSettingsOverriddenSurfaces` branch as round 4 |
| 6 | `35849484523` | `12e3b9c` | audit | **Comparison passed.** Inventory identical (6,362 / 3,847 / 112 / 50). **0 lost, 1 gained**: the shards cover 35,235 blocks, a superset of the reference's 35,234 (the gain is round 4-5's `AdminSettingsOverriddenSurfaces` branch). Floors exit 0 on both. The run's only red job was `QA · Determinism` on `TestShadowExitC7_LatencyBudget` (shadow/observe p99 7.20x vs a 5.0x ceiling), the timing test under separate investigation, which this change does not touch |

**Inventory completeness.** Round 1 compares the sharded run with the reference. Round 2 is the verdict alone, with no reference.

| | Unsharded reference (r1) | Sharded (r1) | Sharded verdict alone (r2) |
|---|---|---|---|
| Root entries discovered / executed, each exactly once | 6,360 / 6,360 | 6,360 / 6,360 | 6,361 (+1 fixture) |
| Skips | 50 | the same 50 | — |
| Subtests | 3,847 | 3,847 (0 missing, 0 extra) | — |
| Packages | 112 | 112 | 111 lane + root |
| Lane top-level entries | — | — | 3,045 reported / 3,045 source-declared |
| Source enumerator vs binary `-test.list` | — | agrees | agrees |
| Block universe (root / lane) | 46,447 | 46,447 | 25,137 / 21,310, each matched exactly |
| Covered blocks | 35,233 | 35,232 (1 lost, 0 gained) | 35,233 |
| Statement coverage / floors | 78.8%, exit 0 | 78.8%, exit 0 | 78.8%, exit 0 |

**Coverage differences, stage by stage.**

| Stage | Reference-only blocks | Sharded-only blocks |
|---|---|---|
| 5A run 3 | 14 | 9 |
| 5B round 1 | 1 | 0 |
| 5B round 3 | 2 | 2 |
| 5B round 4 | 2 | 1 |
| 5B round 5 | 1 | 1 |
| 5B round 6 | **0** | 1 |

Every block a round lost is pinned, and none recurs in a later round. Round 6, on the final code (`12e3b9c`), is the first with no loss at all. No exception was needed, and the exceptions file stays empty.

**What the rounds show about the residue.** Each audit round has found one or
two NEW reference-only blocks, never a repeat. Round 4's two and round 5's one are in
non-root packages, which the lane runs with the reference's exact command, so sharding
cannot have caused them. They are paths that the suite reaches only on some
schedules or map orders, whether sharded or not; two unsharded runs of the
same commit would differ the same way. That is why a loss fails the audit
instead of being tolerated: each audit samples that tail, and each finding
becomes a deterministic fixture, so the tail only shrinks. A run the reference
happens to win does not mean the shards lost a test. The inventory is
identical in every round, and the verdict's completeness checks do not depend
on it.

**Negative tests for incomplete evidence.** These are `cmd/rootshard`'s
`completeness_test.go` cases. They ran in CI as part of the lane (the
`cmd/rootshard` package passed in both rounds) and in the shuffled
determinism lane. Each case produces a real verdict that fails with no
reference run present:
- a lane profile with no blocks, or truncated;
- one test's events lost, or the event stream cut mid-line;
- a ghost entry;
- a missing universe, or lane evidence passed off as the universe;
- a universe from another commit;
- every root profile truncated identically;
- a test added to the source after the build;
- a replaced root universe.

A failed or cancelled producer is refused twice: the verdict marks its
evidence as missing, and the "every producer succeeded" step checks each
`needs.*.result`. 5A run 1 exercised the red path on the real pipeline.

**Wall-clock and runner time.**

| | Before 5B: main push `35829097344` | Before 5B: main push `35782882080` | 5B ordinary, round 2 |
|---|---|---|---|
| QA wall-clock (first job queued to aggregate) | 33.8 min | 27.4 min | **14.8 min** |
| Longest job | race job, 1,986 s | race job, 1,602 s | determinism, 877 s (unchanged job) |
| Race + coverage evidence published (coverage floor done) | +2,016 s | +1,630 s | **+827 s** |
| Runner-minutes (sum of job durations) | 54.7 | 50.3 | **73.0** |

What the round-2 figures show:
- **Measured:**
  - The QA wall-clock fell by 12.6–19.0 min (2.3×) against the two baselines.
  - Runner time rose by about 18–23 minutes (about 35%).
  - The critical path is now the pre-existing shuffled determinism lane (877 s).
  - Next on the critical path: the verdict path (827 s), bounded by the non-root lane (727.7 s of tests, of which `internal/mcp/execution` alone takes 523 s).
  - The four root shards ran 363–477 s of tests against an estimate of 454.5 s each.
- **Estimate, not measured:** splitting `internal/mcp/execution` out of the lane would take about 200 s off the verdict path. It would not shorten QA until determinism is also faster. It is deliberately not done here.
- **Not claimed:** no full-CI speed-up. Only the QA gate changed, and the Fast PR Gate still runs its own unsharded race suite.

**The one red job in round 2 is outside this change.**
- `QA · Determinism` failed on `internal/yara` `TestRegexRunner_ConcurrentScans` (`inflight delta = -1 after all concurrent scans finished`, seed `1790152692675770089`).
- That package is untouched by this branch, and its tests run in their own process.
- The failure is the same timing/ordering class that is being investigated separately. It is recorded here, not fixed.

### 14.8 Remaining work

1. **Fast PR Gate migration.** Done in stage 5C (§15).
2. **`internal/mcp/execution` split.** Unmeasured, and optional. It becomes worthwhile only once the verdict path, not determinism, bounds QA.
3. **Timing refresh cadence.** Replace `.github/qa-root-shard-timings.json` with the file an audit run prints (§14.5) whenever the slowest shard drifts well above the estimate. In round 2 the shards landed at 0.80–1.05× their estimates.
4. **The determinism failures** listed above belong to the separate flaky-test investigation, not to this stage.

## 15. Stage 5C — the Fast PR Gate on the shared sharded engine

Stage 5B made the four-shard race + coverage execution authoritative in QA.
The Fast PR Gate still ran the single-process
`go test -race -count=1 -timeout=40m -coverprofile=coverage.out ./...`, and that
one job was the whole critical path of every code PR (§15.4 baseline:
1,610–2,018 s of a 1,660–2,073 s aggregate). Stage 5C moves Fast onto the SAME
engine. There is still exactly one implementation.

### 15.1 What changed

| | Before 5C (`test-race`, one job) | After 5C |
|---|---|---|
| Race + coverage | one `go test -race ./...` process | `test-race` **calls** `qa-race-shards.yml` (4 root shards + lane + universe + verdict) |
| Coverage floors | a step in the same job | `coverage-floors` job on the verdict's merged profile |
| `fast-gate-coverage` | uploaded `if: always()` by the race job | uploaded by the verdict, only after it proved the evidence complete (same name, `coverage.out`, 30-day retention) |
| Runner hardening | harden-runner (egress `audit`) on the race job | the same step first in **every** engine job, the floors job and the audit jobs |
| Mount-point regression | `sudo go test -run TestRestoreCommit_DataDirIsMountPoint_FailsInsteadOfCommitting .` | `race-privileged`: the SAME prebuilt binary as root; must print PASS (a SKIP fails) |
| Aggregate | skipped = pass for every need | + the race path (`test-race`, `coverage-floors`) must be exactly `success` when the diff classified as code |
| Unsharded run | every code PR | dispatch-only audit (`unsharded_audit: true`) |

Unchanged: the classifier (and so the docs-only skips), the required check name
`✅ Fast PR Gate — APPROVED`, hygiene, lint, benchgate, govulncheck + gosec,
gitleaks, the agent/MCP/frontend jobs, the advisory traffic smoke, the
concurrency group (a new push cancels the superseded run), and the
`pull_request` trigger with read-only permissions and no secrets.

**The engine's caller-specific inputs.** Every default reproduces the QA gate,
which still passes only `shards: 4` (pinned by
`TestQARaceShards_QAKeepsEveryEngineDefault`):

| Input | QA (default) | Fast |
|---|---|---|
| `coverage-artifact` | `qa-coverage` | `fast-gate-coverage` |
| `harden-runner` | `false` | `true` |
| `privileged-test` | *(none: `race-privileged` skipped, and the verdict requires `skipped`)* | `TestRestoreCommit_DataDirIsMountPoint_FailsInsteadOfCommitting` (the verdict requires `success`) |
| `fault` | `none` | forwarded from `workflow_dispatch` (qualification only) |

The engine's evidence artifacts keep their `qa-race-` names in a Fast run: the
prefix names the engine, and artifact names are scoped to the run.

### 15.2 Identity and permissions

- **One checkout.** Every engine job checks out the caller's `$GITHUB_SHA` —
  for a pull request, the PR merge commit — and the build manifest records it.
  The shards, the privileged job and the verdict refuse a binary from another
  commit.
- **No foreign evidence.** Every download is scoped to the current run: none
  passes `run-id` or a token (`TestFastGateRace_CoverageFloorsOnThisRunsMergedProfile`).
  Timing data only balances the shards and never decides inclusion (§14.5).
- **Fork-safe.** The engine asks for `contents: read` only, no secrets are
  passed, and the trigger stays `pull_request`: no `pull_request_target`, no
  `workflow_run`.

### 15.3 Why the aggregate changed

`needs-verdict` treats `skipped` as passing so a docs-only PR can satisfy the
required check. That is right for a job the classifier switched off, and wrong
for the race path when the classifier said *code*: a race path skipped for any
other reason would read as green. `require-success` is therefore computed:

```
format('changes{0}{1}',
  needs.changes.outputs.code == 'true' && ',test-race,coverage-floors' || '',
  inputs.unsharded_audit && ',race-unsharded-audit,race-unsharded-audit-compare' || '')
```

`test-race` is the whole reusable call, so it is `success` only when every
engine job succeeded — including the verdict, which judges each producer's
result itself. A qualification dispatch (`fault` set) fails the aggregate in a
final step, after the verdict has been computed and logged.

### 15.4 Operating instructions

- **A red `test-race` on a PR.**
  - Open `Race · verdict + coverage evidence` first. It names the missing test,
    block, package or producer.
  - Then open the producer it names.
- **A red `Race · privileged test (root)`.**
  - The mount-point regression failed, skipped or did not print PASS as root.
  - A SKIP here means the runner lost `sudo` or bind-mount capability. That is
    an infrastructure change, not a test to skip.
- **A red `coverage-floors`.**
  - Same script, same floors as before 5C, applied to the complete merged
    profile.
- **Qualification on demand.**
  - `gh workflow run pr-fast-gate.yml --ref <branch> -f unsharded_audit=true`
    runs the same-SHA comparison. The comparison is the QA audit's command, pinned
    by `TestFastGateRace_AuditMatchesTheQAAudit`.
  - `-f fault=<value>` exercises one failure path.
  - Both are dispatch-only. A pull request cannot set either.
- **Timings, new tests, new packages.** As in §14.5; the Fast gate reads the same
  `.github/qa-root-shard-timings.json`.

### 15.5 Rollback

Revert the 5C commit(s).

- `test-race` becomes the single hardened job again, with the floors and the
  privileged step inside it.
- The engine loses its four inputs, and QA is untouched because it only ever
  used the defaults.
- The walls revert with it.

Do **not** roll back by removing `test-race` or `coverage-floors` from the
aggregate's `needs`, or by weakening `require-success`. Either leaves a PR
approvable with no race run.

### 15.6 Qualification (actual CI evidence)

Every run is a GitHub-hosted `ubuntu-latest` run on commit `b0a20d9` (PR #1475).
Fault runs are `workflow_dispatch` runs of `pr-fast-gate.yml` with the `fault`
input; all dispatches share one concurrency group, so they ran one at a time.

| Case | Run | Observed |
|---|---|---|
| Code-changing PR, real `pull_request` event, PR merge commit | [35859739941](https://github.com/KidCarmi/Culvert/actions/runs/35859739941) | All 21 jobs green: 4 shards, lane, universe, privileged, verdict, `coverage-floors`, aggregate |
| Privileged mount-point regression | same run; also [35859947671](https://github.com/KidCarmi/Culvert/actions/runs/35859947671) | `sudo env TEST_SEED=… root.test -test.run ^TestRestoreCommit_DataDirIsMountPoint_FailsInsteadOfCommitting$` on this run's prebuilt binary: `--- PASS … (0.03s)`, then "executed as root and passed" |
| Docs-only classification (`fault=docs-only`, a docs-only file list through the real classifier) | [35859812047](https://github.com/KidCarmi/Culvert/actions/runs/35859812047) | `code=false`; `test-race`, `coverage-floors` and every other code job skipped; gitleaks ran; `needs-verdict` **passed**; "Qualification runs never approve" then refused, by design |
| Classifier failure (`fault=classifier-fails`) | [35859745755](https://github.com/KidCarmi/Culvert/actions/runs/35859745755) | Everything downstream skipped; aggregate: `required job 'changes' result=failure — cannot trust the gate` |
| Cancellation (run superseded by a newer dispatch) | [35859947671](https://github.com/KidCarmi/Culvert/actions/runs/35859947671) | Run `cancelled`; shards and lane cancelled; the verdict still ran and **failed**; aggregate **failed** — no green check left behind |
| Missing shard evidence (`fault=shard-evidence-missing`) | [35860261722](https://github.com/KidCarmi/Culvert/actions/runs/35860261722) | Every producer `success`; the verdict alone refused: `shard 0: no usable evidence … failed, cancelled or never uploaded`; floors skipped; aggregate failed |
| Truncated shard profile (`fault=shard-profile-truncated`) | [35861640418](https://github.com/KidCarmi/Culvert/actions/runs/35861640418) | Shard 0's job `success`; the verdict refused: three shards' block universes differ from shard 0's (`admin_settings.go:286.59,288.3` missing) and the merged root coverage is incomplete against the build's expected block set; floors skipped; aggregate failed |
| QA unchanged by the parameterized engine | [35859748488](https://github.com/KidCarmi/Culvert/actions/runs/35859748488) | QA green; `race-privileged` skipped and the verdict required exactly that (`race-privileged=skipped (want skipped)`); `qa-coverage` published (46,447 blocks) and consumed by `QA · Gate-critical coverage floor`; no harden step |

**An unrelated failure the truncated-profile run also exposed.** In
35861640418, shard 3, which the fault never touched, failed
`TestReportCatFeedDBUnavailable_DoesNotClaimRecovery` with a data race:

- `TestLoadCommunityFeedDB_CorruptStoreSelfHealsAndKeepsServing` starts the
  category-feed syncer with `t.Context()`.
- `feedsync.Syncer.Start` gives callers no way to wait for its goroutine, so a
  sync round still running after the test ends logs through the package
  `logger`.
- A later test's `captureLogger` is swapping that same variable at the time.

The failure depends on order and timing, and it is independent of sharding.
It belongs to the flaky-test investigation and is recorded here only as evidence.

**Not run before #1475 merged**, and still open:

- the `producer-fails` fault;
- the `coverage-floor-fails` fault;
- the same-SHA `unsharded_audit` comparison.

The mechanisms these cover are the same verdict producer check that the
cancellation and missing-evidence runs exercised, and the unchanged floor
script. The same-SHA comparison is carried out on the stage-6A branch; see §16.

### 15.7 Measurements

Before is the eight most recent green code-PR Fast runs before 5C. After is
every green code-PR Fast run observed since 5C merged. These are observed
values, not a completion target.

| | Before (8 runs) | After (2 runs) |
|---|---|---|
| Fast aggregate, run start → aggregate done | 1,660–2,073 s (27.7–34.6 min) | 711 s and 732 s (11.9, 12.2 min) |
| Race path, run start → floors done | 1,651–2,062 s | 703 s and 721 s |
| Slowest single job | the race job, 1,610–2,018 s | a root shard, 471 s and 486 s |
| Queue time per job | median 3 s, max 3–39 s | median 3 s, max 4–7 s |
| Runner-minutes | 47.5–51.0 | 67.6 and 67.0 |

Runner-minutes are **not** like for like. Both "after" runs changed workflow
files, so the frontend and MCP jobs ran as well (about 5.7 min in 35859739941).
Without them the cost is about 62 runner-minutes. Sharding therefore spends
roughly 11–14 extra runner-minutes per code PR to save 16–22 minutes of wait.
The critical path is now build (≈138 s) → slowest shard (≈470 s) → verdict
(≈44 s) → floors (≈27 s).

## 16. Stage 6A — restore-archive fixtures: small by default, production size where it belongs

### 16.1 The finding

`restore_decompression_bomb_test.go` guarded `readTarball`'s two
decompression-bomb bounds (256 MiB per entry, 512 MiB in aggregate, `restore.go`)
with two very expensive fixtures:

| Test (pre-6A) | Fixture | Committed CI timing |
|---|---|---|
| `TestReadTarball_RejectsOversizedEntry` | one 300 MiB entry | 29.01 s |
| `TestReadTarball_RejectsOversizedAggregate` | four 200 MiB entries (800 MiB) | 81.56 s — the largest entry in `.github/qa-root-shard-timings.json` |

Both accepted **any** error as a pass: a malformed archive, a truncated body or
an unrelated guard would have satisfied them just as well as the bound.

**Where the time went.** Same machine, same toolchain (go1.26.6, 4 vCPU),
instrumented separately for fixture generation and parsing:

| | Fixture, `-race` | Parse, `-race` | Fixture, no race | Parse, no race |
|---|---|---|---|---|
| per-entry (300 MiB) | 26.83 s | 0.00 s (refused on the header) | 0.70 s | 0.00 s |
| aggregate (4 × 200 MiB) | 71.34 s | 28.59 s (reads 600 MiB before the 4th header) | 1.88 s | 1.74 s |

The files on disk are 0.3 MB and 0.8 MB. The cost is producing and gzipping
hundreds of MiB of zeros under the race detector: the fixture's `zeroReader`
zero-filled byte by byte, and every byte was instrumented.

### 16.2 The change

- **A minimal seam, no new configuration.** `readTarball(path, pass)` now calls
  `readTarballLimited(path, pass, tarballLimits{entry: maxRestoreEntryBytes, total: maxRestoreTotalBytes})`.
  - The limits are built from the unchanged constants on every call. There is
    no mutable global and no flag, env var or setting.
  - The refusal is a typed `*tarballLimitError` whose text is byte-identical to
    the previous messages.
  - The parsing loop and the order of the checks are unchanged: both bounds are
    checked on the header, before `io.ReadAll` touches the body.
- **The same parser, kilobyte fixtures** (4 KiB per entry, 8 KiB aggregate):
  - a valid archive, with its bodies and order;
  - per-entry below, exactly at and above the limit;
  - aggregate below, exactly at and above the limit;
  - aggregate overflow with every entry below its own cap;
  - both refusals happen **before the body is read**: each fixture ends right
    after the offending header, so a parser that read the body would report
    `io.ErrUnexpectedEOF`. A control case proves that it does.
- **Only the intended failure passes.** Each limit test requires
  `*tarballLimitError` with the right scope, entry name, declared figure and
  limit. A separate test proves a non-gzip file, a malformed tar, a
  namespace-guard failure and a truncated body are **not** limit refusals.
- **The production bounds, still proved:**
  - `TestReadTarball_ProductionLimitsAreFixed` checks the constants: 256 MiB,
    512 MiB, and a 2× ratio.
  - `TestReadTarball_ProductionEntryBoundRejectsOnTheHeader` goes through
    `readTarball` at production size (256 MiB + 1, 300 MiB and 1 TiB) for
    nothing: the refusal needs a header, never a body. It runs in the ordinary
    suite on every Fast and QA run.
  - `TestReadTarball_ProductionAggregateBound_Integration` also goes through
    `readTarball` with the production constants. A 256 MiB entry (exactly at the
    cap) is accepted and read, a 1-byte entry follows, and a third header
    declaring 256 MiB takes the total to 512 MiB + 1 and is refused before its
    unwritten body is read. This is the smallest production-size aggregate case
    that exists: every earlier entry must be read in full, and each is capped at
    256 MiB. It costs 1.40 s without race and 43.40 s under race, so it runs in
    **`QA · On-disk contract` (qa-gate.yml), without `-race`**, with
    `CULVERT_RESTORE_PRODUCTION_SIZE=1`. The step fails unless the log carries
    the test's PASS line. That job is in the QA aggregate's `needs`, and
    `qa-gate.yml` is a mandatory row of `.github/release-evidence.txt`, so a
    failure refuses the QA gate and release promotion.
    `restore_limits_lane_test.go` pins every link of that chain. The ordinary
    suite skips the test with a message naming where it runs.

### 16.3 Mutation proof

Each mutation below was applied to `restore.go` and the package's
`TestReadTarball*` tests re-run with `CULVERT_RESTORE_PRODUCTION_SIZE=1`. Every
mutation failed at least one test:

| Mutation | Failing tests |
|---|---|
| per-entry check removed | EntryBoundary, RejectsBeforeReadingTheBody, ProductionEntryBoundRejectsOnTheHeader |
| aggregate check removed | AggregateBoundary, AggregateOverflowWithEveryEntryUnderItsCap, RejectsBeforeReadingTheBody, ProductionAggregateBound_Integration |
| per-entry `>` → `>=` | EntryBoundary, AggregateBoundary, RejectsBeforeReadingTheBody, ProductionAggregateBound_Integration |
| aggregate `>` → `>=` | AggregateBoundary, RejectsBeforeReadingTheBody |
| per-entry check moved after a body read | EntryBoundary, RejectsBeforeReadingTheBody, ValidArchive, AcceptsEntryUnderTheBound, ProductionAggregateBound_Integration, ProductionEntryBoundRejectsOnTheHeader |
| production path handed other limits | ProductionEntryBoundRejectsOnTheHeader, ProductionAggregateBound_Integration |

The lane wall was mutated the same way, and each mutation failed
`TestRestoreLimitsLane_ProductionSizeCaseRunsInQAContract`:

- env var dropped;
- PASS check dropped;
- job no longer running on push.

### 16.4 CI evidence

All runs are GitHub-hosted `ubuntu-latest`.

| What | Run | Commit | Observed |
|---|---|---|---|
| Production-size aggregate case in `QA · On-disk contract` (no `-race`) | [35866546559](https://github.com/KidCarmi/Culvert/actions/runs/35866546559), job 107199502354 | `a606f82` | `CULVERT_RESTORE_PRODUCTION_SIZE: 1`; `--- PASS: TestReadTarball_ProductionAggregateBound_Integration (0.79s)`; job green |
| Same-SHA QA audit (sharded vs unsharded) | same run, `Audit · sharded vs unsharded` | `a606f82` | **Passed.** Root entries 6,381 discovered / 6,381 reference / 6,381 sharded; skips 51 = 51; subtests 3,873 = 3,873 (0 missing, 0 extra); packages 112 = 112. Blocks: **0 lost**, 4 gained (35,243 vs 35,239 of 46,451). `coverage-floor.sh` exit 0 on both |
| Fast PR run, real `pull_request` event | [35867970387](https://github.com/KidCarmi/Culvert/actions/runs/35867970387) | `9fb5e7c` | All 18 jobs green, including the privileged mount-point test, the verdict, both coverage floors and the aggregate |
| Same-SHA Fast audit (the item §15.6 left open) | [35866549240](https://github.com/KidCarmi/Culvert/actions/runs/35866549240), `Audit · sharded vs unsharded` | `a606f82` | **Failed on one block, not a sharding loss.** Inventory identical: root entries 6,381 / 6,381 / 6,381; skips 51 = 51; subtests 3,873 = 3,873; packages 112 = 112. Blocks: 1 lost (`internal/yara/regexrunner.go:184.25,186.4`), 5 gained; `coverage-floor.sh` exit 0 on both. See below |

**The one lost block is scheduling, not sharding.** It is the worker's
`if r.abandoned.Load() { return }` in `internal/yara`'s regex runner, reached
only when the parent abandons a scan while a job is still queued. That package
runs in the non-root lane with the same `go test` invocation as the reference,
so sharding cannot change what reaches it. Running `go test -race -coverprofile`
on `./internal/yara/` alone, six times on the same commit, covered it in five
runs and missed it in one. The QA audit on the same SHA lost no blocks.

The 5B rule for a reference-only block is an isolated deterministic test, not an
exception entry (the exceptions file stays pinned empty).
`TestRegexRunner_AbandonedWorkerSkipsAQueuedJob` arranges the state and drives
`run` synchronously: covered in 6 of 6 runs afterwards, and it fails when the
early return is removed. The Fast audit's lint job was also red on `a606f82`;
that is the `unnamedResult` finding fixed in `9fb5e7c`, so its aggregate was red
regardless.

`9fb5e7c` differs from `a606f82` only by naming `readTarballLimited`'s results,
a gocritic finding from the Fast gate's diff-scoped lint, so the audits on
`a606f82` qualify the parser change.

The superseded PR run on `a606f82` (35866550469) failed root shard 2 with the
§15.6 `feedsync` data race, this time surfacing in
`TestReportCatFeedDBOpened_WordsTheOutcome`. This change does not touch that
path, and the re-run on `9fb5e7c` passed.

It fired again on `7fbc5ae` (run 35870770341, root shard 1, in
`TestReportCatFeedDBUnavailable_DoesNotClaimRecovery`): the third root-shard
failure on this PR. A re-run was only a gamble, so it is fixed here.
- **Cause.** `feedsync.Syncer.Start` launched a goroutine nothing could join.
  The trace reports the reading goroutine as *finished*: it is a missing
  happens-before edge between a sync round's log call and the next test's
  `captureLogger` write, not two goroutines overlapping in time.
- **Fix.** `Syncer.Wait` joins the loop (a `WaitGroup` around the goroutine).
  The three in-process `loadCommunityFeedDB` tests go through
  `loadCommunityFeedDBForTest`, which registers `t.Cleanup(syncer.Wait)`.
  `t.Context()` is cancelled before cleanups run, so the loop exits after its
  round in flight. `TestSyncer_WaitJoinsTheLoop` pins the join.
- **Evidence limit.** Local runs did not reproduce the race with or without the
  join (40 runs, then 25 runs at `-cpu=1,2,4` under CPU load). The fix is
  correct by construction, not shown by a local repro.

### 16.5 Measurements

**Test cost.** "Before" is the same toolchain on the same machine, taken just
before the change (§16.1). "After" is the new tests on the same machine.

| | Before, `-race` | After, `-race` |
|---|---|---|
| The two expensive tests: fixture + parse | 26.83 s + 0.00 s, 71.34 s + 28.59 s = **126.8 s** | none remain |
| Every `TestReadTarball*` test in the file, one run | 126.8 s + 0.14 s control | **≈0.2 s** (the largest is the 1 MiB control, 0.14 s) |
| Production-size aggregate proof | inside the ordinary suite, under `-race` | QA On-disk contract, no race: 1.40 s locally, **0.79 s on CI** |

Per-test CI timings come from the committed timing file and the unsharded
reference in QA audit 35866546559. The two removed tests had 29.01 s and
81.56 s. The new restore tests measure between 0 and 0.06 s each.

**Why summed test time is not the CI saving.** The 110.57 s sat in whichever
root shard the plan gave it, and a shard's time counts only while that shard
is the slowest process. In the QA audit's sharded run, still on the
pre-refresh timing file, the four root shards ran 348–406 s of tests against
estimates of 428 s. The non-root lane ran 722 s. The lane, not a root shard,
now bounds the verdict. It is dominated by `internal/mcp/execution` and is
untouched by 6A.

**Fast and QA, observed.**

| | Post-5C Fast (2 runs) | 6A Fast PR run 35867970387 |
|---|---|---|
| Aggregate | 711 s, 732 s | 779 s |
| Root shards | 439–486 s | 408–443 s |
| Non-root lane | 588 s (35859739941) | **600 s: the critical path** |
| Runner-minutes | 67.6, 67.0, including the frontend and MCP jobs; about 62 without | 60.9 (no frontend or MCP jobs this time) |
| Queue per job | 2–7 s | 3–5 s |

- The root shards got shorter by roughly 30–40 s at the slowest.
- The Fast aggregate did **not** get shorter in this sample: the non-root lane
  was the longest job at 600 s, and the verdict waits for it. The aggregate
  moves with run-to-run variance in the lane (588–722 s across the runs above).
- No wall-clock saving is claimed for 6A.
- The runner-minute saving is the removed fixture work, about 1.8 min per
  race-suite execution: 110 s of CI test time, **estimated** from the
  committed timings. The shuffled determinism lane runs the suite twice
  (`-count=2`), so it saves about twice that. That estimate has not been
  measured separately.

### 16.6 Shard timing refresh

`.github/qa-root-shard-timings.json` is replaced with the file the QA audit's
comparison job derived from its own unsharded reference (run 35866546559 at
`a606f82`), committed as-is per §14.5.

- The two deleted tests (81.56 s and 29.01 s) are gone.
- 23 entries were added: the new restore tests and the stage-5C walls. The new
  restore tests measure 0–0.06 s.
- The rest of the file also moved: summed entries went from 1,794.5 s to
  1,128.7 s. Several unrelated slow tests measured 30–60 % faster in this
  reference, for example `TestConformance_Response_Slice3f` 28.52 → 9.16 s and
  `TestCredWall_EveryClaimedSurfaceIsScanned` 35.69 → 20.85 s. That is
  run-to-run drift since the previous file (commit `21bfd7d`), not a 6A effect.
- The timing file only balances; it never decides what runs (§14.5).
- Because the partition changes with it, the refreshed file was qualified by a
  further same-SHA audit on the final commit (§16.7).

### 16.7 Qualification of the refreshed partition

Both same-SHA audits ran on the final code commit `fef1fd0`, the first commit
carrying the refreshed timing file, the yara test and the feedsync fix.

| Audit | Run | Inventory | Blocks | Floors |
|---|---|---|---|---|
| QA | [35874102885](https://github.com/KidCarmi/Culvert/actions/runs/35874102885) | root 6,381 / 6,381 / 6,381; skips 51 = 51; subtests 3,873 = 3,873; packages 112 = 112 | **0 lost**, 1 gained (35,243 vs 35,242 of 46,453) | exit 0 / 0 |
| Fast | [35874107185](https://github.com/KidCarmi/Culvert/actions/runs/35874107185) | identical to QA | **0 lost**, 1 gained | exit 0 / 0 |

The yara block that failed the `a606f82` Fast audit is covered by both runs.
The gained block (`controlplane_delta.go:207`) is on the sharded side, so it
cannot fail the audit.

On the same commit, the Fast PR run
([35874104460](https://github.com/KidCarmi/Culvert/actions/runs/35874104460)),
Deep ([35874104508](https://github.com/KidCarmi/Culvert/actions/runs/35874104508),
including `Deep · determinism`) and QA's `Determinism` job were all green.

**What the refresh did and did not change.**

| | Estimate per shard | Actual root shards (test s) |
|---|---|---|
| Before, QA `a606f82` | 428 s | 348–406 |
| After, QA `fef1fd0` | 288 s | 323–414 |
| After, Fast `fef1fd0` | 288 s | 267–423 |

- The estimates now match the partition the new file produces.
- The shard spread did not narrow: two runs of the same commit spread 91 s and
  156 s. Runner variance dominates, and no timing file can balance it away.
- The non-root lane (610 s in QA, 724 s in the Fast audit, 761 s in the Fast PR
  run) is still the critical path.
- No wall-clock gain is claimed for the refresh. It removes stale entries and
  keeps the estimates honest.

**Fast PR run on `fef1fd0`:**
- 872 s from run start to aggregate;
- ≈60.1 runner-minutes summed over job durations (no frontend or MCP jobs);
- root shards 360–462 s job time; non-root lane 761 s.

**Open item: one determinism failure on `7fbc5ae`.** `Deep · determinism`
failed once (run 35870770250, root package, no `-race`).
- Rerunning the same seed locally on `7fbc5ae` (`-test.shuffle 1790172022257462916`,
  `-count=2`) passed in 718 s.
- The failing test's name is only in the `deep-determinism-log` artifact, which
  the session environment could not download.
- Both determinism jobs on `fef1fd0` passed.

It is recorded here unresolved, not dismissed as a flake. Anyone with that
artifact can name the test.

### 16.8 Rollback

Revert the 6A commits.

- The tests go back to generating 300 MiB and 800 MiB under `-race`.
- `readTarballLimited` and `tarballLimitError` disappear. `readTarball`'s
  behaviour and text are identical either way.
- The QA contract step and its wall go too.
- The timing file reverts with them.
- `TestRegexRunner_AbandonedWorkerSkipsAQueuedJob` can stay: it only makes an
  existing block's coverage deterministic.

Do **not** remove the QA contract step on its own. That would leave the
production aggregate bound proved nowhere at production size.

## 17. Stage 6B — performance reporting and the weekly equivalence audit

Goal: see CI performance drift and evidence drift early, from evidence that
already exists. No test is re-run to produce a number.

### 17.1 What was added

| Piece | Where | What it does |
|---|---|---|
| Collector | `cmd/cireport` (stdlib only) | `run` → one versioned report (`culvert.ci-run-report/v2` since §18) + step summary per run attempt. `trend` → equivalence groups, provisional statistics, advisory regressions, audit freshness (`culvert.ci-trend-report/v2`). |
| Reporter workflow | `.github/workflows/ci-perf-report.yml` | Runs the collector after gate runs complete, weekly, or on dispatch. |
| Weekly audit | `qa-gate.yml` `schedule: "23 6 * * 0"` | The existing unsharded reference and `rootshard compare`, on the default branch, every Sunday. |
| Baseline | `.github/ci-perf-baseline.json` | Reviewed performance targets. Ships `provisional` and empty. |
| Walls | `ci_perf_report_test.go`, `cmd/cireport/*_test.go` | See §17.9. |

### 17.2 What a report measures, and how

- **Elapsed** = the required aggregate's `completed_at` minus the attempt's
  `run_started_at`, and the same for the race verdict job. It is wall clock.
  Parallel jobs are never added together to produce it.
- **Busy** = the union of job intervals. It is always ≤ the wall span.
- **Runner-minutes** = the sum of executed job durations. Every report says
  this is **not a bill**: GitHub rounds per job, and public-repo minutes are free.
- **Attempt scoping.** A re-run attempt lists the earlier attempt's jobs.
  A job that started before this attempt did is *carried over*: it is listed
  but never timed. Skipped jobs never count.
- **Attempt queue** (§18.2) = the attempt's enqueue time → the first start
  among this attempt's own jobs. It is `null` (unknown), never zero, when the
  attempt's enqueue time was not observed.
- **Phases.** Queue is job `created_at` → `started_at`. Setup, work and
  teardown come from step names. Anything else is recorded under `unknowns`.
  Cache state is **not inferred**.
- **Race evidence.** Read from `qa-race-verdict` (`verdict.json`,
  `results.json`) and `qa-race-shard-N/meta.json`: shard imbalance, slowest
  lane packages, slowest root tests, inventory size, coverage and verdict
  problems. Pre-5C Fast runs used a single race job with no verdict. Their
  job set is `race-unsharded`, so they never share a group with the
  sharded engine.
- **Audit evidence.** Read from `qa-audit-compare` / `fast-audit-compare`
  (`comparison.json`). The audit state is one of:
  - `not-requested`
  - `passed`
  - `failed`
  - `missing` — requested, but the jobs did not execute
  - `unknown` — executed, but the comparison could not be read

  Only `passed` is healthy.
- **Identity.** The verdict's commit must equal `head_sha` on every event
  except `pull_request`, which tests the merge commit. Every shard meta must
  agree on commit and toolchain. A timing candidate's `source` must name this
  run and SHA. Any disagreement is recorded as a **problem**, and the run is
  kept out of the statistics.
- **Classes**, which are never mixed:
  - `pr-code`
  - `pr-docs-only` — the race engine was not *scheduled*
  - `pr-pass-through`
  - `main-qa`
  - `scheduled-audit`
  - `manual-audit`
  - `manual-qualification`
  - `fault-injection`
  - `other`

  Groups are keyed `workflow|class|job set|cohort` (the cohort was added in
  §18.1). The job set comes from what actually executed: `race`,
  `race-unsharded`, `audit`, `qa-layers`, `frontend`, `mcp`, `maint`. So a PR
  that ran the frontend and MCP lanes is never compared with one that did
  not, and a run on another runner image, shard count or Go release line is
  never compared with this one.
- **Run-names.** A dispatch publishes its inputs in its title, which the runs
  API returns:
  - Fast PR Gate: `… · dispatch · audit=<bool> · fault=<choice>`
  - QA Gate: `… · dispatch · audit=<bool>`

  The collector trusts these facts **only on `workflow_dispatch`**. On a pull
  request `display_title` is the PR's own title, so a PR named "fault=x"
  cannot reclassify its run (pinned by test).

**Missing evidence is `unknown`, never healthy.** Expired artifacts, a
refused download or an undecodable document are listed under `unknowns`. The
report still completes.

### 17.3 The weekly same-SHA equivalence audit

A scheduled QA run executes the **full main graph plus** `qa-unsharded-audit`
and `qa-unsharded-audit-compare`. That is the job set an `unsharded_audit: true`
dispatch has run since 5B, with the same comparison engine, inventory checks,
coverage floors, the empty exceptions file and the "both sides must have
succeeded" step. Nothing in the comparison changed.

- **One predicate:**
  `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.unsharded_audit)`.
  It is written in five places, all pinned equal: the concurrency group, its
  cancel flag, both audit jobs' `if:`, and the aggregate's `require-success`.
- **An unexpectedly skipped audit cannot pass.** On an audit run the aggregate
  requires `qa-race`, `qa-coverage`, `qa-unsharded-audit` and
  `qa-unsharded-audit-compare` to be exactly `success`. The test drives the real
  `needs-verdict` shell: `skipped`, `failure`, `cancelled` or an absent entry
  for any of the four refuses. Ordinary runs pass `''` and are unchanged.
- **Separate concurrency.** Audits use the `qa-audit-<ref>` group with
  `cancel-in-progress: false`. Ordinary runs keep `qa-gate-<ref>`, which
  cancels superseded runs. A main push cannot cancel a running audit, and an
  audit cannot cancel the main-push run that is release evidence.
- **Never release evidence.** `require-gate.sh` reads only `event=push` runs of
  `main`. The release manifest does not name the reporter (pinned).
- **Sunday 06:23 UTC.** Monday 02:00–06:00 already starts 14 scheduled runs. Sunday 06:23 is after every daily cron has started and shares a slot with no other schedule.
- **Fast's manual audit is kept** (`pr-fast-gate.yml` `unsharded_audit`) for
  changes to Fast's caller-specific inputs. Only its run-name changed.

### 17.4 Isolation of the reporter

- **Off the PR critical path.** It runs on `workflow_run`, after the gate has
  finished, on the default branch, and posts no check to the PR. Nothing
  requires it, and no workflow chains from it (pinned).
- **Trusted code only.** `actions/checkout` pins `ref:` to the repository's
  default branch, with `persist-credentials: false`, so a dispatch on another
  branch still runs the reviewed collector.
- **Least privilege.** The token has `actions: read` and `contents: read`, and
  no secret is used. `setup-go` runs with `cache: false`, because a cache here
  could have been written by a PR run.
- **Nothing fetched or executed.** `go run` builds with `GOPROXY=off`; the
  collector imports only the standard library (pinned).
- **Artifacts are data.** ZIPs are read into memory, capped in size, and only
  allowlisted JSON members are decoded. Duplicate member names are refused.
  `qa-race-build`, which carries the prebuilt test binary, is **never
  downloaded** (pinned by test). A presigned storage URL's query is stripped
  from errors before anything is written.
- **No shell injection.** Event data reaches shell through `env`, and every
  run id is checked to be numeric. No `run:` body interpolates `${{ }}`
  (pinned).
- **A retained report is authenticated before the trend trusts it.**
  Artifact names are not access-controlled: any run in the repository,
  including a pull request that edits or adds a workflow, can upload an
  artifact named `ci-run-report-<id>-<attempt>`. Without a check, such a
  report could make a failed scheduled audit read as passed. The trend
  therefore accepts a report only when both of these hold:
  1. **Trusted producer.** It was made by a run of `ci-perf-report.yml` on
     the default branch of this repository (not a fork), from an event that
     runs default-branch code: `workflow_run`, `schedule`, or a
     default-branch dispatch.
  2. **Matching identity.** Its run identity matches the API field for
     field: workflow, event, commit, branch, status, conclusion, creation
     time, run id and attempt.

  Anything else is rejected and noted, and the run is measured from
  metadata alone (Codex review, PR #1477). Removing either check alone
  fails a test.

### 17.5 Operation and retention

| Output | Produced | Kept |
|---|---|---|
| `ci-run-report-<run>-<attempt>` (`report.json`, `summary.md`) | After every **non-PR, non-cancelled** Fast/QA run: main pushes, dispatches, the schedule | 90 days |
| `timing-refresh-candidate-<run>-<attempt>` | Only for a **passed** audit: the refreshed timing file + `diff.json` against the committed one | 90 days |
| `ci-trend-report-<collector run>` (`trend.json`, `summary.md`) | Sundays 09:43 UTC, after a scheduled audit completes, or on dispatch | 90 days |
| Raw evidence the reports are built from | Race shard/build/lane/universe artifacts | 7 days |
| | `qa-race-verdict`, audit reference/compare artifacts | 14 days |
| | `qa-coverage` | 30 days |

The 90-day reports outlive the evidence they were built from. The retention
periods are the ones observed on run 35874102885 (`expires_at`). A run can
therefore be enriched on demand (dispatch with `run_id`) only within **7
days**: after that its shard `meta.json` — the only source of the toolchain
— is gone, and the report can no longer verify its cohort. Job logs, the
source of the runner image, are kept longer (90 days by default).

- **Report on any run, including a PR run:** dispatch *CI Performance Report*
  with `run_id`. The trend already lists PR runs from metadata.
- **The trend** reads the newest 25 runs **per workflow and event**. A
  workflow-wide window would let ~240 PR runs a week push every main push
  out. It uses the retained per-run report when one exists, else metadata
  only, and says which.

### 17.6 Expected additional runner usage

These figures are from the last 7 days of gate runs and the measured audit
runs.

| Item | Estimate |
|---|---|
| Weekly audit: one QA run with the audit jobs | **~92–99 runner-min/week**, measured in runs 35866546559 (92.6) and 35874102885 (99.4). An ordinary main QA run is 72 runner-min; the audit jobs are ~24–27 of the total. |
| Per-run reports | ~47 jobs/week (19 main pushes, 27 dispatches, 1 schedule) × ~1–2 min ≈ **50–95 runner-min/week**. This is an estimate: the workflow cannot run before it is on `main`. |
| Trend | 1–2 runs/week × ~4 min, of which 2.5 min is collection measured locally over 102 executions |
| **Total** | **≈ 150–200 runner-min/week** |

None of it is on a required check's path.

Reporting a job per PR run was rejected. About 240 PR runs a week, roughly
half of them cancelled by a newer push, would cost more than the audit
itself.

### 17.7 Baseline policy, ownership, investigation

- **Provisional until reviewed.** A group's statistics count only executions
  that are completed, first attempt, `success` and free of identity problems.
  The window is the newest 20, and the statistics stay *provisional* below 10
  samples.
- **Reviewing a group.** After a group has 10–20 samples, a maintainer copies
  its reviewed medians into `groups` and sets `status: reviewed`,
  `reviewedBy` and `reviewedAt` in a PR. The loader refuses a `reviewed`
  file without a reviewer or date, and sample bounds outside 10..20.
  Extra full-suite runs must **not** be generated to fill a sample.
- **Sustained regression (advisory).** It triggers when the 3 newest counted
  samples of a group all exceed the reviewed median × 1.25. It is emitted as a
  `::warning::` and never fails anything. Performance signals stay advisory.
- **Audit freshness (a correctness signal, not advice).** States:
  `pending-first`, `passed`, `failed`, `stale` (> 8 days since the last pass)
  and `missing`.
  `failed`, `stale` and `missing` make the trend job exit 1 with an `::error::`.
  **Set `audit.introduced` to the merge date when this lands.**
  - **One audit per weekly slot.** The baseline carries the audit schedule
    (`audit.cron`, pinned equal to `qa-gate.yml`'s cron) and `slotGraceHours`
    (3). The latest slot whose grace has passed must have its own completed
    scheduled audit, or the state is `missing`. An age limit alone cannot
    say this: the Sunday backstop runs about three hours after the slot, so
    last week's audit is only ~7.1 days old and would pass a week in which
    no audit ran (Codex review, PR #1477). A wall pins the backstop to the
    same day, at or after slot + grace.
  - **Unknown evidence never passes.** A scheduled run whose jobs cannot be
    read is kept in the report as `unreadable` and judged `failed`. It is
    never dropped: dropping it would let an older passing audit stand in
    for it (Codex review, PR #1477).
- **Owner.** The CI-REDESIGN owner reviews baselines and investigates every
  red trend.
- **Investigating a red audit:**
  1. Open the audit run's `Audit · sharded vs unsharded` summary and
     `comparison.json`. Lost tests or blocks are named there.
  2. Follow §14.2. Every lost block needs an isolated fixture or a reviewed
     exception.
  3. Never re-run a red audit to get a green one. The trend enforces this:
     the runs API reports only a run's latest attempt, so a re-run attempt
     (attempt > 1) never counts as a passing audit. The next scheduled audit
     must pass on its first attempt (Codex review, PR #1477).
- **Investigating a regression warning:**
  1. Compare the group's recent `report.json`s. Look at the job queue, the
     setup phase, shard imbalance and the slowest tests.
  2. A timing-driven imbalance is fixed by reviewing a timing candidate
     (§17.8), not by editing the partition by hand.

### 17.8 Timing-refresh candidates

A **passed** audit's `qa-root-shard-timings.json` is published as a candidate,
with a diff against the committed file listing added, removed and changed
entries. It is **never committed automatically**.

To adopt one, open a PR that replaces `.github/qa-root-shard-timings.json` and
follow §16.6–16.7. Coverage exceptions are never generated.

### 17.9 Validation

- **`cmd/cireport` tests** use 14 real run fixtures and real audit evidence
  from run 35874102885. They cover:
  - every class, including a genuine docs-only run, a cancelled run, a failed
    run and two re-run attempts;
  - that parallel jobs do not inflate elapsed time (4 × 400 s shards → 545 s
    elapsed; runner-minutes = the sum);
  - that carried-over jobs are excluded;
  - mismatched verdict, shard and candidate identities;
  - that an audit that is missing, unreadable or failed never reads as passed;
  - that only allowlisted artifact members are read, and `qa-race-build`
    never;
  - end-to-end collection through a fake API, including a report with no
    artifacts;
  - grouping, windowing, advisory regressions and all audit-freshness states;
  - per-event listing surviving a flood of 30 PR runs.
- **`ci_perf_report_test.go`** covers:
  - predicate single-sourcing and its event matrix;
  - the real `needs-verdict` shell refusing a skipped, failed, cancelled or
    absent audit job on an audit run;
  - separate concurrency;
  - reporter isolation and cost bounds;
  - the collector's standard-library-only imports;
  - release evidence staying `event=push` of `main`;
  - run-name ↔ parser agreement.

  The existing walls were updated rather than bypassed:
  - the trigger matrix now pins exactly one **weekly** schedule;
  - the audit opt-in wall now also proves the audit runs on the schedule and
    on `unsharded_audit=true`;
  - the race-ownership rationale is corrected.
- **Mutation proof.** Each of these 13 defects was injected and failed a test:
  1. an audit job dropped from `require-success`;
  2. `require-success` removed;
  3. the compare job not scheduled;
  4. audits cancellable;
  5. a shared concurrency group;
  6. a daily audit;
  7. a write-scoped reporter;
  8. a reporter cache;
  9. a network `GOPROXY`;
  10. the reporter no longer following QA;
  11. the reporter checking out the PR head;
  12. shell interpolation in the reporter;
  13. a PR title trusted as a run-name.
- **Live API.** `cireport run` on QA audit run 35874102885 produced:
  - class `manual-audit`, job set `race+audit+qa-layers`;
  - elapsed 1939 s to the aggregate and 751 s to the race verdict;
  - wall 1939 s, busy 1870 s;
  - runner-minutes 99.4 over 19 jobs.

  `cireport trend` read 102 executions into 13 groups, with every failed and
  cancelled run listed. Artifact downloads from the authoring session were
  refused by blob storage (403, session egress policy). They were correctly
  reported as `unknown` with verdict `missing`, and no signature leaked into
  the output. Artifact parsing is proven through the fake API. The
  `workflow_run` path runs for the first time after merge.

### 17.10 Rollback

- **Reporting only.** Delete `.github/workflows/ci-perf-report.yml` (and
  optionally `cmd/cireport`, `.github/ci-perf-baseline.json` and
  `ci_perf_report_test.go`). No gate, check or release depends on them.
- **The weekly audit.** In `qa-gate.yml`:
  1. remove the `schedule:` block, the `run-name` and the audit concurrency
     split;
  2. restore the two audit `if:`s to
     `github.event_name == 'workflow_dispatch' && inputs.unsharded_audit`;
  3. drop `require-success`.

  Then revert the matching wall changes in `qa_gate_scheduling_test.go`,
  `qa_race_shards_test.go` and `ci_perf_report_test.go`.

  Do **not** remove only `require-success`: a scheduled audit would then pass
  with its audit jobs skipped.
- Fast's `run-name` can stay or go independently.

## 18. Stage 6B closeout — operational acceptance

Stage 6B merged as PR #1477 (`3febe59`). This closeout corrects two
measurement defects found in review of the merged code, verifies the
reporting on GitHub, and starts the observation period. It changes reporting
only. No required check, gate, release step, permission or race-engine
output changes.

### 18.1 Cohort identity

**Finding.** The trend grouped executions by workflow, class and job set
only. Runs on a different runner platform, shard count or Go toolchain could
therefore enter the same reviewed baseline.

**Change.** Each report derives a **cohort** from what was observed, and the
trend groups by `workflow|class|job set|cohort`:

| Component | Source | Value when not observed |
|---|---|---|
| `platform` | the executed jobs' runner labels + runner group (job metadata), separators percent-escaped so distinct label sets never share a string | `unknown` |
| `image` | the runner image **every measured job** reported in its own log (the "Runner Image" group the runner writes first, e.g. `ubuntu-24.04`) | `unknown` when any measured job was not observed; `mixed:…` when jobs ran on different images |
| `shards` | the root-shard jobs GitHub scheduled | `none` when no race engine ran |
| `toolchain` | Go release line + GOOS/GOARCH from the shards' `meta.json` | `unknown`; `n/a` when no race engine ran |

- **Why the image is keyed.** GitHub annotates every `ubuntu-latest` job on
  this repository: *"The ubuntu-latest label will migrate to Ubuntu 26
  beginning October 19, 2026."* A label is not a platform identity, and the
  job metadata exposes no image.
- **Why every measured job, not just the shards.** A rollout can move one
  job and not another. Elapsed time, runner-minutes and the lane's time come
  from jobs outside the root shards, so an image read only from the shards
  would pool a run whose lane ran on 26.04 under 24.04 (Codex review, PR
  #1478; the first version of this closeout read the image from the shards'
  `meta.json` and was reverted for exactly this). The collector reads the
  first 16 KB of each measured job's log with a byte-range request and
  parses only the `Image:` and `Version:` lines of the "Runner Image" group,
  as data, in a safe character set. It reads nothing else and executes
  nothing. Every hosted job prints the group, so runs without a race engine
  (docs-only, pass-through) get an observed image too.
- **What stays comparable.** Source commits, durations, Go patch releases
  and the weekly runner image build do not split a cohort. The exact Go and
  image versions (including the weekly image build, the value that tells two
  samples of one cohort apart) stay in each report and trend sample row,
  stated only when every shard (or job) reported the same one.
- **Complete evidence only.** The toolchain counts as observed only when the
  `meta.json` of **every** scheduled shard was read — matched shard for
  shard, not by count (documents for shards `{0,1,2,4}` do not cover
  scheduled `{0,1,2,3}`), and each document must name the shard whose
  artifact carried it; the image only when
  **every** measured job's log was. An unread one may have run elsewhere,
  and the others do not speak for it. Shards that disagree on the Go release
  line or GOOS/GOARCH make the toolchain `mixed:…`, like the image, and
  never verified (Codex review, PR #1478).
- **Unknown stays separate.** A component that was not observed reads
  `unknown` (never a guessed value), forms its own unverified cohort, and the
  baseline loader refuses a reviewed median unless the key parses as exactly
  `platform=…;image=…;shards=…;toolchain=…`, every field is non-empty and
  observed, and no field is `mixed:` (Codex review, PR #1478).
- **The image build is stated only when all jobs agree.** During a rollout
  jobs can share an image but not a build; the report then leaves the build
  unstated and says so, and the cohort (keyed on the image) is unaffected
  (Codex review, PR #1478).
- **Metadata-only PR reporting is unchanged.** PR runs are still measured
  from metadata in the trend. A selected natural run is enriched with the
  existing on-demand report (dispatch *CI Performance Report* with `run_id`),
  within the 7-day shard-artifact retention (§17.5). The workflow's
  `actions: read` already covers job logs; no permission changes.

### 18.2 Attempt queue

**Finding.** `runQueueSeconds` was `run_started_at − created_at`. On attempt
1 GitHub stamps both at enqueue, so it was always 0. On a re-run,
`created_at` is attempt 1's, so it measured the gap between attempts.
Observed on run 35034671115: the runs endpoint reports `created_at`
23:13:20, while `/attempts/2` reports 23:47:37 — 34 minutes that are not
queueing.

**Change.** The collector reads through the attempt endpoint, whose
`created_at` is that attempt's enqueue time, keeps the run's own `created_at`
as identity (what the trend compares), and reports
`attemptQueueSeconds` = attempt enqueue → the first start among this
attempt's own jobs — every job that has started, completed or still running
(a run reported in progress), excluding skipped jobs and jobs carried over
from an earlier attempt (Codex review, PR #1478). When the enqueue time was not observed (a re-run read
through the runs list) it is `null` with an `unknowns` entry, never zero.
Elapsed time and runner-minutes are unchanged. Report schemas move to `v2`;
the trend refuses `v1` reports and measures those runs from metadata.

### 18.3 Live verification on GitHub

| Check | Evidence | Result |
|---|---|---|
| First automatic report on main | *CI Performance Report* 35907140269 (`workflow_run`), triggered by *QA Gate* push 35905503217 on `3febe59` | Checked out main `3febe59` (trusted code). Collected in 14 s and published `ci-run-report-35905503217-1` (3,607 bytes, `report.json` + `summary.md`). The `-1` suffix is read from the report's own `run.attempt`, so the report names attempt 1. The trend job was skipped, as designed for a push. |
| It ran on a failed run | The QA run concluded `failure` | Reported, as designed: only cancelled runs are skipped. |
| Evidence it could read | The QA run published `qa-race-verdict` and `qa-race-shard-0…3`, plus `qa-race-build` (56 MB), which the allowlist never reads | Present and unexpired. |
| Report contents | — | **Not verified from the authoring session**: artifact storage (`*.blob.core.windows.net`) is refused by the session's egress policy, and GitHub exposes no API for step summaries. The collector now also prints one sanitized line to its job log (`cireport run: … evidence=… read=… tested=…`), so from the first run after this merges the report's evidence and tested SHA are checkable through the logs API. |
| Pre-merge `workflow_run` triggers | 35905794603, 35906657765 | `skipped`: pull-request runs, as designed. |
| Manual reporting path, known successful audit | Dispatch 35907858252 on main, `run_id` 35874102885 (same-SHA audit at `fef1fd0`) | Published `ci-run-report-35874102885-1` (3,959 bytes) **and `timing-refresh-candidate-35874102885-1` (81,945 bytes)**. The candidate is uploaded only when the collector downloaded and decoded the verdict (ok) and the comparison (passed) and the candidate's provenance names this run — so this is artifact verification, not the metadata fallback. The trend job on the same dispatch succeeded. |
| Audit scheduling | `qa-gate.yml` and `ci-perf-report.yml` are `active`; each has **0** scheduled runs | The first audit is due Sunday 2026-09-27 06:23 UTC and the backstop trend 09:43. Neither has fired yet; nothing here claims it has. |
| Separate concurrency | `qa-gate.yml` on main, lines 120–122 | Audit runs use `qa-audit-<ref>` with `cancel-in-progress: false`; ordinary runs keep `qa-gate-<ref>`. Failure semantics (a skipped, failed, cancelled or absent audit job refuses) are pinned by the walls that drive the real `needs-verdict` shell. |
| `audit.introduced` | `2026-09-23`, the merge date | Left unchanged. The trend reads `pending-first`: the only past due slot, 2026-09-20, predates it. |
| Release safeguards | CI 35905503220 on `3febe59` | Main QA failed, so `Auto-Tag Release` and `Promote moving channels (main)` both refused at their evidence step. Nothing was tagged or promoted. |

The main QA failure is `TestUpgradeApply_RejectsInvalidRef` in
`cmd/culvert-maint` (a separate module untouched since #1300): `connection
refused` on the agent socket in the shuffled double run. The seven previous
main QA runs were green. It is outside this plan, it was not re-run, and it
is left to the separate flaky-test investigation.

### 18.3.1 Schema v2 on natural runs (2026-09-24)

Collector revision for every report below: `ci-perf-report.yml` checks out
the default branch, main `9450d33` (#1478). Each report prints one
`cireport run:` line to its job log, which is how its contents were read
(artifact storage is still refused by the authoring session's egress).

| Check | Evidence | Result |
|---|---|---|
| First automatic v2 report | *CI Performance Report* 35990426653, job 107602944435, for *QA Gate* push 35989051459 on `9450d33` (QA succeeded) | Attempt 1 **failed closed**: `GET …/actions/runs/35989051459: HTTP 403` at 11:00 UTC. No report was published and nothing claimed success. **Cause suspected, not established:** it came minutes after the enrichment burst below, but the collector logs only the status code. The response body and `x-ratelimit-*` headers were not recorded, so the log cannot prove a rate limit. Attempt 2 (re-run of the failed job, 12:06 UTC, job 107624053905) **succeeded**: `attempt=1 event=push tested=9450d33 class=main-qa evidence=artifacts` (same six documents), `image-logs=17/17 verdict=ok verified=true`, same cohort as the PR samples. It published `ci-run-report-35989051459-1` (4,021 bytes). Attempt 1 remains in the run's history. |
| On-demand v2 reports, Fast PR runs | 28 dispatches with `run_id`, e.g. 35990137756 / job 107602002719 for Fast run 35937792762 | All 28 report jobs succeeded. Every line reads `attempt=1 evidence=artifacts image-logs=18/18 verified=true` and names six documents (`qa-race-shard-0…3/meta.json`, `qa-race-verdict/{results,verdict}.json`). Example: `head=c96f0b60 tested=3a99c2be` — the tested SHA is the merge commit, not the PR head, and the report keeps both. |
| Missing evidence stays unknown | The same collector run locally against Fast run 35937792762 without artifact access | `evidence=metadata-only image-logs=0/18`, image and toolchain `unknown`, `verified=false`. It lands in its own cohort and is never pooled. |
| Targeted dispatch after #1486 | *CI Performance Report* 36017569814 on main `75dbb8b`, `run_id` 35989051459 (a run already reported, so nothing new was enriched) | `Report · one run` succeeded and published `ci-run-report-35989051459-1` (4,053 bytes); `Report · trend + audit freshness` was **skipped**. |
| Empty dispatch after #1486 | *CI Performance Report* 36018809544 on main `75dbb8b`, empty `run_id` | `Report · one run` was **skipped** and the trend **ran and succeeded** (2 min 50 s) despite it, publishing `ci-trend-report-36018809544` (6,653 bytes). This is the one deliberate trend over the verified samples. Its verdict is in the artifact and step summary, which the authoring session's egress cannot read; the trend prints no summary line to its log. |
| Trend on those dispatches | The 28 trend jobs of the same dispatches | **All failed** on `HTTP 403` (`list pr-fast-gate.yml push runs`). A dispatch with `run_id` also runs the full trend (the trend job's `if:` accepts any `workflow_dispatch`), so 28 dispatches were 28 trends reading the same history. |

**Finding — enrichment was not bounded.** Enriching N runs cost N full
trends against the shared budget of about 1,000 API requests per hour, and
the likely casualty was an unrelated automatic report. **Fixed:** a dispatch
with a `run_id` now reports that run and skips the trend; an empty dispatch
is the trend. The weekly schedule, the scheduled-audit trigger, `needs:
run-report`, `always()`, the default-branch checkout and the read-only token
are unchanged. `ci_perf_report_dispatch_test.go` evaluates both jobs' real
`if:` conditions, including GitHub's rule that an `if:` without a status
function skips when a `needs` job was skipped or failed. The matrix covers:

- a targeted dispatch;
- an empty dispatch with run-report skipped;
- a scheduled-audit completion whose report failed;
- a cancelled scheduled audit;
- main push completions: success, failure and cancelled;
- pull-request runs.

It rejects the pre-fix condition and the fixed condition without `always()`.

**Enrichment rule until the fix is live on main:** no bulk enrichment.
After it, enrich in small sequential batches (at most five dispatches, each
waiting for the previous one), then dispatch once with an empty `run_id` for
the trend. The 28 reports above are reused and not re-collected.

**Follow-up, not in this change:** have the collector log the status,
`x-ratelimit-remaining`/`-reset` and a bounded API message on failure, so
a 403 can be attributed from its own evidence.

### 18.4 Observation period

Baselines stay `provisional` until a **verified** cohort has 10–20
comparable natural executions. No suite is re-run to produce samples.

Samples available now (trend over 102 executions, newest 25 per workflow and
event; counted = completed, first attempt, success, consistent evidence):

| Workflow | Class | Job set | Executions | Counted | Elapsed to aggregate, median / p90 |
|---|---|---|---|---|---|
| Fast | `pr-code` | `race+frontend+mcp` | 10 | 8 | 754 / 927 s |
| Fast | `pr-code` | `race` | 9 | 6 | 856 / 869 s |
| QA | `main-qa` | `race+qa-layers` | 4 | 3 | 877 / 922 s |
| QA | `manual-audit` | `race+audit+qa-layers` | 9 | 2 | 1,614 / 1,939 s |
| QA | `pr-pass-through` | `minimal` | 25 | 20 | 12 / 14 s |

The rest are pre-5C engine runs (`race-unsharded`), pre-5B QA runs
(`qa-layers` only), fault injections and qualification dispatches, which are
listed and never pooled with the current engine.

**Verified cohorts, 2026-09-24: 1.** Cohort
`platform=ubuntu-latest@GitHub Actions; image=ubuntu-24.04; shards=4;
toolchain=go1.26 linux/amd64`. It holds 28 enriched Fast PR runs
(2026-09-23 12:19 to 2026-09-24 00:18 UTC, 10 branches, all first attempts)
and the first main QA run after #1478 (§18.3.1). Durations are job
metadata; runner-minutes sum every job in the run. Statistics cover
successful executions only.

| Workflow · class · job set | Successful | Failed | Cancelled | Elapsed median / p90 | Race path median / p90 | Runner-min median | Queue median / p90 |
|---|---|---|---|---|---|---|---|
| Fast · `pr-code` · `race` | 16 | 4 (3 with `verdict=failed`, 1 in another job) | 14 | 856 / 951 s | 815 / 908 s | 62.3 | 4 / 99 s |
| Fast · `pr-code` · `race+frontend+mcp` | 8 | 0 | 0 | 754 / 856 s | 712 / 810 s | 67.3 | 4 / 77 s |
| QA · `main-qa` | 1 | 0 | 0 | one sample, not a statistic | — | — | — |

- `race` and `race+frontend+mcp` stay separate groups and are never pooled.
- Cancelled executions are counted from run metadata only; the collector
  does not report them, so they are not verified samples. Another 2
  cancelled code-PR runs in the window stopped before their job set was
  known and belong to neither group.
- Every group stays **provisional**. `race` reaches 10 successes, but they
  all come from one 12-hour window. "Counted" also requires no
  contradictory evidence, which only the trend checks, and no trend has run
  over these samples yet.
- The 101 older-engine and docs-only runs in the same window are
  metadata-only and stay out of every verified cohort.
- PR artifacts expire after 7 days, the first on 2026-09-30. Main QA
  reports are produced automatically.

**Missing evidence:**
- main QA samples beyond the first; they accrue with each main push;
- the first scheduled audit and backstop (due 2026-09-27, **pending** until
  they actually execute);
- the verdict of the one deliberate trend over the verified samples
  (36018809544, §18.3.1): it ran and succeeded, but its artifact has not
  been read from the authoring session.

### 18.5 Observed bottlenecks and the next optimization

Critical path of the counted current-engine runs (job metadata, medians):

| Run kind | Build | Root shards (4) | Non-root lane | Verdict | Aggregate done |
|---|---|---|---|---|---|
| Fast `pr-code`, `race` (6) | 138 s, done at 150 s | 449 s, done at 605 s | **758 s, done at 770 s** | 42 s | 855 s |
| Fast `pr-code`, `race+frontend+mcp` (8) | 141 s | 456 s, done at 611 s | 590 s, done at 605 s | 37 s | 720 s |
| QA `main-qa` (3) | 122 s | 469 s, done at 590 s | 753 s, done at 756 s | 41 s, done at 800 s | 874 s; **Determinism 859 s** |

- **The non-root lane is the Fast gate's critical path.** Across the 14
  counted code-PR runs, the lane finished after the root shards in 10. Those
  runs took a median **854 s** to the aggregate, against **702 s** when the
  shards finished last. The lane added a median 154 s (max 191 s). Its
  duration varies from 476 to 763 s between runs of similar code, while the
  shards stay at 433–499 s.
- **One package dominates the lane.** In audit run 35874102885,
  `internal/mcp/execution` took **436 s of the lane's 610 s**; the other 110
  packages run beside it. §14.8 recorded this split as unmeasured and
  optional; it is now measured.
- **Queueing is not a bottleneck.** The median job queue is 3 s.
- **On main QA the determinism job is last** (≈860 s), after the race
  verdict (≈800 s).

**Next optimization — a hypothesis, re-assessed 2026-09-24.** The original
proposal was to take `internal/mcp/execution` off the non-root lane's
critical path by giving it its own lane job or sharding its tests. The 28
verified runs (§18.4) confirm the lane is the Fast race path's bound, but
not the size of the saving:

- The lane bounds 23 of 24 successful runs: median 752 s against 454 s for
  the slowest root shard in `race` runs.
- In three inspected lane logs, `internal/mcp/execution` was the last
  package to finish (312, 407 and 528 s). It started 160–235 s into the
  lane and ran alone for the final 227–393 s. Its neighbours in
  `internal/mcp` slowed in step, so part of the variance is runner speed or
  contention, not the package alone.
- `go test` already runs packages concurrently. Moving the same package to
  another job removes its contention with the rest of the lane but not its
  own run time; the ≈150 s estimate from §18.5 is unproven.
- **A faster Fast gate does not by itself make PRs green sooner.** Deep
  finished after Fast in 25 of 28 PR runs (median 928 s against 853 s), and
  its determinism job is Deep's longest (median 897 s, p90 913 s, 27
  runs). Main QA ends
  on determinism too (≈860 s). Until determinism shrinks, a lane saving
  moves runner-minutes and Fast's own check, not time to both-green.

**The end-to-end critical path.** A code PR is mergeable when both
required gates are green, so its completion time is the later of Fast and
Deep:

| Path | Median | Bound by |
|---|---|---|
| Fast · `race` race path | 815 s | the non-root lane (median 752 s) |
| Deep | 928 s | determinism (median 897 s) |
| Main QA | ≈870–920 s | determinism (≈860 s), then the lane (≈750 s) |

Any experiment must therefore report three results separately and never
substitute one for another:

1. the **Fast-only** change (lane end and Fast elapsed);
2. the change in **PR completion time**, the later of Fast and Deep;
3. the **runner-minute** cost.

A Fast-only gain with PR completion unchanged is a runner-time result, not
a latency result.

**A bounded comparison comes before any implementation, outside the change
that records this evidence.** Pair same-SHA runs of the arms in one time
window, without re-running failed work:

| Arm | Change |
|---|---|
| A | Current lane (control) |
| B | `internal/mcp/execution` in its own job |
| C | Same lane, with `internal/mcp/execution` started first |

Arm C needs proof from the lane log that the package actually started
first. Package order and `-p` do not establish it, because `go test`
decides when packages start.

A handful of pairs can show whether the median moves. It cannot show that
p90 does not regress; that claim waits for the provisional baselines to
mature. A determinism comparison of the same shape is the candidate that
can move PR completion time. Neither is implemented here.

### 18.6 Validation

- `cmd/cireport` tests:
  - **Separation:** another runner label, a self-hosted group, another shard
    count, another Go release line, another GOARCH, another runner image
    under the same label.
  - **Unverified, never reviewed:** a non-shard job (the lane) on another
    image, one measured job's log not read, one shard's metadata not read,
    four documents for four shards that are not the scheduled four, a
    shard's `meta.json` naming another shard, nothing read, platform not
    observed.
  - **Verified without an engine:** a real docs-only run whose jobs were
    all observed (toolchain `n/a`).
  - **Log parsing:** the real log head of job 107340167293 parses to
    `ubuntu-24.04` / `20260907.300.1`; the provisioner's `Version:` line
    before the group is ignored; an unclosed group, a missing group and a
    hostile value are refused. Through the fake API the collector follows
    the storage redirect, cuts a 1 MB log that ignores the byte range, and
    reads a missing log as unknown with a note.
  - **Still grouped:** another commit, slower jobs, a Go patch release and
    next week's image build.
  - **Trend and baseline:** the trend keeps verified and unknown cohorts
    apart; the baseline refuses an unverified, mixed, incomplete,
    reordered or empty-field reviewed key, and the old key shape.
  - **Re-run queue:** the real 34-minute re-run reads 33 s through the
    attempt endpoint, unknown through the runs list, with elapsed (222 s)
    and runner-minutes (3.1) unchanged. The collector reads the attempt
    endpoint and still matches the runs list's identity.
  - **Evidence source:** the report says `artifacts` or `metadata-only` and
    names every document decoded. The log line cannot carry a workflow
    command (tested with an injection payload).
- `cmd/rootshard` is unchanged from main.
- **Mutation proof.** Each of these was injected and failed a test:
  1. the cohort dropped from the group key;
  2. the full Go version keyed;
  3. a re-run falling back to attempt 1's `created_at`;
  4. a reviewed unknown cohort accepted;
  5. the collector ignoring the attempt endpoint;
  6. the attempt's `created_at` replacing identity;
  7. the runner group ignored;
  8. the image dropped from the key;
  9. jobs on different images not detected;
  10. a cohort verified from a subset of the shards' metadata;
  11. an image accepted from a subset of the measured jobs;
  12. a reviewed `mixed:` cohort accepted;
  13. cohort field names and emptiness unchecked;
  14. one job's image build presented as the run's;
  15. the attempt queue read only from completed jobs;
  16. a skipped job's stamp counted as a start;
  17. shards on different toolchain lines verified, or accepted by a
      reviewed baseline;
  18. the image read from the root shards only;
  19. the parser matching the provisioner group;
  20. an unsafe image value accepted;
  21. shard metadata matched to the scheduled shards by count, not index;
  22. a `meta.json` accepted for a shard it does not name;
  23. one shard's exact Go version presented as the run's when shards
      differ by patch release;
  24. runner labels joined without escaping their separators (including
      the trend's `|`);
  25. the observed image build dropped from the trend sample row;
  26. a toolchain value carrying a key separator accepted as observed;
  27. the run's exact toolchain stated from a partial shard-metadata read.
- `golangci-lint` reports 0 issues; the root CI walls pass.

### 18.7 Rollback

Revert the closeout commits. The trend returns to `workflow|class|job set`
groups and the old queue field, and job logs are no longer read.
No gate, check, release step or permission depends on any of it. A `v2`
report left in retention is refused by a reverted `v1` trend, which then
measures that run from metadata.

## 19. Conformance fixture reuse (first determinism slice)

The determinism job runs the whole module unsharded, shuffled, twice in one
package process (`go test -count=2 -shuffle=on ./...`). It is the longest job
of the Deep PR gate and of main QA (§18.5), and the root package dominates it.

**Evidence (Deep run 35999698583).** The determinism job took 14 min 51 s, of
which the shuffled double run took 13 min 49 s. The root package took
750.2 s; `internal/mcp/execution` 98.7 s.

**What cost the time.** `assertResponseConforms`,
`assertResponseConformsAdmin` and `mutatingResponseCase` each called
`loadContract` for every subtest. `loadContract` calls
`apicontract.LoadSpec`, which loads, parses and validates the entire OpenAPI
document every time. Measured before any edit (4-core box, Go 1.26.6, one
prebuilt test binary per side, fixed shuffle seeds):

| Measure | Value |
|---|---|
| One `LoadSpec` | ≈183 ms (5×20 iterations, 174–190 ms) |
| `loadContract` calls, root package, one pass | 129, of which 99 from per-subtest helpers |
| Share of the `TestConformance_` family's CPU in `LoadSpec` | 72 % (CPU profile). Handlers and response/request validation do not show up among the top entries. |

**Change (test helpers only).**

- Each top-level test loads the spec once and passes it explicitly to its
  subtests. `-count=2` runs each top-level test twice, so every invocation
  still gets a freshly loaded fixture.
- There is no global cache, no `sync.Once` and no `t.Parallel`, and no
  production code changes.
- The response check moved into `checkResponseConforms`, which returns the
  violation instead of failing the test. The helpers call it and fail as
  before.
- Tests that load or modify their own specification are untouched: the
  request-conformance tests, the drift and live gates, and `internal/apicontract`.

**Sharing is safe, and pinned.**

- `kin-openapi`'s `VisitJSON` only fills a package-level regex cache (a
  `sync.Map` keyed by pattern); the schema setters that assign fields are
  builders, not on the validation path.
- `apicontract_shared_spec_test.go` validates every documented JSON response
  status and request body against seven good and bad bodies (8,813
  validations). It then requires the loaded document to marshal
  byte-identically.
- The same file interleaves conforming and malformed responses on one shared
  spec, for both roles. The malformed cases are a wrong status, a wrong
  content type, a wrong field type, a missing required field, an
  undocumented field and a non-JSON body.
- Three injected defects each fail those tests: schema validation off,
  content-type check off, and a spec mutated during validation.
- Every test and subtest name of the root package is unchanged; the full
  `-v` result lists differ only by the two new tests.

**Measured result** (same machine, toolchain and binaries; runs
interleaved base/candidate).

| Level | Baseline | Candidate | Change |
|---|---|---|---|
| Fixture: `loadContract` calls per `-count=2` run of the contract tests | 258 | 92 | −166 (≈30 s of loading at 183 ms) |
| Family: `TestConformance_`, `-count=2`, 5 recorded seeds (101…505), median wall | 41.75 s | 14.31 s | −27.4 s (−66 %) |
| Suite: root package, `-count=2 -shuffle=20260421`, one run each (test-binary time) | 906.2 s (917.3 s in an earlier run) | 889.5 s | ≈−17 s; two baseline runs differ by 11 s, so this single sample does not separate the saving from noise |
| Gate: Deep determinism job on CI (job / shuffled double-run step / root package inside it) | 891 s / 829 s / 750.2 s (35999698583) | 884 s / 820 s / 744.6 s (36035947389, #1487) | −7 s / −9 s / −5.6 s; one sample each, within runner variation |

**Reading the result.** The saving is real and large where it lives: 166
fewer contract loads and −66 % on the conformance family. It is small at
the package and gate level. The root package's double run gained ≈17 s
locally and 5.6 s on CI, one sample each, both within run-to-run variation
(≈11 s between two local baseline runs). So this change removes a named,
repeated cost, but it is **not** a measurable determinism-gate speedup. It
does not move PR completion time or p90, and Deep determinism stays the
PR's longest job (§18.5).

The gap between the family (−27 s) and the package (−6 to −17 s) is
unexplained. Profile the whole root package before the next determinism
slice rather than assume the next family behaves like this one.

**Validation.**

- Targeted race run of the contract tests, `-count=2 -shuffle=303`: passed.
- Complete unsharded shuffled double run, `go test -count=2
  -shuffle=20260421 ./...` with `TEST_SEED=20260421` (the CI seed): **passed**, all
  110 packages, 1,000 s wall, the root package 941.6 s.
- `-count=2` stays in one package process; nothing is split or sharded, so
  state-leak detection across repetitions is unchanged.

**Unrelated test race found, not fixed here.** The root-package-only
candidate run failed once, in `TestChaos64_StaleServesDoNotStackRefreshes`:
`used 1 resolver calls, want 2`. The failure is in the test, not in this
change:

- The test reads the resolver call counter right after its 100 stale serves
  return. It never waits for the asynchronous refresh they started
  (`refreshAsync`) to reach the resolver.
- The log shows the refresh did call the resolver afterwards: its
  `i/o timeout` line comes just before the failure.
- Alone, the test passes 10/10 on both sides, and it passed in the full
  run with the same seed and order.
- The fix is to wait for the second call with the existing
  `waitForResolverCalls` helper. It is recorded for the flaky-test
  investigation and deliberately not bundled here.

The first attempt at these runs also failed 16 support-bundle tests with
`insufficient disk headroom`: the session's disk was full. Those runs were
discarded and repeated after freeing space.

**Side note.** `TestCredWall_LedgerStatesTheRealScanCount` counts source
files on disk, so every new test file changes the MCP ledger's
`SCANNED (N files)` claim. That is its design. This change moves it to
2,605.

## 20. Toolchain consistency: one pinned Go compiler

**Before (main `6ec745d`).** Nothing tied the compiler that CI qualifies to
the compiler that ships:

| Path | How it chose Go | What it actually used |
|---|---|---|
| CI jobs (`setup-go-cache`, `go-version-file: go.mod`) | the `go 1.26.6` line | Go 1.26.6 (`Setup go version spec 1.26.6`) |
| Release binaries (`build-release-binaries`) | same setup | Go 1.26.6 |
| Production `builder` + `maintbuilder` | floating `golang:1.27-alpine` | Go 1.27.1: digest `8a5910f3…` resolved in main's publish (run 35880661983) and E2E (run 36041845052) logs, `go version go1.27.1` |
| Maintenance E2E builder | same floating tag | Go 1.27.1 |
| Agent module | `go 1.25` is its language minimum, not a compiler | built by whichever of the above ran it |

So every image binary came from an unqualified compiler, and govulncheck
scanned a different standard library from the one shipped.

**Choice: Go 1.26.8.** It is the latest patch of the 1.26 line, published
2026-08-28, the same day as 1.27.1 (Go module proxy
`golang.org/toolchain` metadata). Security fixes ship to both supported lines
together, and 1.26 stays supported until Go 1.28.

Go 1.27.1 was tried first, because production already used it. Both modules
`go vet` clean on it, and the agent's tests pass. But the Fast gate's pinned
`golangci-lint` v2.5.0, even rebuilt with 1.27.1, cannot type-check the 1.27
standard library:

> could not load export data … export data version 4 is greater than maximum
> supported version 2

Taking 1.27 therefore means a lint-tool upgrade first, a separate change.
Choosing 1.26.8 moves the shipped compiler back from 1.27.1 to the line CI
qualifies. That is deliberate, not a match of numbers: after this change
every shipped binary comes from the compiler the tests, race runs, lint and
govulncheck ran on. The module minimums (`go 1.26.6`, agent `go 1.25`) are
unchanged.

**What changed.**

- **One source.** The root `go.mod` has `toolchain go1.26.8`.
  `actions/setup-go` reads that line, but only while `GOTOOLCHAIN` is not yet
  `local`; it exports `GOTOOLCHAIN=local` itself afterwards. So no workflow
  may set `GOTOOLCHAIN` before it runs.
- **Pinned images.** `builder`, `maintbuilder` and the E2E builder use
  `golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c`.
  Its index covers linux/amd64 and linux/arm64 (plus others), and the image
  config says `GOLANG_VERSION=1.26.8`, `GOTOOLCHAIN=local`.
- **Checks inside each builder stage.** Every stage:
  - states `ENV GOTOOLCHAIN=local`;
  - refuses to build unless `go env GOVERSION` equals the go.mod toolchain
    line (`maintbuilder` reads the root go.mod, copied to
    `/tmp/culvert-root.go.mod`);
  - checks the compiler recorded in the built binary.
- **CI checks.**
  - `setup-go-cache` prints and verifies the compiler in every job that uses
    it.
  - `build-release-binaries` verifies the compiler recorded in the proxy and
    agent binaries before they are hashed, attested or signed.
- **The agent module deliberately has no `toolchain` line.** With the default
  `GOTOOLCHAIN=auto`, one would send an older host Go to download 1.26.8, and
  the installer's offline source-build fallback would lose its fast host path.
  The agent's controlled builds are pinned through the root line and the
  checks above.

**The wall.** `toolchain_consistency_test.go` requires:

- go.mod has exactly one stable `toolchain` line, not older than the `go`
  line;
- the agent go.mod has no toolchain line, or the same one;
- every golang stage in every Dockerfile uses a digest-pinned
  `golang:<X.Y.Z>-alpine` matching that version, the same image everywhere,
  `ENV GOTOOLCHAIN=local`, the assertion before `go build`, and the
  recorded-compiler check;
- every `actions/setup-go` use reads `go-version-file: go.mod`, with no
  literal version;
- no workflow or action sets or assigns `GOTOOLCHAIN`;
- the last step of both composite actions is the verification.

It also fails if any Dockerfile that builds Go is not on its list. Sixteen
negative controls feed it conflicting declarations derived from the real
files, and each must be rejected:

- a different compiler in go.mod, a missing toolchain line, a release
  candidate;
- a floating tag, a tag without a digest, another version's tag, divergent
  digests between stages or between production and E2E;
- a dropped `GOTOOLCHAIN=local`, compiler assertion or binary check;
- an agent toolchain conflict;
- `GOTOOLCHAIN` set in a workflow `env`, a literal `go-version`;
- either composite action no longer verifying.

The cross-build wall (§11) now reads the builder `FROM` lines from the file
instead of restating the tag.

**Validation (local, Go 1.26.8).**

| Check | Result |
|---|---|
| Proxy + agent, linux/amd64 and linux/arm64, each built twice with the release flags | byte-identical per arch; `go version` reports `go1.26.8` for all four; arm64 binaries are static AArch64 ELF |
| In-build assertion, as in the Dockerfile | passes on go1.26.8; exits 1 on go1.27.1 |
| `go mod tidy -diff`, root and agent | clean |
| `golangci-lint` v2.5.0 `--new-from-rev origin/main` | 0 issues on go1.26.8; typecheck failure on go1.27.1 (above) |
| Agent module tests (`cd cmd/culvert-maint && go test ./...`) | pass on go1.26.8 and on go1.27.1 |
| Full suite, `go test -count=1 -shuffle=20260421 ./...`, `GOTOOLCHAIN=local` go1.26.8 | pending (running) |

Docker image builds need BuildKit, which the authoring session cannot run.
They are qualified by this change's PR: the Deep gate's image build, the
Fast gate's arm64 compile, and the maintenance E2E image build, whose log
shows the assertion's `compiler:` line.

**Performance comparisons.** Every sample in §18.4 and §19 ran Go 1.26.6.
The report's cohort key records the release line (`go1.26`) by design (§18.1),
so 1.26.6 and 1.26.8 runs share a cohort; the exact version stays in each
report's `toolchain` field. Any before/after comparison across this change
must state both exact versions. No timing benefit is claimed: this is a
consistency change.

**Upgrade procedure** (one reviewable change):

1. Pick the release from the Go module proxy (`golang.org/toolchain` list,
   or go.dev/dl). Confirm the CI analysis tools support it: build the pinned
   golangci-lint with the new compiler and run it. That is the step 1.27
   fails today.
2. Set `toolchain goX.Y.Z` in the root `go.mod`.
3. Resolve the digest of `golang:X.Y.Z-alpine` (the manifest-list digest,
   for example `docker buildx imagetools inspect golang:X.Y.Z-alpine`), check
   that the index has linux/amd64 and linux/arm64, and replace the three
   builder `FROM` lines with `golang:X.Y.Z-alpine@sha256:<digest>`.
4. Run `go test -run 'TestToolchain_|TestDockerfileCrossBuild' .`. It fails
   on any line left behind.
5. Let the PR's gates qualify it; the logs name the compiler at every step.

**Rollback.** Revert the PR. Images then build on the floating
`golang:1.27-alpine` (Go 1.27.1 today) and CI on the go.mod `go` line (Go
1.26.6), the unqualified split described above.

**Remaining, outside this change.**

- Adopting Go 1.27 needs the golangci-lint upgrade first.
- The installer's operator-side source-build fallback
  (`scripts/install.sh`, `CULVERT_GO_IMAGE` default `golang:1.25`, or host
  Go) builds an unsigned local agent with its own compiler. It is kept as is,
  so its air-gap behaviour is unchanged.
- The runtime `alpine:3.24` image and its `apk` steps remain mutable (a
  runtime-image refresh).
- `api-contract.yml` and `pr-api-governance.yml` call `actions/setup-go@v7`
  by tag. They read the same go.mod line, so their compiler agrees, but the
  action itself is not SHA-pinned.
