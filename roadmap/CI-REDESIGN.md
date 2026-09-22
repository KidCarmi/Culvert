# CI/CD Redesign — Lane Architecture & Retirement Checklist

Status: **retirement steps 2–4, §3.9 docker-skip, AND steps 5–7 in
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

The signing/publish jobs (`docker`, `catalog-pipeline`, `release`) and
`auto-tag` gate on the gate **workflow files** concluding success for the
commit on its main push, via `.github/scripts/require-gate.sh` (bound to the
workflow path + main-push provenance — a spoofed check-run *name* or a
tag-triggered re-run of the same SHA can no longer self-approve). This is the
in-repo backstop.

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

**Deferred (same class, Phase 2):** on a *main* push the `docker` job publishes
+ cosign-signs `ghcr:latest` in parallel with the gate, with no gate
dependency — a commit that later fails the gate has already shipped a signed
`latest`. Fix by gating the main-push publish/sign the same way (wait mode).

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
same-pinned-toolchain** reproduction (`setup-go-cache` pins Go 1.25.11 for both),
not an independent-environment rebuild — SLSA's trusted builder covers build
integrity; F1 verifies *determinism* (catches dep/toolchain-drift/tampering
nondeterrminism between hashing and signing). The verify job is `contents: read`
only (signs nothing — deliberately no `id-token`). **Guardrail:** never add
`always()`/`success()`/a status function to `provenance`'s `if:`, or the gate
silently opens. **Remaining follow-up** — the **Docker image binary**
(`Dockerfile`) still builds with default `-buildvcs=auto`, and its `.dockerignore`
strips tracked files (`*_test.go`, `*.md`, …) while keeping `.git`, so the
in-container `git status` sees those as deleted and the image binary ships
`vcs.modified=true` (not tree-state reproducible). Disjoint provenance surface
(the image has its own cosign signature), tracked separately.

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

## 10. Stage 2B — the cross-workflow race duplication (NOT yet implemented)

On a main push the full `-race ./...` suite runs twice in two different
workflows. Removing one copy is worth roughly a `qa-logic` (~33 min of runner
time), but it cannot be done by deleting a job, because **the two workflows do
not run on the same events**:

| Event | qa-gate.yml | security-release-gate.yml |
|---|---|---|
| push → main | yes | yes |
| pull_request → main | jobs skip (pass-through) | pass-through |
| tag `v*` | **no trigger at all** | yes |
| schedule (weekly) | no | yes |
| workflow_dispatch | yes (any ref) | yes |

So making Security consume QA's race evidence would leave **tags, the weekly
cron and Security-only dispatches with no race evidence at all** — and
`require-gate.sh` accepts only a main-push run of a named workflow for the exact
SHA, so a tag run cannot borrow QA's. Any 2B design has to answer that
explicitly rather than assume the main-push case generalises.

The two shapes worth weighing:

1. **Shared reusable workflow.** Extract the race suite into a
   `workflow_call` workflow both gates invoke. Each event still gets its own
   execution, so nothing is lost on tags or cron — but the main-push duplication
   is only removed if one caller also learns to skip when the other has already
   run for the same SHA, which reintroduces the evidence question.
2. **Event-scoped ownership.** QA owns the race suite on main pushes; Security
   skips it there and consumes QA's result, while keeping its own execution on
   tags, cron and dispatch. This removes the duplication outright, but it makes
   a Security verdict on main depend on a QA run, so
   `.github/release-evidence.txt` must continue to require BOTH workflows (it
   already does — both rows are `mandatory`) and the skip must fail closed when
   QA's run for that SHA is absent, not silently pass.

Option 2 is the one that actually removes the duplicate execution. It is also
the one that touches release evidence, which is why it is its own reviewed
change and not part of 2A.
