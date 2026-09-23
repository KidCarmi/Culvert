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

### Next original-plan follow-up (NOT in this stage)

`test/e2e/maint-agent/Dockerfile.e2e` — used by the maint-agent update,
backup-upgrade, install-lifecycle and appliance-catalog-update E2E workflows —
has drifted from production: `golang:1.26-alpine` (production 1.27),
`alpine:3.22` (production 3.24), a build-time `go mod tidy` (the divergent-recipe
step production removed), and no `-trimpath`/`-buildvcs=false`. Aligning it is
the next step; it was left alone here to keep this change to the production
image.

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
and is not taken here.

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
| Policy / config / store (stale-version and in-lock 409s, log ring, import arms, top-hosts raced insert, catalog comparator arg order, `WaitOp` cancel, crash collector) | 26 (25 + the `connLimiter.Enable` import arm found by qualification round 1, §14.7) | Earlier test state, or a race / map-order interleaving | `TestCovIsoPolicy_*` (`coverage_isolation_policy_test.go`). Interleavings are forced deterministically, e.g. the existing `policyWriteStateDecisionHook` seam, a lock held while a named frame is parked, or a context cancelled inside the round trip, rather than hoped for |
| Non-root packages (`internal/authcost`, `mcp/upstreamclient`, `policylearn`, `saasfeed`, `urlcat`) | see files | Timing and ordering of the package's own tests | `TestIsolation_*` in each package's `coverage_isolation_test.go` |

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
