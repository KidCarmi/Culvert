# Integration Readiness: #1528 appliance line on latest main (Workstream A)

Prepared by OPUS on 2026-10-23 under owner directive 6369573402. The tree is pushed only to `review/1528-integ-on-main`, which triggers no workflow:
- no PR exists, so no Fast, Deep, QA or Security CI has run on this tree;
- main is not fast-forwarded;
- the frozen #1528 head `4524311b` is untouched;
- no OVA was built, no lab run was dispatched, and no VM action was taken.

Status: MERGE / PILOT / RELEASE remain **NO-GO**.

## Identities

| Item | Commit | Tree |
|---|---|---|
| Base: `main` | `e380b9013a3459932ae84d908624fff6f1655474` | |
| Merged: `review/1528-docs-reconcile` | `95e68e658ed1189953143d638ee236da9b4aeacd` (contains `cfae7d67` R1/R5, which contains frozen `4524311b`) | |
| Merge commit | `369c069d` | `712718519c7142f41a0c0630d4c178d1c66f2d07` |
| + session-admission fix | `e5dc751f92646d8dbe7e1ba0cfc670ccca15bea5` | `93af1bf6e3fd55aed5d70c508e3f526c646e7df0` |
| + R1 test lint | `bf79ed0cce2c010debbf0045c9f2c4a88a6e3329` | `24c18d6e5b351b4596fc1e80036adab8b576db33` |
| + gitleaks fingerprint pin | `ce78db1b80a116cf9a204f94034977de4515436c` | `485c940a13ade7302c4c184c13edeafde3097117` |
| + merge of latest `main` `3c4bf491` (three Dependabot bumps) | **`78f0b6796bf14c73f1579eddaf30ecdbdf50323d`** | **`7cc07e983dc321e6a1f7587d554b2ec1bfa852ea`** |
| Pushed as `review/1528-integ-on-main` (runs no workflow) | this record's commit, documentation only, atop `78f0b679` | |

Ancestry is verified: `4524311b ⊂ cfae7d67 ⊂ 95e68e65 ⊂ tip`, and `e380b901 ⊂ tip`. Toolchain is go1.26.10 (main's pin).

## Conflict resolution

### Textual conflicts (8), resolved in `369c069d`

| File | Resolution | Why |
|---|---|---|
| `ui_session.go` | Kept main's `classifyUISession` and three-way verdict. Kept #1528's `uiSessionAudience` stamp. | Both are security fixes to the same gate; neither may be dropped. See the semantic conflict below. |
| `admin_ui_listener_chaos_test.go` | Main's `startTestAdminUI` helper (5 call sites), plus #1528's bounded `select` on cleanup. | Main refactored; #1528 bounded a hang. Each fix is independent of the other. |
| `d0_helpers_test.go`, `ui_routes_meta_test.go` | Route count set to **254**: #1528 has 253, plus main's `/api/mcp/servers/refresh`. Changelog lines added. | The count is the sum of both route sets. |
| `.github/workflows/_build-image.yml` | Kept #1528's "Candidate version" step and main's `setup-buildx-action` v4.4.1 pin. YAML validated. | They are orthogonal edits. |
| `docs/agent-context/errata.md` | Both sections kept. | Both are additive. |
| `docs/api/API-INVENTORY.md`, `frontend/src/api/types.gen.ts` | **Regenerated** (`make api-bundle`; `generate-types.sh` under Node 24.19.0). Not hand-merged. | These are generated files. Hand-merging them is how drift starts. |

### Semantic conflicts (no textual conflict, found by building and testing)

1. **Duplicate symbol `stampOf`.** The build failed. The #1528 version was renamed to `traceTimeOf` in `backups_list_trace.go`.

2. **The admin session gate regressed (security), fixed in `e5dc751f`.**
   - Main's SEC-UISESS-1 makes a *refused* admin cookie answer 401 and get cleared, and never fall back to HTTP Basic.
   - #1528's audience/roster checks returned an error from `readUISessionCookie`, which `resolveUISession` maps to *absent*.
   - On the merged tree, a proxy-issued token or a deleted user's cookie therefore fell through to Basic again: `/api/auth/status` reported `loggedIn:true`.
   - This was proven red by `TestSECUISESS1_StatusRefusedCookieDoesNotFallBackToBasic` before the fix and green after.
   - **Fix:** one decision. `classifyUISession` now checks provider plus audience, the enrolled role, roster membership, and a roster-capped role. `verifyUISessionCookie` only verifies the signature, expiry and revocation. The resolver and the strict reader both classify through it.

3. **Where the two sides set different policy, the stricter one is kept.** This is not a new trade-off.
   - **Empty role is refused.** Main kept it as pre-RBAC admin compatibility. #1528's required audience already refuses every pre-upgrade cookie once (one re-login).
     - **Correction (Workstream B pre-review F-B1):** the claim originally recorded here, that "this build never mints a role-less session", was **false** on this tree. A pre-RBAC roster (a bare array with no role field) loaded its accounts with role `""`, login minted a role-less cookie, and the gate refused it on every request: a login loop that locked the admin out. It also left such a roster without a legacy admin, which could reopen first-time setup.
     - **Fix:** fixed on `review/1528-wsb-fixes`. The roster loader migrates `""` to `admin` (owner decision), so a role-less session really is never minted, and `TestFB1_*` pins it.
   - **The session role is capped by the current roster.** Demotion takes effect immediately; promotion needs a fresh login.
   - Main's SEC-UISESS-1 fixtures now carry the audience and seed the roster role under test. Main's empty-role control test is replaced by `TestSECUISESS1_EmptyRoleIsRefused`.

4. **R1 tests had never been linted.** They lived only on review branches, which run no workflow. golangci-lint v2.5.0 found `tooManyResultsChecker`, `G204` and `noctx`. Fixed in `bf79ed0c` with no assertion change.

5. **gitleaks: a full-range scan found a #1528 fixture** (`recovery_secrets_test.go` at `42ba4f38`, a synthetic setup token). #1528's PR scans never reached it, because each PR run covers only that push's range. It is pinned as one exact fingerprint, with provenance, in `ce78db1b`.

### Sync to latest main

During verification, main advanced from `e380b901` to `3c4bf491`: brotli 1.2.6, etcd/server 3.7.2 and klauspost/compress 1.20.3.
- The only conflict was adjacent `require` lines in `go.mod`. Main's versions are taken, and the appliance line's `xml-roundtrip-validator` require is kept.
- `go mod tidy` reproduces main's `go.sum` delta exactly.
- Re-run on `78f0b679`, all PASS:
  - full `go test ./...` (119 ok);
  - `-race -count=2 -shuffle=on` over feedsync, catdb, storeguard, logstore and shutdown;
  - govulncheck;
  - gosec;
  - golangci-lint `--new-from-rev origin/main` (0 issues);
  - fork integrity;
  - `go mod verify`.
- Determinism was run on `ce78db1b`; the sync since then is dependency-only.

## Changed-file inventory

Complete lists are kept in the scratchpad, `integ-logs/`:

| Comparison | Files | Breakdown |
|---|---|---|
| tip vs main `e380b901` | 1226 | 1055 A / 171 M. 655 are `third_party/`: badger, ristretto, rekor-tiles and crewjam-saml forks, each fork-verified. |
| tip vs frozen `4524311b` | 188 | 74 A / 112 M / 1 D / 1 R |
| tip vs #1528 line `95e68e65` | 172 | Main's 118 non-merge commits, plus this integration |
| Touched by both sides | 39 | Integration-risk set; every one is covered by the gates below |

## Behaviour differences

### Versus frozen `4524311b` (the identity behind OVA `27006cf4`)

- **R1:** an abandoned category-feed writer latches `WriteAbandoned`. Retry is quiesced. A late return cannot certify. Restart quarantines and reimports. Health, operator row and gauge report "restart required".
- **R5:** splash failed-unit display and the 80-column budget.
- **From main** (118 commits):
  - toolchain go1.26.10 (GO-2026-6809);
  - SEC-UISESS-1 (now unified, see above);
  - SEC-TUNHOST-1 (an inspected tunnel's inner host is pinned to the authorized destination; a bracketed non-IP or absent authority is refused);
  - SEC-ADMISSION-OWNER-1;
  - the admin-roster durability diagnostics row;
  - MCP First-Canary peer freshness and the `/api/mcp/servers/refresh` route;
  - connlimit/catgroup performance;
  - Vite 8.3.5 dist rebuild.
- **Integration:** the stricter session posture (empty role refused, roster-capped role). This is one re-login at upgrade, already implied by #1528's audience.
- **No application bytes have shipped.** Shipping this needs a new candidate identity and R4 delta qualification; OVA `27006cf4` does not contain it.

### Versus main `e380b901`

The whole appliance line, now integrated:
- the OVA build path and first boot;
- console and recovery;
- maintenance agent and release proof;
- restore in place;
- the F-DISK badger/ristretto forks;
- ClamAV posture;
- setup token;
- SSO surrogate and login binding;
- backup crypto.

Plus R1/R5 and the session posture above.

## Gates on the exact tree (local)

| Gate | Tree | Result |
|---|---|---|
| `go build ./...`, `go vet ./...` (root + maint) | `ce78db1b` | PASS |
| `go test ./...` full | `e5dc751f` | **PASS**: 119 ok / 0 FAIL. Tests changed after this only in R1 lint (rerun below); the two later commits change no production Go. |
| R1 chain + catdb/storeguard/logstore/shutdown, `-race -count=2 -shuffle=on` | `e5dc751f` | **PASS** 546 / FAIL 0 / SKIP 4. The skips are the subprocess entry point ×2 and a root-skipped permission test ×2. |
| Every R1 chain step (stall, quiesce, late-return-no-certify, reopen/quarantine/reimport, SIGTERM bounded, SIGKILL recover, deadline not renewed) | `e5dc751f` | PASS ×2 each |
| Root R1 surface + shutdown + SEC-UISESS-1, `-race -count=2 -shuffle=on` | `e5dc751f` | **PASS** 248 / 0 / 0 |
| feedsync `-race -count=3 -shuffle=on` after the lint fix | `bf79ed0c` | PASS |
| R5 `boot-splash_test.sh` | `369c069d` (splash files are unchanged since) | PASS |
| `cmd/culvert-maint` vet + tests | `369c069d` (unchanged since) | PASS |
| `make api-verify` | `369c069d` (no API change since) | PASS |
| frontend `npm run verify` (Node 24.19.0) | `369c069d` (no frontend change since) | PASS. npm audit reports 2 moderate advisories in vitest (pre-existing on main; dev-only). |
| golangci-lint v2.5.0 (built with go1.26.10) `--new-from-rev main` | `ce78db1b` | **0 issues** |
| govulncheck v1.5.0: root, maint, releaseproof | `ce78db1b` | PASS ×3 |
| gosec v2.27.1 with CI excludes ×3 | `ce78db1b` | PASS ×3 |
| gitleaks 8.30.0 `main..tip` + policy canaries + fork integrity | `ce78db1b` | PASS |
| gitleaks full first-parent history | `ce78db1b` | 1 finding, **pre-existing on main** (`b8ac5ac2` hashcache bench fixture). Not introduced here and not reached by a PR-range scan. Left untouched. |
| staticcheck 2025.1 | `ce78db1b` | PASS |
| shellcheck (Deep Gate set + splash) | `ce78db1b` | PASS |
| Determinism `-count=2 -shuffle=on ./...` | `ce78db1b` | **PASS** 119 ok / 0 FAIL. A first run was voided by session-disk ENOSPC and discarded, not counted. |

### NOT RUN (cannot run without a PR or a main push)

- **Fast/Deep PR Gate CI** (`✅ … APPROVED`): needs a PR.
- **Deep image/compose/trivy/appliance-lifecycle/real-ClamAV jobs:** need the CI image build.
- **QA and Security gates:** these are pass-through shells on PRs. Their full runs happen only on main pushes, and a main push is not authorized.
- **CodeQL:** runs on the PR.
- **R5 live VGA proof:** belongs to the R4 replacement boot.
- **Lab / OVA:** not authorized.

`cfae7d67` receipts are **not** reused as merged-root proof. Every result above was produced on the integrated tree.

## True blockers

1. **CI has not run.** Fast/Deep gate verdicts need a PR from `integ/1528-on-main` to `main`, which needs an explicit OK to push it and open the PR.
2. **Owner review of the session-posture decision** (stricter of both sides) before any merge.
3. Merge, pilot and release remain separately gated. A new candidate identity plus R4 delta qualification is required before shipping any of this.
