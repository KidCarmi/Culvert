# TAC Repository Extraction — Migration Record

- **Status:** COMPLETE (all sandbox-runnable gates passed; nested directories replaced with pointer stubs; Culvert build confirmed unaffected).
- **Source:** `KidCarmi/Culvert`, branch `claude/culvert-tac-support-framework-vf4plr`, commit `2f0289533b2606ded4fde42bd0078600305d46e8` (recorded before extraction).
- **Destinations:** `KidCarmi/tac-platform` (executable TAC product code) · `KidCarmi/tac-infrastructure` (desired infrastructure state).
- **Method:** history-preserving extraction with `git filter-repo` on separate working clones. Culvert history is never rewritten or force-pushed. Nested copies are **not** removed from this branch until every migration gate passes (Phase 7).

This file is the authoritative migration record and remains in Culvert as the pointer to the extracted repositories after cleanup.

---

## Phase 1 — Migration inventory (classification)

Every file related to the extraction, classified. Counts from `git ls-files` at the source commit.

| Path (source) | Files | Classification | Destination | Path mapping |
|---|---:|---|---|---|
| `tac-platform/**` | 41 | **move to tac-platform** | tac-platform (repo root) | `tac-platform/` → `` (root) |
| `tac-infra/**` | 7 | **move to tac-infrastructure** | tac-infrastructure (repo root) | `tac-infra/` → `` (root), then restructured |
| `docs/support/infra-ops/**` | 40 | **move to tac-platform** (design + qualification + Python test-oracle) | tac-platform | `docs/support/infra-ops/` → `docs/design/` |
| `docs/support/*.md` (appliance supportability: ARCHITECTURE, SUPPORT-BUNDLE-SPEC, COLLECTOR-CONTRACT, REDACTION-MODEL, DIAGNOSTIC-COMMAND-FRAMEWORK, HEALTH-AND-EVENT-MODEL, SECURE-UPLOAD-ARCHITECTURE, SUPPORTABILITY-THREAT-MODEL, SUPPORTABILITY-TEST-STRATEGY, SUPPORTABILITY-ROADMAP, CURRENT-STATE-GAP-ANALYSIS, README) | 12 | **remain in Culvert** (appliance-side supportability program) | Culvert | — |
| `docs/support/TAC-CLOUD-ARCHITECTURE.md`, `docs/support/ANALYSIS-MODEL-DECISION.md` | 2 | **remain in Culvert** (design reference for the appliance's outbound integration + cloud-first decision; not code) | Culvert | copied-by-reference to tac-platform docs index |
| `docs/adr/0008–0022` | 15 | **remain in Culvert** (single sequential engineering decision log; 0019–0022 pertain to tac-platform and are cross-referenced) | Culvert | — |
| `tac-platform/evidence/*.txt` | 3 | **move to tac-platform** (synthetic test transcripts; no secrets) | tac-platform | with `tac-platform/` |

### Ambiguous files — resolved explicitly
- **`docs/support/infra-ops/qualification/staging-proof/tac_proof.py` (+ evidence):** the Python behavioral oracle for the Go spine → **tac-platform** (`docs/design/qualification/staging-proof/`). It is a test oracle, not appliance code.
- **`docs/support/TAC-CLOUD-ARCHITECTURE.md` / `ANALYSIS-MODEL-DECISION.md`:** describe the cloud but are the *appliance's* outbound-integration counterpart and the cloud-first decision that the appliance's support framework depends on → **remain in Culvert** (design, not application code). tac-platform links to them; no code duplication.
- **ADRs 0019–0022 (infra-ops decisions):** kept in Culvert's ADR log to avoid renumbering a sequential record; tac-platform's `docs/design/` references them. Rationale: ADRs are decision history, not shippable code.
- **`docs/support/infra-ops/qualification/reviews/*` (9 reviewer reports):** part of the platform qualification program → **tac-platform** (`docs/design/qualification/reviews/`).

### Not migrated (verified absent from git)
- Generated database state (`evidence/*.db`) — gitignored, never committed.
- `__pycache__` / compiled binaries — gitignored.
- Local environment files, credentials, provider secrets — none exist (see the per-repo secret-scan reports).

### Copy-as-versioned-shared-contract
- No shared *source-code* package is extracted. The cross-boundary contracts (support-bundle format, upload API, case identifiers, appliance identity, error codes, protocol-version negotiation) are **design-owned by Culvert** (appliance is the producer of bundles / consumer of receipts) and specified as versioned schemas — see `CONTRACTS-OWNERSHIP.md` (Phase 5). Culvert does **not** depend on any `tac-platform` internal Go package.

### Archive / delete-after-verification
- After all Phase-7 gates pass: `tac-platform/` and `tac-infra/` directories in this Culvert branch are **replaced with this migration record + pointers** (not deleted outright), a recovery tag `pre-tac-extraction` is created first, and Culvert CI is confirmed green. Nothing is deleted before gates pass.

---

## Commit mapping

| Item | Source (Culvert) | Destination |
|---|---|---|
| Inventory record (this file) | `2ca7400` | — |
| tac-platform extraction (preserved history) | `2f02895` | `KidCarmi/tac-platform` root `8bf03ca` → `9744cbf` (7 commits, original authorship) |
| tac-platform initialization (module path, PG schema isolation, scaffolding) | — | `KidCarmi/tac-platform` `106dbdf` (main HEAD) |
| tac-infrastructure extraction (preserved history) | `2f02895` | `KidCarmi/tac-infrastructure` `d9fdaa6` (1 commit, original authorship — only ever in one commit; not squashed) |
| tac-infrastructure initialization (structure, provenance pinning, CI) | — | `KidCarmi/tac-infrastructure` `b88960a` (main HEAD) |
| Culvert cleanup (this commit) | _this commit_ | replaces `tac-platform/`, `tac-infra/`, `docs/support/infra-ops/` with pointer stubs |

### Byte-faithfulness proof (Git blob-SHA equality — stronger than diff)
| Extracted repo | Source blobs (Culvert @HEAD) | Destination blobs (pre-init commit) | Match |
|---|---|---|---|
| tac-platform | `tac-platform/` ∪ `docs/support/infra-ops/` = `c6246447…` | `@9744cbf` = `c6246447…` | ✅ identical |
| tac-infrastructure | `tac-infra/` = `8636a25d…` | `@d9fdaa6` = `8636a25d…` | ✅ identical |

(Aggregate = `sha256` of the sorted list of every file's Git blob SHA. Identical
blob SHAs ⇒ byte-identical content.)

## Recovery
- Recovery tag **`pre-tac-extraction`** created on this branch **before** cleanup;
  its tree still contains the full nested source directories. Restore with
  `git reset --hard pre-tac-extraction`.
- The extracted repositories are additive; deleting them has no effect on Culvert.
- Culvert `main` was never touched; this branch was never force-pushed.

## Rollback (fully reversible)
1. The nested `tac-platform/` and `tac-infra/` directories remain in this Culvert branch until Phase 7; if extraction is abandoned, nothing changed in Culvert.
2. Before Phase-7 cleanup, tag `pre-tac-extraction` is created on this branch; `git reset --hard pre-tac-extraction` restores the pre-cleanup tree.
3. The extracted repositories are additive (new repos); deleting them has no effect on Culvert.
4. Culvert `main` is never touched.

## Gates before Culvert cleanup (Phase 7) — results

| Gate | Result |
|---|---|
| tac-platform builds independently | ✅ `go build ./...` green in the extracted repo |
| unit + PostgreSQL tests pass **without `-p 1`** | ✅ `go test -race -count=1 ./...` green (per-schema isolation) |
| file-digest match source ↔ destination | ✅ Git blob-SHA equality (see table above) |
| no secrets / test-credentials migrated | ✅ full-history scan clean (`SECRET-SCAN.md` in each repo) |
| no DB state / private evidence migrated | ✅ `evidence/*.db` gitignored, never committed |
| Culvert build unaffected after removal | ✅ `go build ./...` + `go vet` green post-cleanup |
| recovery tag retained before deletion | ✅ `pre-tac-extraction` |
| Docker Compose acceptance | ⏳ deferred to tac-platform CI (Docker daemon not available in the migration sandbox) — see `HISTORY-MIGRATION.md` |
| tac-infrastructure `tofu validate` | ⏳ deferred to tac-infrastructure CI (`opentofu/setup-opentofu`; OpenTofu release host blocked by the sandbox proxy) |
| contract compatibility | ✅ contracts specified + owned (`CONTRACTS-OWNERSHIP.md`); scheduled compat lane defined (`CROSS-REPO-CI.md`) |

## Companion documents (remain in Culvert)
- `CONTRACTS-OWNERSHIP.md` — Phase 5: versioned cross-repo wire contracts, one owner each.
- `CROSS-REPO-CI.md` — Phase 6: independent per-repo builds + scheduled compatibility lane.
- `REPOSITORY-SETTINGS.md` — recommended (not auto-applied) GitHub settings for the new repos.
