# TAC Repository Extraction — Migration Record

- **Status:** IN PROGRESS (Phase 1 inventory committed before any repository mutation).
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

## Commit mapping (filled in as phases complete)

| Item | Source commit | Destination commit |
|---|---|---|
| Inventory record (this file) | (this commit) | — |
| tac-platform extraction | `2f02895…` | _recorded in tac-platform/HISTORY-MIGRATION.md_ |
| tac-infrastructure extraction | `2f02895…` | _recorded in tac-infrastructure/HISTORY-MIGRATION.md_ |
| Culvert cleanup | _Phase 7_ | — |

## Rollback (fully reversible)
1. The nested `tac-platform/` and `tac-infra/` directories remain in this Culvert branch until Phase 7; if extraction is abandoned, nothing changed in Culvert.
2. Before Phase-7 cleanup, tag `pre-tac-extraction` is created on this branch; `git reset --hard pre-tac-extraction` restores the pre-cleanup tree.
3. The extracted repositories are additive (new repos); deleting them has no effect on Culvert.
4. Culvert `main` is never touched.

## Gates before Culvert cleanup (Phase 7)
tac-platform builds independently · unit + PostgreSQL tests pass without `-p 1` · Docker Compose acceptance passes · tac-infrastructure validates · contract compatibility passes · file-digest match source↔destination · no secrets/test-credentials migrated · no DB state/private evidence migrated. Only then: replace directories, confirm Culvert CI green, retain recovery tag.
