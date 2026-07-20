# API Versioning & Compatibility Policy

## Versions

- **Product version** — the Culvert binary/release tag.
- **API contract version** — `info.version` in `api/openapi/openapi.yaml`
  (`x-culvert-api-contract-version`), SemVer. Starts at `1.0.0`.

The two are traceable per release (see `docs/api/API-IMPLEMENTATION-PLAN.md`,
release integration). The contract version bumps independently of the product
version when the API surface changes.

## SemVer rules for the contract

- **PATCH** (`1.0.x`) — additive documentation, examples, description fixes; no
  schema change.
- **MINOR** (`1.x.0`) — backward-compatible additions: new operations, new
  optional response fields, new optional request fields, new enum values on
  response-only enums.
- **MAJOR** (`x.0.0`) — any breaking change (see below). Requires the exception
  process.

## What counts as breaking (Gate 7, oasdiff `--fail-on ERR`)

- Removing an operation, response, or field.
- Renaming a field or `operationId`; reusing an `operationId` for new behavior.
- Making an optional field required; narrowing accepted input; changing a type;
  incompatible enum or nullability change.
- Changing authentication/authorization requirements incompatibly.
- Removing a content type; changing a parameter's location.

## The gate

`scripts/openapi/breaking-check.sh` (oasdiff, pinned) compares the working-tree
contract against `origin/main`. Because this is the baseline-establishment change,
the gate exits 0 when the base has no contract; **it becomes mandatory once the
baseline merges.** After that, a breaking change fails CI.

## Breaking-change enforcement (Gate 7 — merge-blocking)

Gate 7 runs in `.github/workflows/pr-api-governance.yml` as the check
**`API · breaking-change (blocking)`** on every PR to `main` that touches the
contract. It compares the PR contract against the base contract with pinned
`oasdiff` in **strict mode**: an unavailable tool is a HARD failure (the gate
never passes without running), and any breaking change fails the job.

**Required branch-protection settings** (an admin must enable these once — they
cannot be set from the repository):

- Require status check **`API · breaking-change (blocking)`**.
- Require status check **`API · client-generation (blocking)`** (Gate 9).
- Require review from **Code Owners** (CODEOWNERS already scopes `api/**`,
  `docs/api/**`, `internal/apicontract/**` to the API owner).

Until an admin enables the required checks, the workflow is still **technically
hard-failing** — a breaking change turns the job red — but merge is only
*blocked* once the check is marked required.

## Breaking-change exception process

An intentional breaking change may ship only with ALL of:

1. The PR label **`api-breaking-approved`** — the reviewed override. The gate is
   NEVER relaxed by an environment variable; only this label (which requires repo
   write access to apply) plus the sections below plus CODEOWNER approval.
2. A PR-body line **`Breaking-Change-Rationale:`** — why the break is necessary.
3. A PR-body line **`Migration-Instructions:`** — how consumers migrate.
4. A PR-body line **`Version-Impact:`** — the MAJOR bump + CHANGELOG entry.
5. **CODEOWNER approval** for `api/` (enforced by branch protection, above).
6. **Deprecation evidence** where applicable (the field/op was deprecated first —
   see the deprecation policy).

The workflow verifies (1)–(4) mechanically; CODEOWNER approval (5) is enforced by
branch protection. The override relaxes Gate 7 for that PR only; the change is
still fully reviewed.

## Stability tiers (`x-culvert-stability`)

- `stable` — covered by this policy; breaking changes need the exception process.
- `beta` — may change with a MINOR bump + CHANGELOG note; one release of warning.
- `experimental` — may change or be removed at any time; not covered by compat.

New production endpoints default to `stable` and **cannot merge without contract
coverage** (route-coverage gate).
