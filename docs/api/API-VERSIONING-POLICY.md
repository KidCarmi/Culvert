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

## Breaking-change exception process

A breaking change may ship only with ALL of:

1. A PR label `api-breaking-change` (the reviewed override; never a silent env var).
2. **Rationale** in the PR body — why the break is necessary.
3. **Migration instructions** for consumers.
4. **Deprecation evidence** where applicable (the field/op was deprecated first —
   see the deprecation policy).
5. A **named approver** from CODEOWNERS for `api/`.
6. The **API version impact** recorded (MAJOR bump + CHANGELOG entry).

The override relaxes Gate 7 for that PR only; the change is still reviewed.

## Stability tiers (`x-culvert-stability`)

- `stable` — covered by this policy; breaking changes need the exception process.
- `beta` — may change with a MINOR bump + CHANGELOG note; one release of warning.
- `experimental` — may change or be removed at any time; not covered by compat.

New production endpoints default to `stable` and **cannot merge without contract
coverage** (route-coverage gate).
