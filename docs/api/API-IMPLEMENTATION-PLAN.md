# API OpenAPI Program — Implementation Plan & Status

Tracks the sliced rollout from ADR-0007. Status as of 2026-07-19.

## Slice status

| Slice | Scope | Status |
|---|---|---|
| 0 | Evidence + architecture (inventory, research, risk register, decision matrix, ADR, plan, independent review) | **DONE** |
| 1 | Contract baseline (root, shared schemas, security schemes, representative high-value endpoints, style guide, lint, bundle, offline docs) | **DONE** |
| 2 | Route-coverage enforcement (live enumeration, classification, missing-route + phantom detection, exemption mechanism) | **DONE** |
| 3 | Full supported-API coverage (document all supported endpoints; retire exemptions) | **IN PROGRESS** — 143/284 documented (read surface complete across all domains; first write endpoints documented with request-conformance tests), 141 exempt remaining |
| 4 | Runtime contract tests (request/response/failure/authz/tenant) | **CORE DONE** — 73 live response-conformance tests through real handlers; growing with Slice 3 |
| 5 | Compatibility + generation (breaking-change mandatory post-baseline; committed Go client; changelog; 3.1.1 re-eval) | **SCAFFOLDED** (scripts pinned; deep lane) |
| 6 | Docs + release integration (vendored Redoc/Scalar under CSP; visibility-filtered outputs; release traceability) | **PARTIAL** (offline HTML shipped; richer docs + release wiring TODO) |

## What is enforced today (in the required `go test ./...`)

- Spec validation (Gate 1), style-lint (Gate 2), live route coverage + exemption
  expiry (Gate 3), request/response/authz conformance (Gates 4/5/6), generated-artifact
  drift (Gate 8). Negative tests demonstrate each gate fires.

## Adversarial review outcomes (fresh reviewer, 2026-07-19)

Fixed in this change:
- **HIGH-1** sensitive-schema lint was dead (compared a YAML boolean against the
  string `"true"`) — `extString` now coerces booleans; `ConfigBackup` carries an
  `x-culvert-open-justification`; regression test added.
- **MED-HIGH-3** manifest `min_role`/`mutating`/`audit_expected` are now bound to
  the live router (ROLE/MUTATING/AUDIT DRIFT), so the manifest cannot diverge from
  runtime authorization; role-drift negative test added.
- **MED-6** exemptions are capped at a 270-day horizon (no indefinite deferral).
- **MED-7** offline docs are visibility-filtered (public build + no-leak test) —
  fixed proactively before the review.
- **HIGH-2 (partial)** response-conformance coverage raised from 3 to 5 live-tested
  read ops; see limitations below.

Accepted / latent (in the backlog):
- **HIGH-2 residual** — 14 of 19 documented ops still lack a live response test
  (POST/destructive or fragile-global handlers), and opaque `additionalProperties:true`
  response schemas (CA status, governance, decryption-exclusions, config-backup)
  validate required-fields+types only. Slice-3 tightens these.
- **MED-HIGH-4** — dynamic dispatchers (`apiIdPRouter`, `apiBootstrapRouter`) hide
  sub-actions from endpoint-level coverage; latent while exempt. Guardrail added
  (manifest header rule); full fix when they are documented in Slice 3.
- **MED-5** — breaking-change (Gate 7) is advisory and skips gracefully offline;
  becomes mandatory once the baseline merges and oasdiff is vendored.
- **LOW-8** — the +24h expiry grace makes the expiry date inclusive (documented as
  intentional in `CheckExemptions`).

## Follow-up backlog (ranked by severity × product value)

1. **[High] Scan sidecar is unauthenticated** (risk register §9) — require
   loopback/mTLS/token. Security fix, out of OpenAPI scope but tracked here.
2. **[High] Document all supported endpoints (Slice 3)** — retire the 265 baseline
   exemptions before 2027-01-31. Prioritize policy, cluster, security, PAC, CDR.
3. **[Med] Structured error envelope + admin-plane request IDs** (risk register §1/§4)
   — additive `writeAPIError` + request-ID middleware; generic-ize 5xx bodies to
   close information disclosure.
4. **[Med] Make Gate 7 (breaking-change) mandatory** once the baseline merges; add
   the `api-breaking-change` label workflow.
5. **[Med] Commit a generated Go client (Slice 5)** + compile smoke test in the
   deep lane; wire release traceability (contract digest + version in the release
   artifact, Gate 11).
6. **[Med] Document item routes** with `{param}` templating + `openapi_path` in the
   manifest (PAC profiles/pools, IdP items, support recipients).
7. **[Low] Coalesce nil slices → `[]`** on emit for documented list endpoints.
8. **[Low] 3.1.1 migration** once the kin-openapi filter is proven on 3.1 (or move
   response validation to libopenapi-validator).
9. **[Low] Richer offline docs** (vendored Redoc/Scalar) with a pinned minimal CSP.
10. **[Low] Deep-lane Spectral/vacuum** ruleset for prose-quality lint.

## Release integration (Gate 11 — TODO)

Attach to each release: product version, API contract version, `openapi.json`,
its SHA-256 digest, the offline `index.html`, the oasdiff compatibility report,
and the API CHANGELOG. A released binary and its documented contract must be
traceable to one another.

## Scheduled deep verification (Gate 12 — TODO)

A weekly job that: rebuilds docs, regenerates + compiles the client, runs full
conformance, re-checks route inventory under feature-flag configurations, scans
examples for secrets, verifies tool pins, and flags exemptions expiring < 30 days.
