# ADR-0007: A durable, CI-enforced OpenAPI contract for the Culvert admin API

- **Status:** Accepted (baseline / Slice 0–2 + conformance core shipped)
- **Date:** 2026-07-19
- **Deciders:** API governance (Principal API Architect role)
- **Supersedes:** none
- **Related:** ADR-0002 (internal/ decomposition), the C1/C1.5/C2 admin-route metadata program (`ui_routes_meta.go`)

## Context

Culvert's admin/control-plane REST API is ~180 routes / 284 method-entries
registered on a single `net/http.ServeMux` and already catalogued, with per-method
RBAC, in the `uiRoutes` metadata table (CI-enforced for router parity by the C1
forward/reverse tests). There was **no machine-readable API contract**: no
OpenAPI document, no way for SDKs/automation/SIEM/Terraform integrators to consume
the API, and no gate preventing the documentation (had it existed) from silently
drifting from the running handlers.

The mandate: make the API contract **accurate, complete, security-aware,
backward-compatible, testable, air-gap-compatible, reproducible, and automatically
enforced** — an *enforceable contract*, not documentation that rots.

Hard constraints (from the product): on-prem/air-gapped, **no CDN, no runtime
internet**, reproducible single-binary builds, `go test -race ./...` as the
required gate, pinned tool versions, and **no router/handler rewrite** — runtime
behavior must be preserved.

## Decision drivers

1. **Zero runtime-behavior change.** The router, handlers, and middleware stay
   byte-identical. This rules out contract-first server generation.
2. **Drift resistance without developer discipline.** The contract and the router
   must not be able to diverge silently.
3. **Air-gap + reproducibility.** The enforced critical path must be Go-native,
   offline, and deterministic — no Node in the fast gate, no network at test time.
4. **Reuse the existing single source of truth.** `uiRoutes` already is the
   CI-enforced route registry; the OpenAPI program should bind to it, not create a
   second hand-maintained list.

## Options considered (decision matrix)

Scores: 5 = best fit for Culvert, 1 = worst. Weighted by the drivers above.

| Criterion (weight) | A: Hand-kept OpenAPI | B: Code annotations → OpenAPI | C: OpenAPI-first generated server | **D: Existing handlers + versioned contract + route metadata + contract tests + CI** |
|---|---|---|---|---|
| Migration risk (×3) | 5 | 3 | 1 | **5** |
| Runtime risk (×3) | 5 | 4 | 1 | **5** |
| Drift resistance (×3) | 1 | 4 | 5 | **5** |
| Testability (×2) | 3 | 3 | 4 | **5** |
| Go ecosystem maturity (×1) | 4 | 3 | 3 | **5** |
| Developer experience (×1) | 2 | 4 | 3 | **4** |
| Security accuracy (×2) | 3 | 3 | 3 | **5** |
| Offline support (×2) | 5 | 4 | 4 | **5** |
| Build reproducibility (×2) | 4 | 3 | 3 | **5** |
| Long-term maintainability (×2) | 2 | 4 | 4 | **5** |
| Router compatibility (×2) | 5 | 3 | 1 | **5** |
| Handler compatibility (×2) | 5 | 3 | 1 | **5** |
| Client generation (×1) | 4 | 4 | 5 | **5** |
| Breaking-change detection (×1) | 4 | 4 | 4 | **5** |
| **Weighted total** | 108 | 92 | 71 | **136** |

- **A (hand-kept):** low migration/runtime risk but *fails the core mandate* — no
  drift resistance; documentation rots. Rejected.
- **B (annotations, e.g. swaggo):** couples the contract to handler comments;
  annotations drift from behavior just like prose, and 3.1/security-scheme
  fidelity is weak. Rejected.
- **C (oapi-codegen server-first):** would regenerate handlers and fight the
  existing C2 metadata-enforcement / RBAC / CSRF middleware — a rewrite, exactly
  what the constraints forbid. Rejected (kept as a *client*-generation option).
- **D:** hand-authored versioned contract for existing handlers, **bound to the
  live `uiRoutes` registry** by a coverage gate, validated + conformance-tested in
  `go test`. Selected.

**Decision: Option D.**

## Toolchain decision (evidence: `docs/api/API-OPENAPI-RESEARCH.md`)

| Concern | Tool | Pin | Why |
|---|---|---|---|
| Spec dialect | **OpenAPI 3.0.4** | `openapi: 3.0.4` | see below |
| Parse/validate + request/response validation, in-process | **getkin/kin-openapi** | `v0.142.0` (in `go.mod`) | pure Go, offline, runs in `go test`; MIT |
| Route/RBAC coverage | *(no dep)* Go test binding `uiRoutes` ⇄ spec ⇄ manifest | — | reuses the existing single source of truth |
| Bundle + offline docs | *(no dep)* `cmd/apibundle` (Go) | — | deterministic JSON + self-contained HTML; no Node, no CDN |
| Breaking-change | **oasdiff** | `v1.11.7` (pinned in script; not in module graph) | Go single binary; Apache-2.0 |
| Client generation (deep gate) | **oapi-codegen** | `v2.4.1` (pinned in script) | generates a *client* only; Apache-2.0 |
| Style lint | *(no dep)* Go-native `StyleLint` over the parsed doc | — | avoids Node in the fast gate entirely |

### Why OpenAPI 3.0.4 and not 3.1.1

The research recommends 3.1.1 *in the abstract* (JSON-Schema-2020-12 alignment,
no `nullable` foot-gun) **but flags one caveat that is decisive for Culvert**:
kin-openapi's *request/response validation* path (`openapi3filter` / `Schema.VisitJSON`)
matured on OpenAPI 3.0; 3.1 schema constructs are less battle-tested there. Our
enforced conformance gates (4/5) run **exactly that in-process validation path**
against real handler traffic. Choosing 3.0.4 keeps the enforced critical path on
the most-proven code and avoids validator surprises; 3.1.1 migration is a recorded
follow-up (Slice 5) to revisit once we either prove the filter on 3.1 or move
response validation to `libopenapi-validator`. This is a deliberate, evidence-based
trade of a newer dialect for a de-risked validator.

### Why Go-native / no Node in the fast gate

Spectral/Redocly/Scalar all require Node; a Node dependency in the required PR gate
is friction for an air-gapped, reproducible, single-binary shop. All enforced gates
are Go tests (kin-openapi) and a Go bundler; Node tools (Spectral, Redoc rendering)
are optional deep/out-of-band lanes whose outputs, if used, are committed artifacts.

## The enforced governance flow

```
Live route registration (uiRoutes) ── CI-enforced parity (C1) ──┐
                                                                 ▼
                       api/route-classification.yaml  (every route: documented OR exempt+owner+expiry)
                                                                 ▼
                     api/openapi/openapi.yaml (3.0.4, x-culvert-* metadata, actual behavior)
                                                                 ▼
   internal/apicontract  →  Gate1 validate · Gate2 style-lint · Gate3 coverage+expiry ·
                            Gate4 request · Gate5 response · Gate6 authz · Gate8 drift
                                                                 ▼
        cmd/apibundle → deterministic openapi.json + self-contained offline index.html
                                                                 ▼
              oasdiff breaking-change gate (Gate7) · oapi-codegen client compile (Gate9)
```

The router and the spec **cannot drift independently**: `TestOpenAPI_Gate3_RouteCoverage`
enumerates the live `uiRoutes` table and fails on any route that is neither
documented in the contract nor carried by an unexpired exemption, and on any
contract operation that maps to no live route.

## Consequences

**Positive**
- New/removed/changed routes cannot merge undocumented — the required gate fails.
- Contract describes *actual* behavior (plain-text errors and all), so it never
  lies about security posture; RBAC in the contract is cross-checked against the
  router's recorded `MinRole`.
- Entire enforced path is offline, Go-native, deterministic; adds one MIT Go
  dependency (kin-openapi) and no Node to the fast gate.
- Baseline exemptions are time-boxed (expire 2027-01-31), converting undocumented
  routes into tracked, expiring documentation debt rather than silent gaps.

**Negative / accepted**
- The baseline documents 19 of 284 method-entries; the remaining 265 are exempted,
  not yet documented (Slice 3 backlog, deadline-enforced).
- 3.0.4 (not 3.1.1) until the validator caveat is retired.
- Breaking-change (Gate 7) and client-generation (Gate 9) run in the deep/scheduled
  lane and skip gracefully when their pinned tools can't be fetched offline.
- One shared baseline expiry date is a cliff; deliberate (a single documentation
  deadline) and revisitable per-domain.

## Follow-ups (tracked in `docs/api/API-IMPLEMENTATION-PLAN.md`)

Slice 3 (document all supported routes, retire exemptions), Slice 5 (oasdiff
baseline made mandatory post-merge; committed generated client; 3.1.1 re-evaluation),
Slice 6 (richer offline docs via vendored Redoc/Scalar under CSP), and the
consistency-remediation backlog in `docs/api/API-CONSISTENCY-RISK-REGISTER.md`
(structured error envelope, admin-plane request IDs, scan-sidecar auth).
