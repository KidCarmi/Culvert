# API Documentation — OpenAPI Tooling Research

External research supporting ADR-0018. Scope: tooling to author, validate, lint,
diff, and render the Culvert admin REST API (~180 `net/http` ServeMux routes).
Constraints: single static Go 1.25 binary, air-gapped, **no CDN/no runtime
internet**, reproducible builds, `go test -race ./...` as the required gate,
pinned tool versions, minimize Node in the fast gate.

Every claim is tagged **[VERIFIED]** (official source, URL), **[INFERENCE]**, or
**[RECOMMENDATION]**. Version *strings* were read from official release pages and
are reliable; exact release *dates* were lower-confidence in extraction — re-read
the linked release page before pinning.

## 0. Culvert adoption decision (what we actually shipped)

The abstract research recommendation is 3.1.1. **Culvert adopted 3.0.4** for one
decisive, context-specific reason documented below and in ADR-0018: our enforced
conformance gates use kin-openapi's in-process request/response validation, which
is 3.0-mature. Everything else in the recommended Go-native toolchain was adopted:

| Concern | Adopted | Pin |
|---|---|---|
| Spec dialect | **OpenAPI 3.0.4** (not 3.1.1 — see §2) | `openapi: 3.0.4` |
| Parse/validate + request/response validation (in `go test`) | **getkin/kin-openapi** | `v0.142.0` (go.mod) |
| Route/RBAC coverage | Go test binding `uiRoutes` ⇄ spec ⇄ manifest | — |
| Bundle + offline docs | `cmd/apibundle` (Go) | — |
| Breaking-change | **oasdiff** | `v1.11.7` (script pin) |
| Client generation (deep gate) | **oapi-codegen** | `v2.4.1` (script pin) |
| Style lint | Go-native `StyleLint` | — |

## 1. Executive summary of findings

- **Author by hand, validate against `uiRoutes`.** Culvert already owns a
  single source of truth for routes and RBAC; the OpenAPI doc should be *validated
  against* it, not generated from handlers. **[RECOMMENDATION]**
- **The critical path is Go-native and offline.** Parsing/validation/coverage run
  inside `go test` via kin-openapi (no new process, no Node). Breaking-change uses
  oasdiff (single Go binary). Docs render from a committed self-contained file.
- **Node stays out of the fast PR gate entirely.** **[RECOMMENDATION]**

## 2. OpenAPI 3.0.4 vs 3.1.1

- **[VERIFIED]** 3.0.4 and 3.1.1 both released 2024-10-24 (<https://github.com/OAI/OpenAPI-Specification/releases>).
- **[VERIFIED]** 3.1 aligns with JSON Schema Draft 2020-12; 3.0 uses a divergent subset (<https://apichangelog.substack.com/p/migrating-from-openapi-30-to-31>).
- **[VERIFIED]** 3.1 removes `nullable` in favour of union types; adds top-level `webhooks` (<https://beeceptor.com/docs/concepts/openapi-what-is-new-3.1.0/>).

**Decision → 3.0.4 for Culvert.** **[RECOMMENDATION]** The one caveat that decides
it: kin-openapi's request/response *validation* (`openapi3filter` / `Schema.VisitJSON`)
matured on 3.0; 3.1 schema constructs are less battle-tested there
(<https://pkg.go.dev/github.com/getkin/kin-openapi/openapi3>). Our Gates 4/5 run
exactly that path against real handler traffic, so 3.0.4 keeps the enforced code on
the most-proven validator. 3.1.1 migration is a recorded follow-up.

## 3. Go-native critical path

**getkin/kin-openapi** — **[VERIFIED]** latest v0.142.0, MIT, pure Go, supports 3.0/3.1/3.2 document validation; 3.1 landed v0.136.0 (<https://github.com/getkin/kin-openapi/releases>). Runs inside `go test` — the single most important property for an air-gapped shop. Limitation: request/response *middleware* is 3.0-mature (§2).

**Route/RBAC coverage (no new dep)** — bind the live `uiRoutes` table (already
C1-enforced) to the spec via a Go test: every documented op maps to a real route
and every non-exempt route is documented. Strictly better than any external
route-coverage scanner because Culvert's routes are dynamic and already reflected
in metadata. **[RECOMMENDATION]** *(This is exactly `TestOpenAPI_Gate3_RouteCoverage`.)*

**oasdiff** — **[VERIFIED]** latest v1.23.0 (2026-07-10), Apache-2.0, Go binary,
3.1-aware, 450+ rules (<https://github.com/oasdiff/oasdiff/releases>, <https://www.oasdiff.com/docs>).
Fast cadence → **pin exactly**. We pin conservatively in the script and skip
gracefully offline.

## 4. oapi-codegen (client generation only)

**[VERIFIED]** v2.8.0 requires Go 1.25 and adds *initial* 3.1 support; Apache-2.0
(<https://github.com/oapi-codegen/oapi-codegen/releases>). **[RECOMMENDATION]** Do
**not** adopt for server generation (it would fight the existing middleware — a
rewrite). Use it only to generate a *client* from the same spec to prove the
contract is code-generation-safe (Gate 9, deep lane).

## 5. Request/response validation options

- **kin-openapi** `openapi3filter` / `Schema.VisitJSON` — Go-native, strongest on
  3.0. **Used in-tests only** (validate real handler traffic), never in the proxy
  hot path. **[RECOMMENDATION]**
- **pb33f/libopenapi-validator** — first-class 3.1 request/response validation
  (<https://github.com/pb33f/libopenapi-validator>); the fallback if we later move
  to 3.1. **[INFERENCE]**

## 6. Breaking-change: oasdiff (Go) vs OpenAPITools/openapi-diff (Java)

**[VERIFIED]** oasdiff = Go single binary, Apache-2.0, active, 3.1-aware, 450+ rules.
openapi-diff = Java (needs JVM/Docker), slower cadence. **Decision → oasdiff** — a
Go binary pinned in a script is a perfect fit for an air-gapped Go shop; the JVM
tool adds a runtime for no benefit.

## 7. Linters: Spectral vs Go-native

**[VERIFIED]** Spectral (`@stoplight/spectral-cli` 6.16.1, Apache-2.0) requires
Node — disqualifying for the fast gate. **[VERIFIED]** vacuum/libopenapi (pb33f,
MIT) is Go-native. **Decision:** we implemented style/governance lint as a
**Go-native `StyleLint`** over the parsed doc (zero Node, runs in `go test`),
enforcing operationId/summary/description/tags/security/responses and the
`x-culvert-*` extensions. Spectral/vacuum remain optional deep-lane additions.

## 8. Offline documentation — self-contained, CDN-free, CSP-friendly

- **[VERIFIED]** Swagger UI (`swagger-ui-dist`, Apache-2.0), Redoc (`redoc` 2.5.3
  `redoc-static.html`, MIT), Scalar (`@scalar/api-reference` 1.62.9, MIT) can all be
  made single-file/CDN-free, but **none is guaranteed CSP-clean without testing**
  (Redoc needs `worker-src blob:`, etc.).
- **Decision (shipped):** `cmd/apibundle` renders a **self-contained static HTML**
  (server-side rendered operation list, **no JS, no external assets**) that is
  trivially CSP-clean and deterministic. Richer Redoc/Scalar vendoring under a
  documented CSP is a Slice-6 follow-up. **[RECOMMENDATION]**

## 9. Risks / limitations

1. Release *dates* in this doc are lower-confidence; re-verify before pinning.
2. oasdiff's fast cadence → pin exactly, bump deliberately.
3. kin-openapi 3.1 request-validation maturity → the reason we ship 3.0.4.
4. oapi-codegen 3.1 support is "initial" (not on our critical path).
5. Docs-renderer CSP compliance unproven for Redoc/Scalar → we render plain HTML
   instead for the baseline.
6. Node stays out of the fast gate by construction (all enforced gates are Go).

## 10. Recommendation (as adopted)

Author the contract by hand in **OpenAPI 3.0.4**; validate + enforce route/RBAC
coverage **inside `go test`** with **kin-openapi v0.142.0** cross-checked against
`uiRoutes`; bundle deterministically and render offline HTML with a Go tool; gate
breaking changes with **oasdiff** and prove client-generation with **oapi-codegen**
in the deep lane; keep Node out of the fast gate. The entire enforced path is
Go-native, offline, reproducible, and reuses Culvert's existing metadata
architecture.
