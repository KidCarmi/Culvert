# OpenAPI Program — Final Implementation & Verification Report

Date: 2026-07-19. Branch: `claude/culvert-openapi-program-iqx2lt`.
Every statement is tagged **[FACT]** (verified in-repo), **[INFERENCE]**,
**[RECOMMENDATION]**, **[IMPLEMENTED]** (a control that exists and is enforced),
or **[RISK]** (remaining exposure).

## 0. Status update (Slice 3 complete)

**The entire admin REST API is documented.** 275/284 route method-entries are in
the OpenAPI contract (171 paths); the remaining 9 are `intentionally-undocumented`
non-REST surfaces (static SPA `/`, SSE `/api/events`, the dynamic sub-routers
`/api/idp/` + `/api/cluster/bootstrap/`, and the public browser SSO flow
`/auth/*`), each carrying a specific recorded reason in the classification
manifest. Coverage spans reads, writes, deletes, action verbs, item routes
(`{param}` via `openapi_path`), legacy aliases, multipart upload, PEM/binary
downloads, and public PAC files. 100+ conformance tests (response + request +
authz) run through real handlers under `-race`.

Honest quality caveat: to reach full coverage at pace, many write bodies and
some read models use open `GenericWriteInput`/`GenericRead` schemas
(`additionalProperties: true`). These are documented-but-loose — they validate
presence and JSON-object shape, not every field. Tightening them to precise,
per-endpoint schemas is the top Slice-3.1 follow-up (the response-conformance
tests already pin the ~90 endpoints that have real schemas).

## 1. What shipped

**[IMPLEMENTED]** A durable, CI-enforced OpenAPI contract for the Culvert admin
API, per ADR-0007 (Option D). The enforced critical path is Go-native, offline,
deterministic, and runs inside the required `go test -race ./...`.

- **Contract:** `api/openapi/openapi.yaml` (OpenAPI 3.0.4), 19 operations spanning
  public/admin/health, safe/destructive, GET/POST/DELETE, with `x-culvert-*`
  metadata describing **actual** behavior (plain-text `http.Error` responses).
- **Engine:** `internal/apicontract` (getkin/kin-openapi v0.142.0, MIT) —
  validation, Go-native style-lint, bijective route⇄manifest⇄spec coverage +
  role/mutating/audit binding + exemption expiry & horizon, request/response
  validators, deterministic bundler, visibility-filtered offline HTML renderer.
- **Live binding:** `apicontract_live_test.go` enumerates the real `uiRoutes`
  table (284 method-entries) and enforces coverage against the contract + manifest.
- **Manifest:** `api/route-classification.yaml` classifies **all 284** entries
  (19 documented + 265 exempt with owner + reason + security_class + expiry).
- **Conformance:** request/response/authz tests through real handlers; secret
  scanner; public-docs no-leak test; permission↔manifest cross-check.
- **Tooling/CI:** `Makefile` `api-*` targets; pinned offline scripts (oasdiff,
  oapi-codegen; graceful-skip); advisory `.github/workflows/api-contract.yml`
  (core gates also enforced in the required fast gate); CODEOWNERS + PR-template.
- **Docs:** ADR-0007, research, consistency/risk register, style guide, versioning
  & deprecation policies, inventory, contributing, implementation plan.

## 2. Route inventory totals

**[FACT]** 180 routes / 284 method-entries on the admin mux (dumped from the live
`uiRoutes`). Supported/documented in the contract: 19. Classified-but-exempt: 265
(time-boxed to 2027-01-31, within the 270-day horizon). Visibility split:
public-supported 13, health-ops 1, admin-supported 270.

**[FACT]** The admin mux ⇄ `uiRoutes` is enforced by the existing C1 parity tests;
the only other HTTP surfaces (scan sidecar, proxy-listener built-ins) are separate
muxes, out of OpenAPI scope, and documented — the scan sidecar as a **High**
finding (unauthenticated). Verified independently: mux paths not in `uiRoutes` are
exactly `/scan`, `/health`, `/status` (the sidecar's own mux).

## 3. Gates & negative tests demonstrated

| Gate | Enforced by | Negative test proving it fires |
|---|---|---|
| 1 validation | `TestOpenAPI_Gate1` | invalid-spec fixtures via `LoadSpec` |
| 2 style-lint | `TestOpenAPI_Gate2` + engine | `TestStyleLint_CatchesMissingVisibility`, `_MutatingWithoutAudit`, `_SensitiveOpenSchema_BooleanExtension` |
| 3 coverage | `TestOpenAPI_Gate3_RouteCoverage` | `TestCoverage_{Unclassified,StaleRow,Phantom,DocumentedButMissing,Neither,RoleDrift}`, `TestOpenAPI_Gate3_DetectsNewUndocumentedRoute` |
| 3 expiry/horizon | `TestOpenAPI_Gate3_NoExpiredExemptions` | `TestExemptions_Expired`, `_TooFarFuture` |
| 4 request | `TestConformance_Request_Login` | rejects body missing required field + malformed JSON → 400 |
| 5 response | `TestConformance_Response_{SetupStatus,AuthStatus,Healthz,Stats,Governance}` | schema mismatch fails `VisitJSON` |
| 6 authz | `TestConformance_Authz_*` | viewer-on-admin → 403; permission↔manifest cross-check |
| 8 drift | `TestOpenAPI_Gate8_BundleNotStale` | stale `openapi.json`/`index*.html` fails |
| 10 secrets | `TestOpenAPI_Gate10_NoSecretsInContract` | PEM/AWS/GH-token/private-IP patterns |
| 7 breaking | `scripts/openapi/breaking-check.sh` (deep) | oasdiff `--fail-on ERR` |
| 9 client | `scripts/openapi/generate-client.sh` (deep) | oapi-codegen generate+compile |

## 4. Independent reviewer reports (5 perspectives)

- **Repository Cartographer** — verified `uiRoutes` ⇄ admin-mux completeness (C1),
  identified the two out-of-scope muxes, confirmed no admin route escapes the gate.
  See §2. **[FACT]**
- **API Contract Architect / toolchain research** — `docs/api/API-OPENAPI-RESEARCH.md`.
  Recommended a Go-native, offline toolchain; flagged the kin-openapi 3.1 validator
  caveat that drove the 3.0.4 decision.
- **Application-Security reviewer** — `docs/api/API-CONSISTENCY-RISK-REGISTER.md`.
  No error envelope, ~113 raw-error leaks, per-method dynamic-router RBAC, the
  unauthenticated scan sidecar (High).
- **CI/Reliability** — designed the split fast (Go-native gates in the required
  `go test`) vs deep (oasdiff/oapi-codegen, out-of-band) lanes; deterministic,
  offline, no Node in the fast gate.
- **Enterprise Integration** — the deterministic `openapi.json` + generated client
  (Gate 9) make the API consumable by SDKs/automation; release traceability (Gate
  11) is a tracked follow-up.
- **Adversarial reviewer (fresh, post-implementation)** — found HIGH-1 (dead
  sensitive lint), HIGH-2 (thin response coverage), MED-HIGH-3 (manifest role not
  bound to handler), MED-HIGH-4 (dynamic-router endpoints hidden), MED-5/6, MED-7,
  LOW-8. Dispositions in `API-IMPLEMENTATION-PLAN.md` §"Adversarial review outcomes":
  HIGH-1, MED-HIGH-3, MED-6, MED-7 **fixed**; HIGH-2 partially fixed; the rest are
  latent/by-design with guardrails + backlog items.

## 5. Remaining risks

- **[RISK]** 14/19 documented ops lack a live response test; opaque response
  schemas validate required-fields+types only. Mitigation: Slice 3 tightens them.
- **[RISK]** Dynamic dispatchers hide sub-actions from endpoint-level coverage
  while exempt (guardrail + rule added; full fix on documentation).
- **[RISK]** Gate 7 is advisory and skips offline until oasdiff is vendored and the
  baseline merges.
- **[RISK]** Product-wide: no structured error envelope, no admin-plane request IDs,
  unauthenticated scan sidecar — all in the risk register, out of this change's scope.

## 6. Verification performed

**[FACT]** `gofmt -l` clean on all new files; `go vet` clean; `go build ./...` and
`CGO_ENABLED=0 go build -o culvert .` succeed; `go test -race ./internal/apicontract/`
and `go test -race -run 'TestOpenAPI_|TestConformance_' .` pass; `go mod tidy` is
stable; kin-openapi is MIT. Bundle output is byte-deterministic across runs; the
offline HTML contains zero external asset references.

## 7. Acceptance-criteria status (summary)

Met: every registered route inventoried + classified; supported routes documented;
exclusions carry reviewed, expiring exemptions; no phantom operations; spec
validates & bundles; unique/stable operationIds; security schemes reflect runtime;
permissions/danger/audit/stability declared; public docs contain no internal ops;
adding an undocumented route / removing a documented one / phantom op / schema-violating
response / weakened auth / stale generated artifact / expired exemption all fail
CI (demonstrated). Offline, no CDN, pinned tools, deterministic output, existing
tests green. **Not yet met (tracked):** full supported-API documentation (Slice 3),
mandatory breaking-change gate + committed client (Slice 5), release traceability
(Gate 11), scheduled deep verification (Gate 12).
