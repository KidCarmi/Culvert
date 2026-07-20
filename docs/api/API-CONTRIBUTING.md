# Contributing to the Culvert API

The safe path is the easy path. Follow this when you add or change an admin-API
endpoint — CI enforces every step.

## Adding a new endpoint

1. **Register the route** and add its `uiRoutes` entry (`ui_routes_meta.go`) with
   per-method `MinRole`/`Mutating`/`AuditExpected` — same as today. The C1 gate
   already enforces this.
2. **Run the coverage gate** to see it flag your new route:
   ```
   make api-route-coverage        # → UNCLASSIFIED ROUTE: POST /api/your-thing
   ```
3. **Choose:** document it, or exempt it.

   **Document it (preferred for supported routes):**
   - Add the operation to `api/openapi/openapi.yaml` following `API-STYLE-GUIDE.md`
     (operationId, summary, description, tags, security, responses, `x-culvert-*`).
     Errors are `text/plain` — reuse the `Plain*` responses.
   - Add a manifest row in `api/route-classification.yaml` with `documented: true`.
   - `make api-bundle` and commit ALL regenerated artifacts: `openapi.json`,
     `index.html`, `index.public.html`, and `docs/api/API-INVENTORY.md` (all four
     are drift-gated by `TestOpenAPI_Gate8`).

   **Exempt it (internal/agent/cluster/debug routes not yet contracted):**
   - Add a manifest row with `documented: false` and an
     `exemption: {owner, reason, security_class, expires: YYYY-MM-DD}`.
     Pick a real owner and a real, near-term expiry — the expiry gate WILL fail CI
     when it lapses.

4. **Verify everything:**
   ```
   make api-verify
   ```

## Changing an existing endpoint

- If you change the response shape, update the schema — the response-conformance
  gate replays the real handler and fails on drift.
- If you change the RBAC role, update both `uiRoutes` and `x-culvert-permission`
  — they are cross-checked.
- If the change is not backward-compatible, follow `API-VERSIONING-POLICY.md`
  (label + rationale + migration + approver + MAJOR bump).

## The gates

Gates 1–6 + 8 are ordinary Go tests, so they run inside the required fast PR gate
(`go test ./...`). Gates 7 and 9 are **separate merge-blocking checks** in
`.github/workflows/pr-api-governance.yml` (strict mode — a missing pinned tool is
a hard failure, never a skip).

| Gate | Test / check | Fails when |
|---|---|---|
| 1 validation | `TestOpenAPI_Gate1_SpecValidates` | spec is invalid ($ref, schema, dup opId) |
| 2 style-lint | `TestOpenAPI_Gate2_StyleLint` | missing metadata/extensions |
| 3 coverage | `TestOpenAPI_Gate3_RouteCoverage` | a route is unclassified / a phantom op / stale row |
| 3 expiry | `TestOpenAPI_Gate3_NoExpiredExemptions` | an exemption expired |
| 4 request | `TestConformance_Request_*` | request schema wrong |
| 5 response | `TestConformance_Response_*` / `TestConformance_MutatingResponses` | handler output violates schema |
| 6 authz | `TestConformance_Authz_*` | documented role ≠ enforced role |
| 8 drift | `TestOpenAPI_Gate8_BundleNotStale` | any generated artifact (json/html/inventory) not regenerated |
| **7 breaking** | check **`API · breaking-change (blocking)`** (`pr-api-governance.yml`) | unapproved breaking change (exception = `api-breaking-approved` label + PR-body sections + CODEOWNER approval) |
| **9 client** | check **`API · client-generation (blocking)`** (`pr-api-governance.yml`) | contract not code-gen-safe |

Gates 7 and 9 become *merge*-blocking once an admin marks the two check names as
required in branch protection (see `API-VERSIONING-POLICY.md`); until then the
workflow is still technically hard-failing on a violation.

## Local commands

```
make api-verify            # full PR-safe gate (offline, Go-native)
make api-bundle            # regenerate openapi.json + offline HTML + API-INVENTORY.md
make api-route-coverage    # coverage + exemption expiry
make api-contract-test     # request/response/authz conformance
make api-breaking-check    # oasdiff vs base (skips offline; strict in CI)
make api-client-generate   # typed client gen + compile (skips offline; strict in CI)
make api-docs-build        # offline HTML docs
```
