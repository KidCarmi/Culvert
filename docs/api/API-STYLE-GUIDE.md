# Culvert API Style Guide

Rules for the admin REST API contract (`api/openapi/openapi.yaml`). The
Go-native `StyleLint` gate (`internal/apicontract`) enforces the machine-checkable
rules; the rest are review conventions. Mutating/destructive endpoints have
stricter requirements than read-only ones.

## Contract targets OpenAPI 3.0.4

See ADR-0018 §"Why 3.0.4". Do not use 3.1-only idioms (`type: [x, "null"]`,
top-level `webhooks`) until the contract is migrated.

## Operations (ENFORCED)

Every operation MUST declare:

- **`operationId`** — stable, unique, camelCase verb-noun (`rotateCA`,
  `listUsers`). Never reuse an `operationId` for different behavior (breaking).
- **`summary`** — one line.
- **`description`** — at least one sentence; more for security-sensitive ops.
- **`tags`** — at least one, from the top-level `tags` list.
- **`security`** — explicit. Public routes use `security: []`. Protected routes
  list the accepted schemes (`sessionCookie`, `basicAuth`).
- **responses** — at least one `2xx` AND at least one `4xx`/`5xx`.
- **`x-culvert-visibility`** ∈ {public-supported, admin-supported,
  appliance-internal, cluster-internal, agent-internal, debug, health-ops}.
- **`x-culvert-permission`** ∈ {public, viewer, operator, admin} — MUST equal the
  route's `min_role` (cross-checked by `TestConformance_Authz_PermissionMatchesManifest`).
- **`x-culvert-stability`** ∈ {stable, beta, experimental}.
- **`x-culvert-introduced-version`** — the contract version it first appeared in.

Mutating operations (POST/PUT/PATCH/DELETE) additionally MUST declare:

- **`x-culvert-danger-level`** ∈ {none, low, medium, high}.
- **`x-culvert-audit-event`** — the audit event the handler emits.

Recommended extensions: `x-culvert-tenant-scope` (always `appliance` today —
Culvert is single-appliance, not multi-tenant), `x-culvert-idempotency`
{safe, idempotent, non-idempotent}.

## Accuracy over aspiration (ENFORCED by conformance tests)

The contract describes **actual runtime behavior**, not the ideal design.

- **Errors are `text/plain`.** Today handlers use `http.Error` → plain text.
  Document error responses with `text/plain: {type: string}` and the reusable
  `Plain*` responses. Do NOT document a JSON error envelope that the handler does
  not emit — the response-conformance gate will fail.
- The proposed structured error envelope is a **future target** in the risk
  register, not the contract.
- Document `security` **per method** — dynamic-dispatch routers diverge by verb.

## Schemas

- Name schemas PascalCase (`LoginRequest`, `StatsSummary`).
- Prefer `additionalProperties: false` on strict request bodies (handlers using
  `decodeJSON` reject unknown fields).
- Read models that return an open superset may use `additionalProperties: true`,
  BUT a schema marked `x-culvert-sensitive: true` may NOT unless it also carries
  `x-culvert-open-justification` (ENFORCED). Never leak secrets in examples.
- Provide at least one example per operation; examples must validate against the
  schema (implicitly checked by the conformance tests).
- Mark collection fields nullable where the handler can emit JSON `null` for an
  empty slice (see risk register §2).

## Paths & naming

- Admin API is under `/api/`; keep kebab-case segments (`/api/decryption-exclusions`).
- Item routes use `{param}` templating (`/api/idp/{id}`); set the manifest row's
  `openapi_path` when the ServeMux pattern is a trailing-slash prefix.

## Security examples

Never include real credentials, tokens, private IPs, hostnames, or customer data
in examples. Placeholders only.
