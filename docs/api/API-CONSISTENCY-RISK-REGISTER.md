# API Consistency & Risk Register

Evidence-based survey of the Culvert admin REST API (~180 routes in `uiRoutes`,
`ui_routes_meta.go`) plus the non-admin HTTP surfaces (proxy-listener built-ins,
scan sidecar, bootstrap, cluster gRPC). Every claim is read from handler source
and labeled `[VERIFIED file:line]`, `[INFERENCE]`, or `[RECOMMENDATION]`. This
register documents **current behavior**; it does **not** prescribe a global
breaking migration. See "Standard error contract" at the end for the
migration-safe target. Produced by an independent Application-Security reviewer
as part of ADR-0007.

## 0. Executive summary

- There is **no authoritative error envelope**. Errors are emitted almost entirely
  as `http.Error(w, msg, code)` — plain `text/plain` bodies. `[VERIFIED ui_rbac.go:51]`
- Raw internal error strings reach clients in ~113 call sites via
  `http.Error(w, err.Error(), …)`. `[VERIFIED]`
- Success responses go through one soft helper, `jsonOK` (bare-value encode, no
  envelope). `[VERIFIED ui_helpers.go:83]` A second helper `writeJSONStatus` exists
  only in the release surface. `[VERIFIED release_api.go:300]`
- Success **shapes are heterogeneous**: bare objects, `{ok:true,…}`, `{data:…}`,
  `{status:…}`, `{error,issues}` all coexist. `[VERIFIED ui_policy.go:848; ui_config.go:181; pac.go:79]`
- Request decoding is **mostly** strict (`decodeJSON` → `DisallowUnknownFields`,
  84 uses) but several mutating handlers use lax `json.NewDecoder(...).Decode`. `[VERIFIED pac.go:68; ui_security.go:1159]`
- **No request-correlation ID** on admin responses; `X-Request-ID` exists only on
  the proxy datapath. `[VERIFIED proxy.go:604; connlimit.go:17]`
- Three HTTP surfaces bypass the admin middleware chain: proxy-listener built-ins,
  the **unauthenticated scan sidecar**, and the cluster gRPC server (mTLS). `[VERIFIED pac.go:122; scan_svc.go:71; controlplane_server.go:730]`

## 1. Error responses

| Finding | Evidence | Severity | Contract impact | Disposition |
|---|---|---|---|---|
| No envelope; errors are `http.Error` plain text across the whole API. | `ui_rbac.go:51`, `bandwidth.go:103`, `cdr_ui.go:87` | High | Every error response is `text/plain: string`. Documented as-is. | document-as-is + additive follow-up |
| Raw internal `err.Error()` leaked (~113 sites) — discloses paths/internals. | `bandwidth.go:73`, `pac.go:69`, `ui_security.go:1204` | Med | Non-deterministic bodies; cannot pin schema. | fix-if-backward-compat (generic-ize 5xx) |
| A minority emit JSON error bodies (`{error,issues}`). | `pac.go:79`, `ui_policy.go:1387` | Med | Two error content-types on `/api/*`. | document-as-is per-route |
| Ad-hoc but conventional status codes; no shared constants. | `configversion.go:168` (405), `cdr_ui.go:305` (409) | Low | Enumerate per route. | document-as-is |
| Two distinct 403 bodies (metadata gate vs `requireRole`). | `ui_rbac.go:51` | Low | — | document-as-is |

## 2. Success response shapes

| Finding | Evidence | Severity | Contract impact | Disposition |
|---|---|---|---|---|
| One soft helper `jsonOK` encodes the **bare value** (273 call sites). | `ui_helpers.go:83` | Low | Describable but no top-level wrapper. | document-as-is |
| Envelope inconsistent: bare vs `{ok}` vs `{data}` vs `{status}` vs `{error,issues}`. | `ui_policy.go:848`, `ui_config.go:181`, `ui_security.go:1177` | High | Each route needs a bespoke schema. | document-as-is; standardize NEW routes only |
| `nil` slice serializes as JSON `null`, not `[]`. | `configversion.go:174`, `events.go:261` | Med | Clients must handle both; mark arrays nullable. | fix-if-backward-compat (coalesce on emit) |
| Mixed timestamps: audit has BOTH `TS` (unix ms) and `Time` (formatted, no TZ); elsewhere RFC3339. | `ui_helpers.go:62-63`, `backup.go:164`, `autoexclude_resolve.go:269` | Med | No single timestamp type. | document-as-is per-field |
| No standard ID format (names, ULIDs, numeric versions). | `ui_helpers.go:53`, `configversion.go:174` | Low | Typed per-route. | document-as-is |

## 3. Request decoding

| Finding | Evidence | Severity | Disposition |
|---|---|---|---|
| Canonical strict `decodeJSON` rejects unknown fields (84 uses). | `ui_helpers.go:194` | Low (good) | strict routes → `additionalProperties:false` |
| Several mutating handlers use lax `json.NewDecoder(...).Decode`. | `pac.go:68`, `ui_security.go:1159` | Med | migrate to `decodeJSON` where safe |
| **No Content-Type validation** on JSON endpoints. | absence across `ui_*.go` | Low | `requestBody.content` is aspirational, not enforced |
| Body size limits from `securityMiddleware` + per-handler `MaxBytesReader`. | `cdr_ui.go:850`, `ui_security.go:269` | Low (good) | document-as-is |

## 4. Request IDs / correlation

| Finding | Evidence | Severity | Disposition |
|---|---|---|---|
| `X-Request-ID` generated/honored on the **proxy datapath only**; admin API has none. | `proxy.go:599-604`, `connlimit.go:17` | Med | follow-up: additive admin-plane request-ID middleware |

## 5. Auth / RBAC per handler

| Finding | Evidence | Severity | Disposition |
|---|---|---|---|
| Two-layer model: C2 metadata gate (`MinRole`) + handler `requireRole`. | `ui_rbac.go:46-53`, `ui.go:97` | Low (good) | document min role per method |
| **Dynamic-dispatch routers** where per-method role diverges from `MethodAny` metadata (C4 case). | `ui_auth.go:517` `apiIdPRouter`→`apiIdPItem` (GET viewer, PUT/DELETE admin) | Med | **document security PER METHOD** |
| Same pattern in other routers. | `pac_profiles_api.go:211,371`, `support_recipients.go:252` | Med | per-method security |
| Intentionally no `requireRole` (auth elsewhere): PAC files, bootstrap (token), `/metrics` (optional bearer), health probes, scan sidecar (none). | `pac.go:270`, `bootstrap.go:33`, `metrics.go:432`, `scan_svc.go:50` | High (scan)/Low (rest) | see §9 for scan sidecar |

## 6. Non-standard endpoints

| Endpoint | Evidence | Content-Type / semantics | Disposition |
|---|---|---|---|
| SSE live dashboard `apiEvents` | `events.go:162-234` | `text/event-stream`; viewer; re-validates auth periodically | document-as-is (note streaming) |
| Multipart upload — CDR test file | `cdr_ui.go:838-871` | `multipart/form-data` OR raw bytes; 64 MiB cap | document-as-is |
| Multipart upload — TLS cert/key | `ui_security.go:254-269` | `multipart/form-data` fields cert/key/target; 1 MiB | document-as-is |
| CA cert download (PEM) | `ui_security.go:1111` | `application/x-pem-file`; attachment | document-as-is |
| Config/policy/traffic export | `ui_config.go:671`, `ui_policy.go:2046` | attachment JSON/CSV | document-as-is |
| Support bundle download | `ui_support.go:681` | `application/octet-stream` (sensitive) | document-as-is |
| Bootstrap script / compose | `bootstrap.go:51-95` | `text/x-shellscript` / `application/x-yaml`, token-gated | document-as-is |
| PAC files | `pac.go:204-225` | `application/x-ns-proxy-autoconfig`; ETag/304/HEAD | document-as-is |

## 7. Destructive / security-sensitive operations

| Route | Evidence | Why sensitive | Audits? | Disposition |
|---|---|---|---|---|
| CA rotation `apiCARotate` | `ui_security.go:1144-1216` | invalidates trust chain; two-step confirmation-token flow | Yes (`ca.rotate_requested`, `ca.rotate`) | document-as-is |
| Config import `apiConfigImport` | `ui_config.go:910` | replace-mode wipes stores; `?dryRun`,`?mode` | Yes (dry-run skips audit) | document-as-is |
| Decryption-exclusion evict/clear (DELETE) | `ui_policy.go:838-853` | alters TLS-inspection bypass posture | Yes | document-as-is |
| IdP profile delete/update | `ui_auth.go:567,580` | auth-backend mutation | Yes | document-as-is |
| Release dispatch (host upgrade) | `release_api.go:419` | triggers agent upgrade/rollback | verify audit | follow-up |
| Cluster node enroll (gRPC) | `controlplane_server.go:282` | grants a DP into the fleet | cluster-plane log | separate plane |
| Bootstrap token endpoints | `bootstrap.go:33,61` | emit enrollment material | **no audit** | follow-up (audit on consumption) |

## 8. Health / metrics / bootstrap / cluster / debug endpoints

| Endpoint | Evidence | Class | Auth |
|---|---|---|---|
| `/healthz` (admin mux) | `diagnostics.go:1037` | health-ops | public |
| `/health`,`/ready` (proxy port) | `healthcheck.go:75,227` | health-ops | public |
| `/metrics` (proxy port) | `metrics.go:431` | metrics | optional bearer (`metricsToken`) |
| `/proxy.pac`,`/pac/{id}.pac` | `pac.go:271` | appliance-public | public |
| Bootstrap `/api/cluster/bootstrap/{token}` | `bootstrap.go:22` | cluster-onboarding | token-gated |
| Release `/api/releases*` | `release_api.go:288` | admin | viewer/admin |
| Governance `/api/governance/control-plane` | `ui_governance.go` | admin | admin-only |
| Scan sidecar `/scan`,`/health`,`/status` | `scan_svc.go:72` | appliance-internal | **none** (§9) |
| Cluster gRPC (CP↔DP) | `controlplane_server.go:730` | cluster-internal | mTLS |

## 9. Middleware bypass

| Surface | Evidence | Detail | Severity | Disposition |
|---|---|---|---|---|
| Proxy-listener built-ins | `pac.go:122-138` | served on the proxy port; per-endpoint auth | Med | document-as-is; set metrics token in prod |
| **Scan sidecar HTTP** | `scan_svc.go:64-88` | separate server, **no auth/CSRF/rate-limit/role**, accepts arbitrary bytes on `/scan` | **High** | follow-up: require loopback/mTLS/token |
| Cluster gRPC | `controlplane_server.go:730` | mTLS-authenticated, not an HTTP mux | Low (good) | document-as-is |

`[VERIFIED]` only two `http.NewServeMux()` exist in non-test code: `ui.go:72` (admin) and `scan_svc.go:71` (sidecar).

## 10. Pagination / filtering / ordering

| Finding | Evidence | Severity | Disposition |
|---|---|---|---|
| Only the request-log list paginates (`?q`,`?limit`,`?offset`). | `ui_policy.go:68-71` | Med | document-as-is; add limits to large lists (follow-up) |
| Other list endpoints return the full slice, no cursor. | `configversion.go:174`, `events.go:261` | Med | document unbounded |
| Ad-hoc per-route query params (`?strict`,`?mode`,`?dryRun`,`?host/scope`). | `healthcheck.go:252`, `ui_config.go:930` | Low | document individually |

## Standard error contract (proposal — additive, non-breaking)

**Current behavior (documented as-is):** errors are `text/plain` `http.Error` bodies
with a route-specific status; a minority return ad-hoc JSON. Internal error strings
are frequently included. The OpenAPI contract therefore models errors as
`text/plain: string` for existing routes. Do **not** force a global migration —
700+ `http.Error` sites and existing UI/CLI consumers depend on the current text.

**Migration-safe target for NEW routes / opt-in adoption** `[RECOMMENDATION]`:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "human-readable summary",
    "details": [ { "field": "priority", "issue": "already in use" } ],
    "request_id": "0a1b2c3d4e5f6a7b"
  }
}
```

Adoption rules that preserve backward compatibility:
1. Add `writeAPIError(w, status, code, msg)` next to `jsonOK`; new routes use it.
2. Replace `err.Error()` 5xx bodies with a generic message + logged detail now
   (backward-compatible; closes the §1 information-disclosure findings).
3. Add an admin-plane request-ID middleware and echo it in the envelope + header.
4. Coalesce `nil` collection slices to `[]` on emit for new routes.
5. Standardize new success responses on one shape; do not retrofit existing routes.

**OpenAPI guidance:** generate `security` **per method** (dynamic routers diverge by
verb), model legacy errors as `text/plain`, mark array fields nullable, and
enumerate the non-JSON media types in §6 explicitly.
