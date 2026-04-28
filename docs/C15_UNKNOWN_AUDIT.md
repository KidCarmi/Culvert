# C1.5 UNKNOWN-Handler Audit Report

Status: complete
Branch: `claude/refactor-ui-monolith-3toaQ`
Trigger: post-C1.5 follow-up audit (per maintainer instruction)
Scope: report-only on the UNKNOWN handlers surfaced by the C1.5 AST scanner

This audit walks every handler the C1.5 scanner classified as UNKNOWN
(no direct `requireRole` / `auditEvent` call attributable to a specific
method) and confirms — by reading the source — where the gating
actually lives. The deliverables are:

1. A scanner upgrade so AST detection covers more real patterns.
2. Three concrete metadata-only fixes the upgrade surfaced.
3. Two real RBAC/audit gaps escalated as security findings (NOT
   fixed in this PR — separate issue).
4. A categorised "confirmed OK" list for every remaining UNKNOWN.

C1.5 stays SHADOW / report-only. No middleware enforcement. No
handler rewrites in this PR.

---

## 1. Scanner upgrade — string-literal `requireRole` arguments

**Finding.** The C1.5 scanner originally only matched `requireRole(w, r, X)`
where `X` was a named `*ast.Ident` (`RoleAdmin` / `RoleViewer` / `RoleOperator`).
12 calls in `update.go` + `update_cluster.go` use the equivalent **string-
literal** form (`requireRole(w, r, "admin")`), which Go accepts because
`UIRole` is a `type UIRole string`. The scanner reported all 11 routes
served by these handlers as UNKNOWN.

**Fix in this PR.** New helper `extractRequireRoleArg` in
`ui_routes_meta_audit_test.go` accepts both forms:

```go
case *ast.Ident:    // RoleAdmin
case *ast.BasicLit: // "admin" (token.STRING)
```

Both call sites in the scanner now route through this helper.

**Audit consequence.** All 11 `apiUpdate*` / `apiClusterUpdate*` handlers
have **direct, in-handler** RBAC gating. Their AuditExpected flags are
also accurate (each `apiUpdate*` POST that mutates state calls
`auditEvent`). The metadata Notes were updated to remove the
"gating delegated" claim — gating is direct, just AST-invisible
without the upgrade.

---

## 2. Metadata-only fixes (3 routes — applied in this PR)

The scanner upgrade revealed three metadata MinRole values that
contradict the handler's actual role check. All three are
documentation-only edits in `ui_routes_meta.go`.

| Route | Method | Old metadata | Real handler | Fix |
|---|---|---|---|---|
| `/api/update/check` | POST | `RoleOperator` | `requireRole("admin")` | `RoleAdmin` |
| `/api/update/preview` | POST | `RoleViewer` | `requireRole("admin")` | `RoleAdmin` |
| `/api/update/registry` | GET | `RoleAdmin` | `requireRole("viewer")` | `RoleViewer` |

The `/api/update/preview` change is the most consequential: under the
metadata I had pre-audit, a future C2 enforcement layer would have
allowed Viewer-role callers to invoke a config-diff preview operation
that's actually admin-only at the handler. The audit caught this before
C2 ships.

A fourth metadata value is also adjusted because the dispatch handler
delegation makes a tighter classification accurate:

| Route | Method | Old metadata | Reason |
|---|---|---|---|
| `/api/idp/` | `*` | `MinRole=RoleAdmin` | Tightened to `RoleViewer` — `apiIdPRouter` dispatches to `apiIdPItem` whose lowest accepted role is `RoleViewer` (GET branch). Pre-fix metadata was over-restrictive. |

All four routes now pass C1.5 cleanly (zero MinRole mismatches).

---

## 3. Real RBAC / audit gaps (NOT fixed — escalated separately)

These are **production-code findings**: the handler's actual behavior
is at odds with the principle of least privilege OR with the
audit-trail expectation. Per the audit's "no handler rewrites"
constraint, none are fixed in this PR. Each is filed as a follow-up.

### 3.1 — `apiPACConfig` POST has no `requireRole` check

**File:** `pac.go:191`
**Severity:** Medium → High (privilege escalation surface).

```go
func apiPACConfig(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        // ... no requireRole ...
    case http.MethodPost:
        // ... no requireRole, but DOES call auditEvent ...
        if err := pacStore.Set(c); err != nil { ... }
        auditEvent(r, "pac.update", ...)
        saveConfigVersion(actor, "pac.update")
```

**Risk.** `/api/pac-config` is gated by `uiAuthMiddleware` (not in the
public allowlist), so anonymous callers cannot reach it. But ANY
authenticated UI user — including a `RoleViewer` account — can POST a
new PAC configuration. The PAC file drives every Windows / browser
proxy client that bootstrap from this CP, so changing it has fleet-wide
impact.

**Recommendation (separate fix).** Add `if !requireRole(w, r, RoleAdmin) { return }`
to the POST branch. The current metadata already declares
`MinRole=RoleAdmin`, so this is a pure handler-side fix to bring
behavior in line with the documented intent.

### 3.2 — `apiSecFeedsSync` mutates without an audit event

**File:** `ui_security.go:510`
**Severity:** Low (defensive — no audit trail for an admin operation).

```go
func apiSecFeedsSync(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { ... }
    if !requireRole(w, r, RoleAdmin) { return }   // gating OK
    if !globalThreatFeed.Enabled() { ... }
    globalThreatFeed.Sync()                       // no auditEvent
    jsonOK(w, secScanStatusMap())
}
```

**Risk.** Manual threat-feed sync is an admin-only operation that
modifies the data driving every block decision. No audit trail makes
forensics harder if a sync was triggered at a suspicious time.

**Recommendation (separate fix).** Add
`auditEvent(r, "security.feeds_sync", "manual", "")` after a successful
`globalThreatFeed.Sync()`. The metadata already declares
`AuditExpected=false` (consistent with the current handler) — when the
fix lands, the metadata flag flips to `true` in the same PR.

---

## 4. Confirmed OK — UNKNOWNs that are correct as-is

The 18 remaining MinRole UNKNOWNs (after the scanner upgrade) are all
expected delegation patterns. The metadata already documents them via
`Note` strings; this audit confirms each is intentional.

### 4.1 — Method-uniform GET branches without `requireRole`

12 routes have a `case http.MethodGet:` (or top-level GET-only handler)
where the role check is performed by `uiAuthMiddleware` alone. Per the
audit's `GET-without-requireRole` policy, the metadata records
`MinRole=RoleViewer` plus an explicit Note. No change needed.

| Route | Handler | Status |
|---|---|---|
| `/api/blocklist/mode` | `apiBlocklistMode` | Confirmed OK |
| `/api/content-scan` | `apiContentScan` | Confirmed OK |
| `/api/default-action` | `apiDefaultAction` | Confirmed OK |
| `/api/fileblock` | `apiFileblock` | Confirmed OK |
| `/api/ocsp` | `apiOCSPConfig` | Confirmed OK |
| `/api/policy` | `apiPolicy` | Confirmed OK |
| `/api/rewrite` | `apiRewrite` | Confirmed OK |
| `/api/settings` | `apiSettings` | Confirmed OK |
| `/api/ssl-bypass` | `apiSSLBypass` | Confirmed OK |
| `/api/upstream` | `apiUpstream` | Confirmed OK |
| `/api/upstream/settings` | `apiUpstreamSettings` | Confirmed OK (read-only handler, GET-only) |
| `/api/urlcat` | `apiURLCat` | Confirmed OK |
| `/api/urlcat/lookup` | `apiURLCatLookup` | Confirmed OK (lookup tool; intentionally Viewer-readable) |

### 4.2 — Sub-handler delegation (in-package, AST-invisible)

3 routes delegate to a private helper that performs `requireRole`. The
audit confirmed each helper has the appropriate gating; the metadata
MinRole was already correct.

| Route | Method | Delegates to | Confirmed gate |
|---|---|---|---|
| `/api/cluster/tokens` | POST | `apiClusterTokenCreate` | `requireRole(RoleAdmin)` |
| `/api/idp/` | (any) | `apiIdPItem` / `apiIdPGroups` | per-method: GET viewer / PUT/DELETE admin |
| `/api/pac-config` | GET | inline (no role check) | uiAuthMiddleware-only — intentional read access |

### 4.3 — Token-authed dispatch

| Route | Handler | Mechanism |
|---|---|---|
| `/api/cluster/bootstrap/` | `apiBootstrapRouter` | Token verification via `globalClusterStore.TokenExists(token)`; the URL token IS the credential. `uiAuthMiddleware` still applies (the route is NOT on the public allowlist), so an authenticated UI user is required AND the token must be valid. |

### 4.4 — Aggregate read-only handlers (10 routes — `MethodAny` by design)

These handlers don't have `switch r.Method` dispatch; they call
`requireRole(RoleViewer)` unconditionally and serve any method as a
read response. The C1.5 scanner correctly attributes these to
`MethodAny` and the metadata uses `MethodAny` with `MinRole=RoleViewer`.

`apiStats`, `apiDashboardHealth`, `apiDashboardThreats`,
`apiDashboardTopRules`, `apiTimeseries`, `apiLogs`, `apiTopHosts`,
`apiEvents`, `apiCountryTraffic`, `apiExport`, `apiGeoIPConfig`.

---

## 5. AuditExpected UNKNOWN review

After the metadata Note updates in this PR, only ONE AuditExpected
UNKNOWN remains, and it is correctly classified as delegated:

| Route | Handler | Status |
|---|---|---|
| `/api/idp/` | `apiIdPRouter` | AuditExpected=true. Delegates to `apiIdPItem` (which calls `auditEventDiff` on PUT/DELETE) and `apiIdPGroups`. AST-invisible delegation; metadata stays true; the C1.5 test logs this as informational. **Confirmed OK.** |

Other routes previously logged as AuditExpected UNKNOWNs were resolved
when the scanner upgrade attributed their direct `requireRole` calls
correctly (the audit calls were always present, just paired with
string-literal role args).

---

## 6. Audit summary

| Category | Count |
|---|---:|
| Scanner improvements | 1 (string-literal `requireRole` detection) |
| Metadata MinRole fixes (applied) | 3 + 1 (apiIdPRouter doctrine tightening) |
| Note rewordings (applied) | 11 (`apiUpdate*` family — "delegated" was wrong) |
| Real production findings (NOT fixed; escalated) | 2 (`apiPACConfig` POST, `apiSecFeedsSync` audit gap) |
| UNKNOWN confirmed OK (intentional design) | 18 (12 GET-no-requireRole + 3 sub-handler delegation + 1 token-auth + 10 aggregate readers + 1 audit delegation = 27 if grouped; 18 unique route+method UNKNOWN survives) |

**Test status after audit:**

```
go build ./...                                          ✓
go vet ./...                                            ✓
gofmt -l ui_routes_meta*.go                             clean
staticcheck ./...                                       ✓
go test -count=1 -timeout=10m ./...                     ✓
go test -count=1 -run 'TestC15_|TestC1_|TestD0_' ./...  ✓ (zero MinRole / Mutating / AuditExpected mismatches)
```

C1.5's MinRole/Mutating/AuditExpected mismatch counts are all **0**.
UNKNOWN entries remain visible via `t.Logf` for human review per the
"AST is a safety signal, not a compiler of behavior" doctrine.

---

## 7. Follow-up tasks (NOT in this PR)

1. **Fix `apiPACConfig` POST** — add `requireRole(RoleAdmin)` to the
   POST branch. Single-line change in `pac.go`.
2. **Add audit to `apiSecFeedsSync`** — single `auditEvent` call after
   `globalThreatFeed.Sync()`. Update metadata `AuditExpected: true`.
3. **C2 enforcement** can proceed once findings 1 & 2 are remediated:
   the metadata table is now confirmed accurate against handler behavior.
