# Culvert Diagnostic Command Framework

- **Status:** Proposed (design).
- **Depends on:** `SUPPORTABILITY-ARCHITECTURE.md`, `SUPPORT-BUNDLE-SPEC.md`, `HEALTH-AND-EVENT-MODEL.md`.
- **Reuses:** `register*Routes`/`uiRoutes` (route metadata + C1/C1.5/C2 parity), `requireRole` RBAC, `auditEvent`/`auditEventDiff`, the `main.go:319` one-shot dispatch table, the maintenance-agent argv-template model.
- **Absolute rule:** these commands expose **product-level operations, never a shell**. No command takes free-form OS input; no command runs `sh -c`; no command reaches a host binary except through the agent's fixed argv registry.

---

## 1. Surfaces (one contract, three front-ends)

| Front-end | How | Availability |
|---|---|---|
| **Admin API** `/api/support/*`, `/api/diagnose/*` | `registerSupportRoutes(mux)` + `uiRoutes` rows | requires the server running |
| **GUI** `data-view="support"` | SPA panel calling the API | requires GUI healthy |
| **Culvert CLI** `culvert support …` / `culvert diagnose …` | thin verb shim over the API **plus** direct one-shot flags for recovery mode | **works when GUI/API are down** (P5) |

The CLI is primary for degraded-appliance scenarios: `culvert --support-bundle <out> [--scope <s>]` is a one-shot (dispatched from `handleOneShotCommands`) that boots a minimal collector set and writes a bundle **without a running server or GUI** — the recovery path. Online, the same CLI verbs call the API so behavior is identical.

---

## 2. Command catalog

Read/collect verbs (idempotent, side-effect-free except bundle files + audit):

| Command | API | Role | Effect |
|---|---|---|---|
| `culvert support status` | `GET /api/support/status` | viewer | health verdict + active debug level + recent bundles |
| `culvert support collect [--scope] [--level] [--window] [--case]` | `POST /api/support/bundles` | operator/admin* | run a bundle; prints redaction report; `--yes` to export |
| `culvert support inspect <bundle>` | `GET /api/support/bundles/{id}` | operator | show manifest + redaction report of a finished bundle |
| `culvert support validate <bundle>` | local | viewer | verify integrity hashes + schema of a bundle file |
| `culvert support history` | `GET /api/support/bundles` | operator | list past bundles (id, case, hashes, timestamps) |
| `culvert support upload <bundle> --case <id>` | `POST /api/support/uploads` | admin | explicit, audited upload (post-MVP; §7) |
| `culvert diagnose dns <host>` | `POST /api/diagnose/dns` | operator | bounded DNS resolution probe |
| `culvert diagnose tls <host:port>` | `POST /api/diagnose/tls` | operator | handshake + chain/expiry check (no MITM) |
| `culvert diagnose upstream [name]` | `POST /api/diagnose/upstream` | operator | upstream pool health + circuit state |
| `culvert diagnose storage` | `POST /api/diagnose/storage` | operator | writability + free space + data-dir stat |
| `culvert diagnose policy [--url] [--identity]` | `POST /api/diagnose/policy` | operator | dry-run policy evaluation (reuses policy tester) |
| `culvert diagnose cluster` | `POST /api/diagnose/cluster` | admin | fan-out cluster correlation (local vs cluster-wide) |
| `culvert health explain [component]` | `GET /api/health/explain` | viewer | CHR detail: cause, impact, evidence, remediation |

Control verbs (mutating, admin, audited, bounded):

| Command | API | Role | Effect |
|---|---|---|---|
| `culvert support debug set <level> --ttl <dur>` | `POST /api/support/debug` | admin | raise debug level with a **mandatory TTL** (P9) |
| `culvert support debug status` | `GET /api/support/debug` | viewer | current level + remaining TTL |
| `culvert support debug clear` | `DELETE /api/support/debug` | admin | revert to L0 immediately |

\* `collect`'s required role is the max of its scope's collectors (operator for standard; admin when host/runtime/cluster sections are included).

---

## 3. Command contract (every command obeys)

Each command is a typed operation, never a shell. The contract:

```go
type DiagCommand struct {
    Name        string          // "diagnose.dns"
    MinRole     Role            // requireRole gate
    Args        []ArgSpec       // typed, validated, allowlisted — no free-form OS strings
    Timeout     time.Duration   // hard cap; ctx-cancelled
    RateLimit   RateSpec        // per-actor token bucket
    Mutating    bool            // → CSRF + audit + saveConfigVersion where relevant
    AuditAction string          // auditEvent action key
    Output      OutputSchema    // typed JSON contract, versioned
    Cancellable bool            // long ops return an op id; DELETE cancels
}
```

- **Authorization:** `requireRole` at the handler + C2 metadata gate; `uiRoutes` entry mandatory (C1 parity). Remote/upload/cluster verbs are admin-only.
- **Safe arguments:** every arg is a typed `ArgSpec` with validation (a hostname is parsed + `isPrivateHost` checked for `diagnose dns/tls`; a level is an enum L0–L4; a duration is bounded). **No argument is ever concatenated into a command line or path** without validation; host-touching diagnostics go through the agent argv registry, not string building.
- **Timeouts & cancellation:** `http.NewRequestWithContext`/`ctx` deadlines everywhere; long operations (bundle collect, cluster fan-out) return an op id and support `DELETE …/{id}` cancel; a cancelled op cleans up partial artifacts.
- **Rate limits:** per-actor token bucket (reuse the sharded limiter) so a support command storm can't DoS the proxy hot path; bundle collection is single-flight per node.
- **Output contracts:** every command returns a typed, versioned JSON schema (golden-tested); the CLI renders it, the GUI renders it, automation parses it — one schema.
- **Audit:** every invocation emits `auditEvent` (`support.<verb>` / `diagnose.<verb>`); mutating debug-level changes use `auditEventDiff` (before/after level+ttl). Diagnostic reads are audited too (who pulled a bundle is security-relevant).

---

## 4. Privilege boundaries & break-glass

- **Privilege tiers:** viewer (read status/health), operator (collect standard bundles, run diagnostics), admin (host/runtime/cluster collection, debug levels, upload, remote support).
- **No shell, no arbitrary exec:** enforced by construction (no `exec` in the proxy; agent argv registry only) and by `TestNoShellInCommands`.
- **Break-glass (recovery):** the one-shot `culvert --support-bundle` runs with the privileges of the OS user that launched it (the operator on the host console) and collects only what that context can reach — it is the *degraded* path, explicitly bounded to a minimal collector set, and it audits to the bundle's own manifest since the audit ring may be unavailable. It cannot enable debug levels or upload; it only produces a local bundle.
- **Command allowlisting / signing:** the command set is a **fixed in-binary registry** (like `uiRoutes` and the agent's template registry) — there is no dynamic command loading, so allowlisting is structural. If a future release adds operator-defined diagnostic scripts, those would require the agent's argv-template + signing model and a separate ADR; **not in scope for this framework**.

---

## 5. Remote-support restrictions (interface only; see SECURE-UPLOAD §remote)

The command framework reserves `culvert support remote {approve|status|revoke}` as **admin-only, explicitly-consented, time-bound** verbs, but they are **not implemented in MVP**. The contract slots exist so the API/CLI shape is stable when remote support is added: any remote session is per-command authorized through this same `DiagCommand` registry (no new command types, no shell), fully audited, and immediately revocable. Until then the verbs return `not_enabled`.

---

## 6. GUI parity (mandatory)

Per CLAUDE.md, every CLI verb has an API endpoint and a UI affordance in `data-view="support"`:
- Status card (health verdict + debug countdown), Collect wizard (scope → preview → download/upload), History table, Health-explain drill-down, Diagnose sub-tabs (dns/tls/upstream/storage/policy/cluster), Debug-level control with a visible TTL countdown and a "clear now" button.
- The panel needs a nav-item, a view div, and load/render JS, and each new route needs its `uiRoutes` metadata row (or D0/C1/C2 tests fail).

---

## 7. Upload verb (deferred wiring, stable shape)

`culvert support upload <bundle> --case <id>` and `POST /api/support/uploads` are specified now (SECURE-UPLOAD-ARCHITECTURE) but gated `not_enabled` until M6. The shape (explicit, admin, per-bundle, case-bound, audited, returns an upload receipt) is fixed so enabling it later is a flag flip, not a redesign — satisfying "architect so Culvert can later integrate a cloud TAC portal without redesigning the appliance framework."

---

## 8. Test surface

| Test | Asserts |
|---|---|
| `TestSupportRoutesHaveMetadata` (C1) | every `/api/support|diagnose` route has a `uiRoutes` row |
| `TestSupportRBAC` (C1.5) | metadata `MinRole` matches handler `requireRole` |
| `TestNoShellInCommands` | no command reaches `exec`/`sh -c` |
| `TestDiagnoseArgsValidated` | malformed/hostile args rejected before any action (SSRF host check, enum bounds) |
| `TestCommandOutputSchema` | golden output schema per command version |
| `TestCommandAudited` | every invocation emits the expected audit action |
| `TestRecoveryBundleNoServer` | one-shot bundle works with server/GUI down |
| `TestDebugSetRequiresTTL` | debug-level set with no/oversized TTL rejected |
