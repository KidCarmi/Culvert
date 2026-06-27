# Authentication Policy — Frozen Architecture Spec

**Status:** FROZEN (architecture). Implementation not started.
**Scope:** Replace production reliance on global Unauth Mode with scoped,
context-aware **Authentication Policy** evaluated inside a unified Policy
Decision Point (PDP). Optimize for maintainability, operator experience, and
long-term evolution toward a commercial enterprise SWG / Browser Security /
ZTNA product.

This document freezes the architecture. It does **not** authorize runtime code
changes. No proxy behavior changes are introduced by this commit.

---

## 0. Problem statement

`UnauthMode` (`store.go:1326`) disables end-user authentication **globally**.
That is acceptable for lab/setup, but unsafe for production, where only specific
legacy / service / unmanaged machines cannot authenticate via the IdP.

The current end-user auth gate is a single boolean (`proxy.go:241`):

```go
authRequired := !cfg.UnauthMode() &&
    (cfg.AuthEnabled() || cfg.ProviderEnabled() || len(idpRegistry.EnabledProviders()) > 0)
```

There is no scoped way to exempt a narrow set of clients from authentication
while keeping everyone else authenticated. This spec introduces that capability
**without** the strategic debt of a CIDR-keyed standalone bypass list.

---

## 1. Frozen architecture

### 1.1 Unified PDP

A single decision entry point evaluates every request:

```
Decide(ctx RequestContext) AccessDecision
```

- One ordered ruleset (the existing `policyStore`), one priority model, one
  persistence / sync / config-versioning mechanism, shared matchers
  (`matchSource`, `matchIPOrCIDR`, `matchFQDN`, `matchCategory`).
- Locked evaluation order (resolves the circular dependency — see §1.2/§1.3):

  ```
  Decide(ctx):
    Stage 1  Authentication Policy   (filtered pre-pass; does NOT read authSource)
    Stage 2  Access Policy           (reads the resolved authSource)
  ```

`Decide()` is the only place that encodes stage ordering. Stages must not call
each other; Stage 1's output (`authSource`) is an input to Stage 2.

### 1.2 Stage 1 — Authentication Policy

Decides **what authentication a request requires**, per context. It runs **only**
when the request is unauthenticated **and** authentication is otherwise required.
(Valid credentials and fully-disabled auth / lab `UnauthMode` both skip Stage 1.)

- Matches a typed subset of rules: `RuleType: "auth"`.
- Matches on the **unauthenticated** context only (source / destination /
  protocol / method). It **does not** read `authSource`; this is what dissolves
  the auth↔policy circular dependency.
- **Validation forbids identity/group predicates on `auth` rules** — there is no
  identity yet at Stage 1. Enforced at the API layer and on load.
- Outcome is a **string enum**, never a bool:

  | Outcome         | Status | Meaning                                            |
  |-----------------|--------|----------------------------------------------------|
  | `idp_required`  | v1     | Current behavior — must authenticate via IdP/local |
  | `exempt`        | v1     | No end-user auth required for this scoped context   |
  | `mtls_required` | future | Device/client certificate required                 |
  | `surrogate_ip`  | future | Transparent / surrogate identity                   |

- **Fail-closed default (configurable via `defaultAuthOutcome`):** no Stage-1
  match ⇒ the global `defaultAuthOutcome` applies. It defaults to `Default`
  (auth required / `407` — the structural fail-closed default, unchanged), and
  may be set to `Exempt` for open-by-default on *unmatched* traffic only.
  Scoped rules always win by priority; the kill switch forces `Default`. This
  global default replaces the retired `UnauthMode` toggle — see
  `AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md` (the authority for that work).
- On `exempt`: set `authSource = "exempt"`, leave identity empty, do **not** set
  `X-User-Identity`. No real user identity is minted. Execution continues to
  Stage 2 — policy still governs.

Hook point: the no-credentials branch of the auth gate (`proxy.go:284`), before
the `407` / captive-portal response.

### 1.3 Stage 2 — Access Policy

The existing policy engine, semantics **unchanged**:

- `policyStore.Evaluate(clientIP, identity, authSource, host, groups)`
  (`policy.go:658`), first-match by priority, terminal actions
  (`Allow`/`Drop`/`Block_Page`/`Redirect`), default-**deny** Zero Trust backstop.
- Runs with the resolved `authSource` (real source, or `"exempt"`).
- **Zero-regression guarantee.** Existing `PolicyRule` semantics, priority, SSL/
  file dimensions, and default-deny are untouched. A `RuleType` discriminator is
  added with **load-default `access`** so all pre-existing rules (and JSON
  without the field) remain access rules — mirroring the `Enabled *bool` nil
  convention (`policy.go:340`).

**Key safety property:** `exempt` waives *authentication only*. Blocklist,
threat feed, file-block, SSRF, and the full Stage-2 access policy (including
default-deny) all still apply. **Exempt ≠ allow.**

### 1.4 RequestContext seam

A protocol-neutral struct is the single input to `Decide()`:

```
RequestContext {
    ClientIP   string
    Host       string
    Port       int
    Protocol   string   // "http" | "connect" | "socks5"
    Method     string   // HTTP method; empty for SOCKS5
    Identity   string   // resolved identity, empty if none
    AuthSource string   // resolved by Stage 1 / auth gate
    Groups     []string
    DeviceSignals any    // reserved: posture / device identity (future)
}
```

This seam is **mandatory in v1** even though only HTTP/CONNECT populate it and
several fields stay empty. It is the seam that makes SOCKS5 alignment (§1.7) and
posture/device extensibility (§1.6) **additive** rather than a breaking refactor.

### 1.5 Stable ULID rule IDs

Every rule (auth and access) carries a stable **ULID** `id`:

- `id` is the durable key for SIEM joins, cluster sync, and APIs.
- `name` is display-only; `priority` is ordering-only.
- IDs are assigned on load to existing rules (additive migration) and persisted.
- The existing priority-keyed `apiPolicy` surface keeps working during the
  migration; the ID becomes the canonical key over time.

Rationale: name- or priority-keyed identity breaks SIEM history on rename/reorder
and cannot survive multi-node reconciliation.

### 1.6 Typed SubjectMatch (extensibility seam)

Source matching is a **versioned, typed predicate list** — never a flat
`SourceCIDR` scalar:

```jsonc
"subjectMatch": {
  "schemaVersion": 1,
  "all": [
    { "type": "cidr",            "values": ["10.0.5.0/24"] },
    { "type": "directory_group", "values": ["ServiceAccounts"] },  // future
    { "type": "tag",             "values": ["no-idp"] },           // future
    { "type": "asset_group",     "values": ["legacy-pos"] },       // future
    { "type": "device_id",       "values": ["dev-abc"] },          // future
    { "type": "posture", "op": "gte", "values": ["compliant"] }    // future
  ]
}
```

- Semantics: predicate **types are AND'd**; **values within a type are OR'd**.
- v1 implements `cidr` only. Other types are reserved.
- **Unknown predicate type ⇒ hard fail-closed** (validation error on input; on a
  config from a newer node, the rule does not match / requires auth). Silent
  "ignore unknown" is banned — on an exemption it is a fail-open trapdoor.
- Dynamic signals (`tag`, `asset_group`, `device_id`, `posture`) are resolved at
  **runtime** via pluggable interfaces, never baked into the rule:
  - `InventoryResolver` — name → identifiers, cached + TTL.
  - `PostureProvider` — device → current posture signal, cached + TTL,
    **fail-closed** (unknown posture ⇒ predicate false).
  Interfaces are defined in v1 seams; implementations are deferred (§3 Phase 5).

Adding a new predicate type is purely additive: bump `schemaVersion`, no breaking
migration.

### 1.7 SOCKS5 invariant

**Today `handleSOCKS5` (`socks5.go:120`) never calls the policy engine** — it
runs only blocklist + plugin + SSRF.

> **Hard invariant:** SOCKS5 authentication exemption MUST NOT ship before
> SOCKS5 is routed through the unified `Decide()` (i.e., before SOCKS5 enforces
> Stage 2 access policy). Exempting auth on a path with no policy engine would
> create an open SOCKS proxy gated only by the blocklist.

SOCKS5 alignment is deferred (§3 Phase 4), behind a migration toggle that
defaults to **legacy allow-through** (routing SOCKS5 through default-deny is a
breaking change for existing SOCKS5 users and must be opt-in). The
`RequestContext` seam (§1.4) is shaped to accommodate SOCKS5 from v1.

### 1.8 Normalized SIEM schema

`LogEntry` (`store.go:108`) **is** the SIEM contract — `syslogWriter.WriteRequest`
emits `json.Marshal(LogEntry)` (`syslog.go:88`). Today it has no `authSource`
field at all. The following normalized, dimensional fields are added (additive;
old consumers unaffected):

| Field                    | Cardinality | Purpose                                        |
|--------------------------|-------------|------------------------------------------------|
| `schema_version`         | const       | Event schema version                           |
| `auth_source`            | low (enum)  | `idp` \| `local` \| `oidc:x` \| `saml:x` \| `exempt` \| `unauth` |
| `auth_policy_rule_id`    | dimension   | ULID of the matched Stage-1 rule (nullable)    |
| `auth_policy_rule_name`  | dimension   | Display name (nullable)                         |
| `access_rule_id`         | dimension   | ULID of the matched Stage-2 rule (nullable)    |
| `subject_match_types`    | small set   | Which selector dimensions matched (e.g. `["cidr"]`) |

**Banned:** `auth_source = "bypass:<rule_name>"`. Packing a high-cardinality
identifier into a categorical field breaks `GROUP BY auth_source`, forces SIEM
string-parsing, and corrupts history on rename. Rule identity is carried by the
stable `*_rule_id` dimensions.

### 1.9 Cluster: max-staleness / fail-closed semantics

- `ConfigSnapshot` (`controlplane.go:70`) gains `AuthPolicyRules` +
  `AuthPolicyVersion` (monotonic) when exemptions can run in a clustered build.
  Omitting them = CP/DP enforcement divergence.
- **Exemptions are more perishable than allow/block rules.** A Data Plane node
  past its **max-staleness TTL** must **fail closed on Stage 1** (require auth)
  while continuing to serve its last-known Stage-2 access policy. A stale waiver
  is a security hole; a stale allow/block is merely outdated.
- **Fail-closed everywhere in Stage 1:** stale config, missing posture signal,
  unknown selector type, kill switch engaged, or parse error ⇒ auth required.
- Revocation converges via the monotonic epoch (a DP refuses exemptions unless it
  confirms it is on the latest epoch within TTL). `ExpiresAt` is absolute UTC;
  a clock-skew guard is applied. (Epoch fast-revocation + skew guard land with
  the cluster phase; the semantics are frozen here.)

### 1.10 UI parity + simulator

- **UI parity is mandatory** (CLAUDE.md GUI-parity rule): every shipped API
  endpoint gets a panel. Minimum = Authentication-Policy CRUD with **clear
  visual separation from access rules**, inline breadth warnings, and owner /
  reason / expiry surfaced.
- **Two-stage simulator** (operator-safety control, not polish): extend
  `apiPolicyTest` (`ui_policy.go:1069`) to answer "would this request be
  exempted, then allowed/blocked?" — the primary defense against fail-open
  misconfiguration.

### 1.11 Operational safety (frozen requirements)

- **Kill switch — two:** `CULVERT_AUTHBYPASS_DISABLE` env (read-once, immutable
  break-glass, mirrors `CULVERT_C2_ENFORCE`) **and** an audited runtime admin
  toggle. Both **fail to "auth required,"** never fail-open.
- **Mandatory metadata:** `owner` and `reason` required on every auth rule.
- **Mandatory expiry:** TTL field present from v1; hard-cap enforcement and
  auto-disable land in Phase 2.
- **Breadth warnings:** broad `cidr` (e.g. `0.0.0.0/0`, prefixes broader than
  `/24`), dest-any, no-expiry, and **any exemption active while
  `defaultPolicyAction()=="allow"`** (exempt + passthrough = open proxy) are
  surfaced via diagnostics (mirroring `checkUnauthMode`, `diagnostics.go:503`).
- **Drift / usage detection** (Phase 2): unused-rule, expired-but-enabled,
  over-broad, usage-anomaly, and bypass-budget signals via metrics +
  diagnostics/governance.
- **Approval state machine** (`draft → pending_approval → active →
  expired/revoked`): the `state` field is reserved from v1 so enforcement is a
  later, non-breaking addition.

---

## 2. Non-goals

This spec explicitly does **not** include, and future work must not silently
introduce, the following:

- **~~No removal of global `UnauthMode`.~~** *(Amended.)* `UnauthMode` is
  **retired** and replaced by the scoped-policy-aware global
  `defaultAuthOutcome` (`Default` = fail-closed; `Exempt` = open-on-no-match,
  kill-switch-guarded). The global toggle no longer overrides scoped rules:
  scoped `Exempt`/`CredentialRequired`/`SSORequired` win by priority. See
  `AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md` for the frozen contract and the
  Slice 1–5 program.
- **No admin UI authentication changes.** Admin RBAC, sessions, and the admin
  login path are out of scope. "Exempt" applies to **end-user proxy traffic
  only** and is never an admin-UI actor.
- **No SOCKS5 auth exemption before SOCKS5 policy alignment** (the §1.7
  invariant).
- **No standalone `AuthBypassStore`.** Authentication Policy is a typed rule
  class inside the single unified engine — not a parallel subsystem with its own
  store / API / priority order.
- **No terminal `BypassAuth` `PolicyAction`.** `PolicyAction`s are terminal and
  return; auth requirement is a non-terminal, orthogonal dimension (Stage 1),
  structurally like `SSLAction`.
- **No CIDR-only / flat-scalar permanent schema.** Source matching is the typed,
  versioned `SubjectMatch` from day one (§1.6); `SourceCIDR string` as the
  permanent shape is banned.

---

## 3. Implementation roadmap

### Dependency graph

```
Phase 0 (seams) ──┬─► Phase 1 (Stage-1 exempt, HTTP/CONNECT)  ◄── minimal v1
                  │        │
                  │        ├─► Phase 2 (operator safety)
                  │        ├─► Phase 3 (cluster)
                  │        └─► Phase 4 (SOCKS5)   ── requires RequestContext (P0)
                  └─────────────► Phase 5 (extensibility activation)
```

**Minimal shippable v1 = Phase 0 + Phase 1.** All later phases are additive on
frozen seams — no breaking migration at any later phase.

### Phase 0 — Foundations / seams *(no behavior change)*

- **Build:** `RequestContext`; `Decide()` skeleton delegating to current logic;
  `RuleType` discriminator (load-default `access`); ULID `id` on all rules
  (assigned on load + persisted); `SubjectMatch` schema (`cidr` only);
  `InventoryResolver` / `PostureProvider` **interfaces**; normalized `LogEntry`
  fields + `schema_version`; `CULVERT_AUTHBYPASS_DISABLE` env constant.
- **Deps:** none.
- **Risks:** ID retrofit vs priority-keyed `apiPolicy`. *Mitigation:* additive
  ID; keep priority API working.
- **Acceptance:**
  - All existing tests green; D0 route count unchanged.
  - Existing policy JSON loads with `RuleType=access` + assigned IDs.
  - `Decide()` produces decisions byte-identical to current `proxy.go`.
  - SIEM output is a strict superset (existing fields intact).

### Phase 1 — Stage-1 Authentication Policy *(HTTP/CONNECT; `exempt`; `cidr`)* — MVP

- **Build:** Stage-1 hook in the no-creds branch (`proxy.go:284`);
  `authSource="exempt"`, identity empty, `X-User-Identity` unset, **Stage 2 still
  runs**; per-request log/metrics; CRUD API + `uiRoutes` metadata (admin write /
  viewer read, `AuditExpected`) + `saveConfigVersion`; UI panel + breadth
  warnings; diagnostics check; validation (no identity predicates, mandatory
  owner/reason, TTL cap, fail-closed); env **and** runtime kill switch (fail to
  auth-required); two-stage simulator.
- **Deps:** Phase 0.
- **Risks:** fail-open misconfiguration. *Mitigation:* fail-closed everywhere +
  breadth warnings + simulator + default-deny backstop.
- **Acceptance (decision matrix):**
  - Valid creds win (exemption not consulted).
  - No-creds + exempt ⇒ proceeds; identity empty; `X-User-Identity` unset;
    Stage 2 evaluated.
  - No-creds + no match ⇒ `407`.
  - **Bad creds ⇒ `407`, never exempted.**
  - Exempt + default-deny ⇒ blocked (`POLICY_DEFAULT_DENY`).
  - Expired / disabled rule ⇒ `407`.
  - Kill switch (env or runtime) ⇒ auth required.
  - Analytics fields populated correctly (`auth_source="exempt"`, rule IDs).
  - C1 / C1.5 / D0 parity for new routes; config-version snapshot created.
  - Audit asserted by **content**, not audit-ring length (ring saturation rule).

### Phase 2 — Operator-safety hardening *(deferred)*

- **Build:** max-count cap; mandatory-expiry enforcement + auto-disable;
  drift / usage-anomaly / bypass-budget detection + metrics; approval
  state-machine field (enforcement flag-gated).
- **Deps:** Phase 1.
- **Acceptance:** cap rejects overflow; expired rules auto-disable and require
  auth; drift checks surface in diagnostics/governance; simulator decision
  matches runtime.

### Phase 3 — Cluster *(deferred)*

- **Build:** `ConfigSnapshot.AuthPolicyRules` + `AuthPolicyVersion`; DP
  fail-closed past max-staleness TTL; epoch-based revocation; clock-skew guard;
  global-unauth-in-cluster diagnostics escalation.
- **Deps:** Phase 1 (schema reserved in Phase 0).
- **Acceptance:** snapshot round-trips auth rules; DP requires auth when stale;
  epoch revocation converges; export/import + config-rollback round-trip.

### Phase 4 — SOCKS5 alignment *(deferred)*

- **Build:** SOCKS5 builds `RequestContext` → unified `Decide`, behind a
  migration toggle (legacy allow-through default); then SOCKS5 exemption.
- **Deps:** Phase 0 (RequestContext), Phase 1.
- **Risks:** default-deny is breaking for existing SOCKS5 users. *Mitigation:*
  opt-in toggle + diagnostics nudge.
- **Acceptance:** toggle off ⇒ byte-identical legacy behavior; toggle on ⇒
  policy enforced, default-deny, exemption works; decision matrix as Phase 1.

### Phase 5 — Extensibility activation *(deferred; stable schema)*

- **Build:** `InventoryResolver` / `PostureProvider` implementations; predicate
  types `device_id` / `tag` / `asset_group` / `posture`; `mtls_required`
  outcome; approval-workflow UI; drift dashboards.
- **Deps:** Phases 1–2.
- **Acceptance:** new predicate types fail-closed when their provider is
  unavailable; all additions are schema-additive (zero migration);
  `schemaVersion` bump only.

---

## 4. Cross-cutting risks

| Risk | Mitigation |
|------|------------|
| Fail-open on misconfiguration | Fail-closed defaults everywhere; breadth warnings; simulator; default-deny backstop |
| Scope explosion / over-engineering | Ship seams in Phase 0, minimal behavior in Phase 1; defer the rest behind flags |
| Hot-path latency (extra pass) | Stage 1 runs only for unauthenticated requests; index by source |
| Stable-ID migration vs priority-keyed API | Additive ID; keep priority API working during migration |
| External posture/inventory providers on request path | Cache + TTL + fail-closed; never synchronous-to-CP on the hot path |
| SOCKS5 default-deny is breaking | Opt-in migration toggle, legacy default |
| `LogEntry`/SIEM schema is a breaking contract | Get normalized field names right in Phase 0; additive only; `schema_version` |

---

## 5. References (current code)

- Auth gate / `authRequired`: `proxy.go:237`–`315`
- `UnauthMode`: `store.go:1326`–`1346`; setter `ui_config.go:769`; setup
  `ui_auth.go:358`; diagnostics `diagnostics.go:503`
- Policy engine: `policy.go:315` (`PolicyRule`), `policy.go:658` (`Evaluate`),
  `policy.go:778` (`matchSource`), `policy.go:786` (`matchAuthSource`)
- Policy actions (terminal): `policy.go:18`–`24`; `SSLAction` (orthogonal
  precedent): `policy.go:28`–`32`, applied `proxy.go:467`
- Request logging / SIEM: `store.go:108` (`LogEntry`), `store.go:1712`
  (`recordRequest`), `syslog.go:88` (`WriteRequest`)
- Cluster snapshot: `controlplane.go:70` (`ConfigSnapshot`), `:77`
  (`UnauthMode`), `:1802`
- Policy CRUD pattern: `ui_policy.go:783` (`apiPolicy`), `:1069`
  (`apiPolicyTest`), `:1300` (`registerPolicyRoutes`)
- Config export/import + rollback surface: `ui_policy.go:640` (`configBackup`)
- SOCKS5 (no policy engine today): `socks5.go:120`–`300`
