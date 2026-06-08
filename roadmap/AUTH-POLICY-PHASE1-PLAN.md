# Authentication Policy — Phase 1 Implementation Plan (FINAL / FROZEN)

**Status:** Design FROZEN. Implementation NOT started.
**Supersedes:** the earlier "Stage-1 exempt hook" framing. The architectural
spine is now the **AuthOutcome resolver**, not a boolean gate with an exempt
escape hatch.
**Builds on:** `roadmap/AUTHENTICATION-POLICY-SPEC.md` (Phase 0 seams, merged via
#397/#401/#403/#406).

This document freezes the Phase 1 design. It authorizes **no** runtime code and
**no** change to `proxy.go`. Implementation begins only after explicit approval.

---

## 0. Product vision this plan must satisfy

Culvert must scale Home Lab → SMB → Mid-market → Enterprise on **one engine**,
with **no separate operating modes, deployment modes, or auth architectures**.

> Core principle: **authentication is policy-driven, not globally configured.**

The same policy engine resolves an **AuthOutcome** for every request:

| Deployment | Primarily uses |
|---|---|
| Home Lab | `Exempt` (default outcome = Exempt) |
| SMB | `BasicRequired` |
| Enterprise | `SSORequired` |
| ZTNA / SWG (future) | `+ mTLSRequired`, `StepUpRequired`, device/posture |

Global switches (`UnauthMode`, global Basic, global SSO, portal behavior) survive
only as **shorthands that set the default outcome** — never as a parallel auth
architecture.

---

## 1. FROZEN DECISIONS (normative — do not change without a new freeze)

1. **The architectural spine is the AuthOutcome resolver.**
   The end-user auth gate is a single function:
   ```
   resolveAuthOutcome(ctx RequestContext) → (AuthOutcome, *PolicyRule)
   ```
   It is NOT a boolean `authRequired` with special cases. Every later outcome is
   additive on this resolver; none requires a gate rewrite.

2. **The AuthOutcome enum is frozen:**
   ```
   Default        // no auth rule matched → fall through to the global-config-derived default
   Exempt         // skip end-user authentication (no identity created)
   BasicRequired  // require Proxy-Authorization / Basic / token
   SSORequired    // require browser SSO (portal / OIDC code flow / SAML)
   ```
   Reserved (future, additive only): `mTLSRequired`, `StepUpRequired`,
   `DeviceRequired`. `BasicRequired` and `SSORequired` are **distinct** — never
   collapsed into one `idp_required`.

3. **Global auth configuration remains infrastructure only.**
   IdP/provider connection configs and secrets (OIDC/SAML/LDAP endpoints), the
   local credential store, the session HMAC key, CA/TLS, and the admin-UI auth
   plane stay GLOBAL. They describe *how to authenticate*. They never move onto
   policy rules, and rules never carry secrets.

4. **Authentication decisions become policy-driven.**
   *Whether / which* auth a request needs is the resolver's output. Global config
   maps to the **default outcome** (`UnauthMode` → default `Exempt`; configured
   creds/IdP → default `BasicRequired`/`SSORequired`). The globals are routed
   THROUGH the resolver, not around it.

5. **Portal eligibility must not depend on User-Agent heuristics.**
   Redirect-to-SSO is a two-layer decision:
   - **Intent (policy):** outcome `SSORequired`.
   - **Mechanism (deterministic capability):** the request is redirectable —
     non-`CONNECT` AND HTML-navigable (`Accept:` contains `text/html`, optionally
     corroborated by `Sec-Fetch-Mode: navigate` / `Upgrade-Insecure-Requests`).
   `User-Agent` is NOT a gate. No new UA dependence is added. The legacy
   `Mozilla` heuristic is quarantined inside the unchanged `Default` path and is
   replaced when `SSORequired` ships.

6. **Exempt rules require a destination decision.**
   An `Exempt` rule MUST carry a source `SubjectMatch` AND a destination decision:
   ≥1 of `DestFQDN` / `DestCategory` / `DestCategoryGroup`, **or** an explicit,
   acknowledged `broadExemption: true`. A blank/omitted destination is REJECTED at
   validation — never silently treated as "any". `broadExemption` is breadth-
   warned, audit-logged, and diagnostics-escalated.

7. **Phase 1 implements only `Exempt`; `Default` is byte-identical to today.**
   The resolver returns `Exempt` (when a matching, valid exempt rule applies) or
   `Default`. `Default` runs the EXISTING auth gate verbatim. The only `proxy.go`
   change is a single outcome-seam insertion that is byte-identical when no exempt
   rule matches. `BasicRequired`/`SSORequired` are NOT implemented in Phase 1.
   SOCKS5 is NOT touched.

---

## 2. Runtime architecture

### 2.1 The resolver seam (new spine)

```
              ┌─────────────────────────────────────────────┐
  request ──▶ │ resolveAuthOutcome(ctx) → (outcome, rule?)  │
              └─────────────────────────────────────────────┘
                         │
   ┌─────────────────────┼───────────────────────────────────────────┐
   ▼                     ▼                     ▼                       ▼
 Exempt            BasicRequired          SSORequired              Default
 (Phase 1)         (Phase 2)              (Phase 3)                (today's gate)
   │                     │                     │                       │
 authSource=          407 Basic        portal? 302 : 407        run existing
 "exempt",            challenge        (policy + Accept,         session/Basic/
 no identity,                          NOT User-Agent)           SSO logic verbatim
 → Stage-2 policy
```

- **Resolution order inside the gate** (frozen precedence):
  1. Global off (`UnauthMode` → default outcome `Exempt`) — unchanged short-circuit.
  2. Valid **session cookie** (real creds win).
  3. Valid **Proxy-Authorization / Basic / token** (real creds win).
     - **Failed credentials → 407 immediately; never eligible for Exempt.**
  4. **Auth Bypass / Exempt rule** (explicit, scoped) — *before* the SSO redirect
     so an admin-authored rule beats the spoofable heuristic.
  5. **SSO redirect** (browser + portal-capable), i.e. the `Default`/`SSORequired`
     mechanism.
  6. **407** fallback.
- Phase 1 wires only steps 1–4 + the existing 5–6 as `Default`.

### 2.2 Two stages, one ruleset (unchanged from the spec)

- **Stage 1 (AuthN):** `resolveAuthOutcome` evaluates `RuleType:"auth"` rules by
  priority on the *unauthenticated* context. No identity-dependent predicates.
- **Stage 2 (AuthZ):** the existing `policyStore.Evaluate` (access rules), default-
  deny intact. Runs AFTER the auth outcome, with `authSource` = `exempt` or the
  resolved real source. **Exempt waives authentication only** — blocklist, threat,
  file-block, SSRF, and default-deny all still apply. **Exempt ≠ allow.**

### 2.3 Why this avoids a future migration

Because the gate already returns an *outcome with a default*, adding
`BasicRequired` (Phase 2) and `SSORequired` (Phase 3) means decomposing the
`Default` branch into explicit outcomes — purely additive. The Home Lab→SMB→
Enterprise progression is a change of **default outcome + rules**, never an engine
rewrite.

---

## 3. Auth (Exempt) rule model — Phase 1

Reuses `PolicyRule` with `RuleType:"auth"` plus an auth-only nested spec
(nil for access rules; access rules untouched):

```
PolicyRule{
  Priority      int             // ordering (exists)
  Enabled       *bool           // active flag (exists)
  RuleType      "auth"          // discriminator (exists, Phase 0)
  SubjectMatch  *SubjectMatch   // SOURCE — cidr only in P1 (exists; matcher wired in P1)
  DestFQDN / DestCategory / DestCategoryGroup  // DESTINATION (exist)
  Schedule      *PolicySchedule // optional time window (exists)
  Auth          *AuthRuleSpec   // NEW — non-nil only for auth rules
}

AuthRuleSpec{
  Outcome        "Exempt"   // P1 only; enum frozen (Default/Exempt/BasicRequired/SSORequired)
  Protocol       "http"|"connect"|""   // "" = any; "socks5" REJECTED in P1
  Method         string     // optional HTTP method; "" = any
  Owner          string     // REQUIRED
  Reason         string     // REQUIRED
  ExpiresAt      string     // RFC3339 UTC; "" = no expiry (breadth-warned)
  BroadExemption bool       // explicit ack for destination=any; warned + audited
  // State reserved for the Phase-2 approval workflow
}
```

- **Source** → `SubjectMatch` typed schema (`cidr` in P1; fail-closed on unknown
  type; mandatory).
- **Destination** → existing `matchDest` (FQDN/category/group); REQUIRED per
  Freeze #6 unless `BroadExemption`.
- **Validation (auth/exempt rules):** require source + destination decision;
  `Owner`+`Reason` mandatory; `Protocol ∈ {http, connect, ""}` (`socks5`
  rejected); `ExpiresAt` parseable UTC; **no identity-dependent predicates**
  (no identity at Stage 1).

---

## 4. Logs / SIEM (Phase 0 fields populated in Phase 1)

`LogEntry` already carries the normalized fields. Phase 1 populates them:

| Field | Phase 1 value |
|---|---|
| `auth_source` | `"exempt"` (categorical enum; never `"bypass:<name>"`) |
| `auth_policy_rule_id` | matched auth rule ULID |
| `auth_policy_rule_name` | matched auth rule display name |
| `subject_match_types` | `["cidr"]` |
| `schema_version` | flips to `1` (announced additive SIEM change) |

Plus request log line `AUTH_EXEMPT rule=… src=… host=… proto=…` and metric
`culvert_auth_exempt_total{rule_id}`. Admin CRUD audited via `auditEventDiff` +
`saveConfigVersion`.

---

## 5. Safety guarantees

| Guarantee | Mechanism |
|---|---|
| Exempt never creates a real identity | `identity=""`, `X-User-Identity` not set |
| Failed credentials are never exempt | Resolver consults Exempt only in the no-credentials path; failed Basic → 407 first |
| Default deny still applies | Stage-2 unchanged; Exempt waives auth only |
| Destination least-privilege | Freeze #6: destination decision required; blank rejected; broad = explicit + warned |
| Broad-bypass warnings | `validatePolicyRule` + `checkAuthBypass` diagnostics: `0.0.0.0/0`, prefix > /24, dest-any/`broadExemption`, no-expiry, exempt-while-`default==allow`, source overlaps interactive subnet |
| Kill switch (fail-closed) | `CULVERT_AUTHBYPASS_DISABLE` (env, read-once) + runtime admin toggle → auth-required |
| Expiry / unknown predicate / parse error | All fail-closed (auth-required), never fail-open |
| No runtime change until proven | Empty auth ruleset ⇒ byte-identical; full decision-matrix tests gate the hook |

---

## 6. Cluster / import / rollback

- **Validation choke point:** `validatePolicyRule` now ACCEPTS a `SubjectMatch` on
  `RuleType:"auth"` rules (still REJECTS it on access rules until the access-rule
  matcher lands). The Phase-0 `ReplaceAll` blanket drop-guard is updated to:
  *keep valid auth rules; still drop `SubjectMatch` on access rules.*
- **Cluster sync:** `ConfigSnapshot` gains the auth-rule fields (+ schema/min-
  version for capability negotiation). A DP that meets an unknown predicate type
  or whose resolvers are unavailable **fails closed** (drop/quarantine rule;
  exempt → auth-required) with warn + metric. DP max-staleness fail-closed for
  exempt rules is a later cluster slice (documented limitation; Phase 1 ships
  single-node-correct).
- **Import/export + rollback:** `configBackup` round-trips auth rules (rollback-
  surface inclusion — no secrets). Bulk paths inherit the `ReplaceAll` guard.

---

## 7. SOCKS5 — EXCLUDED from Phase 1 (frozen)

`socks5.go` does not run the policy engine. Per the spec invariant, **no SOCKS5
exemption may ship before SOCKS5 runs the engine.** Phase 1 touches HTTP/CONNECT
only; `AuthRuleSpec.Protocol="socks5"` is rejected at validation; `socks5.go` is
unchanged (asserted by test). SOCKS5 alignment (RequestContext → engine → then
exemption, behind a migration toggle) is Phase 4.

---

## 8. Portal / SSO model (frozen design; realized when SSORequired ships)

Replacement for the `User-Agent contains "Mozilla"` heuristic:

- **Layer 1 — intent (policy):** outcome `SSORequired` (explicit, admin-declared).
- **Layer 2 — mechanism (deterministic):** redirectable iff non-`CONNECT` AND
  `Accept:` contains `text/html` (corroborated by `Sec-Fetch-Mode: navigate` /
  `Upgrade-Insecure-Requests`). Else → `407` with `Proxy-Authenticate` + `Link`
  to the authorization endpoint (so API/agent clients get an actionable challenge,
  CONNECT gets 407).
- **Client distinction** (priority): (1) policy outcome the admin declared;
  (2) deterministic capability (CONNECT vs HTTP, `Accept`, presence of creds);
  (3) future device identity / posture (mTLS, agent, EDR). **Never** UA.
- **Shared subnet / NAT:** scope exempt devices to host `/32` + destination; when
  an interactive user and a legacy device share a NAT'd IP, **destination scoping
  is the only disambiguator** until device identity exists. Reinforces Freeze #6.
- **PAC determinism:** behavior keys on policy + `method` + `Accept` — all
  deterministic; no UA guessing.

Phase 1 does NOT change the legacy redirect behavior (it lives in the unchanged
`Default` path). This model is frozen so `SSORequired` (Phase 3) replaces the
heuristic without a migration.

---

## 9. Implementation slices (small, independently shippable)

Slices 1–6 touch **no runtime path**; slice 7 is the single `proxy.go` change and
the go/no-go gate.

1. **AuthOutcome + resolver contract** — enum (frozen), `resolveAuthOutcome`
   signature returning `(outcome, *rule)`; `Default` maps to current behavior.
   Pure, table-tested. Not wired.
2. **Exempt rule model + validation** — `AuthRuleSpec`; source+destination
   required; owner/reason mandatory; protocol∈{http,connect,""} (socks5 rejected);
   `BroadExemption` ack; expiry parse; no identity predicates.
3. **Subject matcher** — `matchSubject(SubjectMatch, clientIP)` for `cidr`,
   fail-closed; unit-tested in isolation.
4. **Stage-1 evaluator** — `evaluateAuthPolicy` over `RuleType:"auth"` rules
   (source + dest + protocol + method + schedule + enabled + not-expired); returns
   `Exempt` or `Default`. Pure, table-tested.
5. **Persistence update** — `validatePolicyRule` accepts SubjectMatch on auth rules
   (still rejects on access); `ReplaceAll` keeps auth, still drops access
   SubjectMatch; import/export/rollback/cluster round-trip.
6. **SIEM population + metrics + diagnostics** — populate the LogEntry fields;
   `culvert_auth_exempt_total`; `checkAuthBypass` breadth warnings; runtime kill
   switch.
7. **`proxy.go` outcome-seam insertion** — call `resolveAuthOutcome` at the top of
   the gate; `Exempt` short-circuits (authSource=exempt, no identity, → Stage-2);
   everything else == `Default` == today. Byte-identical with an empty auth
   ruleset. **Go/no-go gate.**
8. **API + UI** — CRUD endpoints (`uiRoutes` metadata; admin write / viewer read;
   `AuditExpected`; `saveConfigVersion`); panel with breadth banners + expiry; the
   two-stage simulator (extend `apiPolicyTest`).

---

## 10. Files expected to change

| File | Change |
|---|---|
| `authpolicy.go` | `AuthOutcome` enum; `resolveAuthOutcome`; `AuthRuleSpec`; `evaluateAuthPolicy`; `matchSubject`; runtime kill-switch state |
| `policy.go` | `PolicyRule.Auth` field; `ReplaceAll` guard split (auth vs access); Stage-1 helpers |
| `ui_helpers.go` | `validatePolicyRule` auth-rule rules (source+dest required, owner/reason, protocol, expiry, accept SubjectMatch on auth) |
| `store.go` | populate the six SIEM fields; `recordRequest` wrapper |
| `proxy.go` | **single** outcome-seam insertion (slice 7 only) |
| `metrics.go` | `culvert_auth_exempt_total` |
| `diagnostics.go` | `checkAuthBypass` breadth warnings |
| `controlplane.go` | `ConfigSnapshot` auth-rule fields + capability metadata |
| `ui_config.go` / `configversion.go` | import/export + rollback round-trip |
| `ui_policy.go` / `ui_routes_meta.go` / `static/index.html` | CRUD API + metadata + panel + simulator |
| `socks5.go` | **unchanged** (asserted by test) |

---

## 11. Required regression tests

- **Decision matrix (proxy):** valid creds win (Exempt not consulted) · no-creds +
  matching exempt ⇒ proceeds, identity empty, `X-User-Identity` unset, Stage-2
  runs · no-creds + no match ⇒ Default==today · **failed Basic ⇒ 407, never
  exempt** · exempt + default-deny ⇒ `POLICY_DEFAULT_DENY` · expired/disabled ⇒
  Default · env kill switch ⇒ auth-required · runtime kill switch ⇒ auth-required
  · **Exempt evaluated before SSO redirect** (browser-UA device on exempt host/dest
  ⇒ exempt, not redirected).
- **Destination scoping:** exempt with no destination ⇒ rejected · explicit
  `broadExemption` ⇒ accepted + warned + audited · dest-scoped exempt ⇒ unauth only
  to named dest; non-exempt dest from same source ⇒ 407.
- **Matcher:** cidr in/out, multi-CIDR, malformed (fail-closed), unknown predicate
  (fail-closed).
- **Persistence:** auth rule survives ReplaceAll/import/rollback/cluster; access
  rule with SubjectMatch still dropped/rejected; export/import + config-version
  round-trip.
- **SIEM:** `auth_source="exempt"`, rule id/name, `schema_version=1`, metric
  increment; audit on CRUD asserted by **content**, not ring length.
- **Validation/warnings:** owner/reason required; socks5 rejected; broad-bypass +
  exempt-while-default-allow warnings.
- **Zero-change:** empty auth ruleset ⇒ proxy/SOCKS5 byte-identical; `socks5.go`
  untouched; `UnauthMode` unchanged.
- **Admin plane:** D0 route count bump, C1/C1.5 metadata parity, RBAC, CSRF,
  config-version snapshot.

---

## 12. Risk matrix

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Fail-open (rule too broad) | Med | **Critical** | Mandatory source+dest scoping; fail-closed defaults; default-deny backstop; breadth warnings; simulator |
| Boolean spine creeps back in | Low | **Critical** | Freeze #1/#7: resolver returns outcome+default; reviewed at slice 7 |
| Basic/SSO conflated later | Low | High | Freeze #2: enum distinct |
| UA heuristic re-entrenched | Low | High | Freeze #5: no new UA dependence; quarantined in Default |
| `ReplaceAll` relaxation re-opens access footgun | Low | High | Guard split + dedicated tests |
| `recordRequest` signature churn | Med | Med | Wrapper + default-empty; omitempty fields |
| Cluster DP divergence pre-snapshot | Med | Med | Ship single-node; gate multi-node; fail-closed on unknown |
| Scope creep into Basic/SSO/SOCKS5 | Med | Med | Freeze #7: Exempt only; SOCKS5 excluded |
| Expiry clock skew (cluster) | Low | Med | UTC absolute; cluster staleness deferred + documented |

---

## 13. Go/No-Go

The design is internally consistent with the product vision and the current tree.
The only runtime change is a single, gated outcome-seam insertion in `proxy.go`
(slice 7), behind a "no auth rules ⇒ byte-identical" guarantee. Approval of this
document authorizes implementation of slices 1–8 in order; slice 7 is the
behavior-change gate and must pass the full decision matrix before merge.
