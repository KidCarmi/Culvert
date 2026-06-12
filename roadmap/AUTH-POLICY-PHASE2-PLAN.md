# Authentication Policy — Phase 2 Plan: `CredentialRequired`

Status: **APPROVED — pre-Phase-2 corrections shipped; slices not yet implemented.**
Predecessors: `AUTHENTICATION-POLICY-SPEC.md` (Phase 0 seams), `AUTH-POLICY-PHASE1-PLAN.md`
(Exempt, Slices 1–8, shipped through PR #443).

## 1. Goal

Introduce `CredentialRequired` as the second first-class Stage-1 outcome:
policy-driven, mechanism-neutral, additive opt-in. No change for any
deployment without a `CredentialRequired` rule.

## 2. Frozen decisions (Phase 2 freezes — do not relitigate in slices)

| # | Freeze |
|---|--------|
| P2-F1 | **`CredentialRequired` is mechanism-neutral.** It is a requirement class — "the request must carry an authenticated identity" — never a mechanism (Basic/LDAP/bearer/mTLS are configuration, not rule semantics). |
| P2-F2 | **Any established identity satisfies `CredentialRequired`.** Session identity included. Outcomes differ only in the **challenge issued to the unauthenticated**, never in the acceptance set. |
| P2-F3 | **`CredentialRequired` only changes the unauthenticated challenge path**: suppress the captive/SSO redirect and emit the deterministic 407 + `Proxy-Authenticate` (+ `Link`). It is fail-closed by construction. |
| P2-F4 | **`authRequired` / `UnauthMode` decomposition is out of scope for Phase 2.** `Default` remains compatibility behavior, verbatim. The booleans are retired in a later phase by demotion into a synthesized default outcome — never by breaking migration. |
| P2-F5 | **Kill-switch asymmetry.** `CULVERT_AUTHBYPASS_DISABLE` / the runtime toggle force *exemptions* off (fail to auth-required). They must **never** disable `CredentialRequired` — that would fail open. |
| P2-F6 | **Credential validation reuses the existing global chain unchanged** (IdP registry → legacy provider → local bcrypt). Per-rule provider pinning is Phase 3 (`providerRefs` activation). |

## 3. Reserved authSource namespace (pre-Phase-2 correction #1 — SHIPPED)

`exempt`, `unauth`, `local`, `system` have fixed meaning in Stage-2 policy
matching, request logs, and SIEM exports. IdP profile **IDs and names** are
rejected (case-insensitive, trimmed) when they collide — provider `Name()`
values are `oidc:<ID>`/`saml:<ID>`, `matchAuthSource` strips those prefixes,
and sessions carry the bare profile ID as `Identity.Provider`, so a colliding
ID/name would make `authSource`-scoped access rules ambiguous. Enforced in
`validateIdPProfile`; declared in `reservedAuthSourceNames` (authpolicy.go).

## 4. `providerRefs` (pre-Phase-2 correction #2 — SHIPPED)

`AuthRuleSpec.IdPRef` (reserved, never activatable) is **superseded by
`providerRefs []string`** — wire-safe because validation rejected any non-empty
`IdPRef`, so no stored data can carry it. `providerRefs` is reserved the same
way: validation-rejected when set, `omitempty`-serialized (round-trips intact),
dropped fail-closed by the persistence gate if found on disk (an older binary
cannot honor a provider restriction). Phase 3 activates it: SSORequired target
IdP (single ref) / CredentialRequired validator subset (empty = global chain).

## 5. Slice roadmap

Same discipline as Phase 1: pure → persisted → observable → wired → surfaced.
proxy.go is touched exactly once (Slice 3); socks5.go never. Every slice ships
with its tests, passes the D0/C1/C1.5/C2/C2c/C4 parity suites, the full suite,
`-race`, and the `-count=2 -shuffle=on` determinism gate.

### Slice 0 — Spec freeze + plumbing (no behavior change) ✅ partially shipped
- This document (freezes, namespace, providerRefs). **Shipped.**
- Reserved-namespace enforcement + IdPRef→providerRefs supersession. **Shipped.**
- Remaining: cached `hasAuthRules` flag on PolicyStore (maintained on mutation)
  so the no-credentials hot path skips `List()` when no auth rules exist.

### Slice 1 — Validation + persistence accept `CredentialRequired`
- `validateAuthOutcomeAndProviders` accepts `Outcome=CredentialRequired`
  (providerRefs still must be empty; owner/reason/source/destination/expiry
  rules identical to Exempt; `broadExemption` semantics reviewed — a broad
  CR rule is *hardening*, not a waiver, so the broad-destination error relaxes
  to a warning for CR only if review agrees; default: keep identical, decide at
  slice review).
- Persistence (Load/ReplaceAll/import/rollback/cluster snapshot) is already
  outcome-generic — pin with round-trip tests.
- Runtime resolver continues to **act on Exempt only**: `authRuleMatchesExempt`
  stays Exempt-only this slice, so a stored CR rule is inert.
- Tests: accept/round-trip CR rule; invalid CR variants rejected; resolver
  still returns Default for a matching CR rule; proxy.go/socks5.go untouched.

### Slice 2 — Pure resolution + observability (still inert)
- Matcher generalizes: `authRuleMatches` returns the matched rule for both
  outcomes; resolver returns `AuthDecision{Outcome: CredentialRequired, Rule}`.
  **Not consumed by proxy.go yet** (it only acts on Exempt).
- Observability: `auth_outcome="CredentialRequired"` log fields (already
  generic via `AuthLogFields`); `culvert_auth_credential_required_total`
  defined, not incremented from runtime.
- Diagnostics additions (WARN/FAIL, report-only):
  - `auth_cr_dead_under_unauth_mode` — CR rules exist while UnauthMode is on
    (the gate is skipped; the rule can never fire).
  - `auth_cr_no_credential_provider` — CR rules exist but no credential-capable
    provider is configured (covered requests would 407 forever; fail-closed but
    operationally bricking) — **FAIL** severity.
- Simulator: CR outcome rendered as its own challenge class (distinct from
  Exempt and from Stage-2); credentials-presented short-circuit already ships.
- Tests: matcher precedence (priority order across mixed Exempt/CR rules),
  kill switch forces Exempt→Default but leaves CR resolution intact (P2-F5),
  diagnostics fire/quiet, simulator output.

### Slice 3 — Runtime wiring (the one proxy.go change)
- One branch in the existing arm-3 location (`resolveNoCredAuthOutcome`
  call site): outcome `CredentialRequired` → suppress captive redirect,
  emit 407 + `Proxy-Authenticate: Basic realm="Culvert"` + `Link` header,
  attach auth log fields, increment the CR metric, `AUTH_CR` log line.
- Invariants preserved (all tested): session wins; valid credentials win;
  invalid/malformed `Proxy-Authorization` 407s in arm 2 before the hook;
  byte-identical behavior with zero CR rules; UnauthMode skips the gate;
  Exempt behavior unchanged; CONNECT gets 407 (no redirect was possible
  anyway); SOCKS5 untouched.
- Brute-force review: confirm lockout/rate-limit coverage on the proxy
  credential-verify path; add if missing (CR increases 407→guess surface).
- Tests: full Slice-7-style matrix for CR + regression of the Slice 7 matrix.

### Slice 4 — API / UI / Simulator surfacing
- `/api/authpolicy` accepts CR via the same validators (no new routes);
  outcome selector (Exempt | CredentialRequired) in the Auth panel with
  per-outcome copy: Exempt = "skips authentication"; CR = "forces a
  non-interactive credential challenge; never redirects to SSO".
- Panel warnings surface the two new diagnostics; rule table shows outcome.
- Docs + GUI parity per CLAUDE.md.

### Slice 5 — Post-merge verification + Phase 3 gate review
- Full battery on merged main; checklist mirror of the Phase 1 final
  verification; go/no-go for Phase 3 (`SSORequired` + `providerRefs`
  activation + SOCKS5 CR mapping).

## 6. Explicitly deferred
- Per-rule provider pinning (`providerRefs` activation) — Phase 3.
- `SSORequired` — Phase 3.
- SOCKS5 enforcement (RFC 1929 mapping) — Phase 3+.
- `defaultAuthOutcome` / retirement of `authRequired`+`UnauthMode` — Phase 4,
  alone, as its own program.
