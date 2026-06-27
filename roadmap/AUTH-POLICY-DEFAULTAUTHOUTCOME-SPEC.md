# `defaultAuthOutcome` — UnauthMode Retirement Spec (FROZEN)

**Status:** FROZEN (contract). Implementation staged across Slices 2–5.
**Scope:** Replace the global `UnauthMode` boolean with a scoped-policy-aware
global **`defaultAuthOutcome`**, so the Authentication Policy layer becomes the
single source of truth for Stage-1 authentication and the global toggle can be
deleted.

This document is the **authority for Slices 2–5**. It freezes the contract; it
authorizes **no** runtime code change by itself. Slice 1 (this governance
change) is documentation-only: zero Go, zero tests, zero behavior change.

---

## 0. Problem statement

`UnauthMode` (`store.go`) is a single global boolean checked *before* the
Authentication Policy layer (`proxy.go`, `authRequired := !cfg.UnauthMode() && …`).
When it is on, the **entire** Stage-1 layer is skipped — every scoped
`Exempt` / `CredentialRequired` / `SSORequired` rule goes dead. The global
toggle is therefore *stronger* than the scoped policy layer that is meant to
replace it, which is backwards: scoped intent ("this traffic must authenticate")
is silently overridden by a global lab switch.

This was already the documented end-state: `AUTH-POLICY-PHASE2-PLAN.md`
slated UnauthMode retirement "via a synthesized `defaultAuthOutcome`." This
spec finishes that plan.

---

## 1. Model

`defaultAuthOutcome` is the global Stage-1 outcome applied **only when no auth
rule matches** — it replaces today's implicit fail-closed default. It is a
*default*, not a short-circuit: it is consulted **after** the scoped rules, never
before.

- **Config surface (frozen):** `DefaultAuthOutcome string`, JSON
  `default_auth_outcome`, default value `"Default"`.
- **v1 allowed values** (reuse the existing `AuthOutcome` string constants for
  consistency):
  - `"Default"` — current fail-closed / default auth behavior (today's gate;
    auth required iff a backend exists).
  - `"Exempt"` — open-by-default for **unmatched** traffic only.
- **Reserved / out of scope:** `CredentialRequired` and `SSORequired` as
  *global* defaults are intentionally not offered in v1. Only `Default` and
  `Exempt` are valid global defaults.

---

## 2. Resolution semantics (S2 — default-on-no-match)

This is the frozen behavioral contract. It is **default-on-no-match**, **not**
global short-circuit.

1. Auth rules are evaluated first.
2. First matching auth rule wins by priority.
3. If no auth rule matches, `defaultAuthOutcome` applies.
4. `defaultAuthOutcome="Default"` means current fail-closed / default auth
   behavior.
5. `defaultAuthOutcome="Exempt"` means open-by-default **only for unmatched
   traffic**.
6. Scoped `Exempt` / `CredentialRequired` / `SSORequired` rules still win by
   priority — they are never overridden by the global default.
7. The Exempt kill switch (`authExemptKillSwitchEngaged`) forces
   `defaultAuthOutcome` to `Default`.
8. Default-`Exempt` (open) traffic carries `authSource="unauth"`.
9. Explicit `Exempt`-rule traffic carries `authSource="exempt"`.
10. Stage-2 access policy still runs, and **default-deny remains the backstop**.
11. No global-exempt may leak into the SOCKS5 path (§6).

### Decision matrix (no presented credentials)

| Case | Stage-1 outcome | `authSource` | Stage-2 |
|---|---|---|---|
| Scoped `Exempt` rule matches | waive auth | `exempt` | runs (default-deny applies) |
| Scoped `CredentialRequired` matches | `407` challenge | — | not reached |
| Scoped `SSORequired` matches | `302` (browser) / `403` (non-browser/CONNECT) | — | not reached |
| No rule matches, `defaultAuthOutcome=Default` | today's gate (`407`/captive, or inert if no backend) | `unauth` | runs |
| No rule matches, `defaultAuthOutcome=Exempt` | open | `unauth` | runs (default-deny applies) |
| Kill switch engaged | forced `Default` (rows above re-evaluated) | per above | per above |

Presented credentials (valid or invalid) are unchanged and take precedence over
any Stage-1 outcome — `defaultAuthOutcome` is irrelevant when credentials are
presented.

### Relationship to UnauthMode (intentional behavior change)

- **Common case — UnauthMode with no auth rules:** S2 is identical to UnauthMode
  (no rules to match ⇒ the global `Exempt` default applies ⇒ open).
- **Edge case — UnauthMode with scoped CR/SSO rules:** under UnauthMode those
  rules are **dead** (and already WARN'd by diagnostics today). Under S2 they
  **enforce** by priority. This is an intentional change and a bugfix; it must
  be surfaced (§4 migration diagnostic), not silent.

---

## 3. Migration (one-way, on load)

- Persisted `unauth_mode=true` → `defaultAuthOutcome="Exempt"`.
- Persisted `unauth_mode=false` / absent → `defaultAuthOutcome="Default"`.
- The legacy `unauth_mode` field is read during a deprecation window; the new
  `default_auth_outcome` field is authoritative. The legacy field is removed in
  Slice 5.
- No-backend clarification: `Default` preserves today's backend-gated behavior
  (zero-backend ⇒ Stage-1 inert, unchanged). `Exempt` opens unmatched traffic
  regardless of backend (matches UnauthMode).

Migration code lands in **Slice 2**.

---

## 4. Migration diagnostic (frozen check code)

`auth_default_exempt_rules_now_enforce` (WARN) — fires when
`defaultAuthOutcome=Exempt` **and** one or more scoped `CredentialRequired` /
`SSORequired` rules exist. It names the rules that were dead under UnauthMode and
will now enforce under S2. Pure observability; never blocks. Diagnostic code
lands in **Slice 3**.

The existing `unauth_mode` / `auth_cr_dead_under_unauth_mode` /
`auth_sso_dead_under_unauth_mode` checks are repointed to read
`defaultAuthOutcome` in Slice 3/5.

---

## 5. Cluster

- `ConfigSnapshot.UnauthMode bool` → `ConfigSnapshot.DefaultAuthOutcome string`
  (Slice 5), with a back-compat read of the old bool during the deprecation
  window.
- Auth rules already propagate to DP nodes inside `ConfigSnapshot.PolicyRules`;
  no change there.
- The exemption-staleness epoch (spec §1.9 `AuthPolicyVersion` / fail-closed
  past max-staleness) is a **separate** hardening track and is **not** in this
  program.

---

## 6. SOCKS5 (out of scope, invariant preserved)

- `UnauthMode` never governed SOCKS5; SOCKS5 auth is gated by `AuthEnabled()`.
- Deleting the field (Slice 5) removes the `AuthEnabled() = … || unauthMode`
  term, which today inverts SOCKS5 to *require* credentials when UnauthMode is
  on. SOCKS5 behavior is otherwise preserved.
- No global-exempt may reach the SOCKS5 path. The §1.7 invariant of
  `AUTHENTICATION-POLICY-SPEC.md` (no SOCKS5 exemption before policy alignment)
  stays intact.

---

## 7. Invariants (non-negotiable for Slices 2–5)

1. Default value is fail-closed: `defaultAuthOutcome` defaults to `"Default"`.
2. The Exempt kill switch governs default-`Exempt` (forces `Default`).
3. `authSource` preservation per the §2 table (`unauth` for default-open,
   `exempt` only for explicit Exempt-rule matches).
4. Scoped rules win by priority; the global default never overrides a match.
5. Stage-2 access policy and default-deny backstop are unchanged.
6. No SOCKS5 leak (§6).
7. v1 global default values are limited to `Default` / `Exempt`.

---

## 8. Slice map

| Slice | Scope | Touches |
|---|---|---|
| 1 (this doc) | Governance / spec freeze | docs only — zero Go/tests/behavior |
| 2 | Config + persistence + migration | `store.go` field/accessor/envelope; load-time migration; `UnauthMode()` kept as a derived shim; no runtime change |
| 3 | Runtime wiring (S2) + migration diagnostic | `proxy.go` no-match default; `authSource` preservation; kill switch; `auth_default_exempt_rules_now_enforce` |
| 4 | UI / API / simulator | replace toggle with "Default authentication: Require / Open"; back-compat `/api/settings/unauth-mode`; simulator surfaces the global default |
| 5 | Cluster + cleanup | `ConfigSnapshot` field swap; repoint diagnostics; decouple `AuthEnabled()`; delete the `unauthMode` field + shim + legacy envelope field; rewrite the CLAUDE.md architecture note |

Each slice is independently shippable, plan-first, and carries no silent behavior
change. Slices 2–5 implement strictly against this document.
