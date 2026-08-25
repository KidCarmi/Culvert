# ADR-0032 — MCP assurance: separate authentication assurance from sender binding (OVN-05)

**Status:** ACCEPTED (architecture) · migration step 4+ **OPEN — product decision required**
**Date:** 2026-08-25 (Shadow-readiness phase)
**Supersedes framing in:** `docs/design/mcp/OPEN-DECISION-assurance-model.md` (kept as the
detailed analysis of record)
**Related:** ADR-0024 (MCP gateway), `SECURITY-REQUIREMENTS.md` MCP-ID-006,
`AUTH-AND-CREDENTIAL-MODEL.md` §3, THREAT-MODEL MCP-T-008

## Context

`AssuranceLevel` (`internal/mcp/identity/principal.go`) is documented as NIST-AAL
authentication assurance (Low = single-factor, Medium = MFA, High = phishing-resistant).
But the runtime derives it from the **sender binding**: `assuranceCeiling`
(`internal/mcp/authn/authenticate.go:229`) maps DPoP/mTLS → `AssuranceHigh`, and the
observe runtime asserts `Human.Assurance = High` then clamps to that ceiling — so any
DPoP/mTLS-bound token yields `AssuranceHigh`. **DPoP proves possession of a key
(RFC 9449); mTLS proves possession of a client certificate (RFC 8705); neither proves a
human completed MFA.** A password-only human at an IdP that issues DPoP tokens is
reported `assurance = high`. This is a truthfulness/expressiveness defect (OVN-05,
MEDIUM), not an authentication bypass — the level is derived from something genuinely
verified and the mapping is monotone — but the control does not mean what its name,
docs, and `increase_assurance` remediation all claim.

`amr`/`acr` — the token claims that actually carry authentication method/context — are
**never parsed** (`internal/mcp/authn/claims.go`). No AAL source exists in the product.

## Decision

**Two independent dimensions, separated permanently:**

```
authentication_assurance : unknown | low | medium | high   (from amr/acr — the IdP's statement about how the human authenticated)
sender_binding           : bearer | dpop | mtls             (proof of possession, verified on THIS request)
```

Adopt **Option 1** from the analysis doc — *split, deprecate, migrate*:

1. **DONE (PR #1224, non-widening, verified in main):** first-class `principal.sender_binding` /
   `session.sender_binding` (`none`/`dpop`/`mtls`) and `principal.sender_bound` policy
   vocabulary, populated from the VERIFIED constraint; durable event records
   `sender_binding` separately from `assurance`; anti-escalation test that fails if
   `authn` starts parsing `amr`/`acr` without this decision; corrected enum doc comments.
   Zero value is the UNBOUND one ⇒ a binding requirement fails closed.
2. Document the split; mark MCP-ID-006 as depending on step 4.
3. Policy-compile **warning** (not error) when a rule conditions on
   `principal.assurance`/`session.assurance`, naming the sender-binding field.
4. **[OPEN]** Parse `amr`/`acr` into `authn.Claims` behind an explicit per-capability
   `AuthStrengthClaims` config; absent claims ⇒ `unknown`, never a default level; expose
   as a **separate** `principal.auth_strength`. Removing the §5.4 anti-escalation test is
   the marker that this step is being taken.
5. **[OPEN]** Decide the fate of `assurance`: retire, or redefine with a release-gated
   migration.
6. **[OPEN]** Revisit `engine.go`'s `Unknown ⇒ hard-deny` for write-or-higher once a real
   AAL source exists (until then it must key on a value the runtime can produce).

## Why steps 4–6 are NOT taken unilaterally (do not fake closure)

Redefining `assurance` as AAL is *correct* and a *tightening*, but unsafe to do without a
migration window: nothing supplies AAL, so every request becomes `AssuranceUnknown`;
`policy/engine.go` hard-denies write-or-higher on `Unknown`; **every write/destructive
MCP operation in every deployment would begin failing closed**, and every rule using
`principal.assurance >= high` to mean "sender-bound" would stop matching (safe in the
deny direction, possibly not in the rule-selection direction). That is a product decision
about migration, not a code fix.

## Fail-closed / zero-value proof

- `AssuranceUnknown` is the zero value and is rejected wherever a minimum is required —
  unchanged.
- `sender_binding` zero value is `none` (unbound) ⇒ a "require dpop/mtls" condition fails
  closed on an input that never sets it.
- A future `auth_strength` zero value is `unknown` ⇒ any `min auth_strength` condition
  fails closed until an IdP supplies `amr`/`acr` AND the operator opts in. No path widens
  authorization: every new dimension defaults to the most-restrictive value.

## Consequences

- The correct vocabulary (`sender_binding`) exists today; operators can express "require a
  sender-constrained token" precisely, without conflation.
- Shadow evidence (ADR: `SHADOW-ARCHITECTURE.md` §9) records `authentication_assurance`
  and `sender_binding` as **separate** fields, so the Shadow archive never launders a
  sender-binding fact into an AAL claim.
- **RISK stays OPEN** for steps 4–6 until a product owner accepts the migration. This ADR
  records the decided architecture (permanent separation, additive, fail-closed) and the
  bounded open item (when/whether to make `assurance` mean AAL).

## Status for the phase report

`assurance model` = **PARTIALLY DECIDED**: separation architecture DECIDED and the
non-widening half shipped; the AAL-source migration (steps 4–6) OPEN and correctly
requires a human product decision.
</content>
