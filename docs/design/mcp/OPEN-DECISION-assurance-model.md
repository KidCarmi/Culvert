# Open Decision — what does MCP `assurance` mean?

**Status:** OPEN. Needs a human product/security decision.
**Raised:** 2026-08-24 (MCP overnight hardening run, finding OVN-05)
**Owner:** MCP Agent Security Gateway (ADR-0024) · IAM
**Related:** `SECURITY-REQUIREMENTS.md` MCP-ID-006, `AUTH-AND-CREDENTIAL-MODEL.md` §3,
`MCP-POLICY-MODEL.md` §Principal, `THREAT-MODEL.md` MCP-T-008

---

## 1. The collision

`Assurance` is defined in two places, identically:

```go
// internal/mcp/identity/principal.go
// AssuranceLevel is the authentication assurance of the subject (loosely NIST AAL).
//   AssuranceLow    — single-factor / basic
//   AssuranceMedium — multi-factor
//   AssuranceHigh   — hardware-backed / phishing-resistant
```

and the design documents commit to that reading:

> **Assurance level** travels with the Human/Workload link and **can be elevated by
> step-up authentication**; policy may require a minimum assurance level before
> permitting write or high-risk actions.
> — `AUTH-AND-CREDENTIAL-MODEL.md` §3

> MCP-ID-006 · Assurance level **SHOULD** be carried and **MAY gate step-up** for
> sensitive operations.
> — `SECURITY-REQUIREMENTS.md`

That is unambiguously **NIST AAL**: a statement about *how the human proved who
they are*. AAL2 means multi-factor; AAL3 means a hardware-backed,
phishing-resistant authenticator.

**Culvert cannot observe that property.** `internal/mcp/authn/claims.go` parses
`iss`, `sub`, `client_id`/`azp`, `aud`, `scope`, tenant, `exp`, `nbf`, `iat`,
`auth_time`, `cnf.jkt`, `cnf["x5t#S256"]` — and nothing else. The claims that
carry authentication method and context class, **`amr` and `acr`, are never
read**. No other source of AAL exists in the product.

What the runtime actually derives is the strength of the **sender binding**:

```go
// internal/mcp/authn/authenticate.go — after the 2026-08-24 P0 fix
func assuranceCeiling(s identity.SenderConstraint) identity.AssuranceLevel {
    case ConfirmDPoP, ConfirmMTLS: return AssuranceHigh
    default:                       return AssuranceLow
}
```

**DPoP proves the presenter controls the private key the token is bound to
(RFC 9449). mTLS proves possession of a client certificate (RFC 8705). Neither
says anything about whether a human completed MFA.** A user who authenticated with
a password alone at an IdP that happens to issue DPoP-bound tokens is reported as
`assurance = high` = *"hardware-backed / phishing-resistant"*.

### Provenance — this is not new, and the P0 fix did not create it

The conflation predates this review. Before the 2026-08-24 P0 fix the runtime did:

```go
assur := identity.AssuranceLow
if req.HasDPoP || req.PeerCertThumbprint != "" { assur = identity.AssuranceHigh }
```

— the same conflation, *plus* a hole (unverified header presence). The P0 fix
closed the hole and moved the mapping into `authn` as a verified ceiling. It made
the existing conflation **more authoritative and better named**; it did not
introduce it. Recording that plainly matters, because "the fix caused it" would
point at the wrong remedy.

## 2. Why it became load-bearing

Until 2026-08-24 there was **no policy field for the sender constraint at all**.
An operator who wanted *"only allow destructive tools for sender-constrained
tokens"* — a completely reasonable and common requirement — had exactly one way to
express it:

```yaml
conditions:
  - field: principal.assurance
    op: min_assurance
    value: high
```

So the conflated field is not merely mislabelled; it is the *only* lever for a real
requirement, which is how a documentation-level mismatch becomes a
policy-authoring convention.

## 3. Reachable impact

| Consumer | Today's behaviour | Consequence |
|---|---|---|
| `principal.assurance` / `session.assurance` policy conditions | Satisfied by any DPoP/mTLS-bound token | An operator who reads the documented meaning believes they required phishing-resistant human auth. They required a token binding. |
| `CapabilityAuthConfig.MinAssurance` | Same | Same, at the admission gate. |
| `engine.go` `writeOrHigher && Assurance == Unknown ⇒ hard deny` | Unreachable from the runtime (see §6) | A hard override that never fires on the live path. |
| Durable decision event `Identity.Assurance` | Records `"high"` | An auditor reading the archive under the documented labels concludes something the product never observed. |
| `RemediationIncreaseAssurance` (`increase_assurance`) | Returned to clients | Tells the caller to strengthen *authentication*, when the actual fix is to obtain a sender-constrained token. |

**Severity:** MEDIUM. It is not an authentication *bypass* — the level is derived
from something genuinely verified, and the mapping is monotone (a bound token is
strictly stronger evidence than an unbound one). It is a **truthfulness and
expressiveness defect**: the control does something real, but not the thing its
name, its documentation and its remediation code all say.

## 4. The two candidate meanings

**A — sender-binding assurance.** "How strongly is this credential bound to its
presenter?" Observable today. Values: none / DPoP / mTLS.

**B — identity authentication assurance (AAL).** "How strongly did the human
authenticate?" Requires reading `amr`/`acr`, trusting the IdP's mapping, and
deciding what to do when they are absent (the common case). **Not observable
today.**

They are independent. A bearer token from an AAL3 session is high-B/low-A; a
DPoP-bound token from a password-only session is low-B/high-A.

## 5. What was implemented (non-widening, no decision required)

Only the part that is unambiguously additive and changes no existing decision:

1. **A first-class sender-binding vocabulary in policy** — `principal.sender_binding`,
   `session.sender_binding` (`none`/`dpop`/`mtls`) and `principal.sender_bound`
   (bool). The zero value is the UNBOUND one, so an input that never sets it fails
   a binding requirement closed. An operator who means "require a sender-constrained
   token" can now say exactly that.
2. **The runtime populates it from the VERIFIED constraint** (`ctx.SenderConstraint()`),
   never from a request header. Proven end-to-end through a compiled rule, with a
   real verified DPoP proof so the non-zero case is covered (a bearer-only test
   cannot distinguish "populated as none" from "never populated").
3. **The durable event records `sender_binding` separately from `assurance`**, so the
   archive stops depending on the conflation to be readable.
4. **Anti-escalation tests**, including one that fails if `authn` starts parsing
   `amr`/`acr` — the change that would silently turn a sender-binding fact into an
   AAL claim without this decision being resolved.
5. **Corrected doc comments** on both `Assurance` enums, stating what the value
   actually is and pointing here. **No value, mapping or decision changed.**

## 6. What was NOT done, and why it needs a human

Making `Assurance` mean **B** would be correct and is a *tightening*, but it is not
safe to do unilaterally:

- Nothing supplies AAL, so every request would become `AssuranceUnknown`.
- `policy/engine.go` hard-denies any write-or-higher operation whose principal
  assurance is `Unknown` (`ReasonIdentityAmbiguous`). **Every write and destructive
  MCP operation in every deployment would begin failing closed**, correctly by the
  new semantics and catastrophically for an operator who did not ask for it.
- Every existing policy using `principal.assurance >= high` to mean "sender-bound"
  would silently stop matching — changing behaviour in the *deny* direction, which
  is safe, and in the *rule-selection* direction, which may not be.

That is a product decision about migration, not a code fix.

## 7. Options

**Option 1 — Split, deprecate, migrate (RECOMMENDED).**
Keep `assurance` as-is for one release with its meaning documented as
sender-binding-derived. Point every operator at the new `sender_binding` fields.
In a later release, parse `amr`/`acr` into a *separate* `principal.auth_strength`
field, and either retire `assurance` or redefine it with an explicit migration and
a compile-time warning on rules that still use it.
*Pros:* no behaviour change now; the correct vocabulary exists immediately; the
redefinition happens once, deliberately, with operators forewarned.
*Cons:* two overlapping fields for a release.

**Option 2 — Redefine `assurance` as AAL now.**
*Pros:* the documented meaning becomes true immediately.
*Cons:* every write/destructive operation hard-denies until IdPs are configured to
emit `amr`/`acr` and Culvert maps them. Unacceptable without a migration window.

**Option 3 — Redefine `assurance` as sender-binding in the docs and keep one field.**
*Pros:* simplest; one concept, honestly named.
*Cons:* abandons MCP-ID-006's step-up requirement, which is a real enterprise
control and a stated product commitment. Also makes `RemediationIncreaseAssurance`
permanently misleading.

**Recommendation: Option 1.** It is the only one that changes no behaviour today,
gives operators the correct control immediately, and keeps MCP-ID-006 achievable.

## 8. If Option 1 is accepted — implementation plan

1. Ship the sender-binding vocabulary (**DONE**, 2026-08-24).
2. Document the split in `AUTH-AND-CREDENTIAL-MODEL.md` §3 and
   `MCP-POLICY-MODEL.md`; mark MCP-ID-006 as depending on step 4.
3. Add a policy-compile **warning** (not an error) when a rule conditions on
   `principal.assurance`/`session.assurance`, naming the sender-binding field.
4. Add `amr`/`acr` to `authn.Claims` behind an explicit per-capability
   `AuthStrengthClaims` config; absent claims yield `unknown`, never a default
   level. Expose as `principal.auth_strength`. Removing the anti-escalation test
   from §5.4 is the marker that this step is being taken.
5. Decide the fate of `assurance`: retire, or redefine with a release-gated
   migration.
6. Revisit `engine.go`'s `Unknown ⇒ hard deny` once a real AAL source exists —
   until then it must keep keying on a value the runtime can actually produce.

## 9. Traceability

| Item | Status |
|---|---|
| Collision proven from code + design docs | DONE |
| Provenance established (pre-existing, not caused by the P0 fix) | DONE |
| `sender_binding` / `sender_bound` policy fields | DONE |
| Runtime populates from the verified constraint (mutation-verified, both sites) | DONE |
| Durable event carries `sender_binding` separately | DONE |
| Anti-escalation test on `amr`/`acr` | DONE |
| Assurance enum doc comments corrected (no value change) | DONE |
| Decision on Option 1/2/3 | **OPEN — human required** |
| `principal.auth_strength` from `amr`/`acr` | NOT STARTED (blocked on the decision) |
| Fate of `assurance` | NOT STARTED (blocked on the decision) |
