# Proof Slice — Policy Engine Rules & Identity/Credential Model

- **Status:** Design (implementation-ready).
- **Rule:** the **deterministic policy engine is the safety boundary.** Multi-agent (security/cost) review is **advisory** and can only add a BLOCK, never widen. A plan that fails any policy rule → `POLICY_REJECTED` (terminal), regardless of reviews or model reasoning.

---

## 1. Policy rules (all must PASS to leave PLANNING)

Evaluated deterministically over the plan artifact + worker_registry + parsed `tofu plan -json` (deploy) or the action descriptor (restart). Code-ready as typed Go predicates (or the equivalent Rego below).

| # | Rule | Pass condition | Source of truth |
|---|---|---|---|
| P1 | **staging only** | `plan.environment == "staging"` | plan/op |
| P2 | **single allowlisted worker** | `worker ∈ worker_registry AND allowlisted AND exactly one worker targeted` | worker_registry |
| P3 | **approved registry** | `target image registry == worker_registry.approved_registry` | worker_registry |
| P4 | **approved image digest** | `plan.target_image_digest ∈ approved_image_digests[worker]` (deploy); restart has none | approved_image_digests |
| P5 | **no DB modification** | plan changes touch no database resource types | tofu plan diff |
| P6 | **no storage modification** | no object-storage/bucket resource changes | tofu plan diff |
| P7 | **no DNS modification** | no DNS record changes | tofu plan diff |
| P8 | **no IAM modification** | no IAM/role/policy resource changes | tofu plan diff |
| P9 | **no new paid resource** | no resource whose plan flags `paid==true` is created | provider/module metadata |
| P10 | **no provider change** | provider block + `.terraform.lock.hcl` digest unchanged vs current | provider_lock_digest |
| P11 | **no destroy action** | zero `delete` actions in the plan diff | tofu plan diff |
| P12 | **max resource-count delta** | `abs(create+delete) == 0 AND update ≤ 1` (only the worker image update) | tofu plan diff |
| P13 | **max cost delta == $0** | `plan.cost_delta_usd == 0` | cost analysis |
| P14 | **mandatory health validation** | plan declares a health-validation step | plan |
| P15 | **mandatory rollback target** | `plan.rollback_target.image_digest` present AND that digest is pullable/known-good | plan + registry |
| P16 | **operation expiry set** | `plan.expires_at` present and ≤ now()+15m; `op.expires_at` set | plan/op |
| P17 | **approval requirement** | deploy(L3) ⇒ requires human approval; restart(L2) ⇒ all structural preconditions (P1–P16 minus P4/P15) pass | level policy |

**Rego sketch (illustrative):**
```rego
package tac.infra.slice
default allow = false
deny[msg] { input.plan.environment != "staging"; msg := "P1: not staging" }
deny[msg] { count(input.plan.workers) != 1; msg := "P2: not exactly one worker" }
deny[msg] { not input.worker.allowlisted; msg := "P2: worker not allowlisted" }
deny[msg] { input.plan.kind == "deploy"; not approved_digest; msg := "P4: image digest not approved" }
approved_digest { input.plan.target_image_digest == input.approved_digests[_] }
deny[msg] { changed := input.tofu_diff.resource_types[_]; forbidden[changed]; msg := sprintf("P5-P8: forbidden change %v", [changed]) }
forbidden = {"database","object_storage","dns","iam"}
deny[msg] { input.tofu_diff.destroy_count > 0; msg := "P11: destroy present" }
deny[msg] { input.tofu_diff.create_count + input.tofu_diff.delete_count != 0; msg := "P12: resource-count delta" }
deny[msg] { input.tofu_diff.update_count > 1; msg := "P12: >1 update" }
deny[msg] { input.plan.cost_delta_usd != 0; msg := "P13: nonzero cost" }
deny[msg] { not input.plan.health_validation; msg := "P14: no health validation" }
deny[msg] { input.plan.kind == "deploy"; not input.plan.rollback_target.image_digest; msg := "P15: no rollback target" }
deny[msg] { not input.plan.expires_at; msg := "P16: no expiry" }
allow { count(deny) == 0 }
```
Policy has **100% branch test coverage** as an acceptance gate (`rules_test.go`): each rule has a pass case and a fail case; a plan that trips any rule lands in POLICY_REJECTED with the rule id in `policy_result`.

**Reviews are advisory:** security-review + cost-review write `reviews` rows; a BLOCK holds the op in REVIEW_PENDING (surfaced to the human) but a policy PASS is still required and is the real gate. A review OK can never substitute for a policy PASS.

---

## 2. Identity matrix

| Identity | Auth method | Scope | Holds provider creds? | Credential lifetime | Audited as |
|---|---|---|---|---|---|
| **Claude / MCP caller** | scoped gateway session token (per operator+env), OIDC-issued | call typed tools in `staging`; level ≤ operator | **No** | session TTL ≤ 1h | `model` (session_meta recorded) |
| **Gateway** | mTLS to internal services | route + authz; no provider access | **No** | service identity | `service:gateway` |
| **Planner** | internal service identity | read state, run `tofu plan` (read-only), emit signed plan | **read-only** provider (plan) creds, short-lived | ≤ 15m per plan | `service:planner` / `model:planner` |
| **Policy evaluator** | internal service identity | evaluate rules over inputs | **No** | service identity | `service:policy` |
| **Approval service** | human SSO session (separate from operator) | record human approvals, bind to plan sig | **No** | human session | `human:<id>` |
| **Executor** | workload identity (OIDC → provider role) | apply a specific approved plan / restart a specific worker | **YES — only after APPROVED**, minted per op | **≤ 15m, single op, auto-revoked** | `service:executor:<instance>` |
| **Validator** | workload identity, read-only | health/digest/synthetic-job/drift reads | **read-only**, short-lived | ≤ 15m | `service:validator` |
| **Audit writer** | internal service identity + signing key (KMS) | append + sign events | signing key (not provider) | KMS-held | `service:audit` |
| **Human approver** | SSO (dual-factor) | approve/reject a specific plan | **No** | human session | `human:<id>` |

**Claude receives no provider credentials and no secret values — enforced structurally** (no tool returns them; the identity broker mints creds directly to the executor's workload identity, never crossing the tool boundary).

---

## 3. Credential minting in the $0 pilot

- **Broker:** `services/identity` mints short-lived provider credentials via **OIDC / workload-identity federation** — the executor's workload identity (e.g. a GitHub-Actions-OIDC-style token, or a self-hosted OIDC issuer in the pilot) is exchanged at the provider for a **scoped, ≤15-minute** access token limited to *this operation's* resource (the one staging worker).
- **Trigger:** the broker mints executor creds **only when an op is APPROVED and enters EXECUTION_QUEUED**; it verifies the approval + plan signature before minting. No standing executor credential exists at rest.
- **Scope:** the minted token can act on exactly `staging/<worker_id>` (restart) or apply exactly the saved plan (deploy); provider IAM binds the executor's workload identity to a least-privilege role for that worker only.
- **Expiry:** creds auto-expire ≤15m; the executor's op has its own apply timeout (≤10m) so creds outlive the op only by a small margin, then revoke.
- **Audit:** each mint records `{op_id, identity, scope, ttl, minted_at}` in `operation_events` (no token value). Revocation on op terminal state is recorded.
- **$0 reality:** the pilot provider (Fly.io Machines assumed) supports scoped API tokens; a thin broker exchanges an OIDC assertion for a short-lived, machine-scoped token. If the provider lacks true workload identity, the pilot uses a **broker-held root secret in a KMS/secret-manager the broker alone can read**, minting derived short-lived tokens — still never exposing anything to Claude or the gateway. This is the one place a longer-lived secret exists, and it lives only in the broker's KMS, audited, rotatable (a Level-3 op itself).

---

## 4. Why policy > reviews > model (the ordering that makes it safe)

```
model proposes  →  DETERMINISTIC POLICY (hard gate; can reject)  →  advisory reviews (can BLOCK, not pass)
                →  human approval (L3)  →  deterministic executor (verifies sig+approval before mutate)
```
A compromised or injected model can, at most, propose a plan; policy rejects anything outside the 17 rules; reviews add scrutiny; a human authorizes L3; the executor re-verifies. No single layer — least of all the model — can push an unsafe change through.
