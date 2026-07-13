# tac-infra — OpenTofu desired-state (repository boundary)

This tree holds **only** Infrastructure-as-Code desired state (OpenTofu modules +
per-environment configuration). It deliberately contains **no application code** —
the deterministic control plane (gateway, operation service, policy, executor,
validator, reconciler, rollback, audit, `tacctl`) lives in **`tac-platform`**.

## The three-repository boundary (as designed; here as sibling folders)
| Repo | Owns | Rule |
|---|---|---|
| `culvert` | the on-prem appliance (Tier 1) | **no implementation changes in this slice** |
| `tac-platform` | the control-plane services + `tacctl` | the only infra mutator; talks to providers via a signed, approved plan |
| **`tac-infra`** | OpenTofu modules + environment desired state | Git is the source of truth for desired state |

They are folders in this branch (repository creation was not authorized in the sandbox);
splitting them into real repositories later requires no code change — the coupling is a
single immutable image digest passed from `tac-platform`'s approved plan into
`environments/staging/workers.tf`.

## What's here
- `modules/analysis_worker/` — one stateless worker, provider-agnostic. The `$0` pilot
  uses the `null` provider (no cloud, no cost) so digest pinning and the plan/apply flow
  are exercised. A real provider (Fly.io Machines / Kubernetes) swaps in behind the same
  variables/outputs — **no rewrite**.
- `environments/staging/` — staging desired state; an L3 deploy changes only
  `worker1_image_digest` (chosen server-side from the approved-digest allowlist).

## How the platform uses this
The controlled executor (`tac-platform/internal/executor`) applies a **signed, approved
plan** — never a fresh one, never a raw tag. The deterministic policy engine enforces
"exactly one worker image update, no create/delete/destroy, `$0` cost, staging only"
before any apply. Rollback is an **explicit reverse-deploy** to the previous known-good
digest, not a Terraform-atomic undo.
