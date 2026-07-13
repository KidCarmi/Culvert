# Proof Slice — OpenTofu Module + Deployment / Validation / Rollback Algorithms

- **Status:** Design (implementation-ready).
- **Key stance:** **OpenTofu does NOT provide transactional rollback.** Rollback is an **explicit reverse deployment** to a previous known-good desired-state commit + image digest, health-validated. `apply` failures are handled by state reconciliation + reverse-deploy, never by assuming atomicity.

---

## 1. OpenTofu module design

```
modules/analysis_worker/
  variables.tf:
    variable "image_digest"  { type = string }          # sha256:… (approved; never a tag)
    variable "replicas"      { type = number  default = 1 }
    variable "config"        { type = map(string) }      # non-secret worker config
    variable "environment"   { type = string }           # "staging"
    variable "health_path"   { type = string default = "/ready" }
  main.tf:
    # ONE stateless worker resource (pilot: fly_machine or equivalent).
    # Image pinned by DIGEST only; no tag interpolation; no secret here (secrets
    # injected at runtime by the platform, not via tofu vars).
    resource "<provider>_machine" "worker" {
      count  = var.replicas
      image  = var.image_digest
      env    = var.config                                # non-secret only
      region = "…"
      # health/restart policy defined here
    }
  outputs.tf:
    output "running_digest" { value = <provider>_machine.worker[*].image }
    output "machine_ids"    { value = <provider>_machine.worker[*].id }
```
```
environments/staging/workers.tf:
  module "tac_analysis_worker_1" {
    source       = "../../modules/analysis_worker"
    environment  = "staging"
    image_digest = var.worker1_image_digest          # supplied by the deploy plan (approved digest)
    replicas     = 1
    config       = { QUEUE = "staging-analysis", LOG_LEVEL = "info" }
  }
```
- **Desired state = this Git tree.** A deploy is a commit that changes `worker1_image_digest`. Nothing else changes (enforced by policy P5–P12).
- **State backend** (`backend.tf`): remote state with locking (pilot: object-storage backend + a lock table, or the free tier of a state service). Executor holds the state lock during apply; the worker apply-lease (op DB) serializes at the op level too.
- **Provider lock** (`.terraform.lock.hcl`) digest is captured into the plan artifact (P10) so a provider change invalidates the plan.

---

## 2. Deployment algorithm (L3 `deploy_new_worker_version`)

```
PLAN (planner service, read-only):
  1. resolve image_ref → approved image_digest (server-side allowlist; reject if not approved)
  2. create a candidate commit on a plan branch: set worker1_image_digest = <digest>
  3. tofu init (locked) ; tofu plan -out=tfplan.bin -json  → parse diff
  4. assert diff == {update:1 (worker image), create:0, delete:0}; else fail → policy will reject
  5. compute config_digest, provider_lock_digest; read current running digest as rollback_target
  6. assemble plan artifact (ARTIFACTS §1); run POLICY; run advisory reviews; SIGN; persist
     → op state → POLICY_REJECTED | APPROVAL_PENDING

APPLY (executor, ONLY after APPROVED; the only mutator):
  7. verify: op APPROVED ∧ approval bound to plans.signature ∧ plan not expired ∧ commit unchanged
  8. acquire worker apply-lease (op DB) + tofu state lock
  9. mint short-lived scoped creds (identity broker)
 10. tofu apply tfplan.bin        # the EXACT saved plan — no fresh plan, no free args
 11. record per-resource outcome into execution_results.applied_resources (partial-success detection)
 12. release state lock; op → VALIDATING (lease held for possible rollback)
```
The executor applies **`tfplan.bin`** — the saved, signed, approved plan binary — never a re-planned diff. A changed commit/config ⇒ different plan ⇒ prior approval invalid (ARTIFACTS §2).

---

## 3. Validation algorithm (validator; gates SUCCEEDED)

Runs after apply/restart. **Provider-200 is NOT success.** All gates must pass:

```
V1 health:        worker process reports healthy on health_path within timeout (poll)
V2 version/digest: running image digest == plan.target_image_digest  (query provider truth, not the plan)
V3 synthetic job:  enqueue a SYNTHETIC job on the staging queue; the worker LEASES it
V4 synthetic task: the worker COMPLETES a safe synthetic analyzer task (no real customer data) → expected output
V5 no-unexpected-change: tofu plan (read) shows NO drift beyond the intended update; diff == ∅
V6 no-permission-expanded: executor/worker IAM unchanged vs pre-op snapshot
V7 no-quota-exceeded: inspect_quota_posture within limits (P13 stays $0)
V8 audit-exists:   operation_events contains the full chain for this op (self-check)
V9 rollback-restorable: rollback_target image digest is still pullable/known-good
→ all pass → SUCCEEDED (release lease) ; any fail → FAILED (hold lease) → ROLLBACK_PENDING (deploy)
```
For **restart (L2)**: V1, V2 (digest unchanged), V3, V4, V8 apply; V5/V6/V7/V9 trivially hold (no desired-state change). A failed restart → FAILED → MANUAL_INTERVENTION_REQUIRED (no version to roll back to).

---

## 4. Rollback algorithm (explicit reverse deployment — NOT tofu-atomic)

```
ROLLBACK (executor + validator), triggered by FAILED deploy or user rollback_operation:
  R0. gate: op.kind==deploy ∧ rollback_target.image_digest present
  R1. (data-affecting? → require approval; not in this slice) 
  R2. create reverse plan: set worker1_image_digest = rollback_target.image_digest (previous known-good)
  R3. verify previous image is AVAILABLE (pullable). If NOT → MANUAL_INTERVENTION_REQUIRED (R-fail-A)
  R4. tofu plan reverse → assert diff == {update:1 back to known-good}; sign; (policy re-check)
  R5. acquire lease (already held) ; mint creds ; tofu apply reverse-plan
  R6. run VALIDATION (V1–V9) against the known-good digest
  R7. pass → ROLLED_BACK ; fail → MANUAL_INTERVENTION_REQUIRED (R-fail-B)
```

### Failure sub-cases (each has a defined persisted state)
| Situation | Detection | Persisted state | Recovery |
|---|---|---|---|
| **Deploy partially succeeds** (some replicas old, some new) | `applied_resources` shows mixed; V2 fails | FAILED → ROLLBACK_PENDING | reverse-deploy restores all replicas to known-good; re-validate |
| **Validation fails** (unhealthy on new digest) | V1–V4 fail | FAILED → ROLLBACK_PENDING → ROLLING_BACK | reverse-deploy to known-good |
| **Previous image unavailable** | R3 pull check fails | **MANUAL_INTERVENTION_REQUIRED** | human picks an alternate known-good via `tacctl`, opens a new op |
| **Provider state drift exists** | R4/V5 detects unexpected diff | **MANUAL_INTERVENTION_REQUIRED** | human runs drift reconcile (`tacctl op reconcile`), then retries |
| **Rollback also fails** | R6 fails / R5 apply errors | **MANUAL_INTERVENTION_REQUIRED** | paged; human runbook; op frozen with full audit; lease released |

`MANUAL_INTERVENTION_REQUIRED` always: releases the lease, records a signed event with the exact failure + last-known applied set, pages the human, and leaves a `tacctl`-resolvable op — never silently stuck, never silently half-applied.
