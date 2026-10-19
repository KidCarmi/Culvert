# Supported upgrade / downgrade transition matrix

Policy source: `release_transition_policy.go` (`releaseMinUpgradeFrom = "1.0.250"`),
stamped into every CI-published catalog manifest as `min_upgrade_from` and
enforced by the dispatch planner (`checkTransition`, `release_dispatch.go`)
BEFORE any request reaches the maintenance agent. Unit gates:
`release_dispatch_test.go` (`TestDispatch_Transition_*`).

Executed evidence: `test/e2e/appliance/lifecycle-qualify.sh` scenario B/C
against REAL published images (see `evidence/lifecycle-REPORT.md` for the
run that produced the rows below). "Representative state" = first-time
setup completed on the predecessor, an admin account, an explicit allow
rule, default action deny, `admin_settings.json` persisted, ClamAV stubbed.

## 1. Upgrades (predecessor → this build)

| From (real release, amd64 digest) | To | Boot | Login | Rules | Default action | Allow/block | Readiness rows | Verdict |
|---|---|---|---|---|---|---|---|---|
| v1.0.250 `sha256:a754b94b…` | this PR's build | pass | pass | pass | deny kept | 200 / 403 | setup_complete=ok, policy_posture=ok | **Supported** (floor) |
| v1.0.258 `sha256:ffc9ab99…` | this PR's build | pass | pass | pass | deny kept | 200 / 403 | ok | **Supported** |
| v1.0.259 `sha256:238ba99b…` | this PR's build | pass | pass | pass | deny kept | 200 / 403 | ok | **Supported** |
| < v1.0.250 | any release carrying the floor | — | — | — | — | — | — | **Refused** by dispatch (`unsupported_transition`, HTTP 409). Step through a release ≥ 1.0.250 first, or restore a backup onto the target |
| non-catalog / custom build with no version stamp | release carrying the floor | — | — | — | — | — | — | **Refused** (`unknown_current`) until `acknowledge_unknown_current` |

Notes
- The three predecessors are consecutive-ish real releases from the same
  1.0.x line; no persistent-state schema migration runs between them and
  this build (state is read in place). The upstream credential document
  (schema v2) is the only versioned on-disk schema; it has not changed.
- Releases published before this PR carry no `min_upgrade_from`, so an
  appliance on one of them is not constrained by the catalog until it runs
  a release that declares the floor; the binary's own version stamp is then
  the predecessor identity when the catalog does not list the running
  release.
- Catalogs carry their release lineage (`release_lineage.go`): every
  published release at or above the floor and older than the target is
  carried, byte-identical, from its own original signed catalog after the
  release gate verifies that catalog with the baked Sigstore root and the
  pinned release identity. The running release — including one a node
  skipped past — is therefore a catalog entry, and the proxy sends its
  signed `prior_release_proof` so an agent with an empty ledger can
  authorize the upgrade. A supported release missing its catalog asset
  fails the release pipeline rather than publishing a catalog that strands
  its nodes. Catalogs published before lineage (v1.0.250–v1.0.259) list
  only themselves; the first lineage catalog is what makes them upgradable
  through Release Management.
- Raising the floor requires evidence from this harness for every
  predecessor that stays supported; the constant and this file move together.

## 2. Downgrades (this build → predecessor)

| From | To | What actually happened (scenario C, informational) | Supported? |
|---|---|---|---|
| this PR's build | v1.0.259 / v1.0.258 / v1.0.250 | the older binary booted on the newer state, login/rules/default action intact; new files it does not know (`release_dispatch_state.json`, `.culvert.lock`) are ignored | **No.** Not an operation: dispatch refuses (`downgrade`) unless break-glass `allow_downgrade`; state written by a newer build may be silently ignored or refused by an older one in general (the upstream schema-v2 document and policy-learning schemas fail closed on a NEWER version). The supported way back is **restore the pre-upgrade backup onto the previous release**. |
| any | the frozen schema-v2 predecessor | `culvert --prepare-downgrade --target-schema 1` rewrites the upstream document for exactly that build | Supported only for that one documented transition (`docs/operator/upstream-proxies.md` §7–10) |

## 3. Interrupted / failed transitions

| Case | Behaviour | Evidence |
|---|---|---|
| Image pulled, agent killed before the tag advanced | safe boundary: record retired at the next agent start, nothing changed | `reconcile_startup_test.go` |
| Tag advanced, container not restarted (agent killed) | TAG HAZARD surfaced on `/v1/status`; not executed automatically; `POST /v1/reconcile/{op}` converges under the health gate | `reconcile_startup_test.go`, `handlers_reconcile_test.go`, agent harness F3 |
| New image failed the health gate | automatic rollback to the prior image from the local cache (registry not required) | `appliance-catalog-update-e2e.yml` P5, agent harness F4 |
| Control plane replaced mid-dispatch | watch resumed by the new process; result shown in the GUI | `release_dispatch_persist_test.go` |
| Newer state restored onto an older binary (restore after downgrade) | the restore validates archive structure, not binary compatibility; use the backup taken BEFORE the upgrade | runbook |
