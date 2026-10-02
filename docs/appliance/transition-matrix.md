# Supported upgrade / downgrade transition matrix (pilot)

Scope: the single-node appliance running the shipped compose topology.
"Supported" means: executed against REAL published release artifacts with
representative persisted state, the assertions in
`evidence/predecessor-upgrade-matrix.md` pass, and the control plane's
dispatcher will admit the transition. Nothing here claims mixed-version
clusters or HA.

## Facts the matrix rests on

- Releases are cut per push to `main` (v1.0.218 on 2026-09-09 … v1.0.259 on
  2026-09-30). Every schema-bearing persisted file was last changed before
  v1.0.218 (`admin_settings_schema` 2, `policy_learning.json` schema 9,
  upstream v2 sealed document, `CULVERT_DATA_DIR`, release-catalog state
  pair) — source history, see `qualification-evidence.md`.
- The dispatcher identifies the running release by the running image
  digest against the signed catalog. Because the catalog is single-release,
  the running version is unknown to it in the ordinary N → N+1 case; this
  PR adds a fallback to the agent-reported image version label and to the
  control plane's own build version, and refuses when the version cannot be
  determined and the target declares a floor.
- `min_upgrade_from` is now populated by CI from
  `release_min_upgrade_from.txt` (`1.0.218`) and enforced at dispatch. The
  published v1.0.259 catalog still carries `""`, so enforcement becomes
  effective with the first release built from this change; until then the
  dispatcher behaves as before for releases that declare no floor.

## Matrix

| From → To | Class | Status | Evidence |
|---|---|---|---|
| v1.0.258 → v1.0.259 | adjacent | **Supported** | `evidence/predecessor-upgrade-258-to-259.md` — 17/19/19 pass, 0 fail |
| v1.0.250 → v1.0.259 | skip 9 | **Supported** | `evidence/predecessor-upgrade-250-to-259.md` — 17/19/19 pass, 0 fail |
| v1.0.235 → v1.0.259 | skip 24 | **Supported** | `evidence/predecessor-upgrade-235-to-259.md` — 17/19/19 pass, 0 fail |
| v1.0.218 … v1.0.234 → v1.0.259 | inside the declared floor, untested | **Supported by declaration, not executed** | same schema set as v1.0.235 (source history); run `test/appliance/predecessor-upgrade.sh` against the exact binary before relying on it |
| ≤ v1.0.217 → ≥ v1.0.259 | below the floor | **Refused by the dispatcher** once the target carries `min_upgrade_from: 1.0.218`; the migration code paths (legacy upstream list → sealed v2, policy-learning schema ladder) exist but have no real-binary proof | `release_dispatch.go` (this PR); `upstream_v2.go:241-296`; `internal/policylearn/store.go:185` |
| v1.0.259 → v1.0.258 / v1.0.250 / v1.0.235 | downgrade within the same schema set | **Tolerated, not supported**: executed reverse legs pass (no quarantine, same files byte-identical, enforcement intact). The dispatcher refuses a downgrade unless `allow_downgrade` is set explicitly. An older binary silently DROPS unknown `admin_settings.json` keys on its first save, so any setting added after that version reverts to its default. | reverse legs in the three evidence files; `admin_settings.go:356` (lenient decode) |
| current → 2F-B predecessor (`--prepare-downgrade --target-schema 1`) | tool-assisted, frozen target | **Unsupported for the pilot** (targets a specific non-release commit; unit-tested only) | `upstream_downgrade.go:58,100-103` |
| anything → anything in a CP/DP cluster | mixed versions | **Unsupported** | out of pilot scope |

## Safe behaviour at the boundaries (what the operator sees)

| Situation | Behaviour | Where |
|---|---|---|
| Target declares a floor and the running version is unknown | dispatch refused with the floor named and the instruction to read the running version from `/healthz`; nothing pulled, nothing tagged | `release_dispatch.go` `Plan` |
| Running version below the floor | dispatch refused (`RefusedUpgradeGap`) | same |
| Target older than running | refused unless `allow_downgrade` (admin, audited) | same |
| Binary older than the state it finds (`admin_settings_schema` newer than the binary knows) | the binary logs, reports a warn row, and will not rewrite the file (read-only latch) so it cannot drop the newer keys | `admin_settings.go` (this PR); `internal/policylearn` already fails closed read-only |
| Agent dies between tag and restart, or after restart before verify | at the next agent start: adopt if the target is running and healthy; retag back if only the tag moved; otherwise mark `needs_attention`, touch nothing, surface on `/v1/status` | `cmd/culvert-maint` boot reconcile (this PR) |
| Rollback with the registry unreachable | rollback proceeds from the locally present prior image (`docker image inspect` before pull) | `rollback_stages.go` (this PR) |
| Control plane restarted mid-dispatch (the proxy container is the control plane) | the agent finishes or self-rolls-back on its own; the control plane reloads `release_dispatch_state.json` and resumes polling; a reaped op is marked needs-attention with the target digest for manual verification | `release_api.go` (this PR) |

## What an image rollback does NOT reverse

Reverting the image never reverses a persistent-state migration. Within
v1.0.218 … v1.0.259 there is no migration to reverse. For a release that
does migrate state, the recovery path is restore-from-backup (see
`recovery-runbook.md`), and the backup must be taken BEFORE the upgrade (the
agent's pre-upgrade backup stage does this when configured).
