# Appliance recovery and restore runbook

Three different things, never confused:

| Layer | Reverses | Does NOT reverse | Tool |
|---|---|---|---|
| **Image rollback** | the running application binary (previous image, from the local cache) | persistent state the newer build wrote | agent `POST /v1/rollbacks {"mode":"image"}` / auto-rollback |
| **Persistent-state restore** | `/data` content to a backup's point in time | the OS, the host components, keys held outside the archive | `cli --restore … --confirm` (offline, in place) |
| **Disaster recovery** | the whole appliance | nothing is kept: new OVA + restore + re-enter custody secrets | OVA import + restore |

A VM snapshot is not an application-consistent backup: it freezes files
mid-write and does not carry the backup passphrase custody. Use it only as
an additional safety net around a maintenance window.

## 1. Image rollback (application only)

The agent keeps the previous image in the local Docker cache and rolls back
without the registry (`rollback_pull: skipped (image present locally)`):

```bash
curl --unix-socket /run/culvert-maint/culvert-maint.sock -X POST http://unix/v1/rollbacks \
  -d '{"mode":"image","image_ref":"ghcr.io/kidcarmi/culvert@sha256:<previous digest>","idempotency_key":"<unique>"}'
```

The previous digest is in the upgrade op's result (`rollback_digest`) and
in the agent audit log. Rolling the image back does NOT roll back state the
newer build wrote; if the older binary refuses or ignores that state,
continue with §2.

**Image rollback vs. data: the compatibility window.** An image rollback
swaps the binary and keeps `/data` as the newer build left it. That is
sound only while the older binary can read that state:

| Situation | Image rollback alone | Use instead |
|---|---|---|
| Rolled back to the release that ran immediately before, in the same window, 1.0.x line (no state-schema migration between v1.0.250 and this build — `upgrade-transition-matrix.md`) | **Measured**: v1.0.250/258/259 boot on this build's state with login, rules and default-deny intact; newer files they do not know are ignored (lifecycle harness C) | — |
| Rolling back across a release that migrated a versioned schema (upstream schema v2, policy-learning schemas: an older build REFUSES a newer version, fail closed) | not sufficient | §2 restore of the pre-upgrade backup onto the older release; the upstream schema-v2 predecessor has its own `--prepare-downgrade` path |
| Rolled back after operators changed configuration on the newer build | the changes stay in `/data`; features the older build lacks are silently ignored | §2 if the old release must also have the old configuration |
| Any rollback older than the supported predecessor floor (`min_upgrade_from`) | unsupported; the dispatch refuses it without break-glass | §2 or §5 |

The agent's own rollback health check reports any `/ready` row that was
`ok` before the upgrade and is not after as `not_restored=[…]` in the op
log (report-only); treat a non-empty list as "check the data", not as a
failed rollback. Rows the older release does not emit at all are not
counted (it predates them).

## 2. Restore persistent state (offline, in place)

Prerequisites in separate custody: the backup archive, `CULVERT_BACKUP_PASSPHRASE`,
and `/srv/culvert/.env` (holds `CULVERT_CA_PASSPHRASE`; without it the
archived `ca.bundle` cannot be validated or used). See
`state-and-key-custody-matrix.md`.

```bash
cd /srv/culvert
docker compose --profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE cli --restore /backup/<archive> --mode full      # dry-run (runtime-OK)
docker compose down                                                                                                   # quiesce (enforced by the data-dir lock)
docker compose --profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE cli --restore /backup/<archive> --mode full --confirm
docker compose up -d
```

Guards (each names its flag): cluster CA change with enrolled DPs
(`--accept-dp-reenrollment`), TOTP counter rollback
(`--allow-counter-rollback`), inspection root CA replaced/removed
(`--accept-root-ca-change`); a restore that would leave no admin is refused.
The previous content stays in `/data/.restore-bak.<ts>-<pid>/` until
`--cleanup-restore-leftovers --confirm`.

After the restore: log in (roster from the archive), confirm `/health`
`ssl_inspection=ready`, re-enter upstream parent-proxy credentials
(`requiresReplacement`), re-upload a custom admin-UI certificate, restore
`.alert_webhook_key` or re-enter webhook secrets, re-enroll CDR instances.

## 3. Interrupted restore

The proxy refuses to start while `/data/.restore-journal.json` exists and
prints the exact commands:

```bash
docker compose --profile cli run --rm cli --recover-restore                      # inspect
docker compose --profile cli run --rm cli --recover-restore --confirm=revert     # or: --confirm=complete
docker compose up -d
```

Both directions are deterministic, and an interrupted recovery is resumed by
re-running the SAME command (the journal records the direction and each
completed sub-step; switching direction is refused; a missing
`.restore-bak.*`/`.restore-staging.*` directory refuses rather than being
read as finished work) — `docs/operator/docker-compose-backup-restore.md` §6.

## 4. Interrupted upgrade / agent restart

`GET /v1/status` on the agent lists `interrupted_operations` with a verdict.
Safe no-ops and healthy targets are retired automatically at agent start;
a **TAG HAZARD** (pinned tag advanced, container not restarted) is never
executed automatically — resolve or dismiss explicitly:

```bash
curl --unix-socket /run/culvert-maint/culvert-maint.sock http://unix/v1/status
curl --unix-socket /run/culvert-maint/culvert-maint.sock -X POST http://unix/v1/reconcile/<op_id> -d '{"action":"resolve"}'
```

Details: `docs/operator/release-management-agent.md` §"Interrupted operations".

## 5. Disaster recovery (new appliance)

1. Import the OVA, first boot (`first-boot.md`) up to the point where the
   stack is running — do NOT complete the setup wizard.
2. Copy the archive to the `culvert-backups` volume (or mount it at
   `/backup`), put the ORIGINAL `.env` back (CA/log passphrases), restore
   with `--mode full --accept-dp-reenrollment --accept-root-ca-change`
   (the fresh appliance minted its own root CA; the archive's replaces it,
   which is what you want — clients trust the archived root).
3. Bring the stack up, verify, re-enter excluded credentials (§2).
4. Re-point clients/PAC at the new address if it changed.

Without `--accept-root-ca-change` the restore is REFUSED, because the new
install's freshly minted root would be replaced. **Executed** exactly as
written above (lifecycle harness scenario R,
`evidence/dr-fresh-volume-REPORT.md`): original install set up with
default-deny + one allow rule, encrypted backup and `.env` copied off the
host, BOTH original volumes destroyed, a new install brought up unclaimed
on fresh volumes, the restore refused without the flag and committed with
it; the new appliance came back with the SAME root CA (SHA-256 fingerprint
equal — clients keep trusting it), the original admin login, the rules,
default-deny, `ssl_inspection: ready`, and real allow/block traffic through
the proxy. Distinct from §2 (same volume, previous data kept beside it). Not
exercised: a different IP/hostname for the new appliance (PAC re-point is
an operator step), and a lost `.env` — without the CA passphrase the
archived `ca.bundle` cannot be decrypted and inspection does not come back
(`state-and-key-custody-matrix.md` §4).

## 6. Failure matrix (what was exercised, where)

| Failure | Expected outcome | Evidence |
|---|---|---|
| Power loss / kill during restore swap | boot refused with journal; explicit revert/complete; both idempotent | `restore_inplace_test.go`, harness scenario E |
| Restore attempted while the proxy runs | refused (data-dir lock) | harness D `commit-refused-while-running` |
| Restore commit attempted after the proxy has run long enough to GC | still refused: the proxy's lock hold is pinned for its lifetime (a GC-released hold once let a commit land on a live stack) | `TestHoldDataDirLock_SurvivesGarbageCollection`, harness D `commit-refused-while-running` |
| Proxy started while a restore commit/recovery holds the lock | proxy boot refused (fatal) until the commit finishes; `restart: unless-stopped` brings it back | `TestHoldDataDirLock_RefusesWhileCommitHoldsIt` |
| Kill after promotion removed the staging dir but before the journal | the commit records `progress: promoted` BEFORE removing the staging dir, so `--confirm=complete` retires the journal; without that marker a missing staging dir is REFUSED (nothing moved, journal kept) | `TestRecoverRestore_Complete_StagingAlreadyRemoved`, `TestRecoverRestore_Complete_MissingStagingWithoutMarker_Refuses`, `TestRestoreCommit_WritesPromotedMarkerBeforeRemovingStaging` |
| Kill DURING a revert — while parking the promoted entries, or while returning the previous entries | re-running `--confirm=revert` resumes: the journal recorded the direction and `progress: unpromoted` before the first previous entry came back, so the returned previous data is never mistaken for promoted data; the live tree equals the previous set byte for byte, staging holds the restored set | `TestRecoverRestore_Revert_InterruptedDuringReturn_Resumes`, `…InterruptedDuringUnpromote_Resumes`, `…InterruptedBeforeJournalRemoval_Retires` |
| Kill during a complete's promotion | re-running `--confirm=complete` resumes; live equals the restored set, bak equals the previous set | `TestRecoverRestore_Complete_InterruptedDuringPromote_Resumes` |
| Operator switches direction after a recovery started | refused with the recorded direction named; nothing moved | `TestRecoverRestore_DirectionSwitchIsRefused` |
| Journal names a previous-data dir that no longer exists | `--confirm=complete` recreates it and says the previous data was not preserved; `--confirm=revert` REFUSES (nothing moved, journal kept) unless `progress: returned` proves the previous data is already live — an absent bak dir with live restored data used to be reverted into an EMPTY data dir with the boot guard disarmed | `TestRecoverRestore_MissingBakDir`, `TestRecoverRestore_Revert_MissingBakInPromoting_RefusesAndMovesNothing` |
| Data dir reached through a symlink with a bind mount inside | nested mount still refused before anything destructive | `TestNestedMountPointsUnder_ResolvesSymlinkedDataDir` |
| Agent cannot inspect the running image or the pinned tag at boot | record kept as `inputs_unavailable`; never retired on absent evidence | `TestReconcile_TagInspectFailureIsInputsUnavailable_NotNoop`, `TestReconcile_RunningCaptureFailureIsInputsUnavailable` |
| Resolve refused at admission (lock held / agent busy) | attempt bound not consumed | `TestReconcileResolve_RefusedLaunchDoesNotChargeAnAttempt` |
| Resolve replayed with the same `idempotency_key` after a failed attempt | the prior op is returned (`deduped`), nothing runs, attempt bound not consumed | `TestReconcileResolve_DedupedReplayDoesNotChargeAnAttempt` |
| Dispatch state file exists but is unreadable at control-plane start | logged, `dispatch_state: unreadable_at_startup` on `/api/releases`, the file is never overwritten; restart once it is readable to resume the watch | `TestDispatchStore_UnreadableStateIsSurfacedNotOverwritten` |
| Agent restart after a reconciled adoption | adopted outcome persists in the idempotency index | `TestOverrideInterrupted_PersistsReconciledOutcomeAcrossRestart` |
| Agent killed between pull and restart / after tag | journal classified at start; safe boundary retired; tag hazard surfaced, resolve-only | `cmd/culvert-maint/internal/server/reconcile_startup_test.go`, agent harness F3 |
| Control plane (proxy) replaced mid-dispatch | dispatch record persisted; watch resumed on boot; GUI keeps polling | `release_dispatch_persist_test.go`, agent harness F1 |
| Duplicate apply request / after agent restart | same op returned (`deduped`) | agent harness F2/F5, `idempotency_persist_test.go` |
| Registry unreachable during rollback | rollback from local cache | agent harness F4, `TestRealDocker_LocalFirstRollbackSurvivesRegistryOutage` |
| Corrupt / unsupported archive or journal | refused before any write; journal never acted on | `restore_test.go`, `TestRecoverRestore_MalformedJournalRefuses` |
| Archive without `ca.bundle` / without admins | refused unless `--accept-root-ca-change` / refused outright | `TestRestoreCommit_RootCAGuard_*`, `TestRestoreCommit_RefusesLeavingNoAdmin` |
| Insufficient disk space | restore stage fails before the swap (staging is written first); upgrade pull fails before tag, running version + data + CA identity + enforcement unchanged, retry succeeds once space is freed | restore: lifecycle harness G (size-bounded ext4 volume); upgrade: `test/e2e/appliance/upgrade-enospc-qualify.sh` (`evidence/enospc-*`) |
| Original appliance lost (DR) | new install + archive + escrowed `.env` comes back as the same appliance | lifecycle harness R (`evidence/dr-fresh-volume-*`) |
| OS/engine maintenance started during an agent operation | `culvert-os-update` refuses (exit 3) while the agent journal holds a record; `--force` overrides | `appliance_os_update_trap_test.go` (`TestOSUpdate_RefusesWhileTheAgentHasAnOperationInFlight`) |
| Unsupported predecessor / downgrade | dispatch refused 409 | `release_dispatch_test.go` transition gates |
| Failed health after update | auto-rollback to prior from cache | `appliance-catalog-update-e2e.yml` P5, agent harness F4 |
