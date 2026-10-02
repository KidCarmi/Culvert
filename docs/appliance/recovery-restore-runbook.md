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

Both directions are deterministic and idempotent
(`docs/operator/docker-compose-backup-restore.md` §8b).

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

## 6. Failure matrix (what was exercised, where)

| Failure | Expected outcome | Evidence |
|---|---|---|
| Power loss / kill during restore swap | boot refused with journal; explicit revert/complete; both idempotent | `restore_inplace_test.go`, harness scenario E |
| Restore attempted while the proxy runs | refused (data-dir lock) | harness D `commit-refused-while-running` |
| Restore commit attempted after the proxy has run long enough to GC | still refused: the proxy's lock hold is pinned for its lifetime (a GC-released hold once let a commit land on a live stack) | `TestHoldDataDirLock_SurvivesGarbageCollection`, harness D `commit-refused-while-running` |
| Proxy started while a restore commit/recovery holds the lock | proxy boot refused (fatal) until the commit finishes; `restart: unless-stopped` brings it back | `TestHoldDataDirLock_RefusesWhileCommitHoldsIt` |
| Kill after promotion removed the staging dir but before the journal | `--confirm=complete` retires the journal; nothing left to move | `TestRecoverRestore_Complete_StagingAlreadyRemoved` |
| Journal names a previous-data dir that no longer exists | revert and complete both succeed (absent dir = nothing to move) | `TestRecoverRestore_MissingBakDirIsNotFatal` |
| Data dir reached through a symlink with a bind mount inside | nested mount still refused before anything destructive | `TestNestedMountPointsUnder_ResolvesSymlinkedDataDir` |
| Agent cannot inspect the running image or the pinned tag at boot | record kept as `inputs_unavailable`; never retired on absent evidence | `TestReconcile_TagInspectFailureIsInputsUnavailable_NotNoop`, `TestReconcile_RunningCaptureFailureIsInputsUnavailable` |
| Resolve refused at admission (lock held / agent busy) | attempt bound not consumed | `TestReconcileResolve_RefusedLaunchDoesNotChargeAnAttempt` |
| Agent restart after a reconciled adoption | adopted outcome persists in the idempotency index | `TestOverrideInterrupted_PersistsReconciledOutcomeAcrossRestart` |
| Agent killed between pull and restart / after tag | journal classified at start; safe boundary retired; tag hazard surfaced, resolve-only | `cmd/culvert-maint/internal/server/reconcile_startup_test.go`, agent harness F3 |
| Control plane (proxy) replaced mid-dispatch | dispatch record persisted; watch resumed on boot; GUI keeps polling | `release_dispatch_persist_test.go`, agent harness F1 |
| Duplicate apply request / after agent restart | same op returned (`deduped`) | agent harness F2/F5, `idempotency_persist_test.go` |
| Registry unreachable during rollback | rollback from local cache | agent harness F4, `TestRealDocker_LocalFirstRollbackSurvivesRegistryOutage` |
| Corrupt / unsupported archive or journal | refused before any write; journal never acted on | `restore_test.go`, `TestRecoverRestore_MalformedJournalRefuses` |
| Archive without `ca.bundle` / without admins | refused unless `--accept-root-ca-change` / refused outright | `TestRestoreCommit_RootCAGuard_*`, `TestRestoreCommit_RefusesLeavingNoAdmin` |
| Insufficient disk space | restore stage fails before the swap (staging is written first); upgrade pull fails before tag | by construction (stage-before-swap); not injected in this run — BLOCKED row in the readiness report |
| Unsupported predecessor / downgrade | dispatch refused 409 | `release_dispatch_test.go` transition gates |
| Failed health after update | auto-rollback to prior from cache | `appliance-catalog-update-e2e.yml` P5, agent harness F4 |
