# Appliance upgrade runbook (application)

Scope: upgrading the Culvert application on an installed appliance. OS
patching is `os-maintenance.md`; replacing the whole OVA is NOT an upgrade
path for an installed appliance (it is a reinstall + restore).

## What an upgrade is

A release is one multi-arch container image published to `ghcr.io/kidcarmi/culvert`
by digest and described by the signed release catalog at
`https://catalog.culvertlabs.com/release-catalog`. The appliance's control
plane (the proxy) verifies the catalog in-binary (keyless Sigstore identity
pinned to this repository's `ci.yml` tag workflow + baked trusted root, or
configured ed25519 roots; freshness and anti-rollback enforced) and asks the
host **maintenance agent** (`culvert-maint`, systemd, sudoers-bounded) to
apply it: pull by digest → retag `culvert/proxy:pinned` → `docker compose
up -d` → health gate → verify running digest → auto-rollback on failure.

**What "the upgrade succeeded" means.** The agent marks an upgrade
succeeded only when ALL of these hold after the restart; any miss fails the
op `health_failed` and rolls the prior image back:

| Condition | How it is checked |
|-----------|-------------------|
| the intended release is what runs | `verify`: the running container's RepoDigests include the pinned `repo@sha256` (hard check) |
| the process serves and its config loaded | `health_gate`: `/ready` answers 2xx within 30 s (a config that does not load is fatal at boot) |
| nothing that worked before broke | `health_gate`: every `/ready` row among `setup_complete`, `session_secret`, `ca`, `policy_loaded`, `policy_posture` that was `ok` BEFORE the restart (read by `capture_before`) is `ok` again; a missing row counts as regressed |

The preserved set is local state only — admin setup and session signing,
the inspection CA, policy loaded and enforcing. Rows that depend on an
external service (`clamav`, `cp_poll`, threat feeds, DNS) are deliberately
outside it: a dependency outage during the window must not roll an upgrade
back, and a rollback would not fix it. A row that was already failing before
(an unclaimed appliance) is not required after. The inline rollback checks
the same rows report-only and lists any that did not come back as
`not_restored=[…]` in the op log. CA *identity* (the same root, not just a
usable one) is outside the agent gate — the bundle lives in `/data`, which an
upgrade never writes; the upgrade qualification compares the CA certificate
fingerprint before and after (`test/e2e/appliance/upgrade-enospc-qualify.sh`). Do not point `ready_path` at `/ready?strict=1`
(now honoured): strict gating makes every report-only row — external ones
included — a rollback trigger.

Persistent state (`/data` volume) is untouched by an upgrade; the new
binary reads the previous build's state. Supported predecessors are
enforced: see `upgrade-transition-matrix.md`.

## Before you upgrade

1. Read the transition matrix: the running release must be at or above the
   target's `min_upgrade_from` (the dispatch refuses otherwise).
2. Take a backup (`docker compose --profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE cli --encrypt --backup /backup/pre-upgrade-<date>.tar.gz.enc`)
   or tick **pre-backup** in the dispatch dialog (needs a passphrase reference).
3. Confirm the agent is reachable: Admin UI → Release Management shows the
   current release and no "Agent unreachable"; `GET /api/releases` shows
   `available: true`.
4. Maintenance window: the proxy restarts once (graceful stop ≤ 60 s, boot a
   few seconds). Client connections through the proxy are reset during that
   window; the admin session is logged out (session key is per process).

## Upgrade (GUI)

1. Release Management → **Dispatch** → choose the release or the
   `recommended` channel → keep **auto-rollback** on → Dispatch.
2. The panel shows the agent op. The control plane is itself the container
   being replaced, so the panel will show "Control plane unreachable
   (restarting during the update?) — retrying"; it keeps polling. After the
   restart the new process re-attaches to the in-flight dispatch
   (`release_dispatch_state.json`) and shows the terminal result
   (`succeeded`, verified by digest) — no action needed.
3. Verify: Release Management → Current shows the new release; `/ready`
   rows `setup_complete=ok`, `policy_posture=ok`; a client request through
   the proxy behaves as before (allow/block).

Refusals you may see (HTTP 409, named in the toast):
- `unsupported_transition` — running release is below the floor; upgrade
  through an intermediate release ≥ the floor first, or restore a backup
  onto the target.
- `unknown_current` — the running build is not a catalog release and has no
  version stamp; tick "Acknowledge unknown running release" only after you
  verified the transition.
- `downgrade` — the target is older; downgrades are unsupported, see below.

## Upgrade (API / CLI)

```bash
# dispatch the recommended channel on the local agent (admin session)
curl -k -b jar -H 'Origin: https://<appliance>:9090' -H 'Content-Type: application/json' \
  -X POST https://<appliance>:9090/api/releases/dispatch \
  -d '{"agent":"local","channel":"recommended","pre_backup":false}'
# follow
curl -k -b jar https://<appliance>:9090/api/releases/dispatch/status?agent=local
```

Agent-direct (host shell, bypasses the catalog — lab/break-glass only):
`curl --unix-socket /run/culvert-maint/culvert-maint.sock -X POST http://unix/v1/upgrades/apply -d '{"image_ref":"ghcr.io/kidcarmi/culvert@sha256:<digest>","rollback_on_failure":true,"idempotency_key":"<unique>"}'`.
Duplicate requests with the same `idempotency_key` return the same op
(also across an agent restart).

## If something goes wrong

| Symptom | Meaning | Action |
|---|---|---|
| Dispatch `failed_rolled_back` | health gate failed; the agent restored the previous image from the local cache (no registry needed) | read the op log (`/v1/operations/<op>/logs`), fix the cause, retry |
| Dispatch `failed_needs_attn` | the agent op ended without a verified success, or the agent no longer knows the op | check `GET /v1/status` on the agent: `interrupted_operations` / `attention_required`; see the recovery runbook |
| Agent restarted mid-upgrade | the journal record is classified at agent start; a safe no-op or an already-healthy target is retired/adopted automatically; anything else (tag advanced, container stale = TAG HAZARD) waits for `POST /v1/reconcile/<op_id> {"action":"resolve"}` | `docs/operator/release-management-agent.md` §"Interrupted operations" |
| Op log shows `pull … no space left on device` | the root disk filled during the image download; the agent stops at `pull`, so the running version, the pinned tag, `/health` and all admin state are untouched (qualified: `evidence/enospc-*`) | `df -h /` on the appliance; free space (`sudo docker image prune` removes images no container uses; grow the virtual disk if it is simply too small — `hypervisor-install.md`); then dispatch the upgrade again (the qualification retried with a NEW idempotency key) |
| `/ready` `policy_posture` fails after the upgrade | the default action or rules did not load | check `/api/default-action` and the policy page; restore from the pre-upgrade backup if state is damaged |

## Downgrade

Not supported as an operation. The dispatch refuses an older target unless
`allow_downgrade` (break-glass) is given; the only tested way back is
**restore the pre-upgrade backup onto the previous release** (recovery
runbook), or the frozen schema-v2 predecessor path
(`culvert --prepare-downgrade`, `docs/operator/upstream-proxies.md` §7–10).
State written by a newer build may be ignored or refused by an older one.

## Host components

An application upgrade replaces the container image only. The compose
files, the maintenance agent binary/unit/sudoers and `.env` are host
components installed by `scripts/install.sh` from the image's
`/app/deploy` bundle. Compatibility rule for the pilot: **the agent and
compose files are forward-compatible within the supported transition
window** (the agent's API and sudoers allowlist did not change across the
qualified releases; the compose `command:` flags are checked by the
installer's preflight). When a release note says host components changed,
re-run `scripts/install.sh` (idempotent: re-extracts the bundle, upgrades
the agent binary/unit/sudoers in place, never overwrites `.env` secrets).
The agent socket mount (`docker-compose.maint-agent.yml`) survives
container recreation because the directory, not the socket file, is mounted.
