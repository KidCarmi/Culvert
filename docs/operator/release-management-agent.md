# Wiring Release Management to the maintenance agent (without the Docker socket)

The admin UI's **Release Management** panel drives catalog dispatch through the
host-side `culvert-maint` agent. On a normal quick-start install,
`scripts/install.sh` wires the local agent automatically after validating the
Docker and host posture. This page explains the model, what the installer
checks, and the manual path for custom deployments.

For the long-term trusted catalog roadmap, see
[`enterprise-release-catalog-plan.md`](enterprise-release-catalog-plan.md).

> **The maintenance-agent socket is not the Docker socket.** This wiring mounts
> the agent's own `/v1` API socket — never `/var/run/docker.sock`. The agent is
> the privilege boundary; mounting it does not grant the proxy raw Docker.

## Deployment model

```
Admin UI / API ──► Release Management API ──► culvert-maint agent /v1 ──► docker compose
  (browser)         (in the proxy container)    (host systemd service)      (sudoers-allowlisted)
```

- The Release Management API (`release_api.go`) runs **inside the proxy
  container** and calls the agent over HTTP on a Unix-domain socket.
- The agent authenticates every caller with `SO_PEERCRED` against `allow_peers`
  and performs Docker actions **only** through the path-locked sudoers allowlist
  (`/etc/sudoers.d/culvert-maint`).
- So reaching the agent grants the proxy the agent's **narrow allowlisted
  surface**, not the Docker daemon. A compromised proxy cannot exceed it.

## Automatic local wiring

The quick-start installer attempts local Release Management wiring by default.
It deploys the stack to `/srv/culvert` (all users; `CULVERT_DIR` overrides) and
installs the agent binary from the proxy image's `/app/deploy` bundle — no
source checkout or GitHub release download needed. The system path matters:
the unprivileged `culvert-maint` user must be able to traverse into the stack
directory, which a `0700`/`0750` home directory (EC2 `ec2-user`, modern
Ubuntu) forbids — a stack placed there makes the installer skip the agent
fail-closed and leaves the panel at **"Agent unreachable"**.

Wiring succeeds only when all safety checks pass:

- Docker is rootful and `userns-remap` is not enabled.
- The proxy container is running and has a non-root numeric UID.
- The proxy container does **not** mount any Docker socket.
- The `culvert-maint` group, config, sudoers file, default socket path, and
  compose project path all match the install.
- The maintenance-agent `proxy_repo` matches the release dispatch repository.
- The installer can authorize exactly the proxy UID in `allow_peers`, start the
  agent, verify `/v1/health`, and mount only `/run/culvert-maint` into the proxy
  with `docker-compose.maint-agent.yml`.

If any check fails, the installer leaves Release Management unwired and prints a
warning. Culvert still runs; the Release Management panel may show
**"Agent unreachable"** until an operator completes the custom wiring below.

The separate "No catalog loaded (available: false)" state is expected until a
trusted release catalog is published into `/data/release_catalog`. The installer
does not download or seed unsigned catalogs.

To opt out of automatic wiring:

```bash
CULVERT_SKIP_RELEASE_AGENT_WIRING=1 bash scripts/install.sh
```

## Manual/custom wiring

Use this section for rootless Docker, `userns-remap`, non-standard compose
layouts, remote agents, or hardened hosts where the installer correctly refused
to infer the peer UID. This is host-local and opens **no network port**.

### 1. Find the `culvert-maint` group GID

```bash
export CULVERT_MAINT_GID=$(getent group culvert-maint | cut -d: -f3)
echo "$CULVERT_MAINT_GID"
```

The proxy must be in this group to connect to the `0660 culvert-maint:culvert-maint`
socket. The override adds it via `group_add`.

### 2. Authorize the proxy UID in the agent

The agent's `allow_peers` is **UID-based**. Find the proxy container's host UID
and add it:

```bash
docker compose exec proxy id -u          # e.g. 100
sudoedit /etc/culvert-maint/config.toml  # allow_peers = ["100", ...]
sudo systemctl restart culvert-maint
```

> With the default Docker setup (no user-namespace remap) the in-container UID
> equals the host UID the agent sees over `SO_PEERCRED`. If you run with
> `userns-remap`, use the remapped host UID instead. Prefer **numeric** UIDs —
> the agent's static build cannot resolve NSS/LDAP usernames.
> Do not add `root`, groups, or wildcard-style entries for the proxy.

### 3. Bring the stack up with the override

```bash
docker compose -f docker-compose.yml -f docker-compose.maint-agent.yml up -d
```

The override (`docker-compose.maint-agent.yml`) mounts
`/run/culvert-maint` read-only into the proxy, adds the `culvert-maint` group,
and sets `CULVERT_MAINT_AGENT_URL=unix:///run/culvert-maint/culvert-maint.sock`.

### 4. Verify

Reload Release Management in the admin UI — **Current Release** should now resolve
instead of "Agent unreachable".

To confirm the agent socket is mounted and visible inside the proxy container:

```bash
docker compose exec proxy ls -l /run/culvert-maint/culvert-maint.sock
# srw-rw---- 1 ... culvert-maint ... /run/culvert-maint/culvert-maint.sock
```

> The stock proxy image is Alpine, whose busybox `wget` has no `--unix-socket`
> option, so the in-container HTTP probe is `ls` of the mounted socket; the admin
> UI is the functional check. To hit `/v1/health` directly from the host, the
> caller must **both** be able to open the `0660 culvert-maint:culvert-maint`
> socket (the kernel checks this on `connect()`, before `allow_peers`) **and**
> have its UID in `allow_peers`. Use the same numeric proxy UID and the
> `culvert-maint` group; do not add `root` just for probing:
> ```bash
> PROXY_UID=$(docker compose exec -T proxy id -u)
> MAINT_GID=$(getent group culvert-maint | cut -d: -f3)
> sudo -u "#${PROXY_UID}" -g "#${MAINT_GID}" \
>   curl --unix-socket /run/culvert-maint/culvert-maint.sock http://unix/v1/health
> ```
> If sudo answers `unknown user #<uid>` (the container UID has no host passwd
> entry — default sudo rejects unknown numeric run-as users), use setpriv,
> which switches to raw numeric IDs: 
> ```bash
> sudo setpriv --reuid "${PROXY_UID}" --regid "${MAINT_GID}" --clear-groups \
>   curl --unix-socket /run/culvert-maint/culvert-maint.sock http://unix/v1/health
> ```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `up` fails: `CULVERT_MAINT_GID` not set | step 1 skipped | export the GID, re-run |
| Still "Agent unreachable", `connection refused` | socket not mounted / agent down | check the agent: `systemctl status culvert-maint` |
| `403` / unauthorized from `/v1` | proxy UID not in `allow_peers` | step 2 |
| `permission denied` connecting | proxy not in `culvert-maint` group | confirm `group_add` GID is correct |
| `connect: no such file` for the socket | legacy socket path | agent on the old layout uses `/run/culvert-maint.sock`; set `CULVERT_MAINT_AGENT_URL` to match |

## What this does **not** do

- It does **not** mount `/var/run/docker.sock` into any container.
- It does **not** open a network port on the agent.
- It does **not** widen the sudoers allowlist or the agent's authz.

## Remote / multi-host Maintenance Agents

This UDS path is for the **CP-local** agent. Reaching an agent on another host
needs an authenticated network endpoint (`CULVERT_MAINT_AGENT_URL=https://…`),
which requires the agent to grow a TLS listener with mTLS/token auth — tracked
in `roadmap/release-management-https-agent-spec.md`.

## Interrupted operations and rollback (startup reconcile)

An `upgrades.apply` or image `rollbacks.create` can be cut off mid-flight — an
agent crash, OOM, host reboot, `systemctl restart culvert-maint`. Every such op
carries a durable journal record (`<state_dir>/reconcile/<op_id>.json`) that
says how far it got (`admitted → captured → resolved → pulled →
restarting → restarted → verified`). The `restarting` entry is a write-ahead
barrier fsync'd *immediately before* the fixed `culvert/proxy:pinned` tag is
advanced, so the danger window is always on disk. Since the reconcile slice,
**rollbacks advance the journal too** (standalone `POST /v1/rollbacks`
mode=image, apply's inline auto-rollback, and reconcile-issued rollbacks all
go through the one shared core).

### What happens on agent restart

1. Every record is read. A record that cannot be parsed is **quarantined**
   (renamed to `<op_id>.json.corrupt.<unixnano>` beside the others), logged at
   WARN, and never acted on — the agent keeps serving instead of crash-looping.
2. Each readable record's op is registered as `failed(agent_restart_interrupted)`
   so `GET /v1/operations/{op_id}` answers.
3. With `reconcile_on_startup = true` (the default; set `false` in
   `config.toml` for mark-only), each record is **classified** against Docker
   truth — the running proxy image (`docker compose ps` + `docker inspect`),
   what `culvert/proxy:pinned` currently resolves to (`docker image inspect`),
   and the record's refs re-validated as repo-bound exact digests — and a
   durable verdict is written to `<state_dir>/reconcile/verdicts/<op_id>.json`.
4. **Only two verdicts are auto-resolved, because they mutate nothing:**
   - `noop` — the tag never advanced, or the stack is already back on the
     prior image: the record is retired; the op stays
     `failed(agent_restart_interrupted)`.
   - `verify_adopt_else_rollback` **when the target image is live AND the
     health probe passes** — the upgrade effectively succeeded: the op is
     re-marked `succeeded` with `result.reconciled=true` and the record retired.
5. **Everything else is surfaced, never executed at boot:** `reup`,
   `rollback_to_prior`, an unhealthy live target, `loud_stop` (invalid refs,
   attempt bound exhausted, no recovery target), `data_manual`
   (`/data` rollback window — never auto-reconciled), and
   `inputs_unavailable` (Docker could not answer when classified — reason
   `docker_unavailable`, `running_capture_failed` or `tag_inspect_failed`).
   Each is a WARN line at startup and an entry on `/v1/status`.

   A capture ERROR is absent evidence, never an empty set: only "the stack is
   down" and "the pinned tag does not exist" count as facts. A record whose
   running image or pinned tag could not be inspected is never retired on
   that boot; the next boot asks Docker again.

The whole pass is bounded by `stage_timeout`; it never prevents the agent
from serving.

### The pinned-tag hazard (`reup`)

`reup` means the crash landed between `docker tag … culvert/proxy:pinned`
and `docker compose up`: the tag already points at the **new, un-health-gated**
image while the container still runs the old one. Nothing is wrong *yet*, but
the next `docker compose up` — by anyone, for any reason — starts that image
silently. The agent calls this out explicitly (`tag_hazard: true`, a dedicated
WARN line) and does **not** converge it on its own; `resolve` runs tag+up
under the health gate, or you repair by hand and `dismiss` with the
acknowledgement flag.

### Status fields

```bash
curl --unix-socket /run/culvert-maint/culvert-maint.sock http://unix/v1/status
```

```json
{
  "attention_required": true,
  "reconcile_on_startup": true,
  "quarantined_journal_records": ["01HX….json.corrupt.1759400000000000000"],
  "interrupted_operations": [
    {
      "op_id": "01HX…", "kind": "upgrades.apply", "phase": "restarting",
      "verdict": "reup", "reason": "tag_advanced_container_stale",
      "recommended_action": "TAG HAZARD: culvert/proxy:pinned already points at target_ref …",
      "tag_hazard": true,
      "target_ref": "ghcr.io/kidcarmi/culvert@sha256:…", "prior_ref": "ghcr.io/kidcarmi/culvert@sha256:…",
      "running_matches_target": false, "tag_matches_target": true,
      "attempts": 0, "computed_at": "2026-10-02T09:00:00Z",
      "last_health": "", "resolve_op_id": "", "last_resolve_op_id": "", "last_resolve_outcome": ""
    }
  ]
}
```

`attention_required` is true whenever any interrupted operation, quarantined
record, or `journal_error` exists. A record whose op is currently running is
not an interrupted one and is not listed. Verdicts: `noop`,
`verify_adopt_else_rollback`, `reup`, `rollback_to_prior`, `loud_stop`,
`data_manual`, `inputs_unavailable`, `unclassified` (mark-only mode, or no
verdict could be written).

### The explicit endpoint

`POST /v1/reconcile/{op_id}` (authenticated like every `/v1` route):

```bash
# act on the recorded verdict (recomputed against live Docker truth first)
curl --unix-socket /run/culvert-maint/culvert-maint.sock \
  -X POST -H 'Content-Type: application/json' \
  -d '{"action":"resolve"}' http://unix/v1/reconcile/01HX…

# clear a record without touching Docker
curl --unix-socket /run/culvert-maint/culvert-maint.sock \
  -X POST -H 'Content-Type: application/json' \
  -d '{"action":"dismiss","acknowledge_tag_hazard":true}' http://unix/v1/reconcile/01HX…
```

`resolve` executes **exactly** the verdict: `noop` ⇒ retire (200);
`verify_adopt_else_rollback` ⇒ health-probe, adopt if healthy (200) else roll
back to `prior_ref` (202); `reup` ⇒ tag+up `target_ref` under the health gate
(202); `rollback_to_prior` ⇒ roll back to `prior_ref` (202). A 202 is an
ordinary journaled, locked, audited `rollbacks.create` op (params carry
`reconcile_of` / `reconcile_action`); poll it via `/v1/operations/{op_id}`.
The original record is retired only when that op **succeeds**; a failure keeps
it listed with `last_resolve_op_id` / `last_resolve_outcome`. Refusals (409):
`verdict_changed` (live state no longer matches the recorded verdict — read
status again), `manual_required` (`loud_stop` / `data_manual`),
`inputs_unavailable` (daemon down or a capture failed), `no_recovery_target`,
`resolve_in_flight` (a resolve is already running — never a second mutation),
`op_running`. Each op_id gets at most 3 resolve attempts, then it is
`loud_stop (reconcile_exhausted)`; a resolve refused at admission
(`concurrency_conflict`, `agent_busy`) ran nothing and does not count.

`dismiss` is free for a `noop` verdict; a tag-hazard verdict requires
`"acknowledge_tag_hazard": true`; any other non-noop or unclassified verdict
requires `"acknowledge_unresolved": true`. Once a record is gone, any further
call answers 404 `record_not_found`.

Audit events: `reconcile.noop`, `reconcile.adopt` (actor `agent:reconcile` at
boot, or the caller on resolve), `reconcile.resolve`, `reconcile.dismiss`.

### Offline rollback floor (local-first)

A rollback's `rollback_pull` — and the upgrade's `pull` — first asks
`docker image inspect <repo@sha256:…>`. A pinned digest is content-addressed,
so when the exact digest is already in the local image store the registry is
**not** consulted (`rollback_pull: skipped (image present locally)` in the op
log) and the rollback proceeds with tag+up. A registry or network outage —
usually the very fault that broke the upgrade — therefore no longer turns a
rollback into `failed(rollback_failed)` with the bad image still running. An
absent image pulls exactly as before.

### Idempotency across restarts

`idempotency.json` in `state_dir` persists the `(actor, kind,
idempotency_key) → op_id + terminal outcome` index for `upgrades.apply` and
`rollbacks.create` (24 h TTL, bounded to 256 entries). A Control Plane retry
with the same key after an agent restart answers 200 with the prior op's
state instead of running a second upgrade.

### What is NOT automatic

- No rollback, re-up, pull, tag or `compose up` ever runs at boot.
- An unhealthy live target is reported, not rolled back.
- `/data` rollback windows (`data_manual`) are never touched.
- A quarantined (unreadable) record is never acted on; inspect and remove it
  by hand.
- Config key: `reconcile_on_startup = true` (default). `false` keeps the
  records, marks the ops interrupted, and lists them `unclassified` — the
  explicit endpoint still works and recomputes on demand.
