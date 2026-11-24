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
  (`/etc/sudoers.d/culvert-maint`). Backup, restore and cleanup, and the
  upgrade's running-container inspect, pinned image pull and retag, all have
  arguments that vary per call. They go through the root-owned wrapper that
  allowlist grants (`/usr/local/libexec/culvert-maint/compose-cli`). The
  wrapper validates the arguments and runs the fixed docker command. Pulls and
  retags are bound to the configured `proxy_repo` at an exact sha256 digest.
  The wrapper replaced sudoers argument wildcards, which sudo-rs on Ubuntu
  26.04 rejects, and digest patterns that sudo-rs can never match.
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

## After the agent stops during an upgrade or rollback

If the agent process dies while an upgrade or rollback is running (crash, OOM
kill, host power loss), the next start reports the operation and **changes
nothing in Docker**. The agent does not roll back or finish the upgrade by
itself ([ADR-0061](../adr/0061-maintenance-agent-crash-journal-lifecycle.md)).

Where to look:

- `GET /v1/status` → `interrupted_operations`. One entry per interrupted
  operation, present on every request and across restarts until a later
  upgrade or image rollback succeeds (an interrupted restore is also cleared
  by a later successful restore; see below).
- `GET /v1/operations/{op_id}` → `state: failed`,
  `failure_reason: agent_restart_interrupted`, with the same detail under
  `result.interrupted`.
- The audit log has one `failed` / `agent_restart_interrupted` entry per
  interrupted operation.

What an entry tells you:

| Field | Meaning |
|---|---|
| `journal_phase` | the last step the operation recorded |
| `docker_state: unchanged` | it stopped before moving the image tag; submit it again if still wanted |
| `docker_state: indeterminate` | it may have moved `culvert/proxy:pinned`, or started an image that was never health-checked |
| `docker_state: data_indeterminate` | a restore or a data rollback: no image tag was involved; see [After the agent stops during a restore](#after-the-agent-stops-during-a-restore) |
| `running_image` | what the proxy runs now: `target`, `prior`, `other`, or `unknown` if Docker could not be read |
| `pinned_tag.matches_running` | `false` means the next `docker compose up` would start a different image than the one running. Reported on every status, with or without an interrupted operation. It is also `false` for a moment during a normal upgrade or rollback, between the tag move and the recreate: read it together with the lock holder / running operation |
| `prior_ref` | the image reference to give a rollback |
| `operator_action` | the same guidance as below, for this entry |

For `indeterminate`:

- **`running_image: prior`** — the proxy still runs the previous image. If
  `pinned_tag.matches_running` is `false`, the tag is ahead of it. Either submit
  the upgrade again, or roll back with
  `POST /v1/rollbacks {"mode":"image","image_ref":"<prior_ref>"}`. Both re-pin
  the tag and run the health check.
- **`running_image: target`** — the new image is running but the agent never
  health-checked it. Submitting the same upgrade again is reported as already
  current and does **not** check it. Verify the proxy yourself, or roll back to
  `prior_ref`.
- Until one of these succeeds, do not run `docker compose up` by hand: it
  starts whatever image the tag is on.
- An upgrade or rollback may wait up to `interrupted_settle` (75s by default)
  after an agent start before it changes anything (an upgrade before its first
  capture, a rollback in its `restart` step). That is deliberate: Docker may
  still be stopping a container for a `compose up` / `compose down` that an
  earlier agent process did not see finish. It applies when such a command was
  left unfinished (a marker under `<state_dir>/mutation`), when an interrupted
  operation is on record, and, after installing or upgrading to an agent that
  tracks this, at every agent start until one upgrade, rollback or restore has
  completed. The same wait starts again, inside a running
  agent, after a `compose up` / `compose down` of its own ended in an error,
  and the startup reconcile observes it too. The operation log says `settle:
  waited …`.
  - When the unfinished command was a `compose up` and Docker shows no proxy
    container running on two reads a couple of seconds apart, the wait ends
    there (`settle: no proxy container is running …`): the proxy is already
    down and nothing is left to wait for.
    After an unfinished `compose down`, and on that first start, the whole
    window is waited.
  - The marker stays until an upgrade, rollback or restore completes its
    compose command with nothing in doubt. An agent restart with no marker and
    no interrupted operation on record does not wait.
- If you downgrade the agent to a version older than this mechanism and later
  upgrade again, remove `<state_dir>/mutation` before starting the newer
  agent, so that it waits once as on a first start.

### After the agent stops during a restore

A restore (`POST /v1/restores/commit`) and a data rollback (`POST /v1/rollbacks`
with `mode=data`) run the same steps: a read-only preflight, `docker compose
down`, the restore's commit command, `docker compose up -d`, a health check. An
agent that dies between them leaves the proxy **down**. The next start reports
the operation in the same three places as above — `interrupted_operations`, the
operation itself (`failed` / `agent_restart_interrupted`, no longer `404`), one
audit entry — and, as for an upgrade, **changes nothing**: it does not start
the stack, repeat the restore or undo it. That holds with
`reconcile_on_startup = "converge"` too (`recovery_required`, reason
`restore_window_manual` or, for a data rollback, `data_window_manual`).

Such an entry has `docker_state: data_indeterminate` (no image tag was
involved) and these fields, all derived from what the agent recorded before
each step:

| `restore_stage` | The operation stopped… | `stack_touched` | `data_changed` | `previous_state` |
|---|---|---|---|---|
| `admitted`, `preflight` | before it asked Docker to stop anything | `false` | `no` | `in_place` |
| `stopping` | after asking Docker to stop the stack, before the commit command | `true` | `no` | `in_place` |
| `committing` | after starting the commit command; its result was never recorded | `true` | `unknown` | `recoverable_at_next_proxy_start_or_manual` |
| `commit_failed` | after the commit command returned an error, before the stack was started again | `true` | `unknown` | `recoverable_at_next_proxy_start_or_manual` |
| `committed`, `starting`, `started` | after the commit command returned success, before the health check passed | `true` | `yes` | `kept_in_backup_dir` |
| `unrecorded` | at a point the record does not give (written by, or passed through, an agent version that did not record it) | absent | `unknown` | `unknown` |

`stack_touched` is what the operation did, not what Docker says now: read
`compose_stack_up` for that. `restart_safe` says, in a sentence, what happens
if you start the proxy now, and `operator_action` what to do. In short:

- **`data_changed: no`** — the data directory is as it was. If the proxy is
  down, submit the restore again (it stops, restores, starts and health-checks
  the stack) or start the stack yourself.
- **`data_changed: unknown`** — the agent cannot tell whether the data
  directory holds its previous content, the restored content or an unfinished
  swap. `commit_failed` is in this group on purpose: the command normally puts
  the previous content back itself, but the agent sees the same error when the
  command was cut off by the stage timeout (its container keeps running and may
  still commit) or could not put the content back. First make sure no `cli`
  container of the compose project is still running (`docker ps -a`). On the
  shipped Docker Compose deployment, starting the proxy — or submitting the
  restore again — then settles it: an unfinished in-place restore is undone
  before the data directory is read, or the proxy refuses to start and its log
  says why; `/data/.restore/last-outcome.json` says `committed` or
  `rolled_back`. With a proxy image that predates the in-place restore, or a
  data directory that is not a volume mount point, follow
  [Recovering from an interrupted restore](docker-compose-backup-restore.md#8b-recovering-from-an-interrupted-restore-risk-005)
  **before** starting anything.
- **`data_changed: yes`** — the restore committed; the previous content is kept
  in the restore's backup directory (`--list-restore-leftovers`). Nobody has
  health-checked the proxy on the restored data. If it is down, start the stack
  and check it. Do not submit the restore again only to start the stack: it
  would restore the same backup a second time.

Before starting the stack by hand in any of these cases, check
`GET /v1/status`: if an interrupted upgrade or image rollback is listed too, or
`pinned_tag.image_id` is not the image you expect to run, deal with that first.
`docker compose up -d` starts whatever image the fixed tag is on, with no health
check, and with the proxy down there is no running image for
`pinned_tag.matches_running` to compare it with.

The entry stays until a later restore or data rollback commits **and** passes
its health check (that operation's result lists it under
`superseded_interrupted_ops`, and the audit log gets a
`<kind>:interrupted_superseded` entry), or until a later upgrade or image
rollback succeeds. A restore never clears the entry of an interrupted upgrade
or image rollback: it does not re-pin the image tag.

A restore whose commit succeeded but could not be recorded in the agent's
journal ends `failed` with `failure_reason: command_error`, a
`run_cli_restore_commit` stage output that says the data directory was
replaced, and `result.restore_committed: true`. The stack is still started and
health-checked. Do not repeat that restore because it "failed".

If the agent will not start and its log says
`journal: refusing to serve — journal: corrupt record <op_id>.json`, a journal
file under `<state_dir>/reconcile/` is unreadable. The agent stops rather than
ignore an operation it cannot classify. Move that file aside, start the agent,
and check `culvert/proxy:pinned` against the running container before the next
upgrade.

## What this does **not** do

- It does **not** mount `/var/run/docker.sock` into any container.
- It does **not** open a network port on the agent.
- It does **not** widen the sudoers allowlist or the agent's authz.

## Remote / multi-host Maintenance Agents

This UDS path is for the **CP-local** agent. Reaching an agent on another host
needs an authenticated network endpoint (`CULVERT_MAINT_AGENT_URL=https://…`),
which requires the agent to grow a TLS listener with mTLS/token auth — tracked
in `roadmap/release-management-https-agent-spec.md`.
