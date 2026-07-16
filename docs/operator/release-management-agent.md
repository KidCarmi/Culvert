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
