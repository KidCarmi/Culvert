# Wiring Release Management to the maintenance agent (without the Docker socket)

The admin UI's **Release Management** panel drives catalog dispatch through the
host-side `culvert-maint` agent. By default the proxy container has no route to
that agent, so the panel shows **"Agent unreachable"**. This page explains the
model and the supported, isolation-preserving way to wire them together.

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
- The agent authenticates every caller with `SO_PEERCRED` against `allow_peers`,
  is read-only in the current slice, and performs Docker actions **only** through
  the path-locked sudoers allowlist (`/etc/sudoers.d/culvert-maint`).
- So reaching the agent grants the proxy the agent's **narrow allowlisted
  surface**, not the Docker daemon. A compromised proxy cannot exceed it.

## Why "Agent unreachable" appears

The agent's socket lives on the **host** (`/run/culvert-maint/culvert-maint.sock`).
The proxy runs in a **container** and, by default, the stock `docker-compose.yml`
neither mounts that socket nor sets `CULVERT_MAINT_AGENT_URL`. The in-container
client therefore dials a socket that does not exist inside the container.

(The separate "No catalog loaded (available: false)" line is expected until a
release catalog is seeded into `/data/release_catalog`.)

## Supported wiring (Unix socket, opt-in)

This is host-local — it opens **no network port**. It requires two
deployment-specific identity facts to line up.

### 1. Find the `culvert-maint` group GID

```bash
export CULVERT_MAINT_GID=$(getent group culvert-maint | cut -d: -f3)
echo "$CULVERT_MAINT_GID"
```

The proxy must be in this group to connect to the `0660 culvert-maint:culvert-maint`
socket. The override adds it via `group_add`.

### 2. Authorize the proxy's UID in the agent

The agent's `allow_peers` is **UID-based**. Find the proxy container's host UID
and add it:

```bash
docker compose exec proxy id -u          # e.g. 100
sudoedit /etc/culvert-maint/config.toml  # allow_peers = [100, ...]
sudo systemctl restart culvert-maint
```

> With the default Docker setup (no user-namespace remap) the in-container UID
> equals the host UID the agent sees over `SO_PEERCRED`. If you run with
> `userns-remap`, use the remapped host UID instead. Prefer **numeric** UIDs —
> the agent's static build cannot resolve NSS/LDAP usernames.

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
> UI is the functional check. To hit `/v1/health` directly, do it from a host
> with GNU `curl` **as a UID listed in `allow_peers`** (the agent authenticates
> the caller), e.g. `sudo -u culvert-cp curl --unix-socket \
> /run/culvert-maint/culvert-maint.sock http://unix/v1/health`.

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

## Remote / multi-host agents

This UDS path is for the **CP-local** agent. Reaching an agent on another host
needs an authenticated network endpoint (`CULVERT_MAINT_AGENT_URL=https://…`),
which requires the agent to grow a TLS listener with mTLS/token auth — tracked
in `roadmap/release-management-https-agent-spec.md`.
