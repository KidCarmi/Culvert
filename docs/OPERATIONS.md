# Operations Guide

This guide is for operators running Culvert in production. It documents the
two distinct readiness surfaces, the operator-contract diagnostics page,
and the routine procedures (startup, backup, upgrade, recovery) that an
operator needs to know.

It is intentionally small and focused on day-2 reality, not feature
catalogues. For configuration knobs see the README; for architecture see
`roadmap/PHASES.md`.

## Installation

Culvert ships with a single canonical installer that handles Docker
Engine + Compose v2 setup across the major Linux distro families
(Ubuntu, Debian, RHEL/CentOS/Rocky/Alma, Fedora, Amazon Linux, Arch),
provisions the install directory **without cloning the source repo** (it
extracts the compose files and maintenance-agent packaging from the pinned
proxy image's built-in `/app/deploy` bundle — see the
[README](../README.md#quick-start) for the full sequence, including the
git-clone fallback for images that predate the bundle), and starts the
stack with `docker compose up -d --wait`:

```bash
curl -fsSL https://raw.githubusercontent.com/KidCarmi/Culvert/main/scripts/install.sh | bash
```

After the installer finishes, follow the three post-install steps in the
[README](../README.md#first-run-checklist): setup wizard, `/ready` check,
and **Infrastructure → Diagnostics**. The rest of this guide assumes
those steps are complete.

---

## 1. Two readiness surfaces

Culvert exposes two endpoints for "is this node healthy". They have
**different audiences and contracts** — do not confuse them.

### `/health` and `/ready` — load balancer probes

* Served on the **proxy port** (default `:8080`), unauthenticated.
* `/health` is a **liveness** probe: the process is up, the request loop is
  scheduling, the CA cert (if loaded) has not expired in place.
* `/ready` is a **readiness** probe: load-balancer signal that this node
  is fit to take traffic. Returns `200` with `{"status":"ready",
  "checks":{...}}` when ready, `503` with `"status":"not_ready"` when not.
* These endpoints have a **stable JSON contract**. CI smoke tests
  (`.github/workflows/ci.yml`) and Kubernetes probes depend on them.

  → Treat `/ready` as an **external interface**. Do not change response
  shape, status codes, or check names without a major-version migration
  plan.

#### `/ready` checks map

Each row in the `checks` object has the shape `{"status":"ok"|"fail",
"detail":"..."}`. A row is included only when the relevant subsystem is
configured (e.g. `clamav` is absent when ClamAV is not configured). Two
classes of row exist:

* **Gating** — a `fail` here forces the response to `503`.
* **Informational** — surfaced for operators but does NOT affect the
  HTTP status. A `fail` row in this class still returns `200`.

| Check                       | Class           | Behaviour                                                                 |
|-----------------------------|-----------------|---------------------------------------------------------------------------|
| `ca`                        | informational   | Absent if no CA is configured (the proxy still works as a plain forward proxy). Otherwise `ok`, or `fail` for either of two distinct causes: the configured bundle failed to load/persist, or a loaded CA is outside its own validity window (expired/not-yet-valid) and can no longer sign a leaf any client accepts. Both `fail` details are fixed, cause-free strings by design (`/ready` is unauthenticated on the proxy port) — see the server log or the `ca_load_failed` alert for the real cause. **Not** `/api/diagnostics`: its `root_ca` check only inspects `certMgr.Ready()`/`Usable()`, so a load failure that still leaves an in-memory CA ready (e.g. generation succeeded but the persist write failed) can report `ok` there while `/ready` correctly shows `ca: fail`. |
| `clamav`                    | gating          | When ClamAV is configured, `fail` if the daemon is unreachable. The detail is a fixed string pointing at Security Scanning status in the admin UI — the AV daemon's address/port is not disclosed on this unauthenticated row. |
| `geoip`                     | informational   | Present and `ok` when GeoIP is enabled.                                    |
| `yara`                      | informational   | Present and `ok` when YARA is enabled.                                     |
| `policy_loaded`             | informational   | `ok` when at least one policy rule has been recorded; `fail` when the ruleset is empty (default-deny is still in effect — fresh installs are expected to start here). |
| `session_secret`            | gating          | `ok` when the admin session HMAC key is initialised; `fail` triggers `503` because signed admin cookies cannot be issued without it. |
| `config_snapshot_validator` | gating          | `ok` when `validateConfigSnapshot` accepts the empty baseline (its identity contract); `fail` triggers `503` because the cluster control-plane apply path is unsafe. |
| `state_file_<kind>`         | informational   | One row per detected state-file corruption (e.g. `state_file_admin_settings`, `state_file_ui_users`, `state_file_cluster`); present when that store's file failed to parse at load and the node fell back to an empty store. The corrupt file is normally quarantined aside (renamed to `<path>.corrupt.<ts>`); if the rename itself also fails, the row still appears but the corrupt file is left in place, exposed to being overwritten by the next save. Absent when nothing is corrupt. |
| `cp_poll` *(DP nodes only)* | informational   | `ok` unless this data-plane node's poll to its control plane has been failing past a grace window, in which case `fail` — the node keeps serving its last-known-good config. Absent on CP/standalone nodes. |
| `node_cert` *(DP nodes only)* | informational | `ok` unless this data-plane node's mTLS certificate renewal is failing, in which case `fail` (detail names days to/since expiry). Absent on CP/standalone nodes. |
| `saas_feed`                 | informational   | `ok` while serving a fresh feed, the embedded baseline, or while syncing/recovering; `fail` when serving a stale/degraded last-known-good, or when a managed node has lost authority / hit a corruption state — the embedded baseline still serves either way, so this never gates by default. |

The new `policy_loaded` / `session_secret` / `config_snapshot_validator`
rows are additive — existing fields, status semantics, and the rest of
the `checks` map are unchanged. Existing probes that look only at
top-level `status` and HTTP code keep working as before.

#### Opt-in strict verdict: `/ready?strict=1`

By default, **informational** rows never flip the top-level `status` to
`not_ready` / `503` — only **gating** rows do. This is a deliberate
availability choice: a fleet-wide condition like an expired root CA
(every node provisioned from the same bundle) or a control-plane outage
would otherwise eject every affected node from the load balancer at once,
taking down plain HTTP and bypassed HTTPS traffic that still works fine.

Pass `?strict=1` (or `?strict=true`) to `/ready` to opt into a stricter
verdict: **any** failing row, informational or gating, flips the response
to `503`. Use this on a probe URL only if you specifically want the load
balancer to eject nodes with a degraded-but-still-serving subsystem (e.g.
expired inspection CA, DP running on stale config) rather than just the
hard-down conditions the default verdict gates on.

### Readiness vs Diagnostics — when to look at which

There is occasional confusion between the two surfaces. Quick rule of
thumb:

* **Use `/ready`** for "should the load balancer / k8s service send
  traffic to this pod?". It is anonymous, narrow, stable, and gates on
  hard-fail conditions only. Polled by infrastructure on a tight loop.
* **Use `/api/diagnostics`** for "is my deployment correctly configured
  and hardened?". It is admin-gated, broad, includes warnings (e.g.
  `cluster-insecure`, unauth mode, validation hints), and is intended
  for human operators or audit dashboards. A `warn` here does NOT make
  `/ready` go red.

A subsystem may legitimately appear in both with different meanings —
for example, `policy_loaded` is **informational** in `/ready`
(default-deny is a valid posture) but appears as a `warn` row in
`/api/diagnostics` because operators usually want to be reminded.

### `/api/diagnostics` — operator contract

* Served on the **admin UI port** (default `:9090`), `viewer` role
  required (or higher), under the same auth middleware as the rest of
  `/api/`.
* Returns the **aggregated operator contract**: every subsystem the
  operator is responsible for, each as a `code / status / message /
  operator_action` row, with a top-level rolled-up verdict
  (`ok` / `warn` / `fail`).
* **Side-effect-free**: reading it never opens files, dials sockets, or
  pings ClamAV. It is safe to poll.
* Visible in the GUI under **Infrastructure → Diagnostics**.
* **What `storage_path` does and does not check.** The `storage_path`
  row reports the result of a **one-shot writability probe** that runs
  once at startup against the configured data directory. The probe
  creates a small temp file, writes a few bytes, then deletes it; the
  outcome is cached for the lifetime of the process. The handler reads
  only the cache — no disk I/O happens at request time, and the probe
  is **not** retried. This means:
  * `ok` — the directory was writable at startup.
  * `fail` — the directory was not writable at startup; persistence is
    broken until you fix permissions / mount and restart.
  * `warn` — no data directory is configured, or the startup probe did
    not run (e.g. embedded test harness path).

  Because the probe is one-shot, this row will **not** notice a mount
  that goes away after startup. Continuous filesystem monitoring (`df`,
  inotify, your platform's volume health signals) still belongs in
  host-level checks.

  → `/ready` answers "should the load balancer send me traffic?".
  `/api/diagnostics` answers "is my deployment correctly configured and
  hardened?". An operator-visible warning is not a readiness failure.

---

## 2. Interpreting `warn` vs `fail`

| Status | Meaning                                                                                       | Operator response                                |
|--------|-----------------------------------------------------------------------------------------------|--------------------------------------------------|
| `ok`   | Subsystem is configured and healthy.                                                          | None.                                            |
| `warn` | Subsystem is in a working but **risky or default-deny** state — by design, never blocked.     | Read `operator_action`; harden or accept risk.    |
| `fail` | Subsystem is broken or misconfigured in a way the operator must fix.                          | Act on `operator_action`; investigate logs.      |

Risky modes such as **explicitly-insecure cluster TLS** and **unauthenticated
proxy mode** always surface as `warn` — Culvert never silently removes
operator freedom, but it always makes the trade-off visible.

---

## 3. Startup checklist

Run these once when bringing up a new node, in order:

1. **Persistent storage.** Mount the data directory (default `/data`)
   on durable storage. The proxy expects to be able to write here for
   policy meta, audit log, request log, blocklist, cluster state, and
   config snapshots.
2. **CA passphrase.** If you are using SSL inspection, set
   `CULVERT_CA_PASSPHRASE` and pass `-ca-path /data/ca.bundle`. The
   first start will generate the root CA; back up `ca.bundle` immediately.
3. **Session HMAC.** For multi-node deployments set
   `CULVERT_SESSION_SECRET` (64 hex characters, ≥32 bytes) on every node
   so admin sessions are valid cluster-wide.
4. **Cluster TLS.** When enabling Control Plane mode, supply
   `-cp-grpc-cert/-cp-grpc-key/-cp-grpc-ca` (Data Plane nodes use
   `-dp-cert/-dp-key/-dp-ca`). Do **not** keep `--cluster-insecure` past
   development.
5. **Day-2 updates.** The legacy Docker self-update sidecar has been
   removed; there is no updater allowlist to configure. Upgrades flow
   through Release Management (the signed release catalog) and the
   host maintenance agent — see §8 below. `--updater-url-allowlist` /
   `update.url_allowlist` are inert, parse-only holdovers that do
   nothing; do not rely on them.
6. **External auth callback URL.** Before enabling production OIDC or
   SAML profiles, set `proxy.base_url` to the externally reachable UI URL
   (for example `https://proxy.example.com` or
   `https://proxy.example.com/culvert`). For SAML, this exact value is the
   SP Entity ID / Audience, and the ACS URL is
   `proxy.base_url + /auth/saml/callback`. `trust_forwarded_headers` helps
   request-derived URLs, but it does not replace `proxy.base_url` for SAML
   SP metadata built at startup.
7. **First admin user.** Visit the UI, complete the setup wizard, and
   create the first admin account.
8. **Open the Diagnostics page** (Infrastructure → Diagnostics). Resolve
   any `fail` entries before exposing the proxy to clients. Decide
   consciously about each `warn`.
9. **SAML behind a load balancer.** If SAML IdPs are enabled in a clustered
   or load-balanced deployment, configure affinity for the browser SSO path,
   especially `/auth/saml/callback`. Culvert keeps SAML AuthnRequest state
   in memory for one-time replay protection, so the IdP response must return
   to the node that initiated the login.
10. **Data Plane CP outage behavior.** After the first successful CP poll,
    each DP writes `/data/dp_last_config_snapshot.json`. If the CP is later
    unreachable, the DP can restart and serve that last-known-good local
    policy/auth snapshot. Diagnostics reports this as
    `dp_last_known_good_config`: `warn` means the DP is serving cached config
    while CP polling is failing; `fail` means CP polling is failing and no
    local snapshot is available.

---

## 4. Backup and restore for `/data`

Culvert keeps **all** persistent state under the data directory. The
supported backup and restore path is the built-in `--backup` /
`--restore` CLI driven through the profile-gated `cli` service in
`docker-compose.yml`. See
**[`docs/operator/docker-compose-backup-restore.md`](operator/docker-compose-backup-restore.md)**
for the full operator surface: encrypted backup, restore dry-run,
restore commit (offline), leftover cleanup, passphrase handling, and
the runtime-vs-offline matrix.

### Manual `tar -C /data -czf …` is unsupported

Filesystem-level `tar` of `/data` is **not** a supported backup
mechanism and the resulting archives **cannot be restored** by Culvert.
Manual `tar` bypasses the Culvert backup format's guarantees:

- No `manifest.json` (sha256, size, mode, tier per artifact).
- No `schema_version` envelope; the restore validator only accepts
  archives produced by `--backup`.
- No checksum verification before swapping `/data`.
- No CA-bundle cross-validation (cluster CA fingerprint vs.
  `cluster.json` enrolled-DP set).
- No Tier-3 exclusion — manual `tar` includes logs, hashcache, hit
  counters, and other operational state that should not survive a
  restore.
- No atomic rename swap; no `/data.bak.<ts>-<pid>` rollback dir.
- No restore dry-run, no DP re-enrollment guard, no TOTP counter
  rollback guard.
- No `--encrypt` integration — operator has to bring their own
  encryption.

Use the `cli` service for everything backup-related. The operator doc
linked above is the only supported reference.

### What's inside `/data`

* `ca.bundle` — encrypted root CA (passphrase required to use)
* `policy.json[.meta]` — policy ruleset and version
* `blocklist.json`, `urlcat.json`, `cdr_policies.json` — content controls
* `cluster.json`, `cluster_ca.crt/key` — cluster identity
* `config_versions/v{N}.json` — automatic config snapshots (50 kept)
* `ui_users.json` — admin accounts (bcrypt hashes)
* `audit.json`, `requests.log` — audit and request logs

The config-version snapshots under `config_versions/` are an in-place
rollback mechanism — separate from your full backup, but useful for
quick "undo" of an admin change.

### Recovering from a `storage_path = fail` on Diagnostics

The `storage_path` row goes red when the startup writability probe
could not create + delete a tiny temp file under the configured data
directory. Common causes and fixes:

1. **Volume not mounted.** In Docker / Kubernetes, confirm the volume
   is bound to `/data` (or your `--data-dir`). `docker inspect` or
   `kubectl describe pod` will show the mount source. Re-create the
   container with the volume attached.
2. **Wrong owner or mode.** The proxy process must own (or be able to
   write to) the data directory. Fix with
   `chown -R <proxy-uid>:<proxy-gid> /data && chmod 0750 /data`. In
   containers, the proxy runs as a non-root UID by default; the host
   directory must permit that UID to write.
3. **Read-only mount.** Some platforms mount volumes read-only by
   default (e.g. some serverless filesystems). Re-mount read-write or
   use a different volume type.
4. **Disk full / quota exceeded.** Check `df -h` on the host. The
   probe writes only a couple of bytes, but a full filesystem still
   refuses the create.
5. **SELinux / AppArmor denial.** Inspect `auditd` or `dmesg` for
   denials referencing the proxy binary; relabel the directory or
   adjust the policy as required.

After fixing, **restart the proxy**. The probe is one-shot at startup,
so the diagnostics row will not flip back to `ok` until the next
process start.

### Config versions vs `/data` backup vs export/import

Culvert has **three** distinct mechanisms that touch persistent
configuration. They solve different problems and the diagnostics page
covers each at the right granularity.

| Mechanism                | What it captures                                  | Where it lives                                | Use it when…                              |
|--------------------------|---------------------------------------------------|-----------------------------------------------|-------------------------------------------|
| **Config versions**      | Automatic numbered snapshots of mutable config (policy, blocklist, file-block, IP filter, rate limit, PAC, etc.) | `/data/config_versions/v{N}.json` (last 50)   | Undoing a single admin change in the GUI  |
| **Config export / import** | A point-in-time JSON bundle the operator triggers manually (`/api/config/export`, `/api/config/import`) | Wherever the operator saves it                | Migrating config between environments     |
| **Full `/data` backup**  | Everything — config versions, CA bundle, audit log, request log, cluster state, ui_users, etc. | Whatever your snapshot/tar tool produces       | Disaster recovery, migrations, machine moves |

A `/data` backup includes the `config_versions` directory, so a full
restore brings the version history back along with everything else.
Config export / import does **not** include the version history — only
the current effective config — so importing into a fresh node leaves
`config_versions` empty until the next admin change seeds a new v1.

The Diagnostics page surfaces three separate health signals for this
subsystem:

* **`config_versions_present`** — `ok` once at least one numbered
  version exists; `warn` on a fresh install or after a config-only
  restore that did not include the version directory. The remedy is
  benign: any admin-side config change seeds `v1.json` automatically.
* **`config_versions_readable`** — `ok` when the **latest** version
  file (selected strictly by numeric `v{N}`, not by file modified
  time) reads cleanly and conforms to the `{meta, config}` envelope
  Culvert writes. `fail` when the file is corrupt JSON or has a
  malformed envelope.
* **`config_rollback_validation`** — `ok` when the latest version
  passes `validateConfigBackup` pre-flight; `warn` when the validator
  flags issues (e.g. an invalid mode string in the snapshot) — the
  diagnostics row reports only the warning **count**, not the raw
  values, to avoid leaking config contents through the viewer-role
  endpoint; `fail` only when the file failed to parse.

### Recovering from corrupt or missing config versions

1. **Latest version is corrupt (`config_versions_readable = fail`).**
   The most recent admin action probably wrote a partial file (disk
   full at the time, or the proxy was killed mid-write). Earlier
   versions remain intact:
   * From the admin UI, **Settings → Config Versions** lists every
     version that parses, descending. Roll back to the highest one
     that succeeds.
   * If you prefer to delete the corrupt file by hand, remove the
     single bad `v{N}.json` from the host filesystem; the next admin
     change will write a fresh `v{N+1}.json`.
2. **Latest version has a malformed envelope.** Same remedy as
   corrupt — the file does not match Culvert's `{meta, config}`
   shape. Likely cause: the file was edited by hand or copied from
   an older release.
3. **Whole directory is missing or empty
   (`config_versions_present = warn`).** Either Culvert has not yet
   completed a config mutation since startup (benign — make any
   change and a `v1` will be created), or the directory was
   excluded from a `/data` restore. If you have a `/data` backup,
   restore the `config_versions` subtree alongside the rest of
   `/data`.
4. **Validation warnings (`config_rollback_validation = warn`).**
   The cached file parses, but rolling back to it would silently
   drop invalid rules or modes. Use the existing dry-run path to
   inspect specifics:

   ```
   POST /api/config/versions
   { "version": <N>, "dry_run": true }
   ```

   The response includes the verbatim `warnings` array and a `changes`
   diff so you can choose between rolling back to an earlier version
   or accepting the warnings.

The diagnostics handler is **read-only** with respect to
`/data/config_versions` — it never writes, deletes, or rewrites
version files. Cleaning up bad entries is always an explicit operator
action.

---

## 5. Upgrade checklist

For routine releases:

1. **Read release notes.** Look for breaking config or schema changes.
2. **Back up `/data`** (see §4).
3. **Take a config snapshot.** From the admin UI, Settings → Config
   Versions → "Save Snapshot" creates a labelled version you can roll
   back to without leaving Culvert.
4. **Update the binary or container.** Use the rolling-update orchestrator
   (Cluster → Updates → Cluster Rolling Update) for HA; for standalone,
   replace and restart.
5. **Watch `/ready`.** Each upgraded node should return `200` within
   the configured `start_period`. Do not advance the rollout if any
   node stays `503`.
6. **Open Diagnostics.** Confirm the verdict is at least `warn`-with-
   known-warnings; investigate any new `fail`.
7. **Roll back path:** revert the binary; if state is incompatible,
   restore `/data` from §4. The previous release is still installed in
   the rollback slot for one cycle.

---

## 6. CDR (Sluice) recovery

The `cdr` check on the Diagnostics page surfaces three states beyond
`disabled`:

* **`enabled-healthy`** — pool is connected, fail-mode and default
  profile are set.
* **`enabled-degraded`** — pool is connected but fail-mode or default
  profile is missing. Set them under CDR → Configuration; otherwise
  CDR cannot make safe decisions on unmatched files.
* **`enabled-broken`** — CDR is enabled but no Sluice instance is
  connected. Either enrol an instance under CDR → Instances or disable
  CDR until you can.

If Sluice is enrolled but reporting unhealthy:

1. Verify the Sluice container is running and reachable from the proxy
   network.
2. Confirm the server fingerprint pinned in CDR config matches the
   Sluice instance certificate.
3. Check the proxy logs for `CDR:` lines — connection errors are logged
   verbatim (with sanitisation) to help diagnose TLS / DNS issues.
4. As a temporary measure, set CDR fail-mode to `fail-open` to keep
   traffic flowing while you fix the engine; remember to revert once
   resolved.

---

## 7. Cluster `cluster-insecure` warning

When a Control Plane is started with `--cluster-insecure`, the
Diagnostics page surfaces a permanent `warn` on `cluster_posture`. This
is intentional: the gRPC channel between Control Plane and Data Plane is
**not** encrypted in this mode, so policy updates and node tokens are
visible to anyone on the cluster network.

To harden:

1. Provision a cluster CA (Cluster → Cluster CA → Import, or let
   Culvert auto-generate).
2. Issue or supply server cert + key for the CP and each DP.
3. Restart with `-cp-grpc-cert / -cp-grpc-key / -cp-grpc-ca` on the
   Control Plane and `-dp-cert / -dp-key / -dp-ca` on each Data Plane,
   **without** `--cluster-insecure`.
4. Diagnostics should switch the `cluster_posture` row to `ok` with the
   message "cluster running with mTLS".

---

## 8. Day-2 updates

The legacy Docker self-update sidecar has been removed. Day-2 upgrades
now flow through **Release Management** (the signed release catalog) and
the **maintenance agent** on the host: the Control Plane dispatches an
upgrade to the agent's `/v1/upgrades/apply`, which pulls a repo-bound
pinned digest, retags it to `culvert/proxy:pinned`, and restarts via the
compose file. See `docs/operator/release-management-agent.md` and
`docs/operator/enterprise-release-catalog-plan.md`.

> The old `update.url_allowlist` / `-updater-url*` knobs are retained only
> as inert, parse-only settings so a legacy config file or launch command
> still starts; they no longer do anything.

---

## 9. Quick reference

| Task                         | Where                                                         |
|------------------------------|---------------------------------------------------------------|
| Liveness / readiness probes  | `:8080/health`, `:8080/ready`                                  |
| Operator contract (GUI)      | Admin UI → Infrastructure → Diagnostics                       |
| Operator contract (API)      | `GET :9090/api/diagnostics` (viewer role)                      |
| Backup                       | snapshot `/data`                                              |
| Config rollback              | Admin UI → Settings → Config Versions                         |
| Config-version health        | Diagnostics rows `config_versions_present` / `_readable` / `config_rollback_validation` |
| Cluster rolling update       | Admin UI → Updates → Cluster Rolling Update                   |
| Audit log                    | Admin UI → Audit Log, or `audit.json` in `/data`              |
