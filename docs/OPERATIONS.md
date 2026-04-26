# Operations Guide

This guide is for operators running Culvert in production. It documents the
two distinct readiness surfaces, the operator-contract diagnostics page,
and the routine procedures (startup, backup, upgrade, recovery) that an
operator needs to know.

It is intentionally small and focused on day-2 reality, not feature
catalogues. For configuration knobs see the README; for architecture see
`roadmap/PHASES.md`.

---

## 1. Two readiness surfaces

Culvert exposes two endpoints for "is this node healthy". They have
**different audiences and contracts** — do not confuse them.

### `/health` and `/ready` — load balancer probes

* Served on the **proxy port** (default `:8080`), unauthenticated.
* `/health` is a **liveness** probe: the process is up, the request loop is
  scheduling, the CA cert (if loaded) has not expired in place.
* `/ready` is a **readiness** probe: critical scanning subsystems
  (ClamAV, GeoIP, YARA — when configured) are reachable. Returns `200`
  with `{"status":"ready", "checks":{...}}` when ready, `503` when not.
* These endpoints have a **stable JSON contract**. CI smoke tests
  (`.github/workflows/ci.yml`) and Kubernetes probes depend on them.

  → Treat `/ready` as an **external interface**. Do not change response
  shape, status codes, or check names without a major-version migration
  plan.

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
  row reports whether the data directory **path is configured** in the
  proxy. It does **not** verify that the directory exists, is mounted,
  or is writable — those would require disk I/O at request time, which
  this endpoint deliberately avoids. Routine `ls` / `df` / write-probe
  monitoring still belongs in your host-level checks.

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
   `CULVERT_CA_PASSPHRASE` and pass `-ca-bundle /data/ca.bundle`. The
   first start will generate the root CA; back up `ca.bundle` immediately.
3. **Session HMAC.** For multi-node deployments set
   `CULVERT_SESSION_SECRET` (64 hex characters, ≥32 bytes) on every node
   so admin sessions are valid cluster-wide.
4. **Cluster TLS.** When enabling Control Plane mode, supply
   `--cluster-grpc-cert/--cluster-grpc-key/--cluster-grpc-ca`. Do **not**
   keep `--cluster-insecure` past development.
5. **Updater allowlist.** If you point the updater at anything other
   than the in-cluster sidecar, list the URL in
   `--updater-url-allowlist` (or `update.url_allowlist` in YAML). The
   admin API alone cannot widen this list.
6. **First admin user.** Visit the UI, complete the setup wizard, and
   create the first admin account.
7. **Open the Diagnostics page** (Infrastructure → Diagnostics). Resolve
   any `fail` entries before exposing the proxy to clients. Decide
   consciously about each `warn`.

---

## 4. Backup and restore for `/data`

Culvert keeps **all** persistent state under the data directory. A
filesystem-level snapshot of `/data` is a complete backup.

**To back up:**

```bash
# Take an atomic snapshot. Stop the proxy or use a snapshotting filesystem
# (LVM, ZFS, btrfs) for crash-consistent state.
tar -C /data -czf culvert-backup-$(date +%F).tar.gz .
```

**To restore:**

```bash
systemctl stop culvert
rm -rf /data/*
tar -C /data -xzf culvert-backup-YYYY-MM-DD.tar.gz
systemctl start culvert
```

**What's inside `/data`:**

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
3. Restart with `--cluster-grpc-cert / --cluster-grpc-key /
   --cluster-grpc-ca` and **without** `--cluster-insecure`.
4. Diagnostics should switch the `cluster_posture` row to `ok` with the
   message "cluster running with mTLS".

---

## 8. Updater allowlist

The proxy's self-update flow refuses to talk to arbitrary URLs. The
allowlist is *startup-only* by design — a config write through the
admin API cannot redirect the updater to an attacker-controlled host.

* If `updater_url` matches the in-cluster default
  (`http://culvert-updater:7123`) or is a loopback address, no
  allowlist entry is needed.
* For any other URL, add it to `--updater-url-allowlist` (CLI) **or**
  `update.url_allowlist` (YAML), and restart.
* The Diagnostics check `updater_url` will show `fail` with a pointer
  to this knob if the configured URL is not in the allowlist.

---

## 9. Quick reference

| Task                         | Where                                                         |
|------------------------------|---------------------------------------------------------------|
| Liveness / readiness probes  | `:8080/health`, `:8080/ready`                                  |
| Operator contract (GUI)      | Admin UI → Infrastructure → Diagnostics                       |
| Operator contract (API)      | `GET :9090/api/diagnostics` (viewer role)                      |
| Backup                       | snapshot `/data`                                              |
| Config rollback              | Admin UI → Settings → Config Versions                         |
| Cluster rolling update       | Admin UI → Updates → Cluster Rolling Update                   |
| Audit log                    | Admin UI → Audit Log, or `audit.json` in `/data`              |
