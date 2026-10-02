# Culvert appliance — OS maintenance runbook

Scope: the **guest OS** and the **host-level components** of the Culvert appliance VM. Application
upgrade/rollback, backup/restore and application readiness are the application's runbooks
(`docs/operator/release-management-agent.md`, `docs/operator/docker-compose-backup-restore.md`); this
document only says when those run relative to OS work.

## 1. The three layers, and who patches what

| Layer | What it is | Source of updates | Mechanism on an installed appliance | Cadence / owner |
|---|---|---|---|---|
| **1. Guest OS packages + kernel** | Ubuntu 24.04 LTS userland (`dpkg-list.tsv` in `/etc/culvert-appliance/`), `linux-image-virtual` 6.8 GA, open-vm-tools, cloud-init, netplan, nftables, openssh | `security.ubuntu.com` / `archive.ubuntu.com` (noble, noble-updates, noble-security) | **unattended-upgrades**, security pocket only, daily (`20auto-upgrades`), `Automatic-Reboot=false` by default; everything else via `apt` in a window | Security: automatic, daily. Non-security + kernel reboots: operator, monthly window. Owner: platform/infra team of the customer; Culvert ships the policy. |
| **2. Docker Engine + Compose** | `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-compose-plugin` (pinned versions in `/etc/culvert-appliance/manifest.env`) | `download.docker.com/linux/ubuntu noble stable` (repo + key installed at bake) | **Operator-driven `apt` in a window.** Excluded from unattended-upgrades twice: Docker's repo is not an allowed origin AND the packages are blacklisted (`52culvert-appliance-unattended`). `live-restore=true` keeps containers running across a daemon restart; `needrestart` never auto-restarts docker/containerd. | Monthly window or on a Docker security advisory. Owner: appliance operator. Culvert re-pins at each OVA release. |
| **3. Container base image + app dependencies** | `ghcr.io/kidcarmi/culvert@sha256:…` (Alpine base, Go binary, bundled agent) and `clamav/clamav:1.4` | Signed release catalog (`catalog.culvertlabs.com`), verified in-binary; ClamAV via Docker Hub tag + its own signature DB via freshclam | **Release Management → maintenance agent** (`/v1/upgrades/apply`, image by digest, retag `culvert/proxy:pinned`, rollback by digest). ClamAV signatures: freshclam inside the container, continuous. ClamAV **image** updates: with the appliance release (compose tag), see §6. | Per catalog release; owner: Culvert releases + appliance operator approves. NOT this runbook's mechanism. |

Host components that belong to layer 3's *delivery* but live on the host (compose files, `culvert-maint`
binary, `config.toml`, systemd unit, sudoers) are covered in §6.

## 2. Standing policy shipped in the OVA

* `/etc/apt/apt.conf.d/20auto-upgrades`: update lists + unattended-upgrade daily.
* `/etc/apt/apt.conf.d/52culvert-appliance-unattended`: Ubuntu default origins (security + ESM-infra/apps,
  the latter inert without Pro), `Automatic-Reboot "false"`, `MinimalSteps`, remove unused deps, docker
  packages blacklisted.
* `/etc/needrestart/conf.d/culvert-appliance.conf`: restart ordinary services automatically after a
  library update; **never** `docker`, `containerd`, `culvert-maint`.
* `culvert-appliance auto-reboot on [--time HH:MM]` writes `53culvert-appliance-reboot` to allow
  unattended reboots when a kernel/libc update requires one (opt-in, off by default). `off` removes it.
* No general privileged remote command channel exists: management is SSH (key-only, `culvert` user,
  optionally restricted to a CIDR allowlist with `culvert-appliance mgmt-allow`) and the hypervisor console.
  The maintenance agent's socket is local to the host and bounded by its sudoers allowlist.

## 3. Emergency patch (CVE with an exploit in the wild)

1. Decide which layer is affected (USN → layer 1; Docker/containerd/runc advisory → layer 2; Culvert or
   its Go dependencies / Alpine base → layer 3, follow the application's release process).
2. Layer 1: `sudo unattended-upgrade -v` applies the security pocket immediately (same job the timer runs);
   check `needrestart -r l` and `/var/run/reboot-required`. If a reboot is required, treat it as a planned
   reboot (§5) in the shortest acceptable window — the proxy is a data-path device, a reboot is an outage
   of a few minutes for that node.
3. Layer 2: `sudo apt-get update && sudo apt-get install --only-upgrade docker-ce docker-ce-cli containerd.io docker-compose-plugin`;
   the daemon restarts, containers keep running (`live-restore`); verify §5.3.
4. Record the action and the versions (`dpkg -l docker-ce containerd.io linux-image-virtual`).

## 4. Routine maintenance window (recommended monthly)

```bash
sudo culvert-appliance status                 # baseline: /ready status, setup complete, addresses
sudo apt-get update
apt list --upgradable                          # review; docker-* appear here only if layer 2 is due
sudo apt-get -y dist-upgrade                   # layer 1 (+ layer 2 if you accept the docker packages)
sudo needrestart -r l                          # what still runs old libraries
[ -f /var/run/reboot-required ] && echo REBOOT NEEDED
```
Then §5 if a reboot is required, else §5.3 verification only.

## 5. Service restart and reboot procedure

5.1 Before: tell users (the proxy is unavailable for ~2–5 min on this node); if the application has a
    backup step in its runbook, run it (application's domain).

5.2 Reboot: `sudo systemctl reboot`. The compose stack is `restart: unless-stopped`, so docker brings
    `culvert-clamav` and `culvert` back automatically; the maintenance agent is a `WantedBy=multi-user`
    unit; `culvert-appliance-mgmt.service` reloads the management allowlist before the network comes up;
    the console timer re-renders `/etc/issue`.

5.3 Verify (all must hold before closing the window):

```bash
sudo culvert-appliance status                                   # addresses, /ready, setup state
curl -s http://127.0.0.1:8080/health ; curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8080/ready?strict=1'
sudo docker compose -f /srv/culvert/docker-compose.yml ps        # proxy + clamav Up (healthy)
sudo docker volume inspect culvert_proxy-data --format '{{.Mountpoint}}'   # /data volume still there
sudo ls /var/lib/docker/volumes/culvert_proxy-data/_data | head   # ca.bundle, ui_users.json, policy.json …
systemctl is-active culvert-maint docker containerd ssh
curl -s -o /dev/null -w '%{http_code}\n' -k https://127.0.0.1:9090/api/setup/status    # 200
# enforcement smoke through the proxy (adapt hosts to the configured policy):
curl -s -o /dev/null -w 'allowed:%{http_code}\n' -x http://127.0.0.1:8080 http://example.com/
curl -s -o /dev/null -w 'blocked:%{http_code}\n' -x http://127.0.0.1:8080 http://<a-host-your-policy-blocks>/
sudo journalctl -b -p warning --no-pager | tail -n 30            # no new host-level errors
```

5.4 Recovery if the stack does not come back: `sudo culvert-appliance logs`, `sudo journalctl -u docker`,
    `sudo docker compose -f /srv/culvert/docker-compose.yml logs --tail 100`. A guest that does not boot:
    use the hypervisor console, boot the previous kernel from GRUB (`Advanced options`), then
    `apt-get install --reinstall` the failing kernel. `/data` is a docker named volume on the root disk —
    it survives any of the above; only a disk replacement loses it (restore from the application backup).

## 6. Host components of the application (compose files, agent, config, unit, sudoers)

Replacing the proxy image does **not** update these. They are installed by `scripts/install.sh` from the
image's `/app/deploy` bundle at first boot, and are updated **the same way**: re-run the vendored installer
after an application upgrade.

```bash
# After Release Management has moved culvert/proxy:pinned to a new digest (agent /v1/upgrades/apply):
sudo CULVERT_INSTALL_OFFLINE=1 CULVERT_PROXY_SEED_REF="$(sudo docker image inspect culvert/proxy:pinned --format '{{index .RepoDigests 0}}')" \
     CULVERT_DIR=/srv/culvert CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1 bash /usr/local/lib/culvert-appliance/install.sh
```
What that does (all idempotent, in `scripts/install.sh`): keeps Docker as is; keeps the pinned tag;
re-extracts `/app/deploy` only if the compose/packaging files are missing — otherwise
`preflight_compose_image_compat` compares the compose `command:` flags with the running image's `-help`
and re-extracts on a mismatch; installs the agent binary **only if its `--version` differs** from the image's
`org.opencontainers.image.version` (fast path otherwise); re-renders sudoers from `packaging/`, reinstalls
the unit, keeps `config.toml`; re-wires the socket override and restarts `culvert-maint`.

Compatibility rule: the agent binary, sudoers template and compose files must come from the **same image
digest** that is running (they are built together in the Dockerfile `maintbuilder` stage). The socket
mount (`/run/culvert-maint`) survives container recreation because the agent runs with
`RuntimeDirectoryPreserve=yes` and the override file is in the agent's `compose_override_file`.

Proposed automation (for Fable, Go side — see ASTRA-STATUS.md): after a successful `/v1/upgrades/apply`
the agent could compare its own `server.Version` with the new image's version label and report
`agent_update_pending` in `/v1/status` and on the Release panel, so the operator is told to run the
command above. Self-replacing the running agent binary from inside the agent is deliberately NOT proposed.

## 7. ClamAV

Signatures: `freshclam` inside `culvert-clamav` updates continuously (needs egress to
`database.clamav.net`); the OVA ships the signatures bundled in the image (Sep 2026) so a freshly booted
appliance scans immediately. Image: `clamav/clamav:1.4` moves with Docker Hub; a new OVA release pins a
new digest. On an installed appliance the operator may `docker compose pull clamav && docker compose up -d clamav`
in a window (the proxy waits for clamav health only at start).

## 8. New OVA release vs. installed appliance

| Change | New OVA (rebuild via `appliance/build.sh`) | Already-installed appliance |
|---|---|---|
| Ubuntu security updates | included up to the guest image date | unattended-upgrades (automatic) |
| Kernel | pinned by the guest image release | `apt` + reboot in a window |
| Docker Engine | pinned in `manifest.env` | `apt` in a window (§3/§4) |
| Application image | pinned digest from the catalog | Release Management / agent, by digest |
| Host components (compose, agent, sudoers, unit) | from the pinned image's bundle | re-run the installer (§6) |
| cloud-init / first-boot scripts / CLI | from this repo at the build commit | **not updated in place** — carried only by a new OVA (or by a manual copy from the repo; documented, not automated) |

## 9. Qualification record

See `docs/appliance/hypervisor-qualification.md` §"OS update + reboot" for the executed procedure, the
exact commands and outcomes, and `ASTRA-STATUS.md` for anything BLOCKED/UNTESTED.
