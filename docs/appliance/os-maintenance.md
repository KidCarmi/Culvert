# Culvert appliance — OS and platform maintenance

The appliance has **three separately maintained layers**. Each has its own
mechanism, owner, cadence and evidence. A replacement OVA is **not** a patch
strategy for installed customers (see the last section).

| Layer | What | Mechanism | Cadence |
|-------|------|-----------|---------|
| **A. Guest OS packages + kernel** (Ubuntu 24.04) | glibc, OpenSSL, OpenSSH, systemd, cloud-init, kernel, … | `unattended-upgrades`, security pocket only, no auto-reboot; operator tool `culvert-os-update` | daily automatic (security); reboot in a maintenance window |
| **B. Docker engine + Compose plugin** | `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-compose-plugin` (held at the appliance pin) | `culvert-os-update docker` (stops the stack gracefully, upgrades, restarts) | operator-driven; monthly review, sooner for engine CVEs |
| **C. Culvert image** (Alpine base + Go app + `culvert-maint`) and the ClamAV sidecar | application code, Go modules, Alpine packages | **Release Management**: signed catalog + maintenance agent (`docs/operator/release-management-agent.md`); ClamAV via the compose image tag | per Culvert release; ClamAV engine with Culvert releases, signatures daily by freshclam |

## A. Guest OS packages and kernel

**Automatic (daily):** `unattended-upgrades` with
[`50unattended-upgrades-culvert`](../../appliance/os-maintenance/50unattended-upgrades-culvert):
`Allowed-Origins` = `noble-security` (+ Ubuntu Pro ESM security origins when
attached), `Package-Blacklist` = the four Docker packages,
`Automatic-Reboot "false"`, unused kernels removed. `apt-daily.timer` /
`apt-daily-upgrade.timer` (Ubuntu defaults) drive it; the log is
`/var/log/unattended-upgrades/unattended-upgrades.log`. Nothing from
`-updates`/`-backports` is installed automatically.

**Operator tool** (`sudo culvert-os-update …`, local console or SSH, sudo-gated;
there is deliberately **no remote command channel** — the maintenance agent's
API is limited to its typed, sudoers-allowlisted operations and never runs
arbitrary commands):

| Command | Effect |
|---------|--------|
| `check` | `apt update`; lists pending security updates (dry run), all upgradable packages, held Docker packages, last unattended run; says whether a **reboot is required** (`/var/run/reboot-required`) |
| `security` | run the same security-only policy now |
| `os` | all guest-OS package updates incl. a new kernel ABI (`apt-get upgrade --with-new-pkgs`; Docker stays held) |
| `reboot` | `docker compose stop` in `/srv/culvert` (each service's `stop_grace_period` applies — the proxy's is 60 s so its shutdown sequence completes and durable state is flushed; `docs/operator/graceful-shutdown.md`) then `systemctl reboot` |
| any + `--reboot-if-required` | reboot at the end only when the kernel/libc update needs it |

A kernel or glibc update is live only after a reboot; `culvert-status` is not
affected, so `check` is the signal. Run `check` weekly, reboot in the window.

**Kernel updates.** An Ubuntu kernel ABI bump ships as a NEW package
(`linux-image-<abi>-generic`) pulled in by `linux-virtual`. A plain
`apt-get upgrade` keeps that back, so the kernel would never move. Reproduced
against the Ubuntu snapshot archive, 6.8.0-142 → 6.8.0-146
([evidence](evidence/kernel-update-reproduction.txt)). `os` therefore runs
`upgrade --with-new-pkgs`, which:
* installs the new kernel **beside** the running one (both `ii`),
* still honours every `apt-mark hold` (Docker stays pinned; never `dist-upgrade`),
* removes nothing, and the following `autoremove` keeps the running kernel, so
  the previous kernel stays in the GRUB menu as the fallback boot entry.

`security` (and the daily `unattended-upgrades` run) move the kernel only when
the bump is published to `-security`. At the reproduction snapshot 6.8.0-146 was
in `-updates` only, and the security path correctly left it alone. **The kernel
actually running after the reboot is not observable in a container.** It is
recorded on real hardware by step 7 of
[`vsphere-qualification.md`](vsphere-qualification.md) (`uname -r` before and after).

**Maintenance-window procedure (host reboot):**
1. Announce; proxy clients lose the gateway for the reboot duration (~1–2 min).
2. `sudo culvert-os-update check` → if REBOOT REQUIRED: `sudo culvert-os-update reboot`.
3. After boot: `sudo culvert-status` must show the previous state; `/ready` 200.

**Emergency patch (e.g. an actively exploited OpenSSH/glibc CVE):**
`sudo culvert-os-update security --reboot-if-required` as soon as Ubuntu
publishes the fix (`ubuntu-security-notices`), outside the window if the
severity warrants; the stack stop is graceful either way.

## B. Docker engine and Compose plugin

Pinned at build time (`manifest.env`) and `apt-mark hold` so an incidental
`apt upgrade` cannot restart the engine under the stack. `live-restore` is on
in `/etc/docker/daemon.json`, but an engine upgrade still restarts containerd,
so the tool stops the stack first:

```
sudo culvert-os-update docker      # candidate versions → compose stop → unhold → upgrade → hold → restart docker → compose up
```

Cadence: review monthly against Docker's release notes; apply within the
window; immediately for an engine/runc/containerd CVE with a published
exploit. The new engine version is recorded in `/var/log/culvert-os-update.log`.

## C. Container base image and application dependencies

Owned by the Culvert release process, not by appliance maintenance:
the signed release catalog decides the digest, the in-appliance Release
Management panel dispatches it to the host maintenance agent, which pulls the
repo-bound digest and retags `culvert/proxy:pinned` at the sudo boundary
(`docs/operator/release-management-agent.md`, `docs/operator/catalog-bootstrap-install-runbook.md`).
Alpine package CVEs in the image are fixed by a new Culvert release (the image
is rebuilt per release); the SBOM/CVE evidence for the pinned image is in
[`sbom-cve-evidence.md`](sbom-cve-evidence.md). The ClamAV sidecar's **engine**
follows the compose file's `clamav/clamav:1.4` tag (updated with Culvert
releases); its **signatures** are refreshed by freshclam inside the container.

## Ownership and cadence summary

| | Owner | Cadence | Evidence |
|---|---|---|---|
| A. OS security | customer platform team (automatic), reboot by operator | daily auto; reboot ≤ 30 days after a kernel/glibc update, ≤ 7 days for critical | `unattended-upgrades.log`, `culvert-os-update check` |
| B. Docker | customer platform team | monthly review; CVE-driven | `/var/log/culvert-os-update.log` |
| C. Culvert image | Culvert release owner publishes; customer applies via Release Management | per release (catalog `recommended`), critical channel for emergencies | catalog decision on `/api/releases`, agent audit log |
| ClamAV signatures | automatic (freshclam) | daily | `docker compose logs clamav` |

## New OVA releases vs already-installed appliances

A new OVA ships a newer base-image serial, newer pinned Docker packages and a
newer pinned Culvert image **for new deployments**. For an installed
appliance, re-importing the OVA would discard its state (CA, policy, admin
roster, logs) — so the OVA is **not** the patch path for existing customers.
Installed appliances are kept current through A + B + C above and reach the
same package state as a fresh OVA through `unattended-upgrades` +
`culvert-os-update docker` + Release Management. Both paths must therefore be
exercised when a new OVA is cut:

* **New OVA:** bump `manifest.env` pins, rebuild, re-run the SBOM/CVE
  evidence, publish `build-info.json` with the OVA.
* **Installed appliances:** publish the matching Culvert release to the
  catalog; note any required Docker engine version in the release notes so
  operators run `culvert-os-update docker`; guest-OS updates flow
  automatically.

## What this track does not do

* No in-place guest-OS **release upgrade** (24.04 → 26.04); that is a new OVA
  + migration (backup/restore, `docs/operator/docker-compose-backup-restore.md`).
* No automatic reboot, by design — the gateway is in the data path.
* No central patch orchestration; the hooks are local scripts and systemd
  timers. A fleet tool may invoke `culvert-os-update` over SSH with the
  operator's key; the appliance exposes nothing else.
