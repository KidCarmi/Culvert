# Culvert appliance — installation runbook (operator journey)

Audience: the operator deploying the OVA. Primary hypervisor: **VMware vSphere/ESXi** (the OVF is written
for it); also usable on **QEMU/KVM** (qcow2 shipped next to the OVA). What was actually tested on what is in
`hypervisor-qualification.md` — read its "what is untested" list before relying on a path.

Artifacts: `culvert-appliance-<ver>.ova`, `culvert-appliance-<ver>.sha256`,
`culvert-appliance-<ver>.build-record.json` (every input digest), `…/culvert-appliance-<ver>.qcow2` (KVM).

## 0. Before you start

| Item | Requirement |
|---|---|
| Verify the download | `sha256sum -c culvert-appliance-<ver>.sha256` (OVA, OVF, VMDK, manifest, qcow2 all listed). The OVF manifest inside the OVA carries SHA256 of the descriptor and the disk; vSphere checks it at import. |
| Resources | 2 vCPU, 4 GiB RAM, 40 GiB thin disk (OVF defaults; raise CPU/RAM for inspection-heavy sites). |
| Network | One NIC ("VM Network"). Clients reach **8080** (proxy) and administrators reach **9090** (admin UI, HTTPS) and **22** (SSH, key-only). DHCP by default; static via console CLI (§3) or cloud-init. |
| Egress the appliance needs | None for first boot (image + ClamAV signatures are preloaded). Afterwards: `catalog.culvertlabs.com` (release catalog), `ghcr.io` (image updates), `database.clamav.net` (signatures), `security.ubuntu.com`/`archive.ubuntu.com` + `download.docker.com` (OS/engine updates), threat-feed origins per the application docs. |
| Time | NTP reachable (open-vm-tools syncs with the ESXi host clock, `tools.syncTimeWithHost=true`; systemd-timesyncd otherwise). A badly wrong clock breaks signature verification of catalog updates. |
| Who gets the first admin | **Trust-on-first-use**: the first person to open `https://<ip>:9090` creates the admin. Do first boot on a management network, or set the management allowlist (§4) from the console before exposing the VM. |

## 1. Import

### 1a. vSphere / ESXi (primary; import UNTESTED in this slice — see qualification doc)

1. vSphere Client → Hosts and Clusters → right-click host/cluster → **Deploy OVF Template** → local file → the `.ova`.
2. Name/folder, compute resource, review details (publisher is unsigned — the trust anchor is the sha256 you verified).
3. Storage: **Thin Provision** recommended.
4. Networks: map "VM Network" to the management/proxy port group.
5. **Customize template** (vApp properties — read by cloud-init at first boot):
   * `hostname` — the appliance hostname.
   * `public-keys` — your SSH public key(s) for user `culvert` (SSH is key-only; leave empty for console-only).
   * `password` — optional initial console password (expires at first login). Leave empty to let the appliance mint a one-time password and show it on the VM console.
   * `user-data` — optional base64 cloud-config (e.g. static network before first boot, §3c).
   * `instance-id` — leave `id-ovf` unless you clone later (§6).
6. Finish, then **Power On**. Open the **VM console** (Web Console) — the whole first boot is reported there.

### 1b. QEMU/KVM (tested under QEMU TCG; see qualification doc)

```bash
qemu-img create -f qcow2 -F qcow2 -b culvert-appliance-<ver>.qcow2 culvert.qcow2    # or copy the qcow2
# optional cloud-init seed (hostname / ssh key / static network):
cloud-localds seed.iso user-data meta-data
qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 2 -m 4096 \
  -drive file=culvert.qcow2,if=virtio -drive file=seed.iso,if=virtio,format=raw,readonly=on \
  -netdev bridge,id=n0,br=br0 -device virtio-net-pci,netdev=n0 -nographic
```
(virt-manager/libvirt: import the qcow2 as a VirtIO disk, VirtIO NIC, 2 vCPU / 4 GiB; attach the seed ISO as a CD-ROM.)

## 2. First boot — what you will see on the console

The console (tty1 banner, refreshed every 15 s) shows:

```
 Culvert Appliance 1.0.259-ova.1   host: culvert   2026-10-02T…Z
 Addresses : ens192=10.0.0.42
 Admin UI  : https://10.0.0.42:9090      Proxy: http://10.0.0.42:8080
 First boot: installing application stack (scripts/install.sh)   → later: provisioned
 Readiness : ready  app v1.0.259   (HTTP 200; /ready?strict=1 → 503)
   admin_ui: ok   ca: ok   policy_loaded: fail (no rules)   session_secret: ok   …
 Setup     : NOT DONE — open https://10.0.0.42:9090 to create the first admin (do this from a trusted network)
 Console   : user 'culvert'  one-time password: XXXXXXXXXXXXXXXX   (you must change it at first login)
 Network   : DHCP — change: sudo culvert-appliance netconfig --help
```

Sequence (all automatic, logged to `/var/log/culvert-appliance/firstboot.log`): new SSH host keys and
machine-id are generated (the OVA ships none) → cloud-init applies hostname/keys/password/network →
`culvert-appliance-firstboot.service` verifies the preloaded images against the build record → mints the
one-time console password if no password was supplied → runs the standard `scripts/install.sh` offline
(seeds `culvert/proxy:pinned` from the preloaded digest, extracts the deploy bundle, generates the data
encryption passphrases into `/srv/culvert/.env`, starts the compose stack, installs + wires the maintenance
agent) → writes `/var/lib/culvert-appliance/provisioned`.

`First boot: provisioned` + `Readiness: ready` is the "application is up" state. The readiness rows come
verbatim from the application's `/ready`; `policy_loaded: fail (no rules)` is expected until you configure
policy, and `/ready?strict=1` answers 503 until every row is `ok`.

If the banner shows `ERROR`: `sudo culvert-appliance logs`, fix the cause (disk full, no docker, …), then
`sudo culvert-appliance firstboot-retry` — every step is idempotent and resumes.

## 3. Networking

3a. **DHCP** (default): read the address off the console.

3b. **Static, from the console** (works on every hypervisor; no SSH needed): log in on the VM console as
`culvert` with the one-time password (you are forced to change it), then

```bash
sudo culvert-appliance netconfig --static 10.0.0.42/24 --gateway 10.0.0.1 --dns 10.0.0.2,10.0.0.3 --search corp.example
sudo culvert-appliance netconfig --dhcp            # revert
```
This writes `/etc/netplan/60-culvert-appliance.yaml`, disables cloud-init's network rendering, validates with
`netplan generate` (nothing is applied if invalid) and applies. The console banner updates within 15 s.

3c. **Static before first boot** (vApp `user-data`, base64 of a cloud-config):
```yaml
#cloud-config
write_files:
  - path: /etc/netplan/60-culvert-appliance.yaml
    permissions: "0600"
    content: |
      network: {version: 2, ethernets: {ens192: {dhcp4: false, addresses: [10.0.0.42/24], routes: [{to: default, via: 10.0.0.1}], nameservers: {addresses: [10.0.0.2]}}}}
runcmd: [ [netplan, apply] ]
```
(Interface name on ESXi with vmxnet3 is usually `ens192`; verify with `ip link` if in doubt.) On vSphere the
DataSourceVMware `guestinfo.metadata` path also works with cloud-init ≥ 23 and open-vm-tools (UNTESTED here).

## 4. Restricting management access (recommended before exposing the VM)

```bash
sudo culvert-appliance mgmt-allow 10.0.0.0/24 192.0.2.10         # ssh (22) + admin UI (9090) only from these
sudo culvert-appliance mgmt-allow --clear
```
Implemented as an nftables table (`inet culvert_mgmt`, loaded by `culvert-appliance-mgmt.service` before the
network comes up) that drops NEW connections to 22 (host) and to the DNAT'd 9090 (container) from any other
source; the proxy port 8080 is not restricted. This is the host-level mitigation for the application's
trust-on-first-use setup.

## 5. First admin, TLS, policy

1. Open `https://<ip>:9090`, accept the self-signed certificate (**or** install your own first: Settings →
   Network → UI TLS cert/key, application docs), and complete the setup wizard — it `POST`s
   `/api/setup/complete` with a username (1–64 chars) and a password (≥ 8, upper + lower + digit); the
   account is written to the `/data` volume (`ui_users.json`) and you are logged in as admin. There is no
   default password and no setup token.
2. Immediately: create a second admin, enable TOTP, note that `/srv/culvert/.env` (root-only) holds the
   generated `CULVERT_CA_PASSPHRASE` / `CULVERT_LOG_PASSPHRASE` — back it up with the application backup; a
   restore to a new appliance needs it.
3. Inspection CA trust for clients, policy rules, upstream, identity providers: application docs
   (`docs/enterprise/FIRST-BOOT-AND-INITIAL-SETUP.md`, admin UI panels). `policy_loaded` turns `ok` once a rule exists.
4. Release Management panel: the maintenance agent is installed and wired at first boot; `available:false`
   is normal until the appliance can reach `catalog.culvertlabs.com`.

Host-level TLS: the admin UI's certificate is the application's (replace it in the UI). The appliance adds
no TLS of its own; SSH host keys are per-instance (fingerprints: `sudo culvert-appliance reidentify --help`
is NOT needed for a first install — see §6).

## 6. Clones, templates, re-identification

The OVA ships with **no** SSH host keys, machine-id or application identity — each first boot mints its
own. If you **clone a provisioned VM**, both copies share host keys and machine-id (and application
identity, which is the application's domain): on the clone run `sudo culvert-appliance reidentify --yes`
(new host keys + machine-id; prints the new fingerprints), set a new hostname/address, and follow the
application's guidance for its own identity (CA, session secret, cluster enrollment) — the host CLI
deliberately never touches `/data`.

## 7. Reboot verification

`sudo systemctl reboot`, then confirm on the console: `Readiness: ready`, `Setup: complete`, addresses
unchanged, and `sudo culvert-appliance status` shows the same `/ready` rows as before. Detailed checklist
and the executed evidence: `os-maintenance-runbook.md` §5 and `hypervisor-qualification.md`.

## 8. Where things live

| Path | Content |
|---|---|
| `/srv/culvert/` | compose files, `.env` (secrets, 0600), `packaging/` — the standard quick-start layout |
| docker volume `culvert_proxy-data` | the application's `/data` (CA bundle, users, policy, logs, catalog) — owned by the image's `proxy` user (uid 100 / gid 101) |
| docker volumes `culvert_clamav-db`, `culvert_culvert-backups` | ClamAV signatures; application backups (cli profile) |
| `/etc/culvert-appliance/` | `manifest.env`, `build-inputs.json`, `bake.env`, `dpkg-list.tsv`, `mgmt-allow.conf`, `release_identity.env` |
| `/var/lib/culvert-appliance/` | first-boot state (`steps/`, `provisioned`, `phase`, `error`) |
| `/var/log/culvert-appliance/` | `firstboot.log`, `bake.log` |
| `/usr/local/lib/culvert-appliance/` | vendored `install.sh`, `firstboot.sh`, `console-status.sh` |
| `/usr/local/sbin/culvert-appliance` | the host CLI |
| `/etc/culvert-maint/`, `/usr/local/bin/culvert-maint`, `/etc/sudoers.d/culvert-maint` | maintenance agent (installed by `install.sh`) |
