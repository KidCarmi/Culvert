# Culvert appliance — hypervisor import

## Supported platforms (pilot)

| Platform | Status | Notes |
|----------|--------|-------|
| **VMware vSphere / ESXi 7.0+** (vCenter or host client, OVA import) | **Primary, declared supported** | OVF `vmx-13` hardware; first-boot properties delivered via `guestinfo.ovfEnv` (open-vm-tools is in the image). |
| VMware Workstation / Fusion | Expected to work, unqualified | Same OVF; properties via guestinfo. |
| VirtualBox (OVA import) | Unqualified | Imports; OVF environment arrives as an ISO (`ovf-env.xml`), which first-boot also reads. Not tested in this track. |
| KVM / libvirt / Proxmox | Unqualified | Convert the VMDK with `qemu-img convert -O qcow2`; supply cloud-init via a NoCloud seed ISO instead of OVF properties. |
| Hyper-V, Nutanix AHV, public clouds | Not supported by this track | |

Architecture: **x86_64 only**. The build asserts the amd64 image digest; there
is no arm64 appliance.

## Resource sizing

| | Minimum (OVF default) | Recommended for >500 users |
|---|---|---|
| vCPU | 2 | 4 |
| RAM | 4 GB (ClamAV keeps ~600 MB of signatures resident) | 8 GB |
| Disk | 40 GB thin (the OVA is ~1.1 GB; `/` grows to the full disk at first boot) | 80 GB thin if request-history logging (`logstore`) is enabled |
| NIC | 1 × E1000 on the management/proxy network | VMXNET3 may be substituted after import; the guest has the driver |

The appliance stores all state on its own disk (`/srv/culvert/.env`, the
`proxy-data` Docker volume). Snapshots/backups of the VM are consistent only
when the stack is stopped (`docker compose stop` in `/srv/culvert`) or via the
in-product backup (`docs/operator/docker-compose-backup-restore.md`).

## Import on vSphere

1. **Verify the download.** `sha256sum -c culvert-appliance-<ver>-ubuntu-24.04.ova.sha256`
   and compare `build-info.json` (shipped beside the OVA) with the release
   notes: application `index_digest`, `cosign: verified`, git commit.
2. vSphere Client → *Deploy OVF Template* → select the `.ova` → name/folder →
   compute resource → review (the descriptor is manifest-checked by vSphere) →
   storage (thin provisioning recommended) → network: map **VM Network** to
   the port group that carries both management and proxy traffic.
3. **Customize template** (the OVF properties — all optional):

   | Property | Meaning |
   |----------|---------|
   | `hostname` | guest hostname (default `culvert-appliance`) |
   | `public-keys` | OpenSSH public key(s) for the `culvert` administrator — **this is how SSH access is granted**; SSH is key-only |
   | `password` | optional initial console password for `culvert`; change forced at first login. Leave empty to get a one-time password printed on the VM console (only when no key is given either) |
   | `culvert.net.mode` | `dhcp` (default) or `static` |
   | `culvert.net.address` / `.gateway` / `.dns` / `.search` | static addressing (CIDR, gateway, comma-separated DNS/search) — used only with `static` |
   | `instance-id` | cloud-init instance id; change it on a clone to re-run identity steps |

   vSphere stores the `password` property in the VM's `vApp Options`; clear it
   after first boot if your policy requires.
4. Power on. Open the **VM console**: the pre-login banner shows the appliance
   version, the management URL and the readiness state, refreshed every minute.
   First boot takes 3–8 minutes (identity, image load, stack start, ClamAV
   signature download). Continue with [`first-boot.md`](first-boot.md).

Command-line alternative (`ovftool`, VMware OVF Tool):

```bash
ovftool --acceptAllEulas --diskMode=thin --name=culvert-gw-01 \
  --net:"VM Network"="Prod-Mgmt" \
  --prop:hostname=culvert-gw-01 \
  --prop:public-keys="$(cat ~/.ssh/id_ed25519.pub)" \
  --prop:culvert.net.mode=static --prop:culvert.net.address=10.0.10.5/24 \
  --prop:culvert.net.gateway=10.0.10.1 --prop:culvert.net.dns=10.0.10.2,10.0.10.3 \
  culvert-appliance-<ver>-ubuntu-24.04.ova vi://administrator@vsphere.local@vcenter.example/DC/host/Cluster
```

## DHCP vs static, and finding the address

* **DHCP (default):** cloud-init configures the first NIC for DHCP. The address
  appears on the VM console banner and in vSphere's VM summary (open-vm-tools
  reports it). The appliance's DHCP lease carries the hostname for DNS
  registration where the DHCP server supports it.
* **Static at import:** set the `culvert.net.*` properties; first-boot writes
  `/etc/netplan/60-culvert.yaml` and applies it before the stack starts.
* **Static later / no DHCP at all:** log in on the console (`culvert`) and run
  `sudo culvert-net static 10.0.10.5/24 10.0.10.1 10.0.10.2,10.0.10.3`
  (`sudo culvert-net dhcp` reverts). The management URL changes accordingly;
  the admin UI's self-signed certificate is regenerated for the new SAN by the
  proxy on restart (`cd /srv/culvert && sudo docker compose restart proxy`).

## Network ports (host firewall, nftables)

Inbound, from any source by default: **22/tcp** (SSH, key-only), **8080/tcp**
(proxy + PAC + `/health` + `/ready`), **9090/tcp** (admin UI, HTTPS). Everything
else is dropped (`/etc/nftables.conf`). Restrict sources once the management
network is known — edit that file and `sudo systemctl reload nftables`, and/or
set `-ui-allow-ip` for the admin UI (`docs/operator/README.md`).

Outbound: the appliance needs HTTPS egress to the hosts listed in
[`first-boot.md` → "Required outbound access"](first-boot.md#required-outbound-access).

## Console access

The vSphere console (or any hypervisor console) is the fallback management
path: user `culvert`. Its credential is per-instance — either the `password`
property, or a one-time password printed on the console at first boot when no
key and no password were supplied. There is **no shared administrator
password** in the image and `root` cannot log in.
