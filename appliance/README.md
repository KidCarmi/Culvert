# Culvert on-prem appliance (pilot)

Everything needed to build, provision and maintain the Culvert virtual appliance
(OVA). It is a thin wrapper around the mechanisms the project already ships —
`scripts/install.sh`, the proxy image's `/app/deploy` bundle, the maintenance
agent and the signed release catalog — plus the guest-OS layer around them.

| Path | What |
|------|------|
| `build/manifest.env` | Every pinned input of the OVA (base image, package versions, image digests, VM sizing). |
| `build/build-ova.sh` | Reproducible (input-pinned) build: verified base image → pinned Docker → pre-baked images → streamOptimized VMDK → OVF + manifest → `.ova`. |
| `build/prepare-guest.sh` | Runs inside the disk during the build (libguestfs). The only place software is installed into the guest. |
| `build/culvert-appliance.ovf.tmpl` | OVF descriptor (vmx-13, 2 vCPU / 4 GB / 40 GB thin, 1× E1000) with the first-boot properties. |
| `provision/` | First-boot service (idempotent, resumable), console status/network helpers, firewall, SSH/cloud-init policy. |
| `os-maintenance/` | Security-only unattended-upgrades policy and the operator `culvert-os-update` tool. |
| `sbom/evidence/` | CycloneDX SBOMs + trivy scans of the pinned images (dated; see `docs/appliance/sbom-cve-evidence.md`). |

Documentation: `docs/appliance/` — `ova-build.md`, `hypervisor-install.md`,
`first-boot.md`, `os-maintenance.md`, `sbom-cve-evidence.md`, and the executed
/blocked evidence record `astra-evidence.md`.

Scope of the pilot: VMware vSphere/ESXi 7+ by OVA import, x86_64, single node,
online (the appliance needs outbound HTTPS at first boot — see first-boot.md).
HA, offline/air-gapped operation, private mirrors and third-party integrations
are NOT qualified by this track.
