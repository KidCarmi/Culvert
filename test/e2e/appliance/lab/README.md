# Appliance lab — reproducible guest boot + qualification

A disposable lab that boots the appliance OVA's **own disk** under QEMU and
runs the guest-OS checks of [`docs/appliance/vsphere-qualification.md`](../../../../docs/appliance/vsphere-qualification.md)
(steps 1 and 3–8) against it. It is a test path on the branch
`test/appliance-lab`: nothing is merged, tagged, released, pushed to a registry
or promoted to the catalog, and nothing here is a customer deployment.

## One command

On a Linux host with usable `/dev/kvm`, ≥ 6 GiB free RAM and ≥ 20 GiB free disk
at `LAB_DIR`:

```bash
LAB_DIR=/var/tmp/culvert-lab \
LAB_OVA=./culvert-appliance-dev-candidate.4c4b7728c0e6-ubuntu-24.04.ova \
LAB_OVA_SHA256=e24eb542f973fb70360bad5124ef81fdab8b6f8d67af601720613cbcca3700a4 \
LAB_EXPECT_IMAGE_ID=sha256:384f4c4b1bad91be93dc8b78adb974b6c57dd9b4c8f534bfdbafc2c1e4f1ab04 \
  test/e2e/appliance/lab/appliance-lab.sh all
```

`all` = `preflight → up → qualify`, with `collect` and `down` always run on exit.
Each phase also runs alone. Exit codes: `0` no failures, `1` failures, `3` the
preflight measured a missing requirement (BLOCKED; nothing was booted).

Tools: `qemu-system-x86_64`, `qemu-img`, `genisoimage` (or `xorriso`), `ssh`,
`curl`, `python3`, `openssl`; plus `libguestfs-tools` for `fingerprint`.
`LAB_ACCEL=tcg` runs without KVM, but expect hours, not minutes.

In CI: [`.github/workflows/appliance-lab.yml`](../../../../.github/workflows/appliance-lab.yml)
runs on every push to `test/appliance-lab` (and on `workflow_dispatch`) on a
standard `ubuntu-24.04` runner.

## The same checks against an appliance deployed elsewhere (ESXi)

`qualify` and `collect` run unchanged against a VM another tool imported and
owns (the ESXi qualification on `test/esxi-qualification`). That tool keeps
the hypervisor, the VM and its SSH key; the lab adds only its own disposable
admin password:

```bash
LAB_DIR=/var/tmp/culvert-esxi-qual LAB_EXTERNAL=1 LAB_HOST=<vm address> \
LAB_SSH_KEY=<private key whose .pub was given as the OVF public-keys property> \
LAB_EXPECT_IMAGE_ID=sha256:384f4c4b1bad91be93dc8b78adb974b6c57dd9b4c8f534bfdbafc2c1e4f1ab04 \
  test/e2e/appliance/lab/appliance-lab.sh qualify
LAB_DIR=/var/tmp/culvert-esxi-qual LAB_EXTERNAL=1 LAB_HOST=<vm address> LAB_SSH_KEY=<key> \
  test/e2e/appliance/lab/appliance-lab.sh collect
```

Ports default to 22/8080/9090. Step 5's traffic goes from the machine running
the lab, through the appliance's proxy, to `example.com`/`example.org`. Run it
on a first boot that has not been set up yet; the setup-token checks need
`setup pending`. What ESXi adds and the lab cannot cover (import, guestinfo
delivery, VMware Tools, LSI Logic, datastore) stays with the ESXi procedure.

## What it does

| phase | does |
|---|---|
| `preflight` | measures KVM (opens `/dev/kvm`), free RAM, free disk at `LAB_DIR`, tools → `preflight.json`; refuses below the budget |
| `up` | verifies the OVA's SHA-256 and every `.mf` digest; converts its VMDK once to a **read-only** qcow2 base; boots a **disposable** qcow2 overlay; delivers the OVF properties (`hostname`, `public-keys`, `culvert.net.mode=dhcp`) as an `ovf-env.xml` ISO; waits, bounded, for SSH and for the guest's own `complete.done` |
| `qualify` | first-boot state + kernel before; setup token required (403 without, 200 with); admin login; default-deny → allow rule → real traffic (403/200/403); `/ready` rows incl. the real ClamAV sidecar; root-CA fingerprint; community category data; agent backup through the product + restore dry run; `culvert-os-update os` + reboot with kernel before/after and Docker holds; after the reboot: admin login, policy, enforcement, CA identity, category data, backup, agent, no first-boot re-run |
| `collect` | guest diagnostics + console log → `evidence/`, secrets redacted, `REPORT.md` + `checks.jsonl` |
| `down` | powers the guest off, deletes the overlay, base, extracted OVA and the disposable credentials; the evidence stays |
| `fingerprint` / `compare` | guest content of an OVA (provisioning, units, sudoers, cloud-init, manifest, package list) for comparing two builds |

Results: `pass | fail | blocked | not-run | known-failure | info`.

## What it substitutes, and therefore does NOT qualify

| vSphere | lab | untested |
|---|---|---|
| ESXi + `ovftool` import | QEMU (KVM) boots the OVA's VMDK | import, vApp property UI, VM hardware version |
| `guestinfo.ovfEnv` (VMware Tools) | OVF **ISO** transport — an `ovf-env.xml` on a CD-ROM, which the OVF declares and first boot reads | the guestinfo transport and VMware Tools |
| LSI Logic SCSI | virtio-scsi (the guest sees `/dev/sda` either way) | the LSI driver path |
| E1000 NIC, BIOS | E1000, SeaBIOS (as the OVF declares) | — |
| datastore, thin provisioning | qcow2 overlay on the host disk | datastore behaviour and capacity alarms |
| customer network | QEMU user-mode NAT; ports bound to `127.0.0.1` | static addressing, firewalls, proxies |

A pass here is **guest-OS qualification**. vSphere qualification
(`vsphere-qualification.md`) and F-DISK-1 stay open until they pass on their
own.

## Artifact identity

A GitHub runner cannot receive an OVA built elsewhere, so the workflow
**rebuilds a separately identified candidate** from the same pinned inputs:
- the CI image tar `bb8a2c75…` (Deep run 37124197333, verified by SHA-256 and
  preserved by the lab as `lab-source-image-37124197333`);
- the appliance source `4c4b772`;
- `manifest.env`'s pins.

The rebuilt OVA gets its own SHA-256, and the report records it. Its guest
content is compared with
`reference/candidate-4c4b772-e24eb542.fingerprint.tsv`, the fingerprint of the
original OVA (`e24eb542…`) taken with the same function. Its application image
must be the original's `sha256:384f4c4b…`. A pass qualifies the rebuilt OVA,
and is evidence about the original only through that comparison.

## F-DISK-1

Not exercised in the guest: no fill ever touches the guest disk or the host.
The workflow's second job runs the existing bounded nested-Docker harness
(`upgrade-enospc-qualify.sh`, `QUAL_ENOSPC_SCENARIO=midwrite`) on a 2 GiB
loop-mounted ext4. Reproducing the crash is a known failure, never a pass; the
recovery (free space → `docker compose up -d --force-recreate proxy`) and the
integrity checks are recorded. The experimental fix is tracked separately in
#1535.

## Cleanup

`appliance-lab.sh down` (also run on exit by `all`), then `rm -rf "$LAB_DIR"`.
In CI the runner is discarded.
