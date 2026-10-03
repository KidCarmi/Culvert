# LOCAL-ESXI qualification lab

This is an **unqualified local execution adapter**, not a pilot acceptance.
Its `up / qualify / collect / down` path has not run against a real ESXi guest.
Status and sanitized local evidence are in
[`evidence/local-esxi-access-20261003.json`](evidence/local-esxi-access-20261003.json).

The harness baseline is `test/appliance-lab` at
`b9fc086f61df4122d0aa2090acd4d41a8f5f7502`. LOCAL-ESXI owns
`test/esxi-qualification`, the ESXi adapter and independent reproduction.
Opus owns product changes and QEMU/CI. The only shared-file change is an
opt-in library return immediately before the QEMU command dispatcher.

## Current access and blockers

The owner designated `https://192.168.1.78`, subsequently authorized its TLS
certificate-verification exception, and supplied a Windows-encrypted
credential. Authenticated read-only inventory now succeeds: **ESXi 8.0.1
build-21813344**. Normal trust still fails (`unable to get local issuer
certificate`); this is an explicit exception, not verified CA trust. No real
VM mutation has occurred.

The owner authorized the default network and 2 vCPU / 4096 MiB / 40 GiB.
Inventory identifies `VM Network` on vSwitch0, VLAN 0, matching the management
network's `192.168.1.0/24`; the local guest-address fence uses that subnet.
The owner accepted `DataStore2` (~498 GiB free). Read-only admission checks
pass for one VM at the requested size: 46 GiB provisioned-space allowance,
9576 MiB host RAM available and 9847 MHz host CPU available at observation.
The OVA file is the remaining blocker; the actual `preflight` command refuses
with `missing scope: ova` before any import.
Conservative local admission thresholds retain 64 GiB datastore space,
4096 MiB host RAM and 2000 MHz host CPU after provisioning. Capacity must be
checked again when the artifact arrives.

The retained evidence from [Appliance Lab run 37139370715](https://github.com/KidCarmi/Culvert/actions/runs/37139370715)
contains a rebuilt candidate checksum
`07ffa55482415016a0654fc24c0debc74abe7d31aeb7de43ff47a832bed826ab`, but no
OVA bytes. That run records successful build/manifest checks followed by
`no SSH within 2400s` under QEMU/KVM and an empty serial console log.
These are remote CI observations, not local ESXi results. Opus must provide
the original transfer route or retain a separately identified rebuilt OVA;
the CI evidence archive alone cannot unblock import.

## Artifact and resources

The original candidate remains:

| Identity | Value |
|---|---|
| OVA SHA256 | `e24eb542f973fb70360bad5124ef81fdab8b6f8d67af601720613cbcca3700a4` |
| Image/provisioning source | `4c4b7728c0e6a1746e968d935b635fc652647e6f` |
| Guest image | `sha256:384f4c4b1bad91be93dc8b78adb974b6c57dd9b4c8f534bfdbafc2c1e4f1ab04` |
| OVA filename | `culvert-appliance-dev-candidate.4c4b7728c0e6-ubuntu-24.04.ova` |

These are **expected identities**, not locally verified bytes. A rebuild
must carry its own SHA/source/image and gets a separate result. No rebuild
can qualify the original file. The pinned manifest declares 2 vCPU, 4096 MiB,
40 GiB and vmx-13; the adapter reads actual limits from the verified OVF.
It requires room for the full disk, all VM RAM as swap, another 2 GiB for
metadata/logs, and the owner's additional datastore headroom. Host RAM and
CPU headroom are measured independently. These checks are conservative
admission checks, not reservations against other users of the shared host.

One VM at a time is supported. A preflight refuses if any `culvert-esxi-*`
VM already exists in the designated folder. Use sequential fresh imports
for identity comparisons. Actual restore may need a separately approved
target budget. No snapshots are created, and unexpected snapshots stop
automatic deletion. No datastore or host configuration is changed.

The local controller needs Python 3.10+, `govc` 0.56.0, OpenSSH, and Bash
with curl, OpenSSL and GNU timeout. Git Bash works for the shell entry;
Python is supplied by the adapter, so a separate `python3` Bash alias is
unnecessary. The guest needs approved network access for Ubuntu updates,
ClamAV signatures, feed download and the example.com/example.org probes.
The controller needs HTTPS to ESXi and SSH to the guest. API/proxy probes
use local SSH forwards bound to `127.0.0.1` only.

## Commands

Copy `test/e2e/appliance/esxi/scope.example.json` into an ignored, private
directory such as `.tools/esxi-scope.json`. Fill the nulls only with the
authorized scope. Use absolute inventory paths and absolute local paths.
Set `govc` and `bash` to executable paths if they are not on PATH. A Windows
run directory can be `D:/AI/Culvert-esxi-qualification/.tools/esxi-run-01`.
Each new import gets a new run directory; keep the previous evidence.

Credentials enter through locally set `GOVC_USERNAME`/`GOVC_PASSWORD`, or
`GOVC_CERTIFICATE`/`GOVC_PRIVATE_KEY`; do not place them in the endpoint,
scope JSON, command arguments, Git or comments. Use `GOVC_TLS_CA_CERTS`
or `GOVC_TLS_KNOWN_HOSTS` for approved trust. govc session persistence and
debug/trace inheritance are disabled. The run's `secrets` directory is
restricted to the current user (and SYSTEM on Windows).

Environment variables created in another already-running PowerShell window
are not inherited by this controller. On Windows, run:

```powershell
& .\test\e2e\appliance\esxi\Set-LabCredential.ps1
```

It prompts for a `PSCredential` and uses Windows DPAPI through `Export-Clixml`
to encrypt the password for the same user on the same computer. The file
is under `%LOCALAPPDATA%\CulvertEsxiLab\192.168.1.78.credential.xml`, with a
restricted ACL, outside the checkout. Set the local scope's `credential_file`
to that path. The controller captures decryption privately and supplies the
credential only in its govc child's runtime environment; it is never printed
or included in evidence. Remove that credential file when lab access ends.
[Microsoft documents the Windows-specific encryption behavior](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml#example-3-encrypt-an-exported-credential-object-on-windows).

TLS verification remains the default. An explicitly authorized exception
requires both `tls_insecure: true` and `tls_exception_endpoint` equal to the
exact scope endpoint; inherited `GOVC_INSECURE` cannot enable it. Preflight
evidence labels this as `owner-authorized-exception`.

From the repository root, in PowerShell or a local shell:

```text
python test/e2e/appliance/esxi/esxi-lab.py --scope .tools/esxi-scope.json preflight
python test/e2e/appliance/esxi/esxi-lab.py --scope .tools/esxi-scope.json up
python test/e2e/appliance/esxi/esxi-lab.py --scope .tools/esxi-scope.json qualify
python test/e2e/appliance/esxi/esxi-lab.py --scope .tools/esxi-scope.json collect
python test/e2e/appliance/esxi/esxi-lab.py --scope .tools/esxi-scope.json down
python test/e2e/appliance/esxi/esxi-lab.py --scope .tools/esxi-scope.json collect
```

Run `collect` and `down` even if qualification fails. Do not loop or retry
`up` after a timeout: import may have created a VM. The ledger is written
before import. `down` re-reads the VM, requiring the random ownership
annotation, exact path/name, recorded UUID/MoRef when available, designated
host, datastore and network. It refuses mismatches before power-off or
deletion. A partially imported VM can be cleaned only when those ownership
checks pass; otherwise preserve the ledger for manual reconciliation.
A stale `operation.lock` requires checking that its process is no longer
running before removing that one local file. Cleanup never deletes a VM
by a name prefix alone. Local evidence and the deletion ledger remain.

Wait bounds: govc reads 120 s, import 1800 s, first boot 2400 s, guest IP
150 s, guest commands 120 s, OS update 2400 s, complete guest suite 10800 s,
delete 300 s. Qualify is single-use on a fresh import: enrollment mutates
state. It checks guest source/image before enrollment. Existing shared
checks then cover setup token, first admin, traffic, real-sidecar readiness,
backup validation, OS update and reboot persistence. An extra before/after
boot-ID check prevents an unchanged running guest from counting as a reboot.

The controller supervises the forwarding process throughout the suite.
After transport loss it re-resolves the address from the owned VM, rechecks
the guest CIDR, and establishes fresh localhost forwards. A stable per-VM
`HostKeyAlias` preserves the initial SSH key across DHCP changes; reconnects
use `StrictHostKeyChecking=yes`. Readiness is tested with a real SSH command
through the forward before declaring the transport recovered. Each recovery
is bounded by 2400 s and the remaining suite budget; failed recovery kills
the check process tree and reaps tunnel processes. Forwarding recovery,
guest availability and changed boot-ID evidence remain separate verdicts.

`up` verifies the outer SHA256 and every manifest payload without extracting
the tar. It refuses duplicate paths, links, traversal, malformed or partial
manifests. It imports powered off with the original virtual hardware and
network mapping, asks govc to verify the upload digest (`-m`), and uses
`InjectOvfEnv` to deliver properties through VMware `guestinfo.ovfEnv`.
Qualification reads the instance ID back through `vmware-rpctool`.
There is no QEMU ISO fixture. This tests direct-host injection; vCenter's
automatic vApp property delivery remains a separate qualification surface.

For a static-address run, add a `static` object containing `address` (CIDR),
`gateway` and comma-separated `dns`. The approved `guest_cidr` still applies.
DHCP and static are separate runs. A temporary network outage must affect
only an owned VM's NIC or guest, never the port group or host.

## Evidence and remaining scenarios

`collect` produces `esxi-evidence.tgz` plus a SHA256. The public bundle
contains structured verdicts and verified preflight provenance only.
Raw logs, API responses, console output, import properties, credentials,
cookies, private keys and backups are **not exported**. They remain local
until inspected and sanitized. The report stays `qualification: incomplete`;
no aggregate green result implies all requested scenarios passed.

| Scenario | Current result / required evidence |
|---|---|
| Original OVA hash and manifest | BLOCKED: file location unavailable |
| ESXi import/property delivery/boot | BLOCKED: OVA file missing; authorized placement, authenticated inventory and requested-profile capacity checks pass |
| Baseline guest checks and reboot | NOT RUN; per-check verdicts required |
| Real ClamAV failure posture | NOT RUN; readiness alone is insufficient. Exercise EICAR and unavailable clamd with actual traffic; report fail-open if observed. No CVE/risk acceptance. |
| Category enforcement | NOT RUN; lookup equality alone does not prove category-based allow/deny decisions |
| Backup → actual restore | NOT RUN; existing baseline is a dry-run validation. Restore into an owned disposable target, then compare contents/admin/CA/policy and real traffic. |
| Interrupted first boot | NOT RUN; record interruption boundary, recover, compare per-instance identity and firstboot markers |
| Two imports | NOT RUN; compare hashed machine-id, SSH public host-key fingerprints and per-instance CA fingerprints |
| DNS/network outage | NOT RUN; bound outage, restore NIC/guest state in cleanup, prove persistence and real traffic |
| Power loss | NOT RUN; select a documented committed persistence boundary and expected recovery before hard power-off |
| F-DISK-1 | KNOWN FAILURE from prior CI, not reproduced on ESXi; issue #1535 remains open |
| Alarm delivery | NOT RUN; host/shared monitoring changes are outside this authorization |

For F-DISK-1 reuse `test/e2e/appliance/upgrade-enospc-qualify.sh` with
`QUAL_ENOSPC_SCENARIO=midwrite` on bounded nested-Docker storage inside an
owned VM, only after baseline qualification and capacity review. Never fill
the shared datastore or the guest root filesystem. Capture container state,
restart count and actual allowed/blocked traffic before/during/after; prove
the write was in flight. Recovery (`free space`, then
`docker compose up -d --force-recreate proxy`) is not survival or a fix.
Report expected versus observed behavior and a candidate-specific regression
plus a small smoke test when Opus supplies a fix. No expensive suite rerun
is needed for documentation-only changes.

## Controller verification

```text
python -m unittest discover -s test/e2e/appliance/esxi -p "test_*.py" -v
python test/e2e/appliance/esxi/simulator-smoke.py --govc PATH_TO_GOVC --vcsim PATH_TO_VCSIM
bash -n test/e2e/appliance/esxi/guest-checks.sh
bash -n test/e2e/appliance/lab/appliance-lab.sh
```

32 safety/evidence tests passed locally, including reboot transport loss,
DHCP re-resolution, retained host-key checking, never-returning guest,
remaining-budget enforcement and real loopback child-process recovery.
These controller tests do not qualify a guest reboot. The simulator smoke uses only a
loopback simulator it launches, synthetic credentials and synthetic disk
bytes. It proves govc JSON integration, owned power-off/delete, wrong-UUID
refusal before power-off, and cleanup after a partial import. **vcsim does
not return the NFC upload digest**, so the production `-m` gate stops that
synthetic import before power-on/property injection. That gate is retained;
upload verification and guestinfo readback remain untested on ESXi.

govc semantics were checked against the pinned
[v0.56.0 import implementation](https://github.com/vmware/govmomi/blob/v0.56.0/cli/importx/options.go)
and [import option schema](https://github.com/vmware/govmomi/blob/v0.56.0/ovf/importer/options.go).
Tool ZIP identities are in the evidence JSON. No runner was registered,
no host was exposed to a cloud agent, and no release, image publication,
merge or customer deployment is part of this lab.
