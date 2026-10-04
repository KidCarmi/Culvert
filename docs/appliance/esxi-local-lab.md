# LOCAL-ESXI qualification lab

## Access-aware workflow for the 4f27d945 LAB candidate

This records the access-aware workflow for the appliance through #1549. The
4f27d945 candidate has since been superseded by integration fixes; completing
its already-started qualification does not qualify the replacement candidate.
Qualification results must come from the completed run, not these instructions. The
older results and commands below are historical; in particular, do **not** use
the legacy `esxi-lab.py qualify`, `restore`, or administrative SSH path for
this candidate. Keep the original OVA unchanged and retained before import.

Completed ESXi evidence for these superseded bytes is in
[`local-esxi-4f27d945-20261004.json`](evidence/local-esxi-4f27d945-20261004.json).
Default PAM bootstrap, operator refusals, actual restore, signed apply/rollback,
OS update and all 12 independent postchecks passed. The report retains the
post-reboot backup-list timeout (a later read confirmed the backup), the earlier
observer interruption and a controller hook-loading error. It is **not an
all-green qualification**. First boot took 482 seconds; maintenance reboot to
health plus operator SSH took 597 seconds. Both disposable import VMs were
removed. F-DISK-1 and the ClamAV disposition remain open.

Freeze controller source files for the entire lifetime of each running shell.
The completed run exposed why: editing a wrapper while Bash retained older
sourced function definitions made its final hook unavailable. Independent
read-only postchecks completed that assertion without repeating guest mutations.
Apply and test harness changes only after the active process exits.

| Input | Pinned identity |
|---|---|
| OVA/application/agent/access/console/provisioning revision | `4f27d945b3c676899e65018e50aafef693c7c227` |
| Retained OVA SHA256 | `ce84809c15ce453335da7d91238dd7c1ce2cd84c5682e405b1fb666d7da86cdd` |
| Shared lab source, branch `test/appliance-lab` | `f1f04cab46875869dbd9d0cd559cc622de81e4b0` |
| Original shared `appliance-lab.sh` SHA256 | `36a672e1e85cb7e4a01d79f52fa42618f152399ac73f541b08c1f4974aceb1b6` |
| Shared script after the local hook patch | `693fd936ab88670b2e7ad4465ded22c5259ac376758db995b74af4d0cc0b7a96` |
| Candidate fixture `main.go` SHA256 | `33034e5994cc9ae7a2b9e9f98a418ffd48165b2de39cfa26fbc620c25d80330e` |
| Candidate fixture `request.py` SHA256 | `fbf7e9df27c190b47155ccbff93b3581cd0342f33cf8c8dbce943a57be49c771` |

The controller uses Windows Python with Pillow and cryptography, Git Bash,
OpenSSH, the approved govc build, and Go **1.26.8**. It uses the same one-VM
budget: 2 vCPU, 4096 MiB RAM, 40 GiB guest disk and the scope's independent
host/datastore headroom checks. No host, datastore, port-group or production
release changes are part of this workflow.

### Stage reproducible controller inputs

Fetch the two pinned commits into the local Git object database. Export
`test/e2e/appliance/lab/appliance-lab.sh` and `console-session.py` from the
shared-lab commit into `.tools/access-aware-shared/`. Use Python
`subprocess.run(['git', 'show', revision + ':' + path], check=True,
capture_output=True).stdout` and `Path.write_bytes()`; PowerShell text
redirection can change the bytes. Verify the original SHA256 above before
applying the checked-in, controller-only patch:

```text
git -c core.autocrlf=false apply --check --directory=.tools/access-aware-shared test/e2e/appliance/esxi/shared-before-signed-update.patch
git -c core.autocrlf=false apply --directory=.tools/access-aware-shared test/e2e/appliance/esxi/shared-before-signed-update.patch
```

The per-command `core.autocrlf=false` preserves LF bytes on Windows; it does
not alter Git configuration. Verify the modified SHA256 above. Record both hashes and the source commit
in `appliance-lab-local-delta.json`. The patch adds one optional plain-command
hook before signed lifecycle step 6c. The external wrapper suppresses the
shared unguarded restore block and runs the existing guarded ESXi restore
fixture from that hook, **before signed update/rollback and the maintenance
reboot**. This makes later persistence checks exercise restored state. The
upstream shared source and deliverable appliance are not modified.

Export `test/e2e/release-proof-fixture/main.go` and `request.py` from the
**candidate** commit into `.tools/access-aware-shared/release-proof-fixture/`,
also preserving exact Git bytes. Its `provenance.json` contains
`source_revision`, `toolchain: "go1.26.8"`, and a `files` object keyed by
`main.go`/`request.py`; each entry records `path`, `sha256` and `git_blob`.
`prepare-signed-fixture.py` refuses source/hash drift before generating trust.

For exact pixel observation, obtain Ubuntu's
`console-setup-linux_1.226ubuntu1.1_all.deb` from the official Ubuntu archive.
Verify package SHA256
`0eb39899bd329dea2286e4223c6a4ec8baa54d26cd292ddce43831805430a415`.
Extract `Uni2-Fixed16.psf.gz` from its console-font payload, then gzip-decompress
that member into a controller-only `.psf` file. The **decompressed bytes** must
hash to `d9025175dcf18f8b7442009a1870837f6ae974fa9561e9d8dae5eb145566fee7`.
Point `CULVERT_ESXI_CONSOLE_FONT` at those decompressed bytes. The original
local experiment retained a `.psf.gz` filename after decompression; the
decoder checks bytes, not the extension. Neither package nor font is installed
in the guest.

`pixel-console.py` matches exact 8×16 glyph bitmaps against that pinned font.
Unknown, multicolor or ambiguous cells remain U+FFFD. Partial cells, oversized
images, expired observations and oversized decoded text are refused. It does
not repair letters, guess passwords, or fall back to fuzzy OCR when the font
path is supplied. Two identical complete credential observations are required
before the first authentication attempt. Shell observation waits for the
cursor's blink-off capture; it does not strip unknown glyphs.

Kernel bridge messages can arrive below an otherwise live shell prompt after
a Docker operation. The observer may issue **one Control-L redraw**, without
Enter, only when it sees a completed-shell marker/recovery banner plus kernel
output and no subsequent PAM/sudo prompt. It then still requires the exact
trailing prompt within the original deadline. `KEY_CTRL_L` is a single
allowlisted USB L event with `LeftControl`; arbitrary control keys remain
refused. Rebuild the private keyboard helper and retain its updated source and
binary hashes before using a changed allowlist. This correction does not
suppress kernel messages or serial diagnostics; pre-redraw captures remain
private evidence.

### Import and perform the one-time bootstrap

Create a fresh private scope/run directory as described below. Set
`credential_mode` to `none`; no password or public key is supplied in the OVF.
Use the normal owner-fenced importer, with the exact retained OVA identities:

```text
python test/e2e/appliance/esxi/esxi-lab.py --scope ABSOLUTE_SCOPE_JSON preflight
python test/e2e/appliance/esxi/esxi-lab.py --scope ABSOLUTE_SCOPE_JSON up
python test/e2e/appliance/esxi/access-aware-bootstrap.py --scope ABSOLUTE_SCOPE_JSON
```

The bootstrap performs actual F2/PAM authentication and the required password
change. Its keyboard helper receives credentials over private stdin; it never
adds administrative SSH or a sudoers exception. Preserve private captures and
attempt markers when anything stops. Do not retry credentials or delete an
attempt marker to restart authentication.

`--resume-initial-observation` is permitted only when the first attempt's
marker is exactly `blocked` at `initial-capture` for the same VM UUID and
`bootstrap-console-password` does not exist. It creates a separate exclusive
marker and extends only observation from 300 to 900 seconds. It cannot resume
a started PAM/password-change attempt. This supports a later font-backed
observation after an OCR-only observation stopped without sending credentials.

### Authenticated administration and operator enrollment

`console-priv.py --scope ABSOLUTE_SCOPE_JSON --bind CONTROLLER_LAN_IPV4` reads
a Bash script on stdin. It navigates the authenticated local recovery menu,
requires the live shell prompt, then asks for password-authenticated sudo.
`--as-user` runs as local `culvert`; `--timeout N` bounds the response wait;
`--nowait` acknowledges authenticated execution starting, not completion.
No privileged operation goes through SSH.

The guest must reach the temporary HTTPS listener on the selected controller
LAN address. Commands pin its ephemeral TLS public key and the script's
SHA256. The listener accepts only the owned guest IP and single-use random
paths, with bounded bodies. A transport timeout is **BLOCKED**, not a reason
to replay a potentially completed mutation.

After bootstrap, enroll the run's generated `id_ed25519.pub` through this
authenticated transport into `/etc/ssh/culvert-authorized-keys/culvert-operator`
as root-owned mode 0644. Validate its `ssh-ed25519` type and base64 key before
constructing the command; do not install it under `/home/culvert/.ssh`.
Read `/etc/ssh/ssh_host_ed25519_key.pub` over the same authenticated transport,
validate it, and create the private `known_hosts` entry as:

```text
OWNED_VM_NAME ssh-ed25519 AUTHENTICATED_PUBLIC_HOST_KEY
```

Refuse an existing contradictory pin. Do not trust an unauthenticated
`ssh-keyscan` result or enable `accept-new`. Record enrollment and the host-key
fingerprint privately; only then set `ESXI_OPERATOR_ENROLLED=1` and
`ESXI_HOST_KEY_PINNED=1`. `culvert-operator` permits only `help`, `status`,
`status-json` and `diagnostics`; shell commands, sudo, forwarding, SCP/SFTP and
SSH as `culvert` must remain refused.

### Prepare the disposable signed-update fixture

Use the owned guest only after bootstrap, outside the immutable OVA. The
current fixture registry binds **guest loopback `127.0.0.1:443`**. Re-push the
OVA's baseline image and verify the registry manifest digest against the
retained baseline. To create the target without Buildx: `docker create` from
that baseline without starting the container; `docker commit --change
'LABEL org.culvert.lab-target=1'`; remove the temporary container; then push
the target. Record the real returned digest, rather than predicting it.
Neither image is published to the public registry.

The registry's fresh TLS private key stays in its root-only guest fixture
directory. Copy only its public `ca.crt` and a `target-digest` record into
`RUN/secrets/signed-update`. Generate evidence with the existing real fixture:

```text
python test/e2e/appliance/esxi/prepare-signed-fixture.py --directory ABSOLUTE_RUN/secrets/signed-update --baseline ghcr.io/kidcarmi/culvert@sha256:BASELINE_DIGEST --target ghcr.io/kidcarmi/culvert@sha256:TARGET_DIGEST --registry-address 127.0.0.1
```

The helper accepts only fresh output or those two parent-prepared files,
checks the target digest, runs the byte-verified Go fixture with Go 1.26.8,
and refuses overwrites. The Ed25519 private key exists only in generator
memory. Outputs include the public keyring, signed baseline/target evidence,
unsigned apply, signed apply with prior-baseline evidence, signed image
rollback, provenance, `fixture.txt`, and `refs.env` published last. Evidence
expires after 24 hours. An expired fixture requires a new recorded directory;
do not silently replace an existing keyring.

Shared step 6c installs **test-only** registry CA trust, the `ghcr.io` hosts
mapping and the agent's fixture public keyring after boot. Its report records
those changes. No fixture key, trust configuration or registry belongs in the
deliverable OVA. Without a real prepared fixture, signed lifecycle remains
BLOCKED. These checks call the real agent socket/verifier; they do not qualify
the web Release Management dispatch path.

### Run, collect and clean up

Invoke `access-aware-qualify.sh` directly through Git Bash, **not** from the
legacy adapter's `qualify` command: that command holds `operation.lock`,
which would conflict with each authenticated console invocation. Provide
these environment variables in the process that launches Git Bash:

| Variable | Value |
|---|---|
| `ESXI_SHARED_LAB` | Absolute staged `appliance-lab.sh` path |
| `ESXI_SHARED_SHA256` | Expected modified hash `693fd936…` above; do not derive the expected pin from arbitrary current bytes |
| `ESXI_PYTHON`, `ESXI_ADAPTER`, `ESXI_SCOPE` | Absolute Python executable, `esxi-lab.py`, and private scope paths |
| `ESXI_HOST_KEY_ALIAS` | Exact owned VM name from the ownership ledger |
| `LAB_DIR`, `LAB_HOST` | Private run directory and current owned guest IPv4 |
| `LAB_PRIV_CMD` | Python + `console-priv.py --scope ... --bind ...`, as a whitespace-separated command; paths must not contain spaces |
| `LAB_EXPECT_IMAGE_ID` | Verified candidate image identity |
| `LAB_UPDATE_DIR` | Prepared private `signed-update` directory, or unset for BLOCKED signed lifecycle |
| `CULVERT_ESXI_CONSOLE_FONT` | Pinned decompressed font path |
| Enrollment/pin flags | Both flags above, after recording those prerequisites |

```text
bash test/e2e/appliance/esxi/access-aware-qualify.sh
python test/e2e/appliance/esxi/esxi-lab.py --scope ABSOLUTE_SCOPE_JSON collect
python test/e2e/appliance/esxi/esxi-lab.py --scope ABSOLUTE_SCOPE_JSON down
python test/e2e/appliance/esxi/esxi-lab.py --scope ABSOLUTE_SCOPE_JSON collect
```

Use direct guest SSH/API/proxy ports (22/9090/8080), not the historical SSH
tunnel settings. The wrapper fences ownership, placement, run directory,
host-key alias and guest address. SSH, SCP and SFTP, including timeout-wrapped
refusal probes, all use strict pinning. Guest address drift stops the run.
Never run `down` or another console operation concurrently with qualification;
reconcile both lock files after an interrupted controller process.

The sequence is bootstrap/access regressions, setup/auth enforcement, backup
and dry-run, guarded actual restore, signed apply/rollback, OS maintenance,
reboot, and persistence. The actual restore holds both maintenance locks,
checks volume mappings and agent compose overrides, and leaves a failed
commit stopped for inspection instead of guessing a recovery. It remains a
**same-volume** restore: fresh-appliance disaster recovery using only a backup
and separately saved CA/log passphrases is not proven by this run.

All console screenshots, decoded text, bootstrap passwords, transport results,
TLS/controller private keys, cookies, backups and raw logs stay private and
must never be published. Share only the sanitized allowlisted `collect`
bundle and reviewed structured verdicts. Record updated hashes for every
controller file actually used; retain original failed attempts separately.
The final status must keep **F-DISK-1 open/known failure** and describe ClamAV
startup, signature availability and failure posture separately. Readiness
alone does not prove antivirus fail-closed behavior. Record boot timings and
journals without claiming the unexplained ESXi delay has been diagnosed.

### Narrow resume after the pre-dry-run observer interruption

The first access-aware attempt completed product backup, then stopped because
kernel bridge messages displaced the shell prompt. The restore dry-run script
had **not** been dispatched: console transport creates its per-command
directory only after obtaining the shell, and the latest transport directory's
creation/birth time preceded creation of the dry-run output file. This is an
observer failure, not a failed product restore. Preserve that failed attempt.

`access-aware-resume.sh` handles only this boundary. Before resuming, retain
the captures and write `evidence/observer-resume-evidence.json` recording the
same owned VM UUID, `restore_dryrun_dispatched: false`, the measured
`latest_transport_creation` and `dryrun_output_creation` values, and the
observation `kernel output displaced shell prompt; no transport created for
dry run`. The script requires the time ordering, the single matching original
dry-run failure, prerequisite PASS rows, no signed/update/reboot rows, and no
existing `checks-resume.jsonl`. These measurements and the retained captures
must establish the boundary; do not fabricate a marker merely to bypass it.

Using the same pinned environment after rebuilding/verifying the keyboard
helper, invoke:

```text
bash test/e2e/appliance/esxi/access-aware-resume.sh
```

The resumed root probe uses `test "$(id -u)" = 0 && echo root`; a semicolon
would incorrectly print success after a failed UID check. The resume retains
the original `checks.jsonl` and writes new verdicts to `checks-resume.jsonl`.
It runs the actual CLI dry run, guarded restore, signed lifecycle and the
hash-bound original step 7/8 body, without repeating setup or enrollment.
It additionally records the exact post-backup mutation name and requires that
mutation to remain absent after the reboot. Do not resume a dispatched or
ambiguous restore, update, password attempt or reboot using this path.

Final reporting must retain the original failure and correction history, then
combine the latest **validated** result for each `(step, check)` with separate
independent observations. A later unsupported PASS must not erase an earlier
failure. The legacy shared `restore-persisted` NOT RUN concerns its suppressed
06b restore; the later exact-mutation check qualifies the guarded restore.
Explain that replacement explicitly. The legacy `esxi-lab.py collect` reads
`adapter.jsonl` and `checks.jsonl`, not `checks-resume.jsonl`; its unmodified
aggregate alone is therefore insufficient for a resumed run. Keep a reviewed,
sanitized combined report alongside both histories.

### Mandatory independent post-reboot evidence

Verify successful reads and expected content, not merely absence of error
strings. Several original shared checks intentionally continue after a
diagnostic command fails; their grep-based verdicts need these independent
checks before claiming PASS. Raw files remain private.

After qualification completes, use the same scope and pinned console observer:

```text
python test/e2e/appliance/esxi/independent-postcheck.py --scope ABSOLUTE_SCOPE_JSON --bind CONTROLLER_LAN_IPV4 --collect
```

The collector performs authenticated read-only guest commands. Any required
command or transport failure invalidates the dependent verdicts. It retains
the complete observation privately in `secrets/independent-postcheck.json`
and writes sanitized checks to `evidence/independent-checks.jsonl`; neither
file is overwritten. Resume proof may use the current-boot journal or the
durable OS-update log when journal flushing missed the final success line.
Durable entries must have UTC timestamps at or after this boot's `/proc/stat`
`btime` and no later than the observation; previous-boot and future lines
cannot prove success. The independent checks supplement the manual evidence
review below; they do not establish a newer candidate's qualification.

| Evidence | Required independent assertion |
|---|---|
| `esxi-boot-id-before.txt`, `esxi-boot-id-after.txt` | Both contain one valid kernel boot UUID; values differ; the after value matches a fresh read from the owned guest. The `--nowait` acknowledgement alone does not prove a reboot. |
| `03-kernel-before.txt`, `07-kernel-after.txt`, `07-check-after-update.txt` | Both kernel reads succeeded and contain valid nonempty release/version lines. Compare those values with installed kernel packages. An empty after-file must not count as a changed kernel. Verify all four Docker package holds. |
| `07-os-update.txt`, `07-reboot.txt` | OS update really completed successfully; distinguish the reboot's start acknowledgement from completion. Correlate with the new boot ID and current-boot service evidence. |
| `08-stack-resume.txt` | Loaded resume unit, `Result=success`, exit status zero, absent resume marker, and current-boot log entries proving both maintenance locks were held and the stack started. Obtain missing exit-status detail independently. |
| `08-firstboot-journal.txt`, `03-state-files.txt`, `08-status-after-reboot.txt` | Independently read the **full** current-boot firstboot journal and unit condition/execution state. A failed read or the shared last-20-lines excerpt cannot prove no step reran. Compare complete marker sets; use timestamps if rerun status is ambiguous. |
| `08-policy.json`, `09-post-backup-mutation-name.txt`, `08-login.txt`, `08-enforce.txt` | Valid authenticated responses; exact mutation absent; original allow rule enabled; original admin login succeeds; actual allowed/denied traffic remains 200/403. |
| `05-ca-fingerprint.txt`, `09-ca-fingerprint.txt`, `08-ca-fingerprint.txt` | All are valid nonempty SHA256 fingerprints and identical across backup, restore and reboot. |
| `08-image.txt`, `08-status-json.json`, `08-agent-status.txt`, `08-backups.txt` | Expected rollback image digest, valid read-only operator JSON with setup completed, healthy reachable maintenance agent, and the same backup listed. Read/parse failures are not absence or success. |
| `05b-lookups-before.txt`, `09-category-lookups.txt`, `08-lookups-after.txt` | Successful meaningful lookups with community-tier results, not three equal error outputs; compare after restore and reboot. Confirm current-process feed synchronization separately. |
| `08d-boot-timing.txt` | Actual `systemd-analyze` summary, critical chain and current-boot monotonic network/cloud-init/Docker/resume journals. Shared output is truncated; capture full relevant journals if needed to explain the delay. |

Correlate each privileged observation with a successful transport result or a
fresh authenticated read. Preserve and report any new transport BLOCKED result
instead of accepting a dependent shared PASS. Independently capture ClamAV
readiness/signature state and any required failure-posture traffic test; these
do not follow from a successful maintenance reboot.

## Historical qualification overview

The integrated `36b5407e` candidate passed the real ESXi functional baseline,
installed-console checks, maintenance reboot and actual same-volume restore.
Current sanitized evidence is in
[`evidence/local-esxi-36b5407e-20261004.json`](evidence/local-esxi-36b5407e-20261004.json).
Full fault and disaster-recovery qualification is **incomplete**; this is not
enterprise or release acceptance. The earlier
[`2026-10-03 report`](evidence/local-esxi-boot-20261003.json) records historical
firstboot and incomplete-image defects on different candidate bytes.

The shared harness was updated from `test/appliance-lab` at `cd43dca5`.
LOCAL-ESXI owns `test/esxi-qualification`, the ESXi adapter and independent
reproduction. Opus owns the integration branch and QEMU/CI. Shared guest
assertion fixes are documented below; product bytes were not modified to make
qualification pass. The owner's subsequent console UX work is isolated on
`feat/appliance-firstboot-guidance` and does not change this candidate's result.

## Current access and blockers

The owner designated `https://192.168.1.78`, subsequently authorized its TLS
certificate-verification exception, and supplied a Windows-encrypted
credential. Authenticated read-only inventory now succeeds: **ESXi 8.0.1
build-21813344**. Normal trust still fails (`unable to get local issuer
certificate`); this is an explicit exception, not verified CA trust. Cleanup
is recorded per candidate in the structured reports. No host configuration changed.

The owner authorized the default network and 2 vCPU / 4096 MiB / 40 GiB.
Inventory identifies `VM Network` on vSwitch0, VLAN 0, matching the management
network's `192.168.1.0/24`; the local guest-address fence uses that subnet.
The owner accepted `DataStore2` (~498 GiB free). Read-only admission checks
passed initially for one VM at the requested size: 46 GiB provisioned-space allowance,
9576 MiB host RAM available and 9847 MHz host CPU available at observation.
The integrated candidate passed checksum/manifest verification, real import
and ClamAV startup. The historical `F-OVA-CLAMAV-1` archive defect does not
describe these corrected bytes; see the historical findings below.
Conservative local admission thresholds retain 64 GiB datastore space,
4096 MiB host RAM and 2000 MHz host CPU after provisioning. Capacity must be
checked again before every import.

The retained evidence from [Appliance Lab run 37139370715](https://github.com/KidCarmi/Culvert/actions/runs/37139370715)
contains a rebuilt candidate checksum
`07ffa55482415016a0654fc24c0debc74abe7d31aeb7de43ff47a832bed826ab`, but no
OVA bytes. That run records successful build/manifest checks followed by
`no SSH within 2400s` under QEMU/KVM and an empty serial console log.
These are historical remote CI observations, not local ESXi results. Artifacts
11282975335 and 11283274993 supplied the earlier ESXi candidates; artifact
11300957991 supplied the integrated candidate. The superseded original remains
unavailable and unqualified.

## Historical original artifact and resource fencing

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
The current access-aware controller needs HTTPS to ESXi and direct access to
the owned guest's SSH/API/proxy ports (22/9090/8080). The guest must reach the
controller's temporary pinned HTTPS transport. Read-only operator SSH does
not permit forwarding. Older transport descriptions below concern historical
adapter runs and must not be used to bypass this access boundary.

## Historical adapter commands

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
python test/e2e/appliance/esxi/esxi-lab.py --scope .tools/esxi-scope.json inspect
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

`inspect` records actual firmware, hardware and power state for the owned VM,
captures its console under the private `secrets` directory, and attempts a
bounded read-only guest observation. It reads the kernel, completion marker,
firstboot service state, current-boot ordering-cycle evidence and VMware
guestinfo instance ID. It never starts or restarts a service. An absent
completion marker is only an observation; a matching systemd ordering cycle
is reported separately as a failure. Review console images before sharing:
the screen can contain a setup token. Console and guest-observation files
are not automatically included in the public evidence bundle.

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
| ESXi import/property delivery/boot | PASS on retained control `60a73475…` and fix variant `e85e3640…`; both default to BIOS and boot Linux |
| First boot | FAIL: control skipped by ordering cycle; fix starts but cannot create ClamAV from its incomplete archive |
| Baseline guest checks and reboot | BLOCKED by firstboot failure; application assertions NOT RUN |
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

38 safety/evidence tests passed locally, including OCI archive closure, owned-VM observation,
private console capture, pending-firstboot handling, reboot transport loss,
DHCP re-resolution, retained host-key checking, never-returning guest,
remaining-budget enforcement and real loopback child-process recovery.
These controller tests do not qualify a guest reboot. The simulator smoke uses only a
loopback simulator it launches, synthetic credentials and synthetic disk
bytes. It proves govc JSON integration, owned power-off/delete, wrong-UUID
refusal before power-off, and cleanup after a partial import. **vcsim does
not return the NFC upload digest**, so the production `-m` gate stops that
synthetic import before power-on/property injection. That gate is retained;
the original simulator result does not establish upload verification or
guestinfo delivery. Those now pass on the real host with the explicit NFC
compatibility patch below.

govc semantics were checked against the pinned
[v0.56.0 import implementation](https://github.com/vmware/govmomi/blob/v0.56.0/cli/importx/options.go)
and [import option schema](https://github.com/vmware/govmomi/blob/v0.56.0/ovf/importer/options.go).
Tool ZIP identities are in the evidence JSON. No runner was registered,
no host was exposed to a cloud agent, and no release, image publication,
merge or customer deployment is part of this lab.

## Direct ESXi NFC checksum compatibility

Real ESXi 8.0.1 testing exposed two differences from the simulator. Stock
govc 0.56.0 requests no checksum algorithm; this host defaults to SHA1,
which cannot satisfy the candidate's SHA256 manifest. After requesting
SHA256 before transfer, the host hashes through the streamOptimized VMDK's
end-of-stream sector. QEMU's file also contains 64,512 trailing zero bytes.
For the control candidate, the observed server digest exactly matches the
locally computed digest through that end marker.

The local [govc patch](../../test/e2e/appliance/esxi/govc-sha256-negotiation.patch)
requests the manifest algorithm with
[HttpNfcLeaseSetManifestChecksumType](https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/sdk/vim25/release/HttpNfcLease/moId/HttpNfcLeaseSetManifestChecksumType/post/)
before transfer. For the supported QEMU v3 streamOptimized layout it verifies
the **entire local VMDK** against the original manifest, parses every grain
through the zero EOS sector, and requires all remaining bytes to be zero
and fewer than one grain. It then compares the server's SHA256 with the
independently derived stream digest. The OVA, its manifest and the uploaded
bytes remain unchanged. Missing digests, unsupported layouts, truncated
grains, nonzero trailers, excessive padding and digest mismatches fail.
The marker format is defined in [QEMU's VMDK implementation](https://github.com/qemu/qemu/blob/v8.2.2/block/vmdk.c).

Build this explicit local tool variant from govmomi tag `v0.56.0`, commit
`81608f9b9725d64e4ed447b9a338c9f03dbf8840`:

```text
git apply /absolute/path/to/govc-sha256-negotiation.patch
go test ./ovf/importer -count=1
cd govc
go build -o /absolute/path/to/govc-sha256-stream.exe .
```

Set the local scope's `govc` path to that executable. Add `govc_build` with
`base_tag`, `base_commit`, `patch` and the executable's measured
`binary_sha256`; preflight verifies and records that identity. The local
Windows executable used for the stream-aware attempt has SHA256
`a28278c8114497e18a02aa2a47c46797d6ec4b64b7c2bef7fb30eb8c2fa550ac`.
This is a patched local tool, not the unmodified upstream release.

## Integrated V1 candidate: 36b5407e (2026-10-04)

The unchanged integrated candidate OVA, SHA256
`7bd09aaac19ab0525654d2863d4382bf0415e0ac75e2b55aee8a424a9df6bca1`,
passed the real ESXi functional baseline and an actual offline full restore on
the existing data volume. The [structured report](evidence/local-esxi-36b5407e-20261004.json)
records 47 final baseline/restore checks, seven installed-console checks,
artifact and harness identities, and independent post-reboot observations.
This result qualifies these bytes; it does not qualify the historical candidates
below or provide enterprise/release approval.

The maintenance reboot moved the guest from `6.8.0-142-generic` to
`6.8.0-146-generic`. The resume service took both maintenance locks, restored
the stack and cleared its marker. Administrator access, policy, real traffic,
CA, category data and backup persisted. Recovery to health and SSH took
**552 seconds** on this host; no startup SLA is established.

The restore test first proved that a live commit is refused, then stopped the
stack and committed onto the same named volume under both maintenance locks.
A policy added after the backup disappeared; original authentication,
allow/deny traffic, CA, rebuilt community categories and agent access returned.
Existing `.env` and key material remained available. Fresh-volume disaster
recovery, missing keys, interrupted restore and corrupt archives remain outside
this result. A failed or ambiguous commit must not trigger an automatic retry
or stack restart.

The installed console was exercised through VMware keyboard events and the
actual tty1 buffer: public views, invalid-password refusal, F2/PAM login,
recovery shell, terminal restoration, correlated native audit and logout.
Passwords use a private stdin-only Go keyboard helper. The key-provisioned
console result does not establish default-credential bootstrap. A separate
fresh import with no supplied credentials proved that the initial password
remained readable across two fresh console captures. After F2, local OCR read
only a truncated password-prompt suffix and the bounded classifier stopped.
No password was sent and no PAM rejection was observed. Forced password change,
handoff cleanup, reboot survival and the two-import identity comparison remain
unqualified. Both disposable VMs were deleted and all private run files removed.

The adapter uses a controller-side loopback TCP relay because the appliance
intentionally disables SSH forwarding. It does not change guest SSH policy.
SSH host keys stay pinned during reconnects. Windows password writes use
binary stdin to avoid CRLF changing the credential. The restore script keeps
Compose stdin separate from its own command stream and requires an explicit
completion marker. Test oracles require successful reads, all mandatory
readiness rows, the full current-boot journal, and dry-run exit status.

Earlier harness failures and corrected attempts are explicitly described in
the report. Read-only independent observations close the weak historical
oracles on the actual guest; improved synthetic tests alone are not presented
as guest evidence. The first disposable VM was deleted and its nested private
credential, capture and build-cache files were removed before the next import.

## Historical artifact findings

| Candidate | Identity and observed result |
|---|---|
| Control, artifact 11282975335 | OVA `60a734756bea788523ffb1d4e6c8ba08f74d16198850a52ed24c85e0deb0b10e`; source/provisioning `78e1bc566e80055f893de41befbbad190ac4dfec`. BIOS boots `6.8.0-142-generic`; firstboot start job is deleted to break the cloud-final ordering cycle. |
| Firstboot fix, artifact 11283274993 | OVA `e85e364081fd13833eb53ea04a365cea4a771911f7edb3e41e6cb6dda401c300`; provisioning `25d0aa83884ec66fe82e82f83d0f9e83b5a85353`, image source `78e1bc56…`, provisioning drift and dirty build state explicitly recorded. Cycle regression passes; application startup fails. |

`F-OVA-CLAMAV-1`: the fix variant's baked `clamav.tar.gz` is 69,562 bytes,
SHA256 `28b73b727cb49fe964c5c17be1a754556eeec363ad0238393fb84882631e6c8f`,
matching its build record. It contains the selected amd64 manifest but lacks
its configuration blob and all seven referenced layers. Docker load and tag
listing succeed, but Compose reports the missing config digest and no
containers are created. An automatic firstboot retry was observed; no image
was pulled or repaired to obtain a pass. The unit fix therefore passes its
ordering regression but does not qualify the appliance.

The read-only reproducer below checks config/layer existence, size and digest
for the explicitly selected manifest. Run it against the baked archive on
the disposable guest, or a retained copy of that archive. It never extracts
files or contacts a registry:

```text
python image-archive-check.py clamav.tar.gz --manifest-sha256 da8463f630e2c9467c74f3da1dee6f096e61a71650e4e9f1ff9b5f687ba91aa0
```

The script is under `test/e2e/appliance/esxi/`. The affected artifact should
report FAIL with one missing config and seven missing layers. Its focused
tests also reject present-but-corrupt blobs and accept complete content.
The actual guest archive was checked with the same descriptor inspection
before cleanup; this reusable CLI was added afterwards and tested with
synthetic archives. [Product handoff and exact reproduction evidence](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-5973232426).
The reviewed [console capture](evidence/esxi-firstboot-fix-login.png) records
the fix variant's Linux login screen; structured journal/service evidence
establishes the firstboot failure.
