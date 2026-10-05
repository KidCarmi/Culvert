# Fresh-appliance ESXi recovery fixture

This is a qualification procedure for candidate
`b579ca28c9d936e9141292ce5ec564a26feeae86`, using the existing authenticated
tty1/PAM/password-sudo transport. It does not enable administrator SSH or change
the product. It requires the same candidate OVA and application image on both
VMs, with at most one qualification VM present at any time.

The helper is deliberately separate from VM lifecycle operations. The owning
orchestrator must collect source evidence, delete the source VM **and its VMDKs**,
confirm deletion, and only then import the fresh appliance. Do not complete the
new appliance's browser setup wizard before restoring.

## Escrow and source export

Pre-create an empty absolute escrow directory outside **both** run directories.
On the Windows controller its ACL must have inheritance disabled and allow only
the current user and SYSTEM, with inheritable child permissions. The helper
verifies that ACL and refuses reparse points. No secret belongs in shell command
arguments or the shared evidence bundle. Keep this directory after `down`, which
deletes the original run's private `secrets` directory.

Example ACL preparation, using a deliberately selected new escrow path:

```powershell
$escrowPath = 'D:\AI\private-escrow\culvert-b579-dr'
New-Item -ItemType Directory -Path $escrowPath -ErrorAction Stop
$escrowIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $escrowPath /inheritance:r /grant:r "$($escrowIdentity):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'
```

Run from the frozen harness checkout after source baseline qualification passes:

```text
python test/e2e/appliance/esxi/fresh-recovery.py export --scope SOURCE-SCOPE.json --escrow ABSOLUTE-PRIVATE-ESCROW --bind CONTROLLER-LAN-IP
```

The helper checks the source's real administrator login, CA identity and
decryption readiness, persisted policy and enforcement, populated community
category lookups and agent reachability. It then obtains both maintenance locks,
creates an encrypted CLI backup, confirms the `CVRTBK01` envelope and successful
restore dry run, and streams it over an ephemeral HTTPS endpoint pinned by SPKI.
Only the owned guest IP and one-use resource paths are accepted; uploads cannot
overwrite files. Archives are capped at 512 MiB; metadata and secrets at 64 KiB.

Escrow contains the encrypted archive, its checksum and volume provenance,
separate backup passphrase, separate CA/log/session-secret JSON, original
`labadmin` password, original owned ledger and API observations. The final
`export-receipt.json` hashes every required file. **Do not delete the source
unless export returned success and this receipt exists.** Partial exports have
no completion receipt and are refused by restore. This fixture supports the
candidate installer's literal generated environment-secret format; it refuses
unrecognized dotenv quoting instead of silently changing secret bytes.

## Source deletion proof and fresh target

The orchestrator must retain the source's deleted `owned.json`, and independently
produce a deletion receipt after confirming datastore deletion. Example shape:

```json
{
  "schema": 1,
  "source_uuid": "UUID-FROM-EXPORTED-OWNED-LEDGER",
  "source_path": "/ha-datacenter/vm/SOURCE-NAME",
  "endpoint": "https://AUTHORIZED-ESXI",
  "source_disks_deleted": true,
  "source_disk_paths": ["[AUTHORIZED-DATASTORE] SOURCE-NAME/SOURCE-DISK.vmdk"],
  "one_vm_limit": 1
}
```

The receipt is an attestation backed by the orchestrator's datastore inventory
evidence, not proof derived from a boolean alone. The helper additionally checks
the deleted owned ledger, live source-path absence, new target UUID, owned fresh
VM identity, and that its disks do not reuse any recorded source disk path.
The normal import preflight enforces the one-VM limit before fresh deployment.

Once first boot of the fresh same-OVA appliance completes, its local console
password is rotated through the existing authenticated procedure and its private
keyboard transport is ready, run:

```text
python test/e2e/appliance/esxi/fresh-recovery.py restore --scope FRESH-SCOPE.json --escrow ABSOLUTE-PRIVATE-ESCROW --bind CONTROLLER-LAN-IP --source-ledger SOURCE-DELETED-owned.json --deletion-receipt SOURCE-DISK-DELETION.json
```

The helper refuses pending maintenance fences, interrupted journals, a claimed
fresh UI, archive changes or provenance changes. Under both maintenance locks it
stops the stack, re-enters only the original CA/log/session secrets while retaining
fresh host settings, validates the backup, demonstrates refusal without
`--accept-root-ca-change`, then uses the documented full restore with
`--confirm --accept-root-ca-change --accept-dp-reenrollment`. It starts the stack
only after confirmed commit and journal absence.

No failure handler restarts the stack or guesses how to repair a journal. A
failure, timeout or ambiguous transport result requires private evidence review;
do not automatically retry. A failure after the successful start, such as a
behavioral-oracle mismatch, leaves the already started service for inspection.
Guest command logs remain root-private under `/var/tmp/culvert-fresh-recovery-*`;
controller reports, keys and raw API observations remain in the private escrow.

## Required verdicts and deliberate limits

After commit, the helper checks original administrator login, exact inspection
CA SHA-256, `ssl_inspection=ready`, persisted non-draft policy equality (excluding
only volatile hit counters), real example.com 200/example.org 403 traffic,
agent availability/stack state/version equality, and community categories after
a completed current-process feed sync. Rehydration is bounded to 1500 seconds;
serving readiness alone does not prove categories rebuilt.

Historical encrypted-log recovery is **BLOCKED**, not passed: the supported
archive intentionally excludes Tier-3 logs (`backup.go`, `defaultBackupArtifacts`).
Escrowing the log passphrase cannot restore absent historical records. This
fixture neither fabricates ciphertext nor copies live Badger files into an
unsupported backup. Any future history-recovery qualification needs a separately
supported consistent log-export/import procedure and a real source proxy event.

The supported full backup also excludes selected external credentials and host
identity. This lab has no configured upstream secrets, custom UI certificate,
webhook-key recovery or CDR enrollment; those recovery procedures remain separate
requirements in [the recovery runbook](recovery-restore-runbook.md). Regenerated
SSH host keys and fresh host maintenance GID are intentionally retained. Passing
this fixture is evidence for this candidate and this configuration, not universal
disaster-recovery coverage or an enterprise-readiness claim.

## Offline tests

```text
python -B test/e2e/appliance/esxi/test_fresh_recovery.py -v
```

These tests use synthetic files, fake inventory and a temporary localhost TLS
listener. They test bounds, one-use/overwrite behavior, required SPKI arguments,
source proof, receipt integrity, path separation and no restart on stop failure.
They do not perform VM operations or claim Linux/ESXi recovery execution.
