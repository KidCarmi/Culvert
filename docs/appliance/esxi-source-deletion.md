# Deleting the exported source before fresh-appliance recovery

`delete-exported-source.py` is the explicit destructive boundary between the
source VM qualification and a sequential fresh import. It performs no guest
operations. Invoke it only after lifecycle qualification, verified external
backup/escrow export, and all seven P1 regression stages have passed:

```text
python test/e2e/appliance/esxi/delete-exported-source.py --scope SOURCE_SCOPE --escrow PRIVATE_EXTERNAL_ESCROW
```

The helper uses `fresh-recovery.py`'s existing private-escrow ACL and complete
export-receipt verification, including hashes of every required archive,
credential and source observation. Exported source UUID/path/owner/endpoint
must match the currently owned source. It preserves sanitized P1 verdicts in
both escrow and the run's evidence directory before private run cleanup.

Before deletion, the helper checks the exact authorized datastore, the owned
VM's configuration folder and every `VirtualDisk` backing. Only persistent
FlatVer2 disks directly under the owned VM folder on that datastore are
accepted. Shared controllers, multi-writer disks, linked parents, split disks,
external paths and unknown disk types are refused. Source disk paths are
recorded before destruction.

The parser follows govc v0.56.0's standard JSON output, which has no VMOMI
`_typeName` markers. Disk capacity and FlatVer2 provisioning fields identify
the disk shape; missing or unknown backing evidence is refused. The required
`datastore.ls -p` flag marks actual folders with a trailing slash, while
`-H=false` preserves their real datastore names. Missing paths and unmarked
files cannot establish that the owned folder existed.

A successful, explicit root `datastore.ls` JSON result must identify that same
datastore root and include the owned VM folder. Under the existing operation
lock, `lab.down()` rechecks ownership/UUID, powers off when needed, destroys
the VM, independently confirms VM absence and cleans the private run files.
This helper then checks VM absence again and requires another valid root
listing in which the formerly observed owned folder no longer exists.
Missing/ambiguous listing data, residual folders or disk metadata drift are
BLOCKED, not proof of deletion. The helper does not recursively delete a
residual datastore folder or retry a partially completed destructive stage.

Only after all checks succeed are these complete, exclusive receipts published
in private external escrow:

- `source-deletion-receipt.json`: schema 1, source UUID/path/endpoint, exact
  recorded disk paths, `source_disks_deleted: true`, `one_vm_limit: 1`.
- `source-deleted-owned.json`: the confirmed source deletion ledger.
- `source-deletion-before.json` and `source-deletion-after.json`: private
  datastore observations supporting the verdict.

Pass the first two files as `fresh-recovery.py`'s `--deletion-receipt` and
`--source-ledger` respectively. A missing receipt blocks fresh recovery even
if the source VM is absent. The retained encrypted backup and escrow remain
outside both run directories. Create the next VM only after this boundary
passes, preserving the one-live-VM limit. Raw diagnostic archival, if wanted,
must be completed separately before private source files are cleaned.

Synthetic `test_delete_exported_source.py` tests validate missing-path refusal,
external/shared backing refusal, actual before/after folder proof and exclusive
receipt publication without contacting ESXi or deleting any VM.
