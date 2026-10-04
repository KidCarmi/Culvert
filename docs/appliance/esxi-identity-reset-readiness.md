# Preparing verified escrow evidence for identity reset

After `fresh-recovery.py export` and `p1-regressions.py identity-before` pass,
run this controller-only preparation:

```text
python test/e2e/appliance/esxi/prepare-identity-reset.py --scope SOURCE_SCOPE --escrow PRIVATE_EXTERNAL_ESCROW
python test/e2e/appliance/esxi/p1-regressions.py --scope SOURCE_SCOPE --bind CONTROLLER_IP --escrow-evidence PRIVATE_EXTERNAL_ESCROW/identity-reset-readiness.json identity-reset
```

Preparation checks the existing private Windows escrow ACL, verifies every file
in the complete export receipt, and binds source UUID, inventory path, owner,
datastore, endpoint, revision, image and OVA to the current scope. It validates
the encrypted archive header, metadata, required recovery credentials and
the exported behavioral baseline. It requires the successful identity-before
stage and refuses an already attempted reset. No guest or hypervisor calls run
during preparation. The second command performs the separately authorized reset.

Only successful checks produce `identity-reset-readiness.json`, published
atomically and exclusively inside escrow. Its two readiness flags are derived
from verified export evidence, with the export receipt and archive hashes;
it includes no credentials. Existing output is never overwritten. This proves
export readiness, not fresh-appliance recovery. Historical encrypted logs remain
explicitly blocked because the supported archive excludes them. Preserve this
private escrow outside both source and recovery run directories.
