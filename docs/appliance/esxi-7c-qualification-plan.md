# Independent ESXi qualification of 7c7b29ee

This is a LAB execution plan, not a qualification result or production approval.

- Product source: `7c7b29ee3be40af6a0809c73ad04d4337303263d`.
- Retained OVA: run `37908313475`, artifact `11605618137`, 1,537,863,680 bytes.
- OVA SHA256: `4b8ae484fd8b9bda8dfc12512e9e0b489edcc96c7590824f22276a19dc6b7a05`.
- Application image: `sha256:398ffaf2090ec32cb9ff0506dd2e92bfd2414d689719373fc00cf96a5c58f906`.
- Shared controller source: `337b4b5b64b4315d3a36b1d1cffe73148be54166`.
- Baked ClamAV image: `sha256:45dbf00306ef19a9c8f9a90a078d73e8131cc6dc03e08d829acdd16816afc94e`.

Preserve the prior 7e fresh-recovery VM's complete private run in verified
DPAPI custody before exact-owned retirement. Verify the replacement OVA's
outer SHA256, every internal manifest digest and virtual hardware first.
Retain the original OVA before boot. Import sequentially within the existing
one-VM, 2-vCPU, 4-GiB, 40-GiB and host/datastore reserve limits.

Commit all helpers and freeze canonical source bytes, both scopes, runner,
fonts and helper executables before preflight or import. Never edit a running
controller. Use default bootstrap, read-only operator SSH and authenticated
local PAM/sudo; test-only registry trust/private keys remain outside the OVA.

Execute the same ordered lifecycle, signed apply/rollback, actual restore,
static-network rollback, identity reset/refusals, three maintenance reboots,
ClamAV outage, browser identity/enforcement, and source-absent fresh recovery
oracles as [the 7e plan](esxi-7e-qualification-plan.md). The recovery budget
remains **120 seconds**, with actual allowed/blocked traffic, ClamAV readiness,
preserved state and the original first backup-list response per reboot.
First-install and deliberate slow-service timing stay separate. Preserve every
failed or incomplete observation rather than replacing it with a later pass.

The reconciled shared collector also tests the engine and module surface after
lifecycle. Require all 24 exact module names, effective install/empty-softdep
rules, the reviewed denylist digest, final-step denial, actual failed load,
named denied target/dependency and unloaded before/after state. Require complete
engine observations so missing negative results cannot become a PASS.

Producer evidence: original QEMU run reports 103 PASS / 6 INFO / 1 BLOCKED;
retained-OVA rerun reports 99 PASS / 6 INFO / 2 BLOCKED. Signed fixture evidence
is in the original run; do not erase the rerun's missing-fixture blocker.

Closeout remains blocked on concrete production evidence: the limited F-DISK
scope, ClamAV runtime behavior, recovery-secret custody, IdP coverage and all
scanner dispositions. In particular, absence of a kernel package fix does not
resolve the 56 present HIGH findings, and source scans must honor the shipped
CGO settings. Coordinate those corrections with Opus. No merge or release.
