# 7c F-DISK-1 and recovery-secret closeout review

Reviewed source `7c7b29ee3be40af6a0809c73ad04d4337303263d`; retained OVA SHA256 `4b8ae484fd8b9bda8dfc12512e9e0b489edcc96c7590824f22276a19dc6b7a05`; application image identity `sha256:398ffaf2090ec32cb9ff0506dd2e92bfd2414d689719373fc00cf96a5c58f906`. This review made no guest or ESXi changes.

## F-DISK-1: PASS for the reproduced database failure

Independent intake verified artifact **11605634977** from run **37908313475**: ZIP SHA256 `41a56f9d6ec162010c98d5da56c94774dcd67c5922c88df0e80eb6b52b4a2471`. The duplicated top-level/attempt-1 reports describe one run, not two repetitions. Its image-content receipts bind the nested registry's re-encoded manifest to the same source tar/config as the OVA application. Harness revision: `9a030bffb76f0b044829f2f5c247d0d691a51d28`.

- A 2 GiB loop-mounted ext4 held nested Docker/containerd, application and maintenance state. During an observed 2,575,820-entry Badger category import it was filled to 6,140 KiB free; the import actually returned `ENOSPC` while creating a memtable.
- After 30 seconds the proxy was running, exit 0, restart count 0, and answered health with the exact 7c version. The original SIGBUS/crash did not recur.
- After releasing the fixture allocation, `docker compose up -d` sufficed. Admin login, user/CA file digest, CA fingerprint and real allowed 200 / blocked 403 traffic passed. Category-store availability was 1, with no recovery/quarantine recorded.
- The failed import retried and completed all 2,575,820 entries **813 seconds after recovery**, within the harness's 1,800-second convergence window. This is category convergence, not the 120-second maintenance-reboot recovery measurement.

This closes the original bounded **active-write database crash** reproduction and its post-recovery checks. It does **not** qualify whole-appliance root exhaustion, inode exhaustion, host datastore/thin-provisioning exhaustion, abrupt I/O failure, or upgrade/rollback under exhaustion: this run uses `midwrite`, with predecessor and current image equal. The agent was built from 7c but ran as `dev` with `docker_group_lab`; this is not production agent privilege-boundary evidence.

Enforcement is measured before injection and after freeing space. Only container state and health are checked during pressure; continuous allow/block, scanner behavior and category decisions during the 813-second incomplete-feed interval are not demonstrated. Do not claim uninterrupted enforcement or complete category coverage from this artifact.

**Whole-appliance disk-pressure production closure remains BLOCKED by missing coverage**, not accepted risk. Required next evidence: a disposable, exact-artifact guest under a bounded root/data and inode pressure fixture, with retained pre-pressure state; actual allowed/blocked and ClamAV probes plus truthful readiness during pressure; authenticated recovery access/maintenance-lock behavior; failed backup/update preserving usable prior state; and verified recovery/reboot persistence after freeing space. Validate guest-capacity alert delivery separately from a datastore-capacity alarm. Never fill the shared ESXi datastore for this test. This review does not authorize or execute that campaign.

## Recovery-secret custody: separate proven layers

**PASS — exact-candidate reveal boundary:** both QEMU artifacts **11606883930** and **11611182595** record an authenticated privileged reveal matching both existing CA/log passphrases, with setup token omitted, custody guidance present, and unprivileged invocation refused (exit 1). No secret values are included in this note or its evidence bindings. This proves the reveal behavior, not off-appliance retention by an operator.

**PASS — exported history recovery under a new log key:** QEMU retained 12 marker records in an independently encrypted history archive, deleted the data volume, restored the application backup into a fresh volume and rotated the log passphrase. The application backup restored zero history records, as documented. Live-store history import and wrong archive passphrase were refused; offline import recovered all 12 records with identical timestamp/host/status/method, followed by working proxy traffic. The old log passphrase is not required to import that separately exported archive; its own export passphrase is required.

**Pending independent ESXi closeout:** the current ESXi campaign must bind its separately retained application backup, backup passphrase and CA/log secrets to verified off-source custody; prove the source VM and volumes unavailable; and demonstrate fresh-appliance recovery. The QEMU volume-loss test does not replace that evidence. Do not inherit the previous 7e ESXi custody verdict for 7c.

Custody instructions must distinguish: (1) application backup + its backup password, (2) CA/log passphrases from authenticated local recovery, and (3) history export + its separate export passphrase when history recovery is required. A console password or setup token replaces none of these. A changed log passphrase does not decrypt the prior node-local logstore. Other configured features can require additional separately held keys; the source custody matrix lists them.

The signed lifecycle's fixture trust is explicitly recorded in **11606883930/06c-test-only-trust.txt** as a post-boot test modification (disposable registry CA/host route/public verifier key/config). Those successful lifecycle checks do not establish production release signatures. Keep fixture private keys and trust outside the retained OVA and remove test trust from any lab VM presented as a clean appliance.

## Documentation correction needed

The pinned candidate's readiness/lab prose still contains older F-DISK-1 failure/pilot risk-acceptance language and older scanner behavior statements. Use the exact evidence above for this closeout; update those operator-facing statements before production readiness is asserted. A bounded F-DISK-1 PASS must not become an unqualified whole-appliance exhaustion claim.

Local `disk-and-custody-bindings.json` contains hashes and lengths of the reviewed, non-secret producer files and the exact harness/workflow source bytes. Raw application state, credentials and archives are not copied into this note.
