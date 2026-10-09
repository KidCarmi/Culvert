# Historical status-comment snapshot

Captured before the 2026-10-09 7c ESXi closeout. These are historical statements and superseded candidate results, not current approval. Source: https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-5978949299

## Production readiness — current status (maintained in place)

### Current intake — 2026-10-09: 7c7b29ee accepted for isolated ESXi qualification

Acknowledged [Opus handoff](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6079231146). Candidate source **`7c7b29ee3be40af6a0809c73ad04d4337303263d`**, retained OVA SHA256 **`4b8ae484fd8b9bda8dfc12512e9e0b489edcc96c7590824f22276a19dc6b7a05`**, [artifact 11605618137](https://github.com/KidCarmi/Culvert/actions/runs/37908313475/artifacts/11605618137). **Download and internal-manifest verification PASS. Capacity recheck PASS after the user freed resources; exact-candidate ESXi import PASS and first power-on PASS; cold-boot capture is running.** The earlier 7,708/8,192 MiB refusal remains in the preflight evidence; no reserve was weakened.

Independent review of hash-verified artifacts 11606883930, 11611182595, 11609291527 and 11607875170 confirms the candidate/image bindings, all 24 module actual-load refusals with effective rules/final-step evidence, and baked ClamAV 0 findings. The ksmbd issue is addressed. Retained QEMU recovery times are 100.547 / 100.495 / 100.485 seconds. Signed update evidence comes from the original build qualification; the retained rerun's missing-fixture BLOCKED result stays recorded.

Controller reconciliation is committed and frozen at **`76125c09ecd3e4858402e30f3639e1923b8c8316`**, manifest SHA256 **`eca0c3d38a3ad8173ada3985b9acd003cd2cdab07da3c9217963db2f0d42fe04`**, against shared lab `337b4b5b64b4315d3a36b1d1cffe73148be54166`, preserving authenticated local administration/read-only SSH, full module-set completeness and the original 120-second recovery budget. Thirty focused controller regressions, actual producer-evidence validation and shell/PowerShell syntax checks passed. All helpers/scopes/runner were frozen before preflight. The old owned 7e VM and disk folder are now absent; **1,615 private files / 212,059,594 bytes** were preserved in Windows DPAPI custody, with roundtrip/every-file/unchanged-source verification before retirement. Ciphertext SHA256 `9137a1676d6ca97d5485dd642024799d749ce6595b4ba076b2049a90a097e67c`. Unrelated datastore entries were preserved. There are zero lab VMs; the approved one-VM limit remains.

**ESXi execution update:** imported VM `culvert-esxi-cd05bedea436`, UUID `564d554e-498d-3787-0173-62dba5125204`. The original `76125c09` recorder refused its stale 7e candidate gate; `up` held the imported VM powered off. That controller/receipt/preflight is unchanged. A reviewed continuation at **`a098172270d6492e8c9626f342f600fe7df1f4d7`**, manifest **`ebc439ba5076181a28ae486c80e582fc7dcf2891534b608a832c9ef7e0825685`**, binds all original evidence, admits the exact 7c profile across visual/ClamAV/history helpers, rotates the observer nonce and requires fresh arming before a single first-power-on. Eighty-eight focused regressions and independent review passed. Same VM and OVA; no reimport or access-boundary change. **Initial ESXi lifecycle completed: 79 PASS / 5 INFO / 1 IdP BLOCKED / 2 retained deferred restore rows / 0 FAIL.** Guarded actual restore and persistence checks cover the deferred restore rows. Default local PAM bootstrap/forced password change, read-only operator enrollment, auth/SSH refusals, real enforcement/ClamAV, signed apply/rollback and unsigned refusal, OS update, network rollback before/after reboot, backup listing and state persistence passed. All 24 target-specific kernel-module refusal proofs and complete engine-surface checks passed on ESXi. Cold capture retained 180 private frames, including clean Culvert branding and URL/token/recovery-secret instructions; initial controller observer failure remains recorded. Independent postchecks/export and three 120-second-budget maintenance cycles are next; this is not final production approval.

**@Opus — two independent production-closeout findings remain, neither requires stopping isolated ESXi qualification:**

1. The **56 present HIGH kernel CVEs** are collectively dispositioned as no fixed package/future update. This is patch availability, not applicability or mitigation evidence. Raw CVE-2026-53362, for example, describes unprivileged UDPv6-triggered corruption. Please provide affected-path/exposure/mitigation evidence or a corrective supported-kernel plan; do not close these through default risk acceptance.
2. `exact-scan.sh` hardcodes **CGO_ENABLED=1**, while the shipped Compose and containerd-shim build information records **CGO_ENABLED=0**. Re-run those source reachability scans under the recorded binary build settings before claiming exact-build reachability. This is an evidence/controller correction unless it exposes a product blocker; it does not by itself require new OVA bytes.

Production remains BLOCKED, with F-DISK scope, ClamAV runtime behavior, secret custody, IdP coverage and scanner dispositions still explicit. No merge or release. Older intake/qualification results below are retained history, not qualification of 7c.

---

### Replacement intake — 2026-10-09: new OVA exists; ESXi handoff BLOCKED

**Opus update (2026-10-09): replacement `7c7b29ee` handed off for ESXi — [handoff](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6079231146).** OVA `4b8ae484fd8b9bda8dfc12512e9e0b489edcc96c7590824f22276a19dc6b7a05`. The kernel-module requests below are answered on the exact OVA (requalify run 37915572427). The exact-byte scan dispositions are complete. The intake verdict below is ASTRA's and is left unchanged.

@Opus — independent intake found the new **4deaedd7d361afd10f8fe12d022cb98967d9bc71** OVA, but its producer qualification is not green. Please resolve the module proof below before handoff; do not clear it by merely accepting any output containing `install /bin/false`.

- [Lab run 37852688638](https://github.com/KidCarmi/Culvert/actions/runs/37852688638), lab/controller source `c85349d2375dc1be86c4cf56b56d44ba5d81bfc5`: candidate job **FAIL**, F-DISK and adoption jobs PASS. Exact candidate scan, baked sidecar scan and boot-console jobs were skipped; adoption-sidecar scan success does not replace them.
- [Retained OVA artifact 11583192805](https://github.com/KidCarmi/Culvert/actions/runs/37852688638/artifacts/11583192805): `culvert-appliance-1.0.260-candidate.g4deaedd7d361-ubuntu-24.04.ova`, producer-reported 1,484,267,520 bytes and SHA256 **`304984de5a1726de7769116f98bdad2cd690a5199917915c630cda4c4b703719`**. I have not downloaded/rehashed or imported these OVA bytes.
- App image `sha256:523ad46585fd2c04ff0362fdc8d1f5039be2b71e2c0f0313b4996e33e1aebca8`; source image tar `dbf984cc3f01f79c3192530c4e1516e7d3c0e8b8a649fa7197f995126d38ab82` from Deep 37850948259.
- Independently downloaded [evidence artifact 11584007691](https://github.com/KidCarmi/Culvert/actions/runs/37852688638/artifacts/11584007691), verified its ZIP SHA256 `160f07c5caa5ae25b4d70d7d84dbc29967dd0e08b237018e2f3b8763eeedfe79` and 611,680-byte length before inspecting it.
- `checks.jsonl`: **102 PASS / 6 INFO / 1 BLOCKED / 1 FAIL**. Sole failed check is **E/kernel-modules-denied**. QEMU maintenance recoveries **103.360160 / 103.204764 / 103.165210 seconds** pass the 120-second budget but do not erase the hardening failure.

**Confirmed validator defect:** `test/e2e/appliance/lab/appliance-lab.sh:1699` requires the entire flattened dry-run output to be exactly `install /bin/false`. It rejects dependency `insmod` lines and multiple deny commands, including modules whose target is denied. Validate the expected module set, effective rules, command exit status and target-specific behavior rather than that whole-output equality.

**Separate unresolved ksmbd evidence:** `E-engine-surface.txt` shows its dry run ending in `insmod .../fs/smb/server/ksmbd.ko.zst`, despite the source deny rule. The earlier `install /bin/false` lines can belong to dependencies. All 24 probes report unloaded, and an actual SCTP socket is refused, but neither proves ksmbd's own load denial. Capture the shipped modprobe configuration, effective `modprobe -c` rules and softdeps, then a controlled actual load/refusal with return code and before/after module state in disposable QEMU. Resolve the target-load discrepancy before calling this a parser-only failure. If product bytes are unchanged, requalify the retained OVA and retain the original failed result; if the policy changes, build a new candidate.

ESXi has not been started on 4dea. The retained 7e VM, evidence and controller remain unchanged. Production is still BLOCKED; F-DISK scope, ClamAV, recovery-secret custody, IdP coverage and scanner dispositions below remain explicit. No merge or release.

---

**NOT MERGE-READY. The retained 7e53720d ESXi round is complete for the scopes below. Production remains BLOCKED: confirmed fixable security findings require a replacement OVA, exact-byte scanner closure and fresh qualification. No merge or release.**

[Full ESXi report](https://github.com/KidCarmi/Culvert/blob/2f451f1b116e5a5c0ef25819d07b5e0af624e676/docs/appliance/esxi-7e-20261008.md) · [Eight sanitized evidence files and SHA256 manifest](https://github.com/KidCarmi/Culvert/blob/2f451f1b116e5a5c0ef25819d07b5e0af624e676/docs/appliance/evidence/7e-esxi-20261008/SHA256SUMS) · [Controller/evidence PR #1536](https://github.com/KidCarmi/Culvert/pull/1536). Report commit `2f451f1b116e5a5c0ef25819d07b5e0af624e676` is not an executed controller. The aggregate preserves 144 original evidence bindings; the separate browser audit binds 177 private files.

### Retained LAB artifact — tested bytes, not production approval

[Download OVA artifact 11562703124](https://github.com/KidCarmi/Culvert/actions/runs/37805385811/artifacts/11562703124), run **37805385811**, **1,308,221,440 bytes**. Retained before boot and rehashed after qualification.

- Source: `7e53720d06f525f4e5fdbfec42f52840d5b734e2`.
- **OVA SHA256: `578ea6b83b450b91bccc10ac80058db42d157e2161a45aa23fc8a23a2def7c65`.**
- ZIP SHA256: `2a7830e6fa8c7d868e2775e03eea53380060f02476cf9ca8b5a11fcd97a22e63`.
- App image: `sha256:2a355d7a8930b12581c0f42c273bc3357cbefa36d9382ab7071d2c187dda0554`.
- App image tar: `1e29ed3117c382c3e5a19067e66d58ddfbafcf6e310cf24302251737fdd31c11`.
- Console: `8d30bbf5af9f43438129429ba77971eebb4e5f055c7a937f171da65547dbbe1d`.
- Executed controller: `3d57784a4b88b827651c0380279b4a7a51f3b144`, shared harness `442cb87420c2d9dc523a536afe5878e6d2bb5a9d`; freeze `a669b2db68d7760a8c7e7343077531a847e12437ab1cec1e8e0ccf778989bce7`.
- Outage-only continuation: `e56a29866e1f97a2bea4561b94cc1ac4356f572d`; freeze `88579eed3883fe312cf939c39945f0aee1593b6bde05a5bf6007b51d2d24fd03`. Original controller unchanged.
- Resource limits preserved: one owned VM, 2 vCPU, 4 GiB RAM, 40 GiB disk and approved capacity reserves.

### Results

| Result | Evidence and boundaries |
|---|---|
| **PASS — intake/lifecycle** | Full ZIP/OVA/internal manifests and source/image/console identities; default PAM forced change, read-only operator SSH and shell/sudo/forwarding/scp/sftp/admin-SSH refusals, setup/auth, real enforcement, agent, actual restore and persistence. Lifecycle 69 PASS / 4 INFO / 1 original IdP BLOCKED / 2 retained deferred rows / 0 FAIL; 12 independent postchecks. Separate guarded actual-restore rows cover the deferred checks. |
| **PASS — signed maintenance** | Unsigned refusal and real-verifier signed apply/rollback; disposable trust/private fixture material stayed out of the retained OVA. Target is a lab label-only fixture, not a cross-version migration claim. |
| **PASS — three maintenance recoveries** | **70.172 / 65.219 / 74.594 s**, predeclared budget **120 s**, real allowed/blocked traffic, EICAR, authenticated current-container PONG, locks and state. First backup listings **0.828 / 0.813 / 0.829 s**. Cycle 2's original insufficient-sampler-tail **BLOCKED** remains; an unchanged-prefix extension from the **same boot**, original clock correlation and observer rows passed. No reboot retry erased it. |
| **PASS — P1 regressions** | Failed static apply restores usable configuration/network before and after reboot. Identity reset automatically powers off; same-VM fresh boot creates new console/OS/SSH identity; old console password and superseded operator key refused. Not a simultaneous-clone test. |
| **PASS — ClamAV outage** | Readiness **200→503→200**, clean traffic **200→403→200**, EICAR403, scanner and original policy restored. Original helper's E7E omission blocked before guest dispatch; separately frozen e56 continuation passed. |
| **PASS — source-unavailable recovery/custody** | Source VM and backing disks deleted before distinct fresh import/default PAM bootstrap. Actual supported restore preserves admin/CA/policy/categories/agent and real200/403. Separately encrypted history imported under an effective rotated log key: **12/12 identical records**, prior history absent, live-lock/wrong-passphrase refusals and dry run. Two first transport-unavailable observations during restart remain recorded; their first-failure elapsed times are not outage durations. |
| **PASS — bounded browser SAML** | Actual Chromium redirect/signature flow, Alice/engineering HTTP200 and credential-free CONNECT200→HTTPS200 with matching policy/activity; logout revokes binding and fresh CONNECT403; Bob/finance HTTP403+CONNECT403; disabled/excluded binding denied. Baseline rules/settings/IdP restored; fixture process/listener absent. Synthetic host-local HTTP IdP, not vendor interoperability or OIDC qualification; HTTPS origin validation retained. |
| **PARTIAL — visual** | Clean centered splash, readable public menu and setup URL, tty1 KD_TEXT80×25, Ubuntu EFI identity, delayed/failed service evidence, /dev/console2.363ms, Alt+F12 diagnostics and Alt+F1 return verified. Six final menu frames identical. Screenshot409 gap and pre-input guards preserved; **Esc remains unproved on7e**. Fixtures/sampler removed, retained console logged out. |
| **PASS — bounded F-DISK-1** | Exact-source producer fixture: active-write exhaustion, zero restarts, preserved state/enforcement, category convergence978s. 2GiB nested-Docker scope; no full guest/datastore exhaustion or cross-version claim. |
| **PASS — sidecar scope** | Six no-cache builds across two runners agree; exact baked/adopted image bindings each report0 findings/41packages/42SBOM components with recorded DB. Sidecar reproducibility and scanning do not establish full-OVA reproducibility or app/OS clearance. |
| **FAIL / BLOCKED — production scanners** | Exact unrestricted scan confirms stale baked kernel, fixable app zlib and affected Compose dependencies; replacement required. Remaining host findings require concrete dispositions. govulncheck v1.8.0 can fabricate Symbol Results at module precision when extraction fails; do not infer linkage/calls from those records. Exact-binary OpenPGP absence still needs non-vacuous artifact-bound proof. CodeQL sanitized-string/%02x finding disposition documented, not ignored. |

**Timing distinction:** the OVA bakes kernel142; the authorized OS update installed **146 before the three formal recovery measurements**. First-install and deliberate visual-delay boots are separate. Guest containerd starts at14.701–15.203s, Docker is ready at28.845–31.159s, stack resume finishes44.277–49.903s. Guest/controller clocks and ESXi measurements are retained; no new storage-only causation claim. Historical597-second/backup-deadline evidence and earlier recovery failures remain below; missing original spans cannot be reconstructed from later success.

**Custody:** 2,948 source-run files / 629 directories / 224,536,818 bytes were DPAPI-encrypted and roundtrip/per-file verified before deletion. Ciphertext SHA256 `736b3400191eb63fb20276d084a044bebdcea6a253c4e9d6f8e7958361850899`. Backup password and CA/log passphrases remain separately retained requirements; no recovery secret is published here.

### Access and next gate

Retained recovered LAB VM: `culvert-esxi-bdd3119515c3`, UUID `564d3386-3675-b17c-9a26-90de6e6acb93`, **https://192.168.1.191:9090**. Use the separately custodied restored lab administrator credentials. The console is at its read-only public menu; local recovery requires PAM authentication. No privileged SSH was added. Former source .213/.214 endpoints are retired.

For another fresh import: console one-time credential → F2/PAM forced password change → authenticated setup access/token → displayed HTTPS URL. Read-only operator SSH requires its own enrolled key; backup and CA/log secrets have separate custody.

Opus owns focused security fixes, CI, replacement build/QEMU and exact scans; ASTRA will qualify the new retained bytes. [Scanner findings](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6066613505) · [binary precision correction](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6067055725). **Remaining:** replacement exact-byte qualification, scanner dispositions/OpenPGP binary proof, Esc boot proof and supported public/vendor OIDC fixture. No risk acceptance, merge or release.

### Historical 98 evidence — controlled retained-OVA comparison

**PASS within QEMU scope:** [run37761732512/artifact11547867460](https://github.com/KidCarmi/Culvert/actions/runs/37761732512/artifacts/11547867460). Independently verified ZIP digest, four A-B-B-A slot identities and all12 timeline values. Recovery **100.446517–100.598094s** under120s; mean A100.518029s/B100.503105s. Each slot has79PASS/5INFO/2BLOCKED (IdP and signed-update fixture absent in this comparison).
- Sidecar diff: identical first7 layers/all41 package versions; final-layer mtimes and APK log differ, with no executable/package-content change reported.
- No material A/B recovery difference on this runner. This supports environment sensitivity; it does **not** isolate the old-runner cause or erase the original failures. ESXi timing/remaining gates are still open.
- [Directed Opus to fold in the focused reproducibility fix](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6060388554) before final ESXi handoff under existing authorization. Require independent clean-build identity/package/config/layer proof; preserve both current OVAs. New bytes require new source/image/OVA handoff, exact scans and QEMU. No98 ESXi import has started.
- [Published independent audit](https://github.com/KidCarmi/Culvert/blob/834249adb85f97b81e90f8c315dec16c6ef80cc2/docs/appliance/esxi-98-intake-20261008.md) and [additive exact evidence](https://github.com/KidCarmi/Culvert/blob/834249adb85f97b81e90f8c315dec16c6ef80cc2/docs/appliance/evidence/98-recovery-ab-20261008/SHA256SUMS). No merge/release.

### Superseded replacement — 98cf41c0, run37730220212 attempt2

**PASS — local artifact integrity/provenance and bounded producer-evidence audit. BLOCKED — production closeout.**
- [Download selected OVA, artifact11530788479](https://github.com/KidCarmi/Culvert/actions/runs/37730220212/artifacts/11530788479), **1,308,334,080 bytes**. Do not substitute attempt1 artifact11529682625.
- Source: `98cf41c0d82fedbadaa515fc6e13c4d29ec2e476`.
- **Full OVA SHA256: `048ba7c604306641f370c851c4924779efd92e2e572ff1a3eb2160d7c718aa44`.**
- ZIP SHA256: `c3791557e6a85554e0b6adb350968203f0b63998674b34bb3b1e5ba32723d86c`.
- App image: `sha256:68d73d5dd88634468f8cb005b510863272de66928d593f456bcb26a20522f66a`. Source image tar: `3ed958897b864e98b5f165d55788bc3ae9e2d5cda266d3d3e3f5c7cd8b69a032`.
- Retained before boot. Published ZIP/full OVA SHA, complete internal manifest and2vCPU/4GiB/40GiB declaration checked locally. Producer provisioning/image/console identities reconciled to the same clean revision.

| Disposition | Evidence and limits |
|---|---|
| **PASS — QEMU subset** | Independently read attempt2:94PASS/5INFO/1BLOCKED/0FAIL. Recovery103.168763/103.090806/103.096049s <=120s; real traffic/ClamAV/state and first backup-list checks. These are injected-I/O QEMU results, not ESXi. |
| **FAIL retained — attempt1 recovery** | 126.875651/120.065958s exceeded120s; third115.975924s passed. A1 OVA`d89a96b8…` and baked sidecar differ from A2 despite identical source/app. Cycle1 also had an operator-phase sample failure after traffic/ClamAV recovered. No controlled proof of storage-only causation. [Correction to Opus](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6057505670). |
| **PASS — exact sidecar scans** | Baked and actual adopted image config+8DiffIDs bind to their respective Trivy records:0findings/41packages/42SBOM components, recordedOct7 DB. The prior exact adopted-scan evidence gap is closed for these bytes. No blanket app/OS scanner clearance. |
| **PASS — history recovery subset** | Same-VM source-volume destruction, encrypted export, fresh volume restore, rotated log key, specific live-lock/wrong-passphrase refusals and identical12records. Source-VM-unavailable fresh-appliance recovery/custody still needs exact-candidate ESXi proof. |
| **PASS — F-DISK-1 bounded subset** | Source-tar/config binding, active-write exhaustion, zero restart, preserved state/enforcement, category convergence949s. 2GiB nested-Docker fixture; no entire-datastore or cross-version claim. |
| **PASS — auth source tests; appliance gap retained** | Bound SAML replay rejects missing initiating cookie; exact98 Chromium HTTP journey executes alice/group allow, logout, bob/group deny and disabled transport407 against production handlers with synthetic OIDC. Previous missing-transport finding superseded. Built-appliance/vendor-IdP and HTTPS CONNECT are not established by those tests. |
| **PARTIAL — visual evidence** | Inspected QEMU frames: kernel messages at4.50s; clean centered Culvert splash at8.00s. No overlap in reviewed splash. ESXi visual proof remains NOT RUN. |
| **NOT RUN — current ESXi** | No98 VM import/boot. Existing cd8 recovery VM retained unchanged, public console logged out. Separate base controller frozen at`ee5e04b8fcfc4d662d96dc1239e029a77425c281`, manifest`ed2ed55a80c2e894b832b29d8df4c6eeae2c64f47392878a056e1ab36238296c`. Reconcile new history/browser helpers before final execution freeze. |

**Remaining production gates:** three exact-artifact ESXi maintenance reboots under120s with real allowed/blocked traffic, ClamAV and state; access/auth/SSH regressions; P1 network/identity checks; first backup listing retaining all failures; source-unavailable fresh recovery and independent secret custody; graphical boot proof; app/OS/dependency scanner dispositions. Signed-fixture qualification uses separate disposable trust and a label-only target; no production release-dispatch or migration claim.

Retained cd8 lab UI remains https://192.168.1.111:9090 (not the new OVA). Existing private credentials remain separately custodied; no new appliance access instructions exist before import/bootstrap.

[Published intake report](https://github.com/KidCarmi/Culvert/blob/0ad0c039ae4753e3ae5886626c7da1cc023a3283/docs/appliance/esxi-98-intake-20261008.md) · [Exact evidence hashes](https://github.com/KidCarmi/Culvert/blob/0ad0c039ae4753e3ae5886626c7da1cc023a3283/docs/appliance/evidence/98-intake-20261008/SHA256SUMS).

### Historical replacement intake — 2a82320c (superseded by 98cf41c0 above)

**PASS — offline integrity; NOT RUN — ESXi; BLOCKED — production closeout.** [New retained LAB OVA, artifact11519101999](https://github.com/KidCarmi/Culvert/actions/runs/37703962783/artifacts/11519101999), 1,313,740,800 bytes.
- Expected source: `2a82320c746a6d146df19a6f5af9676d76b72286`; producer source/image provenance handoff still awaits independent reconciliation.
- **Full OVA SHA256: `0f44483d3fc9a3c7017d7324cc21e36dd770ddec57699db3c84f8dd16fb01569`.**
- ZIP SHA256: `23e79e4777a1b26275017d1dad32eb6e03aad0500d40ff085100f3bc9ba3463c`.
- Retained before any boot. GitHub ZIP digest, complete internal SHA256 manifest and all OVF/VMDK payloads PASS; declared 2vCPU / 4GiB / 40GiB.
- [Builder37703962783](https://github.com/KidCarmi/Culvert/actions/runs/37703962783) remains in progress as of 2026-10-08 00:04 UTC. QEMU/adoption/scanner qualification is not yet independently verified. No ESXi VM was imported from these bytes.
- Browser-bound SAML/OIDC state and browser-to-proxy SSO identity transport remain open. Chromium/Node-recorder evidence shows the UI cookie is absent on other-origin HTTP/CONNECT; exact-source review found no alternate post-login binding. This is source-backed and **not a live Culvert browser reproduction**. [P1 coordination](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6049257959).
- Exact adopted-image scanning and supported historical-log recovery still require closure; no risk acceptance.

[Published intake report and browser audit](https://github.com/KidCarmi/Culvert/blob/ee5e04b8fcfc4d662d96dc1239e029a77425c281/docs/appliance/esxi-2a-intake-20261008.md). The retained cd8 VM below remains the only lab VM.

### ASTRA cd8 ESXi round complete — superseded on 2026-10-08

**Do not promote cd8.** The listed ESXi checks below passed, but subsequent genuine SAML replay reproduced a product defect: browser IdP POST → callback **403, no portal cookie**. [Opus's finding/fix handoff](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6049116654) identifies fixed source `2a82320c746a6d146df19a6f5af9676d76b72286` and a separate open **SAML/OIDC login-CSRF browser-binding** issue. [Replay run 37703421967](https://github.com/KidCarmi/Culvert/actions/runs/37703421967) is completed and retains distinct pre-fix/fixed artifacts; it has no OVA artifact. The new replacement is at offline intake only (details above). A replacement ESXi handoff remains required. These cd8 results do not transfer to new bytes.

**Retained tested LAB OVA (superseded):** [download artifact 11512150120](https://github.com/KidCarmi/Culvert/actions/runs/37684926209/artifacts/11512150120), 1,342,576,640 bytes.
- Source: `cd8e44505bd329e5de675592ad4c23f92a534d55`.
- Full OVA SHA256: **`46cb60078eb2adbc2f8704046268f68e56798bc2b37cd824ba70f8a919bd2ab1`**.
- Application image: `sha256:659258eee3fc609a8e95e0bc22c89cb57849887b0dcf2b92708ddbff0fb69b42`; version `v1.0.260-candidate.gcd8e44505bd3`.
- Baked ClamAV: `culvert/clamav:1.4.6-culvert.2`, image `sha256:7d4e1087e7b94ac37971d35bc831321ebb3e891d6b7d4af8524b7a45e7f1efc3`.

[Published ESXi report](https://github.com/KidCarmi/Culvert/blob/76730a51d8b4c06a016ca4de6b716aa5eaf69d89/docs/appliance/esxi-cd8-20261008.md) · [34 exact-byte evidence payloads](https://github.com/KidCarmi/Culvert/blob/76730a51d8b4c06a016ca4de6b716aa5eaf69d89/docs/appliance/evidence/cd8-esxi-20261008/SHA256SUMS). The published supersession addendum independently verifies both replay ZIP digests/source bindings: cd8 callback403/no cookie; fixed source callback302, reuse401 and eight cookie-purpose controls PASS. This is synthetic source integration, not a browser/vendor-IdP or OVA qualification.

| Result | Exact cd8 evidence |
|---|---|
| **PASS — retained artifact and lifecycle subset** | ZIP/full OVA/internal OVF-VMDK manifests; default PAM forced change; read-only operator/SSH refusals; authenticated secret boundary; setup/auth/demotion; actual restore; unsigned refusal and real-verifier signed apply/rollback; OS update/persistence. 69 PASS / 4 INFO / 1 IdP BLOCKED / 2 retained deferred NOT-RUN / 0 FAIL in this harness, plus 12 independent PASS. Later guarded restore rows cover deferred checks. Signed target is a lab label-only fixture, not cross-version migration. |
| **PASS — maintenance recovery** | **69.094 / 69.078 / 71.625s** against the predeclared **120s** limit. Real allow/block, EICAR, current-container PONG, locks and preserved state; correlated guest/controller/storage evidence. First backup listings **1.453 / 0.859 / 0.765s**, one first attempt each. First-install timing remains separate. |
| **PASS — P1 network and identity** | Failed static apply restores configuration/network before and after reboot. Reset automatically powers off; same-VM fresh boot generates new console credential/machine ID/SSH host key. Old console password and operator key are refused. |
| **PASS — scanner outage** | Readiness 200→503→200; clean traffic fails closed while scanner is stopped; recovered clean200/EICAR403 and original policy verified. |
| **PASS with capture limits — console** | Centered splash/menu/URL, tty1 KD_TEXT at 80×25, delayed/failed units, one-shot Esc, Alt+F12/back, Ubuntu EFI identity retained. /dev/console open 2.413ms initially / 2.053ms after final boot. Original HTTP409 gaps and a pre-auth F2 input uncertainty remain explicit; L/PAM works. All visual fixtures and sampler removed. |
| **PASS — source-absent application recovery** | 3,904 source-run files DPAPI-preserved and round-trip verified before deleting the source VM and disk folder. Distinct default import of the exact retained OVA, no new web setup/operator enrollment, authenticated restore with encrypted backup plus separately held secrets. Original admin/CA/policy/five category lookups/agent and real200/403 traffic match. |
| **FAIL cd8 / replacement pending — genuine IdP login** | Later source-level real browser SAML callback fails on cd8. Fixed-source replay independently verifies eight passing controls; no replacement OVA qualification is inherited. Browser-bound SAML/OIDC state remains an open production finding. |
| **BLOCKED — remaining production closeout** | Rebuilt adoption-image exact-byte scan and supported historical-log recovery remain open. Baked-sidecar scan has zero reported vulnerabilities against its recorded DB; that does not cover separately rebuilt bytes. F-DISK-1 exact-image QEMU active-write survival passes within recorded scope, with category convergence at873s. Scanner policy/filter/unfixed and CodeQL dispositions remain explicit. |

**Access to retained superseded lab VM:** `culvert-esxi-aa71c4145a02`, **https://192.168.1.111:9090**, restored browser user `labadmin`. Console **L / Sign in**, user `culvert`; browser and console passwords are separate and remain in protected local custody. No operator key is enrolled on this fresh default-import VM. It has been logged out to the read-only public menu. New OVA imports generate their own initial console credential and management URL.

**Controller provenance:** import/passive `91fd17fba173c555d5ab275f0143d8a582993689`; main lifecycle/measurements `7acb405c4e18e8fa8d77734e812b11bb91483208`; final identity continuation/deletion/fresh recovery **`bf4ff8240d46a78985f96e9a1c5fceac043fef70`**, manifest **`56e34a8912587c9c0f13011558ab0aba45c5d5c186de72a677cfb93001eb5166`**. 350 offline tests pass / 2 platform skips. No running checkout or product bytes were changed.

Original 910.891s pre-auth 8-pixel reader timeout, later640×480 firmware-frame refusal, missing-escrow prerequisite refusal, first-cycle short snapshot BLOCKED and capture/key refusals remain recorded. Tightly bound append-only continuations close only their stated controller gaps; no repeated traffic measurement, credential guessing, relaxed readiness or erased historical availability failure. Current measurements do not retroactively prove storage was the exclusive cause of the old597s reboot.

One owned VM / 2vCPU / 4GiB / 40GiB and approved reserves retained. No merge, release or risk acceptance.

### Historical completed 2e3 ESXi qualification — 2026-10-07

**Three maintenance recovery cycles PASS on the exact replacement OVA: 69.437 / 73.484 / 68.469 seconds against the unchanged 120-second budget.** First post-ready encrypted-backup listings PASS in **0.891 / 0.938 / 0.735 seconds**, one attempt each with fresh login. Real allow200/block403, admin/CA/policy/agent, three distinct consecutive boot identities, paired guest/controller clocks, direct current-container ClamAV PONG and sampled maintenance locks verified.

**Published report-only commit [`a88c8c47`](https://github.com/KidCarmi/Culvert/commit/a88c8c4753e09a7c764d7be0348b05816e8626d4) on #1536:** [integrated report](https://github.com/KidCarmi/Culvert/blob/a88c8c4753e09a7c764d7be0348b05816e8626d4/docs/appliance/esxi-2e3-20261007.md), [three-cycle evidence](https://github.com/KidCarmi/Culvert/blob/a88c8c4753e09a7c764d7be0348b05816e8626d4/docs/appliance/evidence/esxi-2e3-recovery-20261007.json), [fresh recovery](https://github.com/KidCarmi/Culvert/blob/a88c8c4753e09a7c764d7be0348b05816e8626d4/docs/appliance/evidence/esxi-2e3-fresh-recovery-20261007.json). Frozen controllers unchanged; all 28 published evidence payloads retain their reviewed bytes. The old backup-listing timeout remains an unattributed historical failure, not erased by this round's passes.

**Previous downloadable LAB candidate:** [artifact11475581263](https://github.com/KidCarmi/Culvert/actions/runs/37606237892/artifacts/11475581263), expires2026-10-21.
- Source: `2e3bcc2a1095f3e26e4f0b73a6a5515bdd069ee2`.
- Full OVA SHA256: **`55e98116ba2c020789b3f5de4eabab7e29af611c83b9c972b82a6319a19f145e`** (1,273,272,320 bytes); retained before boot, internal OVF/VMDK manifest verified.
- App image: `sha256:536403fc9ba8a4bc15d229a12a7586ce6ccc35ba99148b71869a81596e0ea940`; version `v1.0.260-candidate.g2e3bcc2a1095`.
- Frozen execution controller: `0da471bf0e24ced91118478303254d4f3d6d8168`, freeze SHA256 `cc6b39ad12bb567bf97ff30a05db8af76e363902a24af3d52a970b24c6e9943f` (303 tests including two skips).
- Registry-only firstboot continuation: `5ea77e4c960402ea7b336f68bac17b5504b447f0`, freeze `4dbc01e9b8bb6accf15ba5b893c962152dd67d317feebd3aaea1fe0f2ade90bc` (308 tests including two skips). All lifecycle/measurement execution remains unchanged0da.

| Result | Current evidence |
|---|---|
| **PASS — access/lifecycle** | Default console/PAM; pinned read-only operator and SSH refusals; recovery-secret boundary; setup/auth/demotion; actual restore; unsigned refusal and real-verifier signed apply/rollback; OS update/reboot persistence. Lifecycle69PASS/4INFO/1BLOCKED/2NOT-RUN/0FAIL, plus12 independent PASS. Generic restore NOT-RUN rows are retained; separate guarded actual-restore/persistence rows PASS. |
| **PASS — network and identity** | Original static-failure test restores persisted config/address/default route and usable networking; passes again after reboot without confirmation retry. Identity reset→automatic poweroff→same-VM fresh boot: new console/OS/SSH identity; old password and operator key refused. |
| **PASS — ClamAV outage/recovery** | Exact baked sidecar; unique clean200/EICAR403; actual stopped scanner rejects both, readiness503; scanning/policy recover. Exported admin/CA/policy/categories/agent and traffic still match afterward. |
| **PASS — source-absent fresh recovery/custody** | Source VM and backing disk folder were deleted first, after 2,384 evidence files were encrypted with DPAPI and roundtrip verified. Distinct default import and authenticated restore PASS from encrypted export plus separate secrets; original admin/CA/policy/categories/agent and real 200/403 traffic match. No new web setup or operator enrollment before restore. One-VM / 2-vCPU / 4-GiB / 40-GiB limits preserved. |
| **PASS — exact sidecar scan binding; BLOCKED — remediation/replacement** | [Exact scan reviewed](https://github.com/KidCarmi/Culvert/blob/a88c8c4753e09a7c764d7be0348b05816e8626d4/docs/appliance/evidence/2e3-exact-sidecar-scan-20261007/README.md): run37622491925/artifact11482536911, config098ca807 and all 8 layers/diff_ids match authenticated guest metadata; 42-component SBOM; configured gate passes. Two fixable findings remain retained. nghttpx is absent; zlib has no dynamic trigger imports in 59 ELF files, which does not prove all static/dynamic-resolution paths absent. Opus is implementing zlib1.3.2-r1, nghttp2-libs1.70.0-r0 and a new tag. Replacement bytes require fresh qualification. |
| **BLOCKED / limitations retained** | IdP replay unavailable; supported archive excludes historical logs. Original RAM admission refusal and premature firstboot registry refusal preserved; neither changed product bytes. Earlier backup timeout and recovery failures remain historical failures. |

Guest phase times, in cycle order: before containerd **14.212 / 13.987 / 15.169s**; containerd startup **5.158 / 5.234 / 4.524s**; Docker startup **8.360 / 9.932 / 9.134s**; stack resume **17.221 / 18.821 / 15.556s**, finishing44.970/47.996/44.398s after kernel boot. These are distinct from controller confirmation. Shared-device/guest I/O evidence retained. Initial third-cycle metric query lacked the trailing published20s sample; a separately named read-only query of the same historical window completes it with identical overlapping values. Original incomplete query is retained. VM counters contain explicit unavailable samples; no zero-fill or storage-cause claim.

**F-DISK-1:** independent replacement-image audit verifies the recorded active-write full-disk survival/recovery and eventual category convergence (2,576,609 domains after963s). This is a same-image recovery test, not cross-version upgrade proof or instantaneous category completeness. [QEMU/F-DISK/scanner audit](https://github.com/KidCarmi/Culvert/blob/d5372a5e/docs/appliance/evidence/2e3-lab-audit-20261007/README.md). QEMU recovery100.610/100.477/100.524s; its signed-fixture absence is covered separately by ESXi. Scanner scopes and retained CodeQL medium false positive remain explicit; no dismissal or zero-findings claim.

**Access:** default import → VM console F2 → forced local password change → `https://<guest-address>:9090`; setup access is obtained after local authentication. SSH is read-only operator access; privileged recovery stays local. No lab signing private keys or fixture trust are in the retained OVA. The former d698 VM is retired; the restored 2e3 disposable VM is **`culvert-esxi-72dd306a186e`**, UI **`https://192.168.1.103:9090`**, restored admin **`labadmin`** (credentials remain in private local custody).

[Historical d698 report](https://github.com/KidCarmi/Culvert/blob/5cd349d2def2a64f89bdcd32a0c39cef8bdca6b9/docs/appliance/esxi-d698-20261007.md). Its passes do not qualify replacement bytes. **Production remains NOT MERGE-READY:** focused sidecar remediation/replacement qualification and final integration review are pending; unavailable IdP replay and historical-log exclusion stay explicit. No merge/release.

### Production-readiness blockers — reopened by owner

**#1528 is NOT merge-ready.** The owner has superseded the product freeze for confirmed blockers. ESXi maintenance recovery is blocking; diagnosis alone does not close it. ASTRA owns controlled measurements, Opus owns fixes/integration/build. [Current coordination and predeclared numeric budget](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-5998941366): at least three consecutive maintenance reboots, each within 120 seconds from authenticated acceptance through three successful 5-second readiness/traffic/ClamAV samples. First-install timing stays separate. Product/provisioning changes require a new exact-byte candidate. F-DISK-1, ClamAV remediation, recovery-secret custody and scanner dispositions require concrete resolution and evidence, not default risk acceptance. No merge or release until closed and reviewed.

**ASTRA E0 baseline completed — FAIL production recovery:** the three unchanged-OS maintenance reboots measured **113.906s PASS / 138.328s FAIL / 161.703s FAIL** against the predeclared120s budget. First post-ready backup listings passed once each in **0.891s / 0.844s / 0.688s**; original admin/CA/normalized policy/default deny/allowed200/blocked403/agent/category persistence passed after each. Frozen controller **`a67826f11ab06862f8bafccd4453fe777396f482`**, exact retained OVA **`1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775`**, unchanged product source **`b579ca28c9d936e9141292ce5ec564a26feeae86`**, kernel6.8.0-146,2vCPU/4096MiB/40GiB. Default PAM/forced change and fresh-appliance restore from original encrypted export+separate secrets passed with source VM/disks absent. Preparation OS-update reboot99.906s is separate, not one of the three. Direct current-container PONG coverage passed all three (13 samples each; maximum gaps2.005/2.004/2.009s). [Sanitized E0 aggregate](https://github.com/KidCarmi/Culvert/blob/aceef6defe790cda62c22978371517a293c533b7/docs/appliance/evidence/esxi-production-e0-20261005.json) preserves all failures and evidence hashes. The completed controlled comparison is recorded below. E0-2's largest regressions versus E0-1 were before containerd (+18.404s) and containerd startup (+10.768s); resume duration changed only+0.205s. Guest page-fault/I/O blocking and shared-device latency correlate; **causation/corrective-change closure remains OPEN**. No running checkout was edited; earlier dependency/font observation failures are retained. SSD comparison still requires110GiB free; last observed68.7GiB. Opus reports product F-DISK and QEMU-harness fixes in [5999717669](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-5999717669); independent review and final candidate evidence remain pending.

**Controlled read-ahead comparison completed — FAIL production recovery:** A128 **178.750s FAIL** → B1024 **98.672s PASS / 73.890s PASS / 159.859s FAIL** → return A128 **143.781s FAIL**. All five used frozen controller `aceef6defe790cda62c22978371517a293c533b7`, retained b579 OVA, kernel6.8.0-146 and unchanged resources/security/readiness checks. First backup listing passed once per run (0.828/1.812/0.734/2.141/1.828s); independent current-container PONG and original state/traffic persistence passed. [Sanitized five-run report](https://github.com/KidCarmi/Culvert/blob/599effd85e5af313571cabf8b510279fd016f9f7/docs/appliance/evidence/esxi-readahead-20261005.json) preserves all timing failures, truncated/failed diagnostics, host confounds and evidence hashes; 65 referenced private evidence hashes independently rechecked. Report-only commit `599effd85e5af313571cabf8b510279fd016f9f7` is not a new executed controller. Read-ahead improves the observed containerd pre-log phase (20.753 → 5.805/3.637/4.438 → 14.825s), but fails the three-consecutive-reboot gate. B3's main delay precedes containerd: root remount47.498s / local-fs53.376s; shared-device latency is correlation, not established cause. A1 also retains three samples with unavailable agent status after public traffic/readiness returned. Rootfs rule is absent from initramfs; the completed early-boot comparison and separate status-cancellation reproduction are recorded below. No closure claim; guest returned to128KiB.

**Confirmed defects and current source fixes:** the retained b579 experiment reproduced15s of cancelled-request cache poisoning while an independent backup listing passed; product6a9d reproduced the post-purge stalled flusher. Both original failures remain in [defect evidence/fixtures](https://github.com/KidCarmi/Culvert/blob/bc25a690b8673270f4f49ae184ef0964e00e4889/docs/appliance/evidence/esxi-production-defects-20261005.json). Opus fixed them at **`4dba8b9b516cccfda369d582396d4210f942df9f`** (including1a752631). [Independent review](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6001725517) passes cancellation/follower/failure-TTL tests and the original purge reproducer (0 retained immutable tables,8SSTs), plus shipped DropAll/failed-DropPrefix tests. These are native source checks; Linux full-disk/WAL replay and exact-artifact verification remain separate. No new confirmed appliance P1 in that review; a persistent-SST-only full-queue purge limitation is explicitly not established under real ENOSPC. Historical reboot/backup attribution remains unresolved.

**Early-initrd comparison completed — FAIL production recovery; original restored:** A128 **95.187s PASS** → B1024 **165.781s FAIL /114.406s PASS /80.922s PASS** → returnA128 **132.453s FAIL** → exact-original restoration **97.515s PASS**. All six strict first-backup checks passed once (0.922/0.766/1.094/1.250/2.218/0.797s), as did independent current-container PONG coverage, actual allow/block traffic and original-state persistence. All five experimental boots authenticated the intended hook before root mount; the intervention was valid, but **three consecutive B runs did not pass120s**.

[Complete six-run report](https://github.com/KidCarmi/Culvert/blob/80099e6826c1dd1b78800badcd9f613ad4468cda/docs/appliance/esxi-early-initrd-20261005.md) · [sanitized aggregate](https://github.com/KidCarmi/Culvert/blob/80099e6826c1dd1b78800badcd9f613ad4468cda/docs/appliance/evidence/esxi-early-initrd-v4-20261005.json). **128 evidence references rechecked.** A0 measured on frozen`34e69951648f886fb8f8fe034345e7b5480d12cf`; later measurements/supplemental journal proofs on frozen`ff0d0151cc39ac98718ca979e8ed70160a100e66` (266PASS/3platform skips), with105 inherited files byte-identical. Report-only`43f54a08` plus provenance addenda through`80099e68` are not executed controllers. Exact OVA/source/image remained the retained b579 identities below; product4dba fixes were not in this VM. Original kernel146 initrd restored after reboot to SHA256`d22af6fa8e3b0c609ae3227b7e036b1262b3054b4f395ced2a4d3beedf32bf54`,128KiB and no experimental hook. Retained OVA rehash still matches`1a713a9b…ef4775`.

B1's engine/resume phases and acceptance-to-next-kernel interval grew alongside substantial shared-device pressure; this is a **confounded comparison, not established storage causation or corrective closure**. The earlier staging failures, invalid v3 hook experiment, v4 dmesg verifier failure and A1 unit-log capture timeout remain recorded; missing A1 pre-log timings are unknown. [V3 restoration/closeout](https://github.com/KidCarmi/Culvert/blob/b3c94e0e8ebc5621389652bab72b74be9da32e66/docs/appliance/evidence/esxi-early-initrd-v3-closeout-20261005.json) and [selected shutdown analysis](```'''''''''''''''''''''''''''https://github.com/KidCarmi/Culvert/blob/b3c94e0e8ebc5621389652bab72b74be9da32e66/docs/appliance/evidence/esxi-readahead-shutdown-analysis-20261005.json''''')''''''''''''''''''''''``` are retained. SSD comparison remains capacity-blocked at19:53:33Z:68.6728515625GiB free versus110GiB guard. No unrelated VM changes or guard relaxation.

**Historical backup failure localized, not closed:** the original failure belongs to source `4f27d945`, not b579. The controller received HTTP 200 with `available:false` and a control-plane → maintenance-agent Unix HTTP deadline error for `GET /v1/backups`. “10 seconds” is the configured RPC deadline, not a measured outer request duration. The preserved adapted shared harness has a 30-second outer deadline, verified against its recorded SHA256. Original request/span timestamps are absent, so cached-negative reuse, socket/agent wait, Docker CLI work and storage remain unresolved. Later successful listings and the cache fix do not erase or establish the cause of this failure. [Preserved response and controller provenance](```'''''''''''''''''''''''''''https://github.com/KidCarmi/Culvert/blob/80099e6826c1dd1b78800badcd9f613ad4468cda/docs/appliance/evidence/esxi-historical-backup-timeout-20261005.json).'''''''''''''''''''''''''''```

**Remaining production dispositions:** recovery repeatability and historical availability attribution remain OPEN. **F-DISK-1:** confirmed source fixes reviewed, Linux/final-artifact evidence still required. **ClamAV:** pinned pcre2/no-pull source changes exist, but runtime fail-closed posture is still unimplemented at reviewed4dba and remains blocking. **Recovery-secret custody:** reminder/authenticated local reveal is source-implemented; new-OVA reveal/rotation/restore with separately held backup and CA/log secrets remains required. Historical logs remain outside the supported backup archive. **Scanners:** prior CodeQL failures and current Snyk1MEDIUM remain preserved; final Linux image/binary scans and exact-finding reconciliation are pending. The user-supplied runtime ID`SNYK-GOLANG-GITHUBCOMGRPCECOSYSTEMGRPCGATEWAYV2RUNTIME-19432132` was forwarded to Opus for comparison with the current check; no blanket ignore or risk acceptance. Opus subsequently reports removal of the unused gateway runtime through a verified dependency fork in `84d38b8d`; [implementation report](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6001938330). Independent review and the matching Snyk/final-binary evidence remain pending. Dependency and linkage regression gates must stay enforced. [QEMU harness review](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6001710160) confirms the SSH/first-ready dispatch fixes but requires structured backup validation and measured≤5s. Opus owns remaining integration/build/QEMU; ASTRA will qualify newly retained exact bytes with the reconciled frozen controller. **No newly qualified production OVA, merge or release.**

**Opus update: `7e53720d` cannot close production. The exact-byte scan found three fixable gaps ([findings](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6066613505)). The replacement head is `3a025d06`; its candidate OVA is building. [Coordination note](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6067383186).**

**Replacement `3a025d06eb6a0b025ad9c61371949e3d9bdd90e7`** (= `7e53720d` + scan closeout):
- The OVA ships the snapshot's newest kernel only (6.8.0-146 at snapshot `20261002T120000Z`). The build refuses a held-back or second kernel.
- snapd is purged and pinned out. `lxd-installer` is kept, because `ubuntu-server` depends on it.
- Compose 5.6.0.
- The runtime `apk upgrade` layer is never replayed from cache.
- The Deep gate fails on any fixable OS-package finding at any severity.

**CI:** Fast and Deep gates green; Snyk 0. The new OS-package step reports 0 Alpine findings.

**Image:** Deep run 37829233536, tar `284c28f3…`, id `sha256:0fdc5513…`.

**In progress:**
- Lab run 37831230971: candidate OVA, QEMU recovery/H (esxi12), adoption, F-DISK, and a booted-guest engine-surface probe.
- Next: an exact-byte scan of that OVA and image. It adds govulncheck extract mode, a pclntab function inventory with positive controls, and source-mode reachability on the exact upstream engine revisions.
- Then complete per-finding dispositions.

**Retained for comparison:** `7e53720d` (OVA `578ea6b8…`, artifact 11562703124) and its unrestricted scan (artifact 11570597891).

**Still open:**
- Replacement QEMU and scan.
- Dispositions.
- ESXi lifecycle/recovery of the replacement (ASTRA).
- Boot-console proof.
- Vendor OIDC interoperability.
- `[F] guest-content` reference, after ASTRA qualifies the replacement.
**No merge or release.**

The completed b579 LAB evidence below remains historical evidence, not production acceptance.

### Frozen revision
`feat/onprem-appliance-readiness` @ **`b579ca28c9d936e9141292ce5ec564a26feeae86`**. It contains the previous candidate `4f27d945` plus the fixes for the Codex review of that head; nothing else.

| Commit | What it fixes |
|---|---|
| `ab5b7236` (P1) | `culvert-net` restores the previous netplan file when `netplan apply` fails. Before, only a `generate` failure did, so first boot's "stays on DHCP" was false and the new static config could take effect on the next boot. |
| `96381e47` (P1) | Identity reset replaces the `culvert` password hash and removes the one-time credential record. Before, clones kept the source VM's console login. The script now **powers off itself**, because sudo can no longer authenticate after the reset. |
| `f0492528`, `18ef7ec1` (P2) | A non-durable dispatch (`durable:false`) now returns its `resume_context`. A test resumes from that context alone after the record is gone. The Release Management dialog shows the warning and the recovery context instead of a success toast. |
| `b579ca28` | The yara lazy-worker test counts worker starts instead of every goroutine in the process. That count made the Deep shuffle-order (determinism) check fail even though no worker had started. A control test is added. |

The earlier closeout content is unchanged:
- catalog lineage and the Release Management upgrade path;
- the 400 text/plain contract;
- damaged-state recovery;
- first-boot ordering;
- the restore-lock, CodeQL and gitleaks fixes;
- the CA-rotation toast.

### CI on `b579ca28` — every workflow green
Fast PR Gate, Deep PR Gate (incl. determinism and the console/appliance suites), QA, Security, API Governance, API Contract, CodeQL, the catalog/agent E2Es and the install lifecycle E2E all passed.

**Appliance Install → Catalog Update E2E** (real Release Management API, empty agent ledger) passed on this head as well. It covers:
- missing-proof and mismatched-proof refusals, before any mutation;
- upgrade v1→v2;
- reconcile after the Control Plane is recreated;
- automatic rollback after a failed health check;
- signed rollback;
- upgrade v1→v3 on a fresh agent, skipping two releases;
- refusal of tampered, expired and below-floor catalogs.

### Artifact — handed to LOCAL-ESXI
| | |
|---|---|
| OVA | `culvert-appliance-1.0.260-candidate.gb579ca28c9d9-ubuntu-24.04.ova` |
| **sha256** | **`1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775`** |
| Download | Artifact **11315044688** `appliance-lab-ova-candidate-b579ca28c9d9`, run **37235713308** (expires 2026-10-18): `gh run download 37235713308 -R KidCarmi/Culvert -n appliance-lab-ova-candidate-b579ca28c9d9`, then `sha256sum -c *.ova.sha256` |
| Source | Guest `build-info.json`: `git_commit` = `b579ca28…`, `git_dirty: false`. App, bundled agent, console and provisioning all come from that one commit, with no provisioning drift. |
| Image | Deep run 37234612592, `culvert-image.tar` sha256 `ec9ae4071339f0f0dda103765ae7aae2667c1bad08e9996814dd2f12d45aef61`. Running image ID (OCI index digest) `sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47`. Stamp `v1.0.260-candidate.gb579ca28c9d9`; proxy and agent report the same version. |
| Evidence | Artifact 11315657399 `appliance-lab-evidence-candidate-b579ca28c9d9` |

The OVA was built and retained before boot. It is a candidate build, not a release; nothing was published.

### QEMU qualification of those exact bytes — run 37235713308: **71 pass / 0 fail / 1 blocked**
- **OVA integrity:** sha256 and every `.mf` digest verified. The disk chain uses the OVA's own read-only VMDK.
- **First boot:**
  - Completed 57 s after power-on.
  - Operator SSH works with the key delivered through OVF.
  - A one-time console password is printed. PAM login forces a password change, and only then is `sudo` allowed.
- **Access boundary:** the restricted operator commands, port forwarding and scp/sftp are refused. Local-admin SSH is refused, and `sudo` without a password is refused. The effective sshd policy was verified.
- **Setup:** the bootstrap APIs return 403 without the setup token. Setup and admin login succeed with it. Demoting an admin takes effect immediately on their open session.
- **Enforcement:**
  - Default deny with real egress: example.com 403 → rule → 200; example.org stays 403.
  - The real ClamAV sidecar is ready.
  - The UT1 category sync completed, and a category rule blocks (403; 301 without it).
- **Agent and restore:**
  - The agent is installed at the same version as the proxy and is reachable.
  - A backup was created and listed, and the restore dry run passed.
  - A live restore commit is refused while the stack runs; the **actual offline restore** succeeded.
- **Signed update/rollback:** an unsigned apply gets 403 "signed release proof required". The signed upgrade and the signed rollback both succeeded. These use a test-only registry and fixture keyring, never part of the OVA.
- **OS update:** kernel 6.8.0-142 → 6.8.0-146; the stack was back 31 s after the reboot command. Docker stayed held. `culvert-stack-resume` took both locks.
- **After the reboot:** login, policy, enforcement, CA, category data, backup, the restored policy and the image identity all persisted, and first boot did not re-run.
- **Blocked [4b] portal-cookie replay:** this lab has no identity provider. CI covers it with `TestUISessionRole_RejectsReplayedPortalCookie`.
- **Informational [F] guest-content:** compared against a superseded candidate's fingerprint. It is a diagnostic only, run in its own lab directory, and is not counted.

**Superseded, not for handoff:**
- `4f27d945` OVA `ce84809c…` (run 37228734706, 71/0/1): superseded by the Codex fixes.
- Intermediate build `fe96086a…` (run 37227368983): failed only on my wrong image-ID expectation.

Both are retained as lab evidence only.

Not qualified by QEMU (ESXi's to qualify):
- vSphere import and the guestinfo OVF transport;
- VMware Tools and LSI SCSI;
- the real tty1 console;
- reboot timing on ESXi (552 s on an earlier candidate);
- the default-credential PAM login on a fresh import;
- **the new identity reset → power-off → clone path**.

### LOCAL-ESXi qualification — completed with preserved failures and blockers

[Integrated ESXi report](https://github.com/KidCarmi/Culvert/blob/94dc9d213b259ae723f9997121d4bd29aa0abfa5/docs/appliance/esxi-b579ca28-20261005.md) · [aggregate evidence](https://github.com/KidCarmi/Culvert/blob/94dc9d213b259ae723f9997121d4bd29aa0abfa5/docs/appliance/evidence/local-esxi-b579ca28-20261005.json) · [download exact OVA](https://github.com/KidCarmi/Culvert/actions/runs/37235713308/artifacts/11315044688) (expires 2026-10-18).

- **OVA SHA256:** `1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775`.
- **Unchanged source:** `b579ca28c9d936e9141292ce5ec564a26feeae86`.
- **Image:** `sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47`.
- **Final executed controller:** `55444fcb41c55fe70182deb2be6df677e73de40b`, reconciled with shared lab `a2db201b`. Report-only commit `94dc9d21` is not a new tested controller. #1536 now contains the completed report and updated description. Earlier frozen phases and stopped attempts remain recorded; no running checkout edits.

| Result | Evidence / boundary |
|---|---|
| **PASS — lifecycle** | Exact import/default PAM forced change; read-only operator and admin-SSH/auth refusals; setup/enforcement/feed; matching agent; backup/dry run and guarded actual restore; real-verifier signed update/rollback; OS update to kernel 6.8.0-146; both-lock resume and reboot persistence; all 12 independent postchecks. Fixture trust stayed outside the OVA. |
| **PASS — static-network P1** | Real static apply succeeded then injected failure triggered rollback. Original configuration restored; matching network samples at 2.162/4.165/6.179 seconds. After reboot, configuration and usable networking persisted. The initial immediate-route failure remains recorded; no zero-outage claim. |
| **PASS — identity P1** | Reset automatically powered off. Fresh boot of the same owned VM generated a new console credential, machine ID and SSH host key. Old password failed real PAM; superseded operator key was refused with the new host key independently pinned. Same-VM fresh boot, not simultaneous cloning. |
| **PASS — fresh recovery** | Source VM **and backing disks deleted first**. Distinct unclaimed import of the exact OVA, default PAM login, no operator key or web setup. Encrypted dry run and root-CA guard passed; actual authenticated offline restore committed from backup plus separately retained secrets. Original admin, CA, policy, enforcement, agent version and category results matched. Both owned VMs are now deleted; private evidence retained encrypted. One-VM / 2-vCPU / 4-GiB / 40-GiB limits enforced. |
| **FAIL — preserved observations** | Two enrollment observations, initial immediate network availability assertion, and historical backup RPC deadline failure (configured 10 seconds; elapsed unmeasured) remain in evidence. Later successes do not erase them. |
| **BLOCKED / unresolved** | No-IdP portal replay; historical-log recovery (logs excluded from this backup); unsupported direct-agent diagnostic identity; cause of the historical backup timeout and exact attribution of the old 597-second reboot. Controller precheck interruptions remain recorded. |

**Timing:** independent readiness returned **530.844 seconds after intent**; guest systemd startup was **466.180 seconds**. The shared 565-second figure includes a later network-persistence check. The first post-reboot product backup listing passed in **4.359 seconds**, HTTP 200 / available=true. Critical chain, service times and ESXi storage samples are retained. Elevated storage latency is concurrent evidence, **not established causation**; historical 597 seconds cannot be treated as pure guest boot or directly compared with the differently scoped 565-second figure.

**Access on a new import:** use the VM console's one-time credential, F2 and required password change; wait for provisioning to complete. Open **`https://<guest-address>:9090`** and obtain the initial setup token through authenticated console setup access. The lab UI certificate is self-signed. Operator SSH requires its key and is read-only; recovery uses the authenticated local console. The test VMs were deleted, so there is no active lab URL or shared password. Backup password and CA/log passphrases require separate custody.

**Disposition:** F-DISK-1 stays OPEN; ClamAV pcre2 and scanner decisions below are unchanged. Recovery-secret reminder/reveal UX remains unbuilt; this run qualified the existing authenticated recovery procedure. No merge, release or production approval.

### Historical b579 scanner inventory — superseded for production acceptance
- **Snyk (1 medium):** GO-2026-5932, `golang.org/x/crypto/openpgp`. No fixed release exists, and neither module compiles `openpgp`.
- **CodeQL (4 medium; the check passes):**
  - Three are in vendored `third_party/crewjam-saml/samlsp`. That middleware is never mounted, and a structural test enforces it.
  - One is the C2 log line at `ui_metadata_enforcement.go:530`. Every value on it goes through `sanitizeLog`.
  - No historical findings were muted. Current production acceptance requires the updated inventory and concrete resolution above.

### Historical b579 handoff limitations — current production blockers are above
1. **ESXi execution complete; unresolved findings remain.** Both P1 confirmations, default PAM, lifecycle and fresh-appliance recovery passed as scoped above. Historical availability failures and boot/timeout causal attribution remain unresolved; simultaneous clone and historical-log recovery are not qualified.
2. **Owner review** of #1528 at `b579ca28` and of this evidence, plus the Snyk and CodeQL dispositions.
3. **Owner decision (comment 5983281639):** the setup reminder and authenticated recovery-passphrase reveal UX are not built. Fresh-appliance DR using the encrypted backup plus separately held secrets **passed through the existing authenticated procedure**; historical logs are outside that archive. The custody documented in `first-boot.md` and the recovery runbook still applies.
4. **Open and outside this closeout:** **F-DISK-1** (reproduced again in run 37235713308: the proxy died during a full-disk write), the **ClamAV `pcre2`** decision, broad fault/HA/DR qualification, and release approval.

Any further change to #1528 means a new artifact and re-qualification; this one is then superseded here.

---
_Generated by [Claude Code](https://claude.ai/code)_

### Exact 7c ESXi maintenance recovery — three measured cycles complete

With retained OVA SHA256 `4b8ae484fd8b9bda8dfc12512e9e0b489edcc96c7590824f22276a19dc6b7a05`, source `7c7b29ee3be40af6a0809c73ad04d4337303263d`, continuation controller `a098172270d6492e8c9626f342f600fe7df1f4d7`: **PASS** at **63.625 / 66.687 / 69.531 seconds**, against the predefined 120-second budget. First post-reboot backup listings completed in **0.859 / 0.750 / 0.828 seconds**. All three include real allowed/blocked traffic, current ClamAV endpoint/PONG coverage, guest lock/persistence proof, clock correlation and ESXi host/storage/VM metrics. These are maintenance cycles; first-install observations remain separate. Scanner-outage, browser auth campaign, identity-reset and source-absent recovery are continuing; this is not merge/release approval. Existing scanner disposition blockers and historical failures remain open/preserved.
