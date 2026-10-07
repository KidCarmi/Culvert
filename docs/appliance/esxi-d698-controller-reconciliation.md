# d698 ESXi controller reconciliation

This is a lab controller change, not qualification evidence or a production release.
The execution checkout is frozen separately before any VM action. Keep earlier
b579 campaigns and failures intact; their narrow continuation and initrd helpers
are not enabled for this candidate.

## Exact candidate

`candidate-identities.py` admits only complete reviewed source/OVA/image tuples.

- Source: `d698a69c5192588d5ed3a85a9f7cd9009fb59b31`
- OVA SHA256: `9e8e067db5f8ee3c6aa55ac3127b008a7fe612dcca89d1cf004ab3ac8b63d1aa`
- App image: `sha256:2c03833c9641a1e24dc5a66b3faa4f0695ac44cdeac931018b9b744be301660e`
- ClamAV image: `sha256:86d71850ea1a01fdbb9c06b82c929d4485718c1d80f19a0824c2c454c2bce97e`

The parent must verify the downloaded OVA hash before import and retain those
bytes. Registry preparation, P1 regression probes, reset readiness, encrypted
recovery export/import and source deletion select the same exact candidate.
Guest P1 probes additionally bind the reviewed network and reset helper hashes.
Unknown or mixed identities are refused. The signed fixture's real Go verifier
sources are byte-identical between b579 and d698; fixture provenance explicitly
names the selected candidate. Private keys and test registry trust remain private
lab fixtures and never enter the retained OVA.

## Shared harness and access boundary

The shared library is refreshed from
`5cae2d5df32980deec3234d681fe915e52d1337b` of `test/appliance-lab`.
`shared-harness-provenance.json` records upstream and locally adapted LF hashes.
Only the three explicit ESXi hooks and controlled Windows AF_UNIX refusal differ
from upstream. The freeze manifest records actual runtime bytes, including any
platform newline representation. Offline tests reconstruct and hash upstream.

The optional pre-signed hook runs the stronger guarded actual restore. The old
shared unsafe restore remains disabled. Network observations remain before and
after the maintenance reboot. Operator SSH/SCP/SFTP and timeout-wrapped refusals
retain pinned host keys. Privileged work uses authenticated local tty1 PAM/sudo;
there is no administrative SSH or forwarding assumption. Direct management and
proxy reachability are required.

The launcher accepts one or two approved console font paths separated by the
platform path separator (semicolon on Windows), resolves each independently and
checks its pinned content hash. Decoding remains exact; unknown or ambiguous
credential glyphs are never repaired.

## Acceptance sequence and evidence

1. Freeze the controller and external tool/font hashes. Import the retained OVA,
   bootstrap once, enroll the operator and pin its host key through local recovery.
2. Prepare disposable signed baseline/target evidence with the selected source.
   Run the main access-aware lifecycle, including auth refusals, recovery-secret
   custody, guarded actual restore, real signed apply/rollback and reboot checks.
3. Run three independently recorded maintenance cycles using the existing
   sampler, dispatch, probe and evidence-controller helpers. Preserve the 120s
   acceptance deadline, three consecutive healthy samples, current-boot and
   direct-PONG/container binding. Run the separate ClamAV outage fixture, then
   complete encrypted source escrow, identity reset, source deletion proof and
   fresh-VM restoration under the one-VM limit.

Each first-ready backup probe starts once in the background at the first healthy
completion. It obtains its own fresh post-reboot session (bounded to 5s), then
performs exactly one listing (separately bounded to 5s), requiring availability,
consistent count and the expected archive identity. The original result persists
through readiness-count resets and later success. Login and listing times are
recorded separately; an unrounded listing duration above 5s fails. Existing
pre-reboot sessions cannot satisfy this check and no retry replaces it.

The shared custody check compares the authenticated root reveal against current
local recovery values and records only booleans/key names, plus unprivileged
refusal. Console captures, passwords, tokens, recovery exports and raw evidence
remain private. Backup encryption credentials remain distinct from CA/log
passphrases; the QEMU baseline backup being unencrypted does not substitute for
the later encrypted source escrow.

`qualify-clamav-outage.py` is a separate bounded fixture for this exact app and
sidecar. It uses both maintenance locks, unique clean/EICAR bodies and exact
responses, checks readiness during the outage, and restores the container and
policy in a guarded finally path. A failed/pending cleanup blocks further work;
a cache-only HTTP health response cannot prove antivirus readiness. Do not run it
concurrently with maintenance, backup/restore or another console operation.

F-DISK and ClamAV disposition must be reported from actual retained run evidence.
Offline controller tests do not qualify the guest or settle scanner findings.

## Offline validation

The ESXi unittest suite passed 293 tests with two environment-dependent skips,
including synthetic identity, custody, timing, PONG and ClamAV outage cases.
PowerShell syntax and the actual isolated two-font launcher block passed with
both approved fonts. Bash syntax checks passed for the refreshed shared library
and access-aware wrapper. No VM calls were made during this reconciliation.
