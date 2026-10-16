# ASTRA ESXi handoff — candidate 9e34452677d7 (F-P2 fix, 1.5.4 sidecar)

**This candidate SUPERSEDES bad788e5 (OVA 87c8ae61…).** The only shipped change
is the ClamAV sidecar engine 1.4.6 → 1.5.4 (owner-approved, closes F-P2 /
PSIRT-0035161972). Because shipped build inputs changed (the sidecar Dockerfile,
manifest.env and both compose files), the prior OVA's qualification does not
carry over — this is a fresh candidate identity, built and qualified from
scratch.

## Artifact to qualify

| field | value |
|---|---|
| OVA | `culvert-appliance-1.0.262-candidate.g9e34452677d7-ubuntu-24.04.ova` |
| OVA sha256 | `47cb50f08d09efac5b6a970cc71517598a8edbb75805cb4b55cc2271e81a5313` |
| OVA artifact | `appliance-lab-ova-candidate-9e34452677d7`, id 12038600454, lab run 38881775755 |
| source | `9e34452677d7` = PR #1528 head `6aa900cd` merged into base main `77c0c583` (the commit the deep-gate image was built + stamped from; what ships when #1528 merges) |
| app image id (manifest) | `sha256:8c306a51083f13c680de4b679884b90f51923b7b50c47192bcb2adb68161e9b3` |
| sidecar | `culvert/clamav:1.5.4-culvert.1`, image id `sha256:dc96d2f249d20a8a899fd1f965af18cd4cd54fe9f66d7a278199fd29195a4280` |

## Already proven in the QEMU lab (no ESXi needed)

- **Full qualify PASS** (runs 38887380422, 38889690485): boot, operator SSH,
  first-boot, setup-with-token, RBAC demotion, `/ready` ca+policy+clamav,
  category enforcement, agent + backup + offline restore, encrypted history
  recovery. **F-DISK-1 PASS**.
- **F-P2 CLOSED** (run 38890228477): isolated reproduction, control 1.4.6 = 60
  EICAR-to-bare-clean (bug reproduces) vs candidate 1.5.4 = 0 (fixed), each
  under a hard verdict.
- **Sidecar CVE scan CLEAN** (run 38892042087): exact-byte Trivy of the 1.5.4
  archive baked in THIS OVA, 0 findings at any severity.
- **Cache-bypass quarantine PASS** (run 38893232784, 9 [CB] checks): a cached
  clean verdict is refused AV-unavailable inside the quarantine window and
  re-scanned before re-cache — no bypass on the 1.5.4 engine.

## What ESXi must repeat on THIS OVA (the sidecar bump changed the OVA bytes)

1. Boot on the real ESXi/vSphere topology (the lab proves QEMU/KVM only).
2. Recovery/reboot timing: **≥3 reboots, each ≤120s** to a ready-to-enforce
   state — the budget the prior candidates were held to. The sidecar engine
   bump does not touch the restore/recovery path, but the OVA bytes changed, so
   the number is re-measured on the new artifact, not inherited.
3. Confirm the baked 1.5.4 sidecar reaches `/ready clamav ok` after boot with
   signatures fetched by the guest.

Do not reuse bad788e5's ESXi result for this candidate. ASTRA's frozen
controller / retained OVA / guest for the bad788e5 round are untouched by this
work.
