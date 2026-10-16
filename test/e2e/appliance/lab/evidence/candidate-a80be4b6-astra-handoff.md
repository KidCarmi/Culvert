# ASTRA ESXi handoff — candidate a80be4b6 (admin-allowlist P1 + F-P2 1.5.4 sidecar)

**This candidate SUPERSEDES 9e34452677d7 (OVA 47cb50f0…).** It is a superset:
it carries the F-P2 1.5.4 sidecar bump AND the owner-P1 fix that preserves the
administrator threat-domain allowlist across fresh recovery (PR #1528 review
5547382867). Shipped build inputs changed (app Go bytes: `backup.go` +
`internal/threatfeed` + scanning startup wiring), so the prior OVA's
qualification does not carry over — fresh identity, built and qualified from
scratch.

**The baked sidecar is an INDEPENDENT 1.5.4 rebuild, not 9e344526's bytes.**
Its image id `b11e29c5` ≠ 9e344526's `dc96d2f2`, baked archive `9404b981` ≠
`39a0f7c8`, upstream `clamav/clamav:1.5` index `638d9020` differs too (same
`pcre2-10.49-r0`). The reproducible build pins byte-identity *within* a run,
not *across* builds on different days — so F-P2 and the CVE scan are re-proven
on a80be4b6's own bytes below, never inherited.

## Artifact to qualify

| field | value |
|---|---|
| OVA | `culvert-appliance-1.0.263-candidate.ga80be4b61ff7-ubuntu-24.04.ova` |
| OVA sha256 | `394788af5b839c8ff895f8e36b67ad0ca89d3c4f6ed9c71d4112416d6626ebe0` |
| OVA artifact | `appliance-lab-ova-candidate-a80be4b6`, id 12047875462, lab run 38903245843 |
| source | `a80be4b6…` = PR #1528 head `99e25cec` merged into base main `dec66e1b` (the commit the deep-gate image was built + stamped from; what ships when #1528 merges) |
| app image id (manifest) | `sha256:ae009528da2c7c17f76be8177cb81d88b4641bbcd25d76b065071de9201f6d92` |
| app image tar sha256 | `fcbaaa89dfd73502a121a4ef546f3afcb95cfb08729df94dbcc11c39ff4fa502` (CI image run 38898100091) |
| sidecar | `culvert/clamav:1.5.4-culvert.1`, image id `sha256:b11e29c503a4acb1c0196db9ad771d2cf49de8991b7c3be1a592292501ab6c0e`, baked archive `sha256:9404b981…` |

## Already proven in the QEMU/Docker lab (no ESXi needed)

- **Full qualify PASS** (run 38903245843, failures 0): boot, operator SSH,
  first-boot, setup-with-token, RBAC demotion, `/ready` ca+policy+clamav,
  category enforcement, agent + backup + offline restore, encrypted history
  recovery. **F-DISK-1 PASS**.
- **Admin threat-domain allowlist SURVIVES recovery** (same run, owner P1): a
  distinct admin marker `allowlist-survives-marker.example` is set BEFORE the
  backup and asserted present via GET WITHOUT being re-added, in BOTH
  `[6b] allowlist-survived-restore` (same-volume) and
  `[H] allowlist-survived-recovery` (fresh-volume: data volume destroyed,
  restored from an encrypted backup, log key rotated, rebooted). Custom
  entries + an explicit full clear are proven to round-trip by 6 engine unit
  tests (`internal/threatfeed/allowlist_backup_survival_test.go`). See
  `candidate-a80be4b6-allowlist-preservation.md`.
- **F-P2 CLOSED on a80be4b6's OWN sidecar** (lab run 38907420854): isolated
  reproduction — control 1.4.6 = 64 EICAR-to-bare-clean (bug
  reproduces), candidate-1.5.4-9e344526 = 0, **candidate-1.5.4-a80be4b6 = 0**,
  each under a hard verdict. Two independent 1.5.4 builds both answer
  wrong-cleans=0 — a direct answer to "a future rebuild is not guaranteed
  byte-identical."
- **Sidecar CVE scan CLEAN** (same run, ova-sidecar-scan): exact-byte Trivy of
  the 1.5.4 archive `9404b981` baked in THIS OVA — `severity-summary.json` = `[]` (0 findings, exit 0) (Deep-gate
  policy: no fixable HIGH/CRITICAL).

## What ESXi must repeat on THIS OVA

1. Boot on the real ESXi/vSphere topology (the lab proves QEMU/KVM only).
2. Recovery/reboot timing: **≥3 reboots, each ≤120s** to a ready-to-enforce
   state — the budget the prior candidates were held to. The allowlist fix and
   sidecar engine do not touch the restore/recovery path, but the OVA bytes
   changed, so the number is re-measured on the new artifact, not inherited.
3. Confirm the baked 1.5.4 sidecar reaches `/ready clamav ok` after boot with
   signatures fetched by the guest.
4. ASTRA's read-only source/restore equality check: the admin threat-domain
   allowlist saved before a backup must equal the restored state (it will
   record a mismatch, not repair).

Do not reuse 9e344526's ESXi result for this candidate. ASTRA's frozen
controller / retained OVA / guest for the 9e344526 (F-P2) and bad788e5 rounds
are untouched by this work.
