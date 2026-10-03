# Culvert on-prem appliance — pilot readiness package

Start with **`readiness-report.md`** (what is implemented, executed,
blocked, unsupported — with SHAs and digests). Then:

| Document | Purpose |
|---|---|
| `requirements-matrix.md` | The ONE declared pilot configuration: confirmed facts, provisional assumptions, customer questions, blockers |
| `customer-questionnaire.md` | Questions for the customer (each maps to a matrix row) |
| `hypervisor-install.md` | OVA import on the supported hypervisor, sizing, networking |
| `first-boot.md` | Operator journey: import → boot → address → storage/identity → first admin → TLS → policy + enforcement check → reboot verification |
| `upgrade-runbook.md` | Application upgrades through the signed catalog + maintenance agent; refusals; host components |
| `upgrade-transition-matrix.md` | Supported predecessor floor, executed predecessor upgrades, downgrade posture |
| `recovery-restore-runbook.md` | Image rollback vs persistent-state restore vs disaster recovery; interrupted operations; failure matrix |
| `state-and-key-custody-matrix.md` | Every persisted file: preserved on upgrade, in backup, restored, separate custody |
| `os-maintenance.md` | Guest OS / Docker / container-base patching, cadence, ownership, reboot procedure |
| `scanning-outage-posture.md` | What happens when the ClamAV sidecar is down (measured: fail-open mid-run, no start at boot, upgrades refused), how it is surfaced, the recommended pilot policy |
| `vsphere-qualification.md` | One copy-paste ESXi/vSphere procedure for the candidate OVA: import, first boot, enforcement, agent, OS update + reboot (kernel before/after), persistence |
| `ova-build.md` | Reproducible OVA build record (pinned inputs, tool versions, digests) |
| `sbom-cve-evidence.md` | SBOMs and CVE scans with tool/database timestamps and coverage limits |
| `astra-evidence.md` | Appliance-track executed/blocked evidence |
| `evidence/` | Harness reports from this PR's qualification runs |

Harnesses: `test/e2e/appliance/lifecycle-qualify.sh` (install, real
predecessor upgrade, restore, fresh-volume disaster recovery, interrupted
restore, full-disk restore), `test/e2e/appliance/agent-qualify.sh`
(maintenance-agent update flow, duplicate requests, agent kill + reconcile,
registry-less rollback), `test/e2e/appliance/upgrade-enospc-qualify.sh`
(upgrade onto a full, size-bounded Docker host) and
`test/e2e/appliance/clamav-image-qualify.sh` (real clamd, PCRE path, JIT
guard, clamd-down posture).
