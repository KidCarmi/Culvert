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
| `ova-build.md` | Reproducible OVA build record (pinned inputs, tool versions, digests) |
| `sbom-cve-evidence.md` | SBOMs and CVE scans with tool/database timestamps and coverage limits |
| `astra-evidence.md` | Appliance-track executed/blocked evidence |
| `evidence/` | Harness reports from this PR's qualification runs |

Harnesses: `test/e2e/appliance/lifecycle-qualify.sh` (install, real
predecessor upgrade, restore, interrupted restore) and
`test/e2e/appliance/agent-qualify.sh` (maintenance-agent update flow,
duplicate requests, agent kill + reconcile, registry-less rollback).
