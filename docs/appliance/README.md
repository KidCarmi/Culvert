# Culvert on-prem appliance readiness (pilot track)

Status: IN PROGRESS. This directory is the single home for the on-prem
appliance pilot deliverables. Nothing here claims production readiness;
`readiness-report.md` states what is implemented, tested, blocked and
unsupported, with evidence.

Baseline: `origin/main` at `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`
(the SHA the prior source review examined; no drift). Shared integration
branch: `claude/onprem-appliance-readiness-bshxxw` (one branch, one PR).

## Ownership and integration protocol

| Track | Owner | Owned paths |
|---|---|---|
| Upgrade compatibility, migrations, `min_upgrade_from` | Fable | `release_*.go`, `upstream_downgrade.go`, `data_dir.go`, `admin_settings.go`, `docs/appliance/transition-matrix.md`, `docs/appliance/upgrade-runbook.md` |
| Backup / restore / rollback / interruption recovery | Fable | `restore*.go`, `backup*.go`, `cmd/culvert-maint/**` (Go), `docs/appliance/recovery-runbook.md`, `docs/appliance/state-backup-key-custody.md` |
| Application initialization + enforcement readiness | Fable | `healthcheck.go`, setup handlers in `ui_auth.go`, policy startup, `docs/appliance/first-boot-app.md` |
| Integration, final review, consolidated PR | Fable | `readiness-report.md`, `qualification-evidence.md`, `requirements-matrix.md`, `customer-questionnaire.md` (all under `docs/appliance/`) |
| OVA build + packaging | Astra | `appliance/**` |
| Guest OS, first-boot provisioning, host lifecycle | Astra | `appliance/**`, `scripts/install.sh` (host side), `packaging/**` (host components) |
| OS patching + vulnerability maintenance | Astra | `docs/appliance/os-maintenance-runbook.md`, `docs/appliance/sbom-cve/**` |
| Hypervisor qualification + installation docs | Astra | `docs/appliance/install-runbook.md`, `docs/appliance/hypervisor-qualification.md`, `docs/appliance/ova-build.md` |

Shared files, edited only by agreement and integrated by Fable:
`Dockerfile`, `docker-compose.yml`, `.github/workflows/*`, `CLAUDE.md`,
`CHANGELOG.md`, `docs/operator/*`.

Shared interfaces:

1. First-boot provisioning (Astra) invokes the existing installers
   (`scripts/install.sh`, `packaging/culvert-maint/install.sh`). It never
   writes application state under `/data` directly and never mints
   application keys; the application mints its own identity on first boot.
2. Readiness contract (Fable): `/health`, `/ready`, `/ready?strict=1` on
   the proxy port and `/healthz` on the admin port. Console status
   reporting consumes these; it does not define its own readiness.
3. Maintenance agent: Fable owns the Go in `cmd/culvert-maint`; Astra owns
   the host install of the unit, sudoers, user and socket, and the
   update strategy for those host components.
4. The signed release catalog manifest (`min_upgrade_from`, image digest)
   is the only source of truth for supported transitions; the OVA records
   the exact image digest it ships.

Runtime coordination: Astra runs as a separate Claude session in the
`Culvert-dev` lab environment (unrestricted egress, Docker), checked out
from the shared branch at the baseline SHA, pushing to its own branch
`claude/onprem-appliance-astra`. Its status channel is
`docs/appliance/ASTRA-STATUS.md` on that branch. Fable is the sole writer
of the shared branch: it fetches, reviews, requests corrections, and
merges Astra's branch in focused commits. No force-push, no history
rewrite.
