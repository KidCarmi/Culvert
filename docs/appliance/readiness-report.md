# On-prem appliance readiness report (Tambour pilot evaluation)

**Branch:** `feat/onprem-appliance-readiness` · **Baseline:** `3fcc07e7ab5d4d19e6cadc8bb63b682f3af` (origin/main, the SHA the prior review examined) · **Final SHA:** see the PR head (the evidence tables below name the exact commit each artifact was built from).

This report separates **implemented**, **tested** (and how: unit gates, executed Docker qualification against real images, CI), **blocked** (exact prerequisite), and **unsupported** (deliberately out of the pilot). Nothing here claims production readiness; the product document deadline is not a deployment date.

## 1. Material concerns — classification

| # | Concern (prior review / prompt) | Classification | Evidence |
|---|---|---|---|
| A | Restore cannot commit when `/data` is a mount point (every container deployment) | **Confirmed, fixed** | `restore_mountpoint_test.go` pinned the failure; now inverted (passes as root); `restore_inplace.go`; harness scenario D on a real named volume |
| A2 | Restore needed application consistency / quiescing | **Confirmed, fixed** | proxy-held `.culvert.lock`; commit refused while running (harness D) |
| A3 | Interrupted restore recovery was a manual `mv` on a layout that could not exist in a container | **Confirmed, fixed** | journal + explicit `--recover-restore --confirm=revert|complete`; harness E |
| B1 | Journal recorded interruptions; reconcile decision table unwired; corrupt record fatal | **Confirmed, fixed** | `cmd/culvert-maint/internal/server/reconcile_startup.go`; unit gates; agent harness F3 (agent SIGKILLed at the restart stage ⇒ `reup` + tag hazard surfaced, converged only via `POST /v1/reconcile`) |
| B2 | Rollback started with a registry pull | **Confirmed, fixed** | local-first `rollback_pull`; `TestRealDocker_LocalFirstRollbackSurvivesRegistryOutage`; agent harness F4 with the registry stopped |
| C1 | `min_upgrade_from` parsed, never enforced, never populated by CI | **Confirmed, fixed** | `checkTransition`, `release_transition_policy.go`, `TestDispatch_Transition_*`; CI stamps the floor |
| C2 | Downgrade dispatch allowed | **Confirmed, fixed** | refused unless break-glass `allow_downgrade` |
| C3 | Real-predecessor transitions untested (CI used relabeled same-source builds) | **Confirmed, addressed** | harness B/C executed v1.0.250, v1.0.258, v1.0.259 → this build with seeded state; `upgrade-transition-matrix.md` |
| D1 | Backup scope / key custody undocumented; archive ≠ recoverability | **Confirmed, addressed** | `state-and-key-custody-matrix.md`; restore verified by boot + login + policy + enforcement + `ssl_inspection=ready` |
| D2 | Root CA silently re-minted after a restore lacking `ca.bundle`; restore could leave no admin | **Confirmed (new finding), fixed** | `--accept-root-ca-change` guard; no-admin refusal; gates in `restore_inplace_test.go` |
| D3 | Single-node compose writes cluster CA/state to ephemeral `/app` | **Confirmed, recorded (not fixed)** | irrelevant to the single-node pilot (no DPs); gap for clusters — follow-up |
| E1 | Control-plane replacement loses the dispatch; GUI stops polling | **Confirmed, fixed** | `release_dispatch_persist.go`; GUI retry; `release_dispatch_persist_test.go` |
| E2 | Duplicate requests / operation identity across agent restart | **Confirmed, fixed** | persisted idempotency index; agent harness F2/F5 |
| E3 | Host components (compose, agent, sudoers) not updated by an image swap | **Confirmed, documented** | `upgrade-runbook.md` §Host components; installer is idempotent and upgrades the agent in place; no behavioural change needed for the qualified window |
| F1 | Fresh install is default-ALLOW passthrough; diagnostics claimed default-deny | **Confirmed, fixed (surfaces) + pilot posture** | `/ready` `policy_posture`, diagnostics text; appliance passes `CULVERT_DEFAULT_ACTION=deny`; existing installs unchanged |
| F2 | `/ready` 200 hides "setup not done" and "not enforcing" | **Confirmed, fixed** | `setup_complete` + `policy_posture` rows; `/health` fields; `healthcheck_posture_test.go` |
| F3 | Unauthenticated setup window (TOFU) | **Confirmed, mitigated, not closed** | appliance firewall + console banner; setup token is follow-up FO-4 |
| F4 | Shared admin password / reusable keys | **Incorrect (no such credential exists)** | `docker-compose.yml`, installer; harness A `no-default-admin-credential`; Grafana `changeme` exists only in the optional monitoring stack |
| F5 | Proxy requires client auth once an admin exists (407 for every client) | **New finding** | the pilot posture (unauthenticated clients, policy by destination) needs `defaultAuthOutcome=Exempt` set explicitly — now step 8 of `first-boot.md`; harness sets it and proves 200/403 |
| G1 | No OVA / provisioning / OS maintenance existed | **Confirmed, implemented (build), boot BLOCKED** | `appliance/`, `ova-build.md`, `astra-evidence.md` |
| G2 | OS vulnerability maintenance undefined | **Confirmed, implemented (design + tooling)** | `os-maintenance.md`, `appliance/os-maintenance/`; SBOM/CVE evidence with timestamps |
| H1 | CI lifecycle workflows are advisory and synthetic | **Confirmed, partially addressed** | real-image Docker harnesses added under `test/e2e/appliance/`; they are NOT yet wired as a CI gate (needs a runner with Docker + root; the privileged fast-gate test now runs the inverted mount-point test) |

## 2. Implemented (code) — commits on the branch

See `git log origin/main..HEAD`. Each commit message carries the why.

## 3. Executed qualification (this environment: Docker 29 on a 4-vCPU container, no KVM, egress through a TLS-intercepting proxy)

Evidence files: `docs/appliance/evidence/lifecycle-REPORT.md`, `docs/appliance/evidence/agent-REPORT.md` (digests of every image inside).

| Artifact under test | How built | Note |
|---|---|---|
| `culvert/proxy:dev-final` | this branch's Dockerfile, built locally with the sandbox CA injected into the alpine stages so `apk`/`go mod` could verify TLS through the intercepting proxy — **a local qualification build, not the CI artifact**; the CI image for the PR head is the Deep PR Gate's `culvert-image-amd64` artifact | functional behaviour identical; the injected CA only affects the image's trust store |
| `ghcr.io/kidcarmi/culvert:v1.0.250 / 258 / 259` | real published releases (amd64 by digest) | predecessor side of the transition matrix |
| `culvert-maint` | built from this branch | privilege_mode=docker_group_lab (no systemd here); sudoers mode is exercised by `install-lifecycle-e2e.yml` in CI |

Scenario summary (pass/fail counts are in the evidence files): A fresh install → setup → posture → actual allow/block → restart; B/C three real predecessors; D backup → mutate → refused-while-running → offline restore → verified; E interrupted restore → refused boot → explicit complete → verified; F1–F5 agent apply, duplicate, kill+reconcile, offline rollback, restart idempotency.

## 4. Blocked (exact prerequisite)

| Item | Why blocked here | Prerequisite / command |
|---|---|---|
| OVA import + first boot on a hypervisor | no KVM, no hypervisor in the build environment | see `astra-evidence.md` (vSphere import / `qemu-system-x86_64 -enable-kvm` commands) |
| Real ClamAV sidecar (signature download, scanning) | the sidecar's HTTPS download cannot verify TLS behind the sandbox's intercepting proxy; proxy never becomes healthy | run `lifecycle-qualify.sh` with `CULVERT_QUALIFY_REAL_CLAMAV=1` on a host with direct egress |
| OS patch + reboot qualification | needs the booted appliance | `os-maintenance.md` procedure on the booted OVA |
| golangci-lint on the root module | installed linter is built with Go 1.25 and cannot analyze a go1.26 module (panics) | CI's diff-scoped lint in the Fast PR Gate |
| Insufficient-disk-space injection | not injected in this run | restore stages before the swap (fails before any move); upgrade pull fails before the tag; a loop-device quota test is a follow-up |
| CI image artifact qualification | the Deep PR Gate builds the amd64 image only after the PR exists | re-run both harnesses against the downloaded `culvert-image-amd64` artifact and attach the reports |

## 5. Unsupported (out of the pilot, deliberately)

HA / CP-DP clusters, mixed-version clusters, offline/air-gapped first boot, private registry mirrors (code paths exist, unqualified), transparent Kerberos SSO, downgrades (except the frozen schema-v2 predecessor), arm64 OVA, hypervisors other than vSphere/ESXi (VirtualBox/KVM import documented, unqualified).

## 6. Follow-up gaps (recorded, not in this PR)

- Setup bootstrap token for the first-time setup window (FO-4).
- Single-node compose: pass `-cluster-db /data/cluster.json` so cluster CA/state persist (needed before any CP/DP topology).
- Wire `test/e2e/appliance/*.sh` into a privileged CI lane and add the real-ClamAV variant.
- GUI surface for the agent's `interrupted_operations` / `POST /v1/reconcile` (today: API + runbook).
- `Status.LastOperation*` on the agent unpopulated; P0-C bind-first reconcile not implemented (startup reconcile is synchronous, `stage_timeout`-bounded).
- `release_dispatch_state.json` and the data-dir lock file are new entries under `/data` (excluded from backup by design); `config_surfaces` registry untouched (neither is a config surface).
