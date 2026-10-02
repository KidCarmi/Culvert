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
| `culvert/proxy:dev-final4` (earlier iterations `dev-final`, `dev-final3`) | this branch's Dockerfile, built locally with the sandbox CA injected into the alpine stages so `apk`/`go mod` could verify TLS through the intercepting proxy — **a local qualification build, not the CI artifact**; the CI image for the PR head is the Deep PR Gate's `culvert-image-amd64` artifact | functional behaviour identical; the injected CA only affects the image's trust store |
| `ghcr.io/kidcarmi/culvert:v1.0.250 / 258 / 259` | real published releases (amd64 by digest) | predecessor side of the transition matrix |
| `culvert-maint` | built from this branch | privilege_mode=docker_group_lab (no systemd here); sudoers mode is exercised by `install-lifecycle-e2e.yml` in CI |

Final run (image `dev-final4` built from commit `61faefc`, the last commit that changes the binary; harness as committed): lifecycle **72 checks passed, 0 failed** (`lifecycle-REPORT.md`, run 20261002T203546Z); agent flow **17 checks passed, 0 failed** (`agent-REPORT.md`, run 20261002T193735Z; note `F3`: the agent was SIGKILLed inside its restart stage, startup reconcile classified the record as `reup` with `tag_hazard=true` and did NOT act, `POST /v1/reconcile/{op}` converged it, a duplicate resolve answered 404). Earlier iterations of the same runs found and fixed harness defects only (compose project naming, cookie-jar scoping, the plain-HTTP registry that the agent's `docker manifest inspect` template correctly refuses, a Unix-socket path over 108 bytes) and one product usability defect (`--confirm complete` had to become `--confirm=complete`).

Scenario summary (pass/fail counts are in the evidence files): A fresh install → setup → posture → actual allow/block → restart; B/C three real predecessors; D backup → mutate → refused-while-running → offline restore → verified; E interrupted restore → refused boot → explicit complete → verified; F1–F5 agent apply, duplicate, kill+reconcile, offline rollback, restart idempotency.

## 3b. Cross-review — what the attack on the recovery assumptions found, and what changed

Two reviews ran against the PR head after the first qualification: an adversarial reviewer with write-free reproduction tests over the recovery paths, and the Codex PR review. Every confirmed finding is fixed on the branch with a gate that was verified failing against the pre-fix tree; nothing was closed by argument.

| # | Finding (severity as reviewed) | Classification | What changed | Gate |
|---|---|---|---|---|
| 1 | Agent boot auto-resolve RETIRED a journal record on absent Docker evidence: a failed `docker image inspect culvert/proxy:pinned` (daemon busy, deadline, sudoers gap) read as "tag not on target", so a real tag hazard became `noop(already_on_prior)` and the un-health-gated target would start at the next `compose up` with nothing left on `/v1/status` (HIGH) | Confirmed | a capture ERROR is `inputs_unavailable` (`running_capture_failed` / `tag_inspect_failed`); only "stack down" and "no such image" are facts; the record is kept and re-asked at the next boot | `TestReconcile_TagInspectFailureIsInputsUnavailable_NotNoop`, `…RunningCaptureFailure…`, control `…StackDownAndAbsentTagAreStillFacts` |
| 2 | `--recover-restore --confirm=complete` failed forever when the staging dir was already removed (kill between staging removal and journal retirement); a journal naming a missing bak dir failed both directions (HIGH/MED; also Codex P2) | Confirmed | recovery treats an absent staging/bak dir as a valid current state; the commit path stays strict | `TestRecoverRestore_Complete_StagingAlreadyRemoved`, `TestRecoverRestore_MissingBakDirIsNotFatal` |
| 3 | The data-dir lock was one-directional: a proxy started while a commit held it (operator, `restart: unless-stopped`, an agent `compose up`) warned, passed the journal guard (the journal is written after the lock) and served a half-evacuated `/data` (MED/HIGH) | Confirmed | the proxy takes the lock BEFORE the interrupted-restore guard and a positively held lock is FATAL; an uncreatable lock stays advisory | `TestHoldDataDirLock_RefusesWhileCommitHoldsIt` |
| 4 | Nested-mount refusal blind through a symlinked data dir (`CULVERT_DATA_DIR` only requires absolute+clean); evacuation hit EBUSY mid-way (MED) | Confirmed | `nestedMountPointsUnder` resolves symlinks (mountinfo reports real paths); an unresolvable dir is an obstacle, not "no mounts" | `TestNestedMountPointsUnder_ResolvesSymlinkedDataDir` (root; real bind mount) |
| 5 | A resolve refused at admission (lock held / agent busy) consumed one of three attempts and cleared another request's in-flight marker; a CP retrying against a busy agent drove every record to `manual_required` (MED/LOW) | Confirmed | attempt refunded on a refused launch; marker cleared only by the request that set it | `TestReconcileResolve_RefusedLaunchDoesNotChargeAnAttempt` |
| 6 | `OverrideInterrupted` never updated the persisted idempotency index, so an adopted op re-materialised as `failed(agent_restart_interrupted)` after the next agent restart (LOW; also Codex P2) | Confirmed | the override persists the terminal outcome by op id | `TestOverrideInterrupted_PersistsReconciledOutcomeAcrossRestart` |
| 7 | `/ready` rows `setup_complete` / `policy_posture` and `/health.setup_complete` are served unauthenticated on the proxy port — a "claim the admin UI now / this gateway filters nothing" beacon (LOW) | Accepted trade, recorded | the rows are the deliverable the readiness contract asked for; details are FIXED strings (no counts), and the unclaimed setup page is itself reachable unauthenticated by design. A neutral-detail variant on the unauthenticated surface is a follow-up, not a blocker for a pilot where port 8080 and 9090 share the same network reach | — |
| 8 | Journal/collision pre-checks ran before the lock, so two racing commits both passed them (LOW) | Confirmed | lock taken before the pre-checks | covered by `TestRestoreCommit_RefusesWhileDataDirLockHeld` |
| 9 | **Found by the lifecycle harness, not by review**: the bidirectional lock from finding 3 held only until the first GC cycle — the refactor discarded the release closure, the lock's `*os.File` became unreachable, and the runtime finalizer closed the descriptor, which releases a flock. A `--confirm` commit against the RUNNING stack printed `Restore committed.` (run 20261002T201749Z, scenario D). Every unit gate stayed green because a test process never GCs between the hold and the check (HIGH) | Confirmed | the release closure is pinned in a package global for the process lifetime | `TestHoldDataDirLock_SurvivesGarbageCollection` (40 GC cycles, verified failing 3/3 against the discarded-closure shape) |
| C1 | First boot: console-password generator died with SIGPIPE under `pipefail` before setting the password or installing (Codex P1) | Confirmed (reproduced: exit 141) | bounded entropy producer + length assertion | script-level proof in the commit; `shellcheck` clean |
| C2 | First boot never exported `CULVERT_INSTALL_DEFAULT_ACTION`, so an imported appliance booted ALLOW against the documented default-deny contract (Codex P1) | Confirmed | exported `deny` | `scripts/install.sh` persists it; `policy_posture` row reports it |
| C3 | `culvert-status` readiness line was a Python `SyntaxError` on Python < 3.12 (Codex P2) | Confirmed | rewritten without backslashes in the f-string; proven to render | — |

Attacked and found sound by the reviewer (kept as recorded): the transition policy (`checkTransition` runs in `Plan` before any apply request; `Resume` never re-applies; prerelease self-version ⇒ unknown ⇒ acknowledgement required), local-first rollback digest matching, cleanup admission (journal re-read at deletion, symlinks refused), the backup's fixed artifact list, and every crash window of the swap except the one fixed as #2.

**Re-qualification after the fixes:** the agent harness was re-run against the agent rebuilt from the fixed source — 17 checks passed, 0 failed (`agent-REPORT.md`, run 20261002T200809Z). The lifecycle harness was re-run three times against images rebuilt from the fixed source: the first re-run failed 7 checks on harness residue (a stale backups volume — compose drops a profile-only volume from `down -v`; harness fixed), the second found the GC-released lock (row 9 — the only product defect any re-run found), and the third, against `dev-final4`, passed 72/72 (`lifecycle-REPORT.md`, run 20261002T203546Z).

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
