# AGT-900 real-Docker e2e

This is the evidence for contract **AGT-900** (`contracts/registry.yaml`): the
maintenance agent's opt-in startup reconcile, `reconcile_on_startup =
"converge"`, run against a **real Docker daemon**. It covers:

- every kill point of the fake-Docker suites
  (`cmd/culvert-maint/startup_crash_recovery_test.go` and
  `startup_reconcile_converge_test.go`);
- kills inside the reconcile itself;
- repeated restarts on one record;
- the durable journal and audit log, read directly after every kill and every
  restart;
- the outstanding recovery cases: standalone `rollbacks.create` image and data
  records, the reconcile deadline (`abandoned`), the verify-to-audit window,
  dockerd stopped and restarted mid-reconcile, a stopped and a paused proxy
  container, and `ok_stale`;
- seven mutants as negative controls.

Every case runs in two execution modes:

- **root** (the original harness): the agent runs as root with
  `privilege_mode = "docker_group_lab"` against a minimal compose file;
- **sudoers** (the production path): the agent runs as the unprivileged
  `culvert-maint` user that the real `packaging/culvert-maint/install.sh`
  created, with `privilege_mode = "sudoers"`, so every Docker call is
  `sudo -n` through the packaged sudoers file and compose-cli wrapper, against
  the shipped `docker-compose.yml` and `docker-compose.maint-agent.yml`. See
  [The sudoers mode](#the-sudoers-mode-production-path).

Every case is checked against the AGT-900 / AGT-004 / AGT-005 transitions on
real Docker state.

It is a manual evidence run. It is **not** a PR gate, and it changes neither the
status of AGT-900 nor the default of `reconcile_on_startup`. The owner decides
both.

## Running

```bash
sudo test/agt900-e2e/run.sh                      # root mode, both image stores (about 25 min)
sudo test/agt900-e2e/run.sh --mode sudoers       # the production sudoers/compose path
sudo test/agt900-e2e/run.sh --mode both          # both modes, both stores (about 55 min)
sudo test/agt900-e2e/run.sh --store classic      # one store
sudo test/agt900-e2e/run.sh --cases '^repeat_'   # a subset (Go regexp on case names)
sudo test/agt900-e2e/run.sh --negative-control   # the seven mutants, root mode (about 12 min)
sudo AGT900_MUTANTS="data_as_image no_deadline_check" \
     test/agt900-e2e/run.sh --negative-control --mode sudoers   # chosen mutants, sudoers mode
```

Options and environment:

- `--mode root|sudoers|both` (default `root`) picks the execution mode(s).
  Each mode runs against the same private daemon per store, one after the
  other; result rows are labelled `<mode>/<store>`.
- `--keep` keeps the work dir (`/tmp/agt900.*`), which holds the per-process
  agent logs and docker call logs (and, for the sudoers mode, the shim's
  per-call privilege log and `logs/sudoers-*/`: the install.sh output, the
  rendered sudoers file, wrapper and config, and `sudo -l` evidence).
- `AGT900_MUTANTS` limits `--negative-control` to the named mutants.
- `AGT900_REGISTRY_BIN` points to a prebuilt `distribution/v3` registry and
  skips the `go install`.
- `AGT900_REGISTRY_PORT` (default 5443) and `AGT900_PROXY_PORT` (default 18480)
  move the ports.

There are four verdicts:

| Verdict | Meaning |
|---|---|
| **PASS** | Every check held. |
| **FAIL** | A contract check failed. |
| **ERROR** | The harness could not evaluate the case (a setup, crash or mutate step failed, a polled kill missed its window, or nothing was checked), and no contract check failed. It fails a normal run, and with `--negative-control` it never counts as catching a mutant, so an infrastructure failure cannot certify a negative control. |
| **GAP** | Every contract check held, but an owner-requested property that is stricter than the AGT-900 contract was violated. GAP is reported and never folded into PASS. |

Exit codes:

| Exit | Meaning |
|---|---|
| 0 | All rows PASS. With `--negative-control`: every mutant was caught by a failed contract check (FAIL), never by an ERROR. |
| 1 | At least one FAIL or ERROR. |
| 3 | No FAIL or ERROR, but at least one GAP. |
| 2 | Incomplete: a prerequisite or setup failed, or the harness produced no rows. |

**Prerequisites:** root, Go, the Docker engine binaries (`dockerd`,
`containerd`, `runc`, and the `docker` CLI with the compose plugin), `openssl`,
`curl`, `chattr`, `python3`, `strace` (the verify-to-audit case) and `nsenter`.
The run needs no Docker Hub and no outbound network, apart from the
`go install` of the registry when `AGT900_REGISTRY_BIN` is unset. Keep
`GOMAXPROCS=2` (the script's default) on small machines.

**Additionally for `--mode sudoers`:** `unshare`, `setpriv`, `sudo` (with
`@includedir /etc/sudoers.d` in `/etc/sudoers`, as every distribution ships
it), `visudo`, `useradd`/`groupadd`/`getent`/`install` (install.sh's own
prerequisites), overlayfs, and the docker CLI at `/usr/bin/docker` (the path
the sudoers rules and the wrapper name). No systemd is needed: install.sh's
`systemctl daemon-reload` is stubbed. Nothing is installed on the host: see
the next section.

## What it builds

- **A TLS registry**, built from source (`distribution` v3.0.0).
  - It needs TLS because the agent's `docker manifest inspect` has no
    `--insecure` flag.
  - The daemon accepts the certificate because `localhost` is an implicit
    insecure registry.
  - The CLI trusts it through `SSL_CERT_FILE`, which the shim sets.
- **Three FROM-scratch images** of `fakeproxy/main.go`, which serves only
  `/health` and `/ready`:
  - `prior`: the image that runs before the upgrade;
  - `good`: a target that passes the health gate;
  - `bad`: a target whose `/ready` always answers 503, so the gate fails and the
    inline rollback runs.

  All three are pushed, then pulled back by digest, the way a customer host
  gets them.
- **A private `dockerd` per image store**, each with its own data-root,
  exec-root, socket and managed containerd:
  - `--feature containerd-snapshotter=true` for the containerd store (the
    Docker 29 default);
  - `=false` for the classic overlay2 store.

  The host's daemon, its images and its `culvert/proxy:pinned` tag are never
  touched. The "Docker unavailable" and dockerd-mid-reconcile cases stop (and
  start) a real daemon. Each daemon is always started in run.sh's own (the
  host's) mount namespace (`nsenter`), also when a sudoers-mode case restarts
  it from inside the private namespace.
- **Root mode: a compose project** (`docker-compose.yml`) that mirrors the proxy service of
  `test/e2e/maint-agent/docker-compose.e2e.yml`. It has:
  - the fixed `culvert/proxy:pinned` tag and a fixed container name;
  - `restart: unless-stopped`;
  - the loopback-published port, a `/data` volume and a healthcheck;
  - one test-only bind mount, `./ctl:/ctl`, so the harness can stall `/ready`.
- **The real agent binary**, built from `cmd/culvert-maint`. In root mode it
  runs as root with `privilege_mode = "docker_group_lab"`, a real config and a
  real `state_dir`, and is killed with real SIGKILLs and really restarted. In
  sudoers mode, see below.

The Go harness is `cmd/culvert-maint/agt900_realdocker_e2e_test.go` plus
`agt900_realdocker_e2e_recovery_test.go` (the outstanding recovery cases),
behind the build tag `agt900_e2e`, so a plain `go build`, `go vet` or
`go test` never compiles it.

## The sudoers mode (production path)

`--mode sudoers` runs every case through the production privilege and Compose
paths. `run.sh` starts the Go harness under
`unshare --mount --propagation private` via `sudoers-env.sh`, which:

1. overlays `/etc`, `/usr/local`, `/var/lib` and `/var/log` **inside that
   private mount namespace only** (writes land in the run's work dir, never on
   the host; the namespace and its mounts vanish with the run, so there is no
   drop-in to clean up and nothing the host's sudo ever reads);
2. writes `/etc/culvert-maint/config.toml` from the shipped
   `packaging/culvert-maint/config.example.toml`, replacing only
   `compose_project_dir`, `allow_peers`, `health_base_url`, `image_allowlist`,
   `proxy_repo`, and uncommenting `compose_override_file =
   "docker-compose.maint-agent.yml"` and `reconcile_on_startup`;
3. runs the **real `packaging/culvert-maint/install.sh`** with the agent
   binary under test (`CULVERT_MAINT_SKIP_VERIFY=1`: a local binary has no
   cosign bundle; `CULVERT_PROXY_SEED_REF=<prior digest>`: the
   existing-install seed path). It creates the `culvert-maint` system user and
   group, installs `/usr/local/bin/culvert-maint`, renders
   `/etc/sudoers.d/culvert-maint` path-bound to the test's compose file (with
   the two-`-f` override line, because `compose_override_file` is set),
   validates it with `visudo -c`, and renders and installs the root-owned
   `/usr/local/libexec/culvert-maint/compose-cli` bound to the compose path and
   the test's `proxy_repo`. Only `systemctl daemon-reload` is stubbed;
4. writes `<project>/.env` with `CULVERT_MAINT_GID` (the operator step
   install.sh asks for when the override is configured);
5. bind-mounts the shim over `/usr/bin/docker`, the path the sudoers rules and
   the wrapper exec.

The harness then starts every agent process as `culvert-maint`
(`setuid`/`setgid`, no supplementary group, so not in the `docker` group),
with `privilege_mode = "sudoers"`, a config `0640 root:culvert-maint` and
`HOME=/var/lib/culvert-maint`, against `/usr/local/bin/culvert-maint` as
install.sh installed it. The agent calls the real `/usr/bin/sudo -n` (sudo
1.9.15p5 here) with the real `/etc/sudoers`.

**The compose project** is the shipped `docker-compose.yml` plus
`docker-compose.maint-agent.yml`, rendered by `render-shipped-compose.py` into
a directory named `culvert` (so the project is `culvert`, the container
`culvert`, as on a customer host) with exactly three substitutions, each
asserted to apply once:

| Shipped | Test | Why |
|---|---|---|
| proxy ports `"8080:8080"`, `"9090:9090"` | `"127.0.0.1:<port>:8080"`, `"127.0.0.1:<port+1>:9090"` | never bind a public or colliding host port |
| proxy volumes | `+ ./ctl:/ctl` | the /ready stall control (kills inside a health gate) |
| override `/run/culvert-maint:/run/culvert-maint:ro` | `<work>/run-culvert-maint:/run/culvert-maint:ro` | the private daemon must not create a directory in the host's `/run` |

Everything else is the shipped file: the `clamav` service and the proxy's
`depends_on: clamav: condition: service_healthy`, container names, restart
policies, `stop_grace_period: 60s`, the proxy command line and environment,
the shipped healthchecks, the `cli` and `ha` profiles, the volumes, and the
override's `group_add: ${CULVERT_MAINT_GID:?...}` resolved from `.env`.

**Stubbed images** (no Docker Hub; each built FROM scratch, locally, in the
private daemon only):

| Shipped image | Stub |
|---|---|
| `culvert/proxy:pinned` (proxy and `cli`) | the fake proxy (`fakeproxy/main.go`, roles prior/good/bad), as in root mode. It ignores the shipped command flags, carries `/usr/bin/wget` (the same multi-call binary) for the shipped `wget -qO- http://localhost:8080/health` healthcheck, and, run as the `cli` service with `--list-backups`, prints one fixed backup entry (the data-rollback preflight); every other cli operation exits 1 |
| `clamav/clamav:1.4` | the same binary in `-idle` mode (waits for SIGTERM), with `/usr/bin/clamdscan` answering the shipped `clamdscan --ping 3` healthcheck. Built under the shipped name, so `depends_on ... service_healthy` gates every `up` exactly as shipped |
| `quay.io/coreos/etcd:v3.6.13` (profile `ha`) | **not stubbed**: the `ha` profile is never activated, so it is never pulled or started |

**Every Docker call is checked to have taken the production path** (check
`P ...`, sudoers mode only). The shim records, for each call, its own uid and
sudo's `SUDO_UID` and `SUDO_COMMAND`. Each restart (and the upgrade controls)
must show: every call ran as root via sudo from the agent's uid, the
argv-varying calls (container inspect, pull, tag, cli runs) through the
compose-cli wrapper's subcommand and everything else through its exact direct
`/usr/bin/docker` rule; and the agent process's real, effective, saved and fs
uid are all `culvert-maint`. The install evidence (`sudo -l -U culvert-maint`,
`visudo -c`, a refused non-allowlisted command, a wrapper refusal of a foreign
repository) is printed with each sudoers run.

**Exact differences from a production host:**

- The agent is started by the harness, not by systemd: the unit's
  `User=`/`Group=` are reproduced, but its sandboxing (`ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `ProtectProc=invisible`, `RuntimeDirectory`,
  `ReadWritePaths`, `LimitNOFILE`, `TasksMax`) is not applied. Socket and
  `state_dir` live in a per-case directory under `/tmp` owned by
  `culvert-maint`, not in `/run/culvert-maint` and `/var/lib/culvert-maint`.
- Each agent process has its own harness-written config: the same
  `compose_project_dir`, `compose_file`, `compose_override_file`,
  `proxy_repo` and `image_allowlist` as the `/etc/culvert-maint/config.toml`
  that install.sh rendered sudoers and the wrapper from, but its own
  `socket_path`, `state_dir`, `stage_timeout` and `reconcile_on_startup`
  (`off` for the off-mode cases), `allow_peers = ["0"]` (the harness is the
  peer) and `operation_timeout = "15m"`.
- `/usr/bin/docker` is the pass-through shim. It execs the real CLI unchanged,
  but sets `DOCKER_HOST` to the store's private daemon (production: the default
  socket) and `SSL_CERT_FILE` to the test registry's CA (production: the
  system CA store), because sudo's `env_reset` strips the environment.
- The registry is `localhost:<port>` (TLS, an implicit insecure registry for
  the daemon), not `ghcr.io`; `proxy_repo` and `image_allowlist` name it.
- The images are the stubs above, not the Culvert proxy and ClamAV.
- The daemon runs with `--bridge=none --iptables=false` (published ports go
  through the userland proxy).
- sudo is classic sudo 1.9.15p5, not sudo-rs (the default on Ubuntu 26.04).

### How the kills land

The kills are deterministic. The agent's `docker` is a **pass-through shim**
that execs the real CLI (root mode: first on the agent's `PATH`; sudoers mode:
bind-mounted over `/usr/bin/docker`, run as root by sudo, and finding the
calling agent by walking its parent chain to the process whose argv holds
`--config <dir>/<tag>.toml`). It logs every argv and can hold one call at a
named point:

- `<cmd>_before:<n>` holds before the real command runs;
- `<cmd>_after:<n>` holds after the real command completed, before the agent
  sees it return.

`<cmd>` is the compose subcommand (after the global `-f`/`--profile` options),
or else the docker subcommand; `any` counts every call. `n` counts per agent
process. While the agent is held, the harness either SIGKILLs it or releases
the call. Nothing in Docker is simulated.

Three kills have no Docker call to hold on to:

- **Inside a health probe:** the harness holds `up_after:<n>`, creates
  `/ctl/hang_ready` and releases the hold. The SIGKILL lands when the probe
  reaches `/ready`.
- **Between `verified` and retirement:** the harness polls the journal record
  and SIGKILLs on `"phase": "verified"`.
- **Between the reconcile's audit write and its record removal:** the harness
  polls `audit.jsonl` and SIGKILLs when the record's `:reconciled` entry
  appears.
- **Between the reconcile's verify and its audit write** (no file write and
  no Docker call): the reconcile is held right after the verify's last read
  (`image_after:13`), `strace -f -p <agent> -P <state>/audit.jsonl -e
  trace=write -e inject=write:error=EIO:signal=SIGKILL:when=1` is attached,
  and the hold is released. The agent dies at the entry of its first
  `write(2)` to `audit.jsonl` (the `:reconciled` entry) before a byte is
  written. Deterministic: no polling, no retry.

A polled kill that lands after the record is gone is retried from scratch, up
to 6 times, and the row says so. In the recorded runs every polled kill landed
on the first try.

The reconcile issues its Docker calls in this order, counted per process:

| Step | Calls |
|---|---|
| Wait for Docker | `ps:1` |
| Facts | `ps:2` |
| TOCTOU re-read after the write-ahead attempt record | `ps:3` |
| Action | `tag:1` or `up:1` |
| Verify | `ps:4` |

Each read is `compose ps`, then `inspect`, then 1 or 4 `image inspect` calls,
so `image:13` is the last read of the verify.

## What is checked

**The fake-Docker suite's expectation for the same kill point**, for every
converge restart:

- the decision and reason;
- the restart's exact state-changing Docker commands;
- the tag and the container afterwards;
- whether the record was retired, and its outcome;
- the `reconcile.startup` op state;
- `status.recovery_required`.

**The AGT-900 invariants on real Docker state.** These are independent of the
table above. "Real Docker state" means `docker inspect` of the compose
container, the id that `culvert/proxy:pinned` resolves to, and `/ready`.

"Prior" below is the image that ran before the interrupted operation, and
"target" an image it was moving to. For an upgrade that is `prior` and
`good`/`bad`; for a standalone image rollback (which starts from an upgraded
stack) it is `good` and `prior`.

| Id | Invariant |
|---|---|
| I1 | The only Docker changes are a tag to the recorded prior ref, and `up` while the tag is already on prior. Never `pull`, `down`, or a tag to a target. |
| I2 | A Docker-converged record (`converged` or `converged_not_retired`) leaves the tag and the container on the same image, running and ready. That image is the prior image, or an `adopt` of a target whose journal said `verified` before the restart. |
| I3 | Anything else leaves Docker unchanged: the same container id, image, state and tag. The one refinement: when a Docker-changing decision (`realign`, `finish_rollback`) fails at a step **after** its change (the daemon vanished before the verify), the contract's other disjunct must hold instead: tag and container both on the prior image, running and ready. |
| I4 | No ungated image is **started** by the reconcile. If a target runs afterwards, the reconcile ran no `up` and the container is the one that was there before. |
| I5 | A failed-gate image is never accepted as converged. |
| I6 | The interrupted op stays `failed(agent_restart_interrupted)`. |
| I7 | A record is retired iff the outcome is `converged`, and never without at least one `:reconciled` audit entry (AGT-005). |
| AGT-004 | No `pull` at startup. |

**Journal and audit consistency (J).** After every kill and every restart, the
harness reads `<state_dir>/reconcile/` and `audit.jsonl` directly, not through
the agent:

- every record file parses and names its own op;
- nothing else is in the directory except `.lock` and the journal's own
  `.journal-*.tmp` files, which are counted and are never parsed as records;
- `phase`, `reconcile_attempts` and `interrupted_seen` never go backwards;
- attempts stay at or below the cap of 2;
- a retired record never reappears;
- `prior_image_id` and `target_image_id` are the real local ids for this store;
- `rollback_armed` appears only at `restarting` or later;
- an **upgrade** record at a safe phase (`admitted` to `pulled`) has the tag
  and the container on the prior image (the write-ahead barrier; a
  `rollbacks.create` record stays at `admitted` whatever it did, so its phase
  proves nothing);
- every audit line parses;
- a retired record has a `:reconciled` audit entry.

**Owner-requested properties (reported as GAP when violated):**

- **OWNER-ungated:** no image that has not passed its health gate is left
  running after the reconcile. The contract only forbids *starting* one (I4).
- **OWNER-audit:** exactly one `:reconciled` audit entry per retirement, and
  none for a kept record. The contract (AGT-005) only requires audit-first.

**Privilege path (P, sudoers mode only):** see
[The sudoers mode](#the-sudoers-mode-production-path).

**One retarget point.** The expectation of the T/T-armed rollback case
(`rb_armed_before_tag`: killed after the inline rollback was durably armed and
before its retag, so tag and container are both on the failed-gate target) is
the single value `xTTArmed` in `agt900_realdocker_e2e_test.go`, under a boxed
`RETARGET POINT` comment. When converge learns to finish that rollback (retag
to prior, `up`, a fresh gate, verify), only that value changes, with
`tagThenUp: true` so I1 accepts the `up` that follows the restart's own retag.

## Outstanding recovery cases

Added in `agt900_realdocker_e2e_recovery_test.go`. Expectations are the V2
decision matrix (`reconcile_decision_v2.go`) and the AGT-900 contract; every
case also gets I1 to I7, J and (sudoers mode) P.

| Case | Setup | Expected |
|---|---|---|
| standalone_rb_before_pull | upgrade to good succeeds; on a fresh agent, `POST /v1/rollbacks mode=image` to prior is killed at `pull_before:1` | S1: `noop/rollback_never_moved_tag`, no Docker change, retired |
| standalone_rb_tag_moved | the same rollback killed at `up_before:1` (tag on prior, good runs) | S2: `recovery_required/rollback_target_partially_applied`, nothing changed, kept |
| standalone_rb_up_done | killed at `up_after:1` (tag and container on prior, not gated by the rollback) | S3: same as S2; OWNER-ungated GAP (the rollback's own gate never ran) |
| data_rollback_record | `POST /v1/rollbacks mode=data` killed at its first Docker call after admission (`any_before:2`) | `recovery_required/data_window_manual`, kept, Docker unchanged, and **Docker never read for the record**: the reconcile's only container read is its wait-for-Docker, no fixed-tag or image-ref inspect |
| reconcile_deadline_abandoned | A = upgrade killed at `verified`; B = standalone rollback killed at `pull_before:1` (B sorts after A); converge with `stage_timeout = "5s"` (deadline 10s) and `/ready` stalled, so A's adopt probe consumes the deadline | A `recovery_required/verified_target_not_ready`; B `recovery_required/deadline_elapsed`, outcome `abandoned`; state `abandoned`, op `failed(recovery_required)`; no Docker change; no Docker call after A's probe began; B's record carries no reconcile write. Next start (ready again): A `adopt`, B `noop/rollback_never_moved_tag`, both retired with one entry each |
| verify_to_audit_window | realign held after the verify's last read, strace SIGKILL at the audit `write(2)` | no `:reconciled` entry, record kept with attempts 1, tag=prior run=prior; next start `noop/already_on_prior`, retired with exactly one entry |
| dockerd_restart_before_action | realign held at `tag_before:1`; private dockerd stopped and started (the proxy comes back by its restart policy); released | `realign`, `[tag:prior]`, converged, retired |
| dockerd_down_at_action | held at `tag_before:1`; dockerd stopped; released | `realign/tag_failed`, outcome `recovery_required`, kept, attempts 1, Docker unchanged; dockerd back, next start: `realign`, retired |
| dockerd_down_at_verify | held at `ps_before:4` (the tag already moved); dockerd stopped; released | `realign/post_verify_failed`, kept, Docker on prior (I3 refinement); next start `noop/already_on_prior`, retired |
| container_stopped | tag ahead, then `docker stop` of the proxy | `recovery_required/stack_down` (see Findings), nothing changed, container stays exited |
| container_paused | tag ahead, then `docker pause` of the proxy | `recovery_required/container_not_running`, nothing changed |
| ok_stale_realign | the compose override pins the proxy to the prior digest (root mode: a case-only `compose_override_file`; sudoers mode: the configured `docker-compose.maint-agent.yml` gains the pin); the upgrade's `up` exits 0 but the container stays on prior; killed at its verify | produced is checked (`up` ran, tag=good, run=prior, phase `restarted`, no `target_image_id`); then V2 row A8: `realign`, `[tag:prior]`, retired |

`ok_stale` is thereby produced on real Docker for the first time, through the
production override mechanism rather than an injected fault.

The reconcile results of `data_rollback_record` and
`reconcile_deadline_abandoned` are read after the reconcile's terminal audit
entry appears, not by polling `GET /v1/status`, because the status handler
itself reads Docker (the running image and the fixed tag) while interrupted
operations exist; that would hide whether the reconcile read Docker.

## Recorded results: 2026-11-23, run 2 (both modes, both stores)

**Environment:**
- Docker Engine 29.10.0 (containerd v2.4.2, runc 1.5.3), Compose v5.7.1,
  sudo 1.9.15p5, strace 6.8, on Linux 6.18 x86_64.
- Harness at `77ded30c3` on top of `agt900-real-docker-e2e` (`e65635b`).
  Production code is unchanged. (The run printed "dirty" only because this
  README was being edited.)
- One invocation: `run.sh --mode both --store both`, containerd store first
  (root, then sudoers), then classic. Exit 3: no FAIL, GAPs only.

**Totals:** 49 cases per mode and store, 196 rows.

| Mode / store | PASS | FAIL | GAP | checks ok | checks GAP | time |
|---|---|---|---|---|---|---|
| root/containerd | 40 | 0 | 9 | 1079 | 12 | 649 s |
| sudoers/containerd | 40 | 0 | 9 | 1187 | 12 | 1000 s |
| root/classic | 40 | 0 | 9 | 1079 | 12 | 570 s |
| sudoers/classic | 40 | 0 | 9 | 1187 | 12 | 906 s |

The sudoers rows carry 108 more checks: 54 per store are the privilege-path
checks (P). Across both stores they covered 3764 Docker calls, 2962 through a
direct `/usr/bin/docker` rule and 802 through the compose-cli wrapper, every
one as root via `sudo -n` from uid 996 (`culvert-maint`); no call was refused.
The sudoers runs are slower mainly because every shipped-compose `up` waits for
the clamav stub's healthcheck.

**Every case, every mode and store** (the 37 original cases are described in
the first-run section below; the 12 new ones in
[Outstanding recovery cases](#outstanding-recovery-cases)):

| Case | root/containerd | root/classic | sudoers/containerd | sudoers/classic |
|---|---|---|---|---|
| control_good_upgrade | PASS | PASS | PASS | PASS |
| control_bad_upgrade_rolls_back | PASS | PASS | PASS | PASS |
| admitted_at_capture | PASS | PASS | PASS | PASS |
| captured_at_resolve | PASS | PASS | PASS | PASS |
| resolved_at_pull | PASS | PASS | PASS | PASS |
| barrier_before_tag | PASS | PASS | PASS | PASS |
| tag_moved_before_up | PASS | PASS | PASS | PASS |
| up_done_unrecorded | GAP | GAP | GAP | GAP |
| restarted_at_health_gate | GAP | GAP | GAP | GAP |
| restarted_at_verify | GAP | GAP | GAP | GAP |
| verified_adopt | PASS | PASS | PASS | PASS |
| verified_target_not_ready_now | PASS | PASS | PASS | PASS |
| rb_armed_before_tag | GAP | GAP | GAP | GAP |
| rb_tag_moved_before_up | PASS | PASS | PASS | PASS |
| rb_up_done | PASS | PASS | PASS | PASS |
| rb_in_rollback_health | PASS | PASS | PASS | PASS |
| rb_at_rollback_verify | PASS | PASS | PASS | PASS |
| operator_retag_unarmed | GAP | GAP | GAP | GAP |
| forged_prior_ref | PASS | PASS | PASS | PASS |
| audit_write_fails_keeps_record | PASS | PASS | PASS | PASS |
| rc_after_writeahead | PASS | PASS | PASS | PASS |
| kill_in_reconcile_tag | PASS | PASS | PASS | PASS |
| rc_after_tag_before_verify | PASS | PASS | PASS | PASS |
| rc_in_verify_last_read | PASS | PASS | PASS | PASS |
| rc_after_audit_before_retire | GAP | GAP | GAP | GAP |
| kill_in_reconcile_up | PASS | PASS | PASS | PASS |
| kill_in_reconcile_after_up | PASS | PASS | PASS | PASS |
| rc_in_post_up_probe | PASS | PASS | PASS | PASS |
| rc_fr_in_verify_last_read | PASS | PASS | PASS | PASS |
| repeat_tag_ahead_exhaust | PASS | PASS | PASS | PASS |
| repeat_rollback_exhaust | GAP | GAP | GAP | GAP |
| repeat_mixed_then_converge | PASS | PASS | PASS | PASS |
| repeat_rr_stable | GAP | GAP | GAP | GAP |
| docker_unavailable_defers | PASS | PASS | PASS | PASS |
| second_instance_skips | PASS | PASS | PASS | PASS |
| off_mode_tag_ahead | PASS | PASS | PASS | PASS |
| off_mode_target_live | PASS | PASS | PASS | PASS |
| standalone_rb_before_pull | PASS | PASS | PASS | PASS |
| standalone_rb_tag_moved | PASS | PASS | PASS | PASS |
| standalone_rb_up_done | GAP | GAP | GAP | GAP |
| data_rollback_record | PASS | PASS | PASS | PASS |
| reconcile_deadline_abandoned | PASS | PASS | PASS | PASS |
| verify_to_audit_window | PASS | PASS | PASS | PASS |
| dockerd_restart_before_action | PASS | PASS | PASS | PASS |
| dockerd_down_at_action | PASS | PASS | PASS | PASS |
| dockerd_down_at_verify | PASS | PASS | PASS | PASS |
| container_stopped | PASS | PASS | PASS | PASS |
| container_paused | PASS | PASS | PASS | PASS |
| ok_stale_realign | PASS | PASS | PASS | PASS |

The verdicts are **identical in both modes and both stores**. Every GAP is an
owner-strict property, the same ones as in the first run plus one new:

- OWNER-ungated (image left running that its own gate never passed):
  `up_done_unrecorded`, `restarted_at_health_gate`, `restarted_at_verify`,
  `rb_armed_before_tag` (the T/T-armed retarget point), `operator_retag_unarmed`,
  `repeat_rollback_exhaust`, `repeat_rr_stable`, and new
  `standalone_rb_up_done` (the standalone rollback's `up` started prior, its
  gate never ran; converge reports `rollback_target_partially_applied` and
  changes nothing);
- OWNER-audit: `rc_after_audit_before_retire` (the duplicate entry, Finding 1).

New-case evidence, identical in all four runs unless noted:

- `data_rollback_record`: the reconcile's own calls were 1 container inspect
  (its wait-for-Docker) and 0 fixed-tag or image-ref inspects.
- `reconcile_deadline_abandoned`: state `abandoned`; A
  `recovery_required/verified_target_not_ready:recovery_required`; B
  `recovery_required/deadline_elapsed:abandoned` with no `reconcile_*` field
  written and no Docker call after A's probe began; op
  `failed(recovery_required)`; Docker unchanged. Next start: A
  `adopt/verified_target_live`, B `noop/rollback_never_moved_tag`, both
  retired with exactly one entry.
- `verify_to_audit_window`: the agent exited by SIGKILL at the entry of
  `write(<audit fd>, "{\"ts\":...", ~394)`; 0 `:reconciled` entries, attempts
  1, tag=prior run=prior; next start `noop/already_on_prior`, retired with 1
  entry.
- `dockerd_down_at_action` / `_at_verify`: `realign/tag_failed` (Docker
  unchanged) and `realign/post_verify_failed` (tag already on prior: the I3
  refinement) with attempts 1; the next start `realign` resp.
  `noop/already_on_prior`, retired.
- `container_stopped` decided `stack_down`, `container_paused`
  `container_not_running` (Finding 5).
- `ok_stale_realign`: produced in all four runs (`up` exited 0, tag=good,
  container prior, phase `restarted`, no `target_image_id`), then `realign`.

### Run 2 negative controls (`--negative-control`, 2026-11-23)

Seven mutants, each applied to a copy of `cmd/culvert-maint` (never the
checked-out source, never committed), root mode, containerd store. The first
three are the first run's; the last four target the new cases.

```diff
# standalone_partial_noop (reconcile_decision_v2.go, decideStandaloneRollbackV2)
-	if ids.target != "" && (ids.tag == ids.target || ids.run == ids.target) {
+	if false && ids.target != "" && (ids.tag == ids.target || ids.run == ids.target) { // NEGATIVE CONTROL: partial rollback not detected
# data_as_image (reconcile_decision_v2.go and startup_reconcile.go)
-	case in.Kind == ops.KindRollbackCreate && in.Mode == "data":
-		// Never touches Docker; the existing manual data-recovery report applies.
-		return rr("data_window_manual")
-	... (in.Kind == ops.KindRollbackCreate && in.Mode == "image")      (both imageKind expressions)
+	... (in.Kind == ops.KindRollbackCreate) // NEGATIVE CONTROL: data treated as image
# no_deadline_check (startup_reconcile.go, runStartupReconcile)
-		if ctx.Err() != nil {
+		if false && ctx.Err() != nil { // NEGATIVE CONTROL: deadline ignored
# no_running_check (reconcile_decision_v2.go)
-	if ids.run != "" && !in.ContainerRunning {
+	if false && ids.run != "" && !in.ContainerRunning { // NEGATIVE CONTROL: stopped container not detected
```

Recorded output, abridged to the new mutants' failing checks:

```
root/containerd/mutant:standalone_partial_noop | standalone_rb_tag_moved | ... | FAIL
  - decision: want recovery_required/rollback_target_partially_applied, got recovery_required/tag_differs_from_running
root/containerd/mutant:standalone_partial_noop | standalone_rb_up_done | ... | FAIL
  - decision: want recovery_required/rollback_target_partially_applied, got noop/rollback_never_moved_tag
  - record retired: want false, got true
  - I2 converged = same image, gated, ready: want tag==run, running, ready, good|verified target, got tag=prior run=prior(running,ready) phase_before=admitted
  - I4 no ungated image started: want no up, same container, adopt|recovery_required, got up=false same_container=true decision=noop outcome=converged
root/containerd/mutant:data_as_image | data_rollback_record | ... | FAIL
  - decision: want recovery_required/data_window_manual, got recovery_required/invalid_record_ref
  - Docker never read for the data record: want 1 container inspect (the wait for Docker), 0 pinned-tag / image-ref inspects, got 2 container inspect(s), 1 pinned-tag/ref inspect(s)
root/containerd/mutant:no_deadline_check | reconcile_deadline_abandoned | ... | FAIL
  - reconcile state: want abandoned, got recovery_required
  - B: want recovery_required/deadline_elapsed:abandoned, got defer/docker_unavailable:deferred
  - B carries no reconcile write: want kept, no reconcile_* field, got kept=true fields=[reconcile_outcome reconcile_decision]
root/containerd/mutant:no_running_check | container_paused | ... | FAIL
  - decision: want recovery_required/container_not_running, got realign/post_verify_failed
  - docker commands: want [], got [tag:prior]
  - tag after: want good, got prior
  - I3 failed action = Docker unchanged or on prior: want tag=good run=prior(paused) id=d0b658e7b1d3 | tag=run=prior(running,ready), got tag=prior run=prior(paused) id=d0b658e7b1d3
NEGATIVE CONTROL adopt_restarted: caught (2 FAIL row(s))
NEGATIVE CONTROL no_write_ahead: caught (2 FAIL row(s))
NEGATIVE CONTROL retire_before_audit: caught (1 FAIL row(s))
NEGATIVE CONTROL standalone_partial_noop: caught (2 FAIL row(s))
NEGATIVE CONTROL data_as_image: caught (1 FAIL row(s))
NEGATIVE CONTROL no_deadline_check: caught (1 FAIL row(s))
NEGATIVE CONTROL no_running_check: caught (1 FAIL row(s))
NEGATIVE CONTROL: every mutant was caught -> OK
```

The three original mutants were caught by the same checks the first run lists
below. The four new mutants were also run through the production path
(`AGT900_MUTANTS="standalone_partial_noop data_as_image no_deadline_check
no_running_check" run.sh --negative-control --mode sudoers`): every one was
caught, by the same failing checks as above (5 FAIL rows, exit 0).

## Recorded results: 2026-11-23 (first run, root mode)

**Environment:**
- Docker Engine 29.10.0 (containerd v2.4.2, runc 1.5.3), Compose v5.7.1, on
  Linux 6.18 x86_64.
- Agent source: `agt900-converge-startup` at `dbbf38f04`. Production code is
  unchanged; the run was made from the harness commit on top of it.
- **Both image stores** were run, in one invocation.

| Store | Daemon reports | Container `.Image` / image `.Id` |
|---|---|---|
| containerd | `overlayfs`, `driver-type io.containerd.snapshotter.v1` | the registry (index) digest |
| classic | `overlay2` | the image config digest, distinct from the registry digest |

**Totals (identical in both stores):** 37 cases per store, 74 rows in all.

| Verdict | Rows |
|---|---|
| PASS | 58 |
| FAIL | 0 |
| GAP | 16 (8 cases × 2 stores) |

Per store, 807 checks passed and 12 owner checks reported GAP. The containerd
run took 533 s and the classic run 502 s. `run.sh` exited 3, meaning no FAIL
but GAPs.

### Kill points of the fake-Docker suites, plus extra converge cases

| Case (kill point) | Result in both stores | Verdict |
|---|---|---|
| control_good_upgrade (no kill) | op succeeded, tag=good run=good, journal empty | PASS |
| control_bad_upgrade_rolls_back (no kill) | op failed(health_failed), rollback_succeeded, tag=prior run=prior, journal empty | PASS |
| admitted_at_capture (`ps_before:1`) | noop/safe_boundary_unchanged, no change, retired | PASS |
| captured_at_resolve (`manifest_before:1`) | noop/safe_boundary_unchanged, retired | PASS |
| resolved_at_pull (`pull_before:1`) | noop/safe_boundary_unchanged, retired | PASS |
| barrier_before_tag (`tag_before:1`) | noop/already_on_prior, retired | PASS |
| tag_moved_before_up (`up_before:1`) | realign, `[tag:prior]`, tag=prior run=prior, retired | PASS |
| up_done_unrecorded (`up_after:1`) | recovery_required/target_live_ungated, Docker unchanged (good runs), kept | GAP: OWNER-ungated |
| restarted_at_health_gate (in the gate's `/ready`) | same as above | GAP: OWNER-ungated |
| restarted_at_verify (`ps_before:3`) | same as above | GAP: OWNER-ungated |
| verified_adopt (polled kill at journal `verified`) | adopt/verified_target_live, no change, retired | PASS |
| verified_target_not_ready_now (same, with `/ready` stalled) | recovery_required/verified_target_not_ready, no change, kept | PASS |
| rb_armed_before_tag (bad, `tag_before:2`) | recovery_required/rollback_armed_target_live, Docker unchanged: **bad runs under the tag** | GAP: OWNER-ungated |
| rb_tag_moved_before_up (`up_before:2`) | finish_rollback, `[up]`, tag=prior run=prior ready, retired | PASS |
| rb_up_done (`up_after:2`) | noop/already_on_prior, retired | PASS |
| rb_in_rollback_health (in the rollback gate's `/ready`) | noop/already_on_prior, retired | PASS |
| rb_at_rollback_verify (`ps_before:3`) | noop/already_on_prior, retired | PASS |
| operator_retag_unarmed (`up_after:1`, then an operator tags prior) | recovery_required/tag_on_prior_rollback_unproven, no change (good runs, tag prior), kept | GAP: OWNER-ungated |
| forged_prior_ref (`up_before:1`, then `prior_ref` is rewritten) | recovery_required/invalid_record_ref, no change; the forged ref never reaches Docker argv | PASS |
| docker_unavailable_defers (dockerd **stopped**) | deferred, no Docker command, no attempt counted, record kept. After dockerd restarts: Docker as before. Next start: realign, retired | PASS |
| second_instance_skips (two agents on one `state_dir`) | instance 2: `skipped_second_instance`, no Docker command, Docker unchanged, record kept. After both are SIGKILLed: the next start takes the lock and realigns | PASS |
| off_mode_tag_ahead / off_mode_target_live (`off`) | no Docker command, no `reconcile` in status, op failed(agent_restart_interrupted), listed, record kept, no lock file | PASS |

### Item 1: crash during recovery, at each reconcile step

In each case below, the upgrade was first crashed at the point shown. The
reconcile was then SIGKILLed at the named step, and the agent restarted with
converge.

The checks on these cases:

- While the reconcile was held, `POST /v1/upgrades/apply` returned 409 naming
  `reconcile.startup`, and status said `in_progress`.
- The write-ahead attempt was durable at every kill (`reconcile_attempts=1`).
- No step was repeated unsafely: after a kill that came after the action, the
  next start saw Docker already on prior and changed nothing (`noop`).
- The interrupted op stayed failed.
- J held after every kill and restart.

| Case | Reconcile killed | Docker at the kill | Next start (both stores) | Verdict |
|---|---|---|---|---|
| rc_after_writeahead | after the write-ahead record, before acting (`ps_before:3`) | unchanged | realign, `[tag:prior]`, retired | PASS |
| kill_in_reconcile_tag | at its retag (`tag_before:1`) | unchanged | realign, retired | PASS |
| rc_after_tag_before_verify | after the retag, before the verify (`ps_before:4`) | tag=prior run=prior | noop/already_on_prior, no command, retired | PASS |
| rc_in_verify_last_read | inside the verify, last read done (`image_after:13`) | tag=prior run=prior | noop/already_on_prior, retired | PASS |
| rc_after_audit_before_retire | after the verify and the audit entry, before the record removal (polled) | tag=prior run=prior | noop/already_on_prior, retired, with a **second** `:reconciled` entry | GAP: OWNER-audit |
| kill_in_reconcile_up | finish_rollback before `compose up` (`up_before:1`) | unchanged (bad runs, tag prior) | finish_rollback, `[up]`, retired | PASS |
| kill_in_reconcile_after_up | `compose up` done, not yet seen (`up_after:1`) | tag=prior run=prior | noop/already_on_prior, retired | PASS |
| rc_in_post_up_probe | inside finish_rollback's readiness probe | tag=prior run=prior | noop/already_on_prior, retired | PASS |
| rc_fr_in_verify_last_read | finish_rollback verify, last read done | tag=prior run=prior | noop/already_on_prior, retired | PASS |
| audit_write_fails_keeps_record | not killed: `audit.jsonl` made immutable (`chattr +i`) mid-reconcile | realigned and verified | realign, record **kept** as `converged_not_retired`, reconcile op failed(recovery_required). Once the log is writable: noop, retired with exactly 1 entry | PASS |

### Item 2: repeated restarts on one record

| Case | Sequence | End state (both stores) | Verdict |
|---|---|---|---|
| repeat_tag_ahead_exhaust | killed at the retag twice (attempts 1, then 2), then 2 full restarts | `recovery_required/reconcile_exhausted` both times, **no Docker command**, attempts stay 2, Docker unchanged (tag good, prior runs) | PASS |
| repeat_rollback_exhaust | killed before finish_rollback's `up` twice, then 2 full restarts | `reconcile_exhausted` both times, no command, attempts 2. **The failed-gate `bad` image keeps running** | GAP: OWNER-ungated |
| repeat_mixed_then_converge | killed in a fact read (attempts stays 0), at the retag (1), in a fact read (1), then a full restart | realign on attempt 2, retired | PASS |
| repeat_rr_stable | killed twice inside the reads of a recovery_required record, then 2 full restarts | `target_live_ungated` every time, no command, attempts 0 | GAP: OWNER-ungated |

The attempt counter persisted across every restart. Kills before the
write-ahead attempt record did not count an attempt. The reconcile never looped
on a mutation: after the cap it issues no Docker command at all.

### Item 3: journal consistency

J held after every one of the kills and restarts above, in both stores. For
each check:

- no record failed to parse, and none was truncated;
- no stray file appeared: temp files were counted, and none was ever treated
  as a record;
- no phase, attempt or start counter went backwards;
- every recorded image id was the real one;
- no record at a safe phase disagreed with Docker;
- no record was retired without its audit entry.

The only audit inconsistency was the OWNER-audit gap described under item 1.

### Item 4: negative controls (`--negative-control`, 2026-11-23)

Each mutant is applied to a copy of `cmd/culvert-maint`. The checked-out source
is never modified, and no mutant is committed.

```diff
# adopt_restarted (reconcile_decision_v2.go)
-	case in.Phase != journal.PhaseVerified:
+	case in.Phase != journal.PhaseVerified && in.Phase != journal.PhaseRestarted: // NEGATIVE CONTROL: adopts an ungated target
# no_write_ahead (startup_reconcile.go, act)
-	if err := s.opts.Journal.Write(*c.rec); err != nil {
+	if err := error(nil); err != nil { // NEGATIVE CONTROL: no write-ahead attempt record
# retire_before_audit (startup_reconcile.go, retire)
-	if err := s.auditReconciled(c, audit.OutcomeSucceeded); err != nil {
-		return s.keepRecord(c, OutcomeConvergedNotRetired)
-	}
 	if err := s.opts.Journal.Remove(c.rec.OpID); err != nil {
 		return s.keepRecord(c, OutcomeConvergedNotRetired)
 	}
+	_ = s.auditReconciled(c, audit.OutcomeSucceeded) // NEGATIVE CONTROL: retired before the audit, audit failure ignored
```

Recorded output, abridged:

```
containerd/mutant:adopt_restarted | restarted_at_health_gate | ... | adopt/verified_target_live ... retired=true | FAIL
  - decision: want recovery_required/target_live_ungated, got adopt/verified_target_live
  - record retired: want false, got true
  - I2 converged = same image, gated, ready: ... got tag=good run=good(running,ready) phase_before=restarted
containerd/mutant:adopt_restarted | restarted_at_verify | (same) | FAIL
containerd/mutant:no_write_ahead | rc_after_writeahead | ... | FAIL
  - k1 attempts after the kill: want 1, got 0
containerd/mutant:no_write_ahead | repeat_tag_ahead_exhaust | ... | FAIL
  - k1 attempts after the kill: want 1, got 0
  - k2 attempts after the kill: want 2, got 0
  - r1 decision: want recovery_required/reconcile_exhausted, got realign/tag_ahead_container_on_prior
containerd/mutant:retire_before_audit | audit_write_fails_keeps_record | ... | FAIL
  - r1 J after the failed audit: ... got 01M84C5NCE7K retired with no `:reconciled` audit entry
  - r1 record retired: want false, got true
  - r1 I7 audit before retire: want >= 1 succeeded, got 0 succeeded
NEGATIVE CONTROL adopt_restarted: caught (2 FAIL row(s))
NEGATIVE CONTROL no_write_ahead: caught (2 FAIL row(s))
NEGATIVE CONTROL retire_before_audit: caught (1 FAIL row(s))
NEGATIVE CONTROL: every mutant was caught -> OK
```

The harness also failed once for a reason in the harness itself, during
development: a restarted agent reused the crashed agent's call log, so the
upgrade's own `pull` was reported as a startup pull. That tripped I1 and
AGT-004. It was fixed before the recorded runs.

## Findings

1. **OWNER-audit: duplicate audit entry (reproducible).** The reconcile's
   `retire` writes the `:reconciled` audit entry and fsyncs it, then removes
   the record. If the agent is killed between those two steps, the record
   survives. The next start reconciles again (`noop`, Docker unchanged),
   writes a **second** `:reconciled` entry and retires the record.

   - Repro: `run.sh --cases '^rc_after_audit_before_retire$'`.
   - AGT-005 holds: there is never a retirement without an audit entry, and
     Docker is not touched again.
   - This is the same at-least-once design that `reportInterrupted` documents
     for the interruption audit.
   - It violates the owner's "never duplicated" requirement. Making it
     exactly-once would need the agent to treat its own audit log as state
     (look up the entry before writing it). That is a design choice, so it was
     **not** fixed here.
2. **OWNER-ungated: an ungated or failed-gate image is left running
   (by design).** Whenever the decision is `recovery_required`, converge changes
   nothing, so an ungated target that was already running keeps running. In
   two cases it is the image that **failed** its gate:
   - `rb_armed_before_tag`: the agent was killed after arming the rollback and
     before its tag;
   - `repeat_rollback_exhaust`: finish_rollback was killed twice before `up`,
     hit the attempt cap, and stopped trying.

   The reconcile never starts such an image (I4 holds everywhere). It reports
   `recovery_required` and leaves the image for an operator, exactly as AGT-900
   states. The `off` mode does the same.
3. **No production defect was found** in the first run. Every contract check
   passed in both stores.

Added by run 2:

4. **The production privilege path works end to end.** In the sudoers mode
   every Docker call of every upgrade, rollback and reconcile ran as root via
   `sudo -n` from the `culvert-maint` uid, through exactly the rule the
   packaging assigns it (the compose-cli wrapper for container inspect, pull,
   tag and cli runs; a direct `/usr/bin/docker` rule for the rest), including
   the two-`-f` `up` of the configured `compose_override_file`, with the
   shipped compose file and its `depends_on: clamav: service_healthy`. No call
   was refused. The verdicts are identical to the root mode.
5. **`container_not_running` is reached only by a paused container.** The
   agent reads the stack with the sudoers-bound `docker compose ps --format
   json`, which lists running and paused containers but **not exited ones**.
   A stopped proxy (`docker stop`) is therefore read as "no proxy container"
   and decided `stack_down` (danger phase) or `stack_down_unverifiable` (safe
   phase), not `container_not_running`. Both are `recovery_required` with no
   Docker change, so AGT-900 holds; only the reported reason differs from what
   the V2 matrix row suggests. Repro: `run.sh --cases '^container_stopped$'`.
   Not a defect against the contract; the owner may want the reason (or the
   matrix comment) to name this case.
6. **An `abandoned` record is left exactly as it was.** After the deadline the
   reconcile neither reads Docker for the remaining record nor writes its
   journal record (no `reconcile_outcome`), and reports it `abandoned` in
   status and in the reconcile op's result. The next start decides it from
   scratch (here: `noop/rollback_never_moved_tag`, retired).
7. **`ok_stale` is real and handled.** With the documented
   `compose_override_file` pinning another image, `compose up` exits 0 while
   the container keeps the prior image; the F1 fix records no target image id,
   and converge realigns the tag (V2 row A8).
8. **No production defect was found in run 2** either.

## Not covered (and why)

Closed by run 2 (see above): the sudoers mode and the compose-cli wrapper; the
shipped compose file with clamav, the `cli` profile and
`compose_override_file`; standalone `rollbacks.create` image and data records;
the reconcile deadline; the verify-to-audit window; dockerd stopped and
restarted mid-reconcile; a stopped and a paused proxy container; `ok_stale`.

Still not covered:

- **systemd.** The agent is started by the harness as `culvert-maint`, not by
  `culvert-maint.service`, so the unit's sandboxing (`ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `ProtectProc=invisible`, `RuntimeDirectory`,
  `ReadWritePaths`, limits) and its interaction with setuid sudo are not
  exercised. Running systemd inside the test environment is not possible here
  (no systemd as PID 1).
- **sudo-rs.** Only classic sudo 1.9.15p5 was available. The packaging is
  written for sudo-rs (Ubuntu 26.04's default; no argument wildcards), and the
  static parity test covers the rule shapes, but no sudo-rs binary evaluated
  the rendered file.
- **The real Culvert proxy and ClamAV images, and the `ha` profile.** The
  images are the stubs described above; etcd is never started.
- **The cli backup/restore through the wrapper.** Only the fixed
  `--list-backups` run (the data-rollback preflight) completes; the data
  rollback is killed at its first wrapper call (`compose-cli restore ...`,
  which the wrapper accepted and exec'd), so no restore actually runs.
- **A kill in the middle of the audit `write(2)`** (a torn line). The fault
  injection kills at the syscall's entry, before any byte is written; a
  partially written line (the J check "every audit line parses" would catch
  it) is not driven.
- **The deadline expiring inside a Docker call.** The deadline case spends it
  in A's readiness probe; a runner call cancelled by the reconcile deadline
  (SIGTERM through sudo to the root docker child) is not driven.
- **dockerd dying during a `compose up`** (finish_rollback's `up` in flight).
  The dockerd cases hold before the retag and before the verify.
- **`container_not_running` for a restarting container.** Only `paused`
  reaches it (see Findings).
- **One run per mode and store, on one host and one Docker version.** There
  are no repeated trials. The polled kills depend on timing; a miss would be
  retried and reported.
- **A CI workflow.** None was added. The run needs root, starts private
  daemons and (sudoers mode) a private mount namespace. It should work on a
  GitHub-hosted Ubuntu runner with `sudo`, but it has not been tried there.
