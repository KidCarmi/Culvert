# Freeze revision 3: the build inputs of the ONE replacement INTERNAL-ONLY OVA (ASTRA closeout item 3)

This supersedes `../freeze-848c2c2f/BOM-DELTA.md` (revision 2) **for the build source and the candidate image**. Everything else in the accepted `../freeze-93c83f90/BOM.md` (with ASTRA's four provenance corrections) and in revision 2 stands, except where corrected below. **ASTRA owns acceptance.**

## 1. The mismatch, and how it is resolved

**The mismatch (ASTRA):**
- Revision 2 named build commit `848c2c2f`.
- The only candidate image available is the Deep gate image of `0648adeb`, stamped `v1.0.360-candidate.g0648adeba52e`.
- `build-ova.sh` candidate mode requires `--candidate-source` to equal both the checkout and that stamp. Building from `848c2c2f` with this image would therefore be refused, or would need a drift override that is meant for something else.

**Resolution: adopt `0648adeb` explicitly as the build commit.**

| | Value |
|---|---|
| **Build commit (checkout)** | `0648adeba52e09f15505095ba1ff556304b9fcef` on `review/1528-m1-engine-pins` |
| **Tree** | `50c3c5cbc32404a35d8d74a8450afa95665935c2` |
| **Relation to `848c2c2f`** (tree `64d5c99c…`) | Its only child, and a **docs-only** commit. `git diff --name-only 848c2c2f 0648adeb` lists six files, all under `docs/appliance/evidence/combined/`. Every runtime path has the same object ID at both commits (table below). |
| **`SOURCE_DATE_EPOCH`** | **`1793096442`, passed explicitly.** Without it, `build-ova.sh` takes the checkout's commit time (`1793112012`) and the reproducible sidecar bytes change. |
| **Provisioning drift flag** | **None.** Provisioning comes from the same checkout as the image. |

Runtime paths, object ID at `0648adeb` = at `848c2c2f`:

| Path | ID | Path | ID |
|---|---|---|---|
| `appliance/` | `7154f12d` | `Dockerfile` | `bdbeb96d` |
| `appliance/provision/` | `53038110` | `go.mod` / `go.sum` | `5381116b` / `76db5afe` |
| `appliance/build/` | `100e1483` | `internal/` | `bcf606a9` |
| `appliance/clamav/` | `8d4df1d9` | `docker-compose.yml` | `08494506` |
| `cmd/culvert-maint/` | `8b1f4c35` | `docker-compose.maint-agent.yml` | `8b647b2d` |
| `cmd/culvert-console/` | `12ad87e0` | `docker-compose.ha.yml` (repo only, §4) | `43f4967c` |
| `scripts/install.sh` | `9eeb145e` | `packaging/` | `412b83d8` |

**Why adopt rather than rebuild the image from `848c2c2f`:**
- A new image is a new, non-reproducible identity. Its tests would start over.
- It would have exactly the same runtime inputs as the image already tested.
- Adopting the tested image changes no byte the appliance runs.

## 2. Candidate image provenance

| | Value |
|---|---|
| **Producer** | Deep PR Gate [40523416237](https://github.com/KidCarmi/Culvert/actions/runs/40523416237): `workflow_dispatch` on `review/1528-m1-engine-pins`, `head_sha` `0648adeb…`, reusable `_build-image.yml@0648adeb…`, **success 17/17** |
| **Artifact** | `deep-gate-image`, id `12743680277`, zip digest `sha256:32f9612a67e83cff56221260257295d29db20146e084420d2b583647b4b530f8`, **expires 2026-10-28T14:43:32Z** |
| **Tar** | `culvert-image.tar`, sha256 **`770c295ca78dc002694604428e7b2e4b293be5d37a784f6768f509dabd1de4e7`** |
| **Image ID** (the OCI index's single manifest; what containerd reports) | **`sha256:20b6abcbc17028e50aa7db1871dd3e6175a61d533afd961302cc7558dc5a8ed0`** |
| **`/app/VERSION`** | `v1.0.360-candidate.g0648adeba52e` |
| **Deploy bundle inside the image** (`/app/deploy`, sha256 equal to the checkout's file) | `docker-compose.yml` `fc57b1da…`, `docker-compose.maint-agent.yml` `a5d965d6…`, `appliance/clamav/Dockerfile` `4b08fcf3…`. The bundled `culvert-maint` is built by the image's own `maintbuilder` stage from the same commit, and `build-ova.sh` requires its version to equal `/app/VERSION`. |
| **Preservation past the expiry** | Lab commit `9dcbb69db0bcc88bcae2c49d38d97d5097add20e` (`[preserve-image]`, no build, no boot) re-derives the sha256, the manifest digest and the VERSION stamp from the tar and re-uploads it as `lab-source-image-40523416237` for 90 days. `obtain-image.sh` already falls back to that name. **Done:** run [40535331028](https://github.com/KidCarmi/Culvert/actions/runs/40535331028) (only that job ran; its identity step asserted all three values), artifact id `12747932343`, zip digest `sha256:58948c5f43e49b5afe1303654541cbb73aff63089279beb595ab520d511b94e4`, **expires 2027-01-25T15:52:41Z**. The build no longer depends on the one-day Deep artifact. |
| **Fast PR Gate** [40523421826](https://github.com/KidCarmi/Culvert/actions/runs/40523421826) | 20 success / 2 skipped / 3 failure. The failures are the same documented exceptions: `golangci-lint` (four diagnostics in unchanged frozen files), `gitleaks` (274 results, 0 added and 0 removed against the adjudicated SARIF), and their aggregate. **Not offered as a pass.** |

## 3. Expected outputs (the identity step stops before any boot if one differs)

| | Expected |
|---|---|
| `build-info.json` `application.index_digest` | `sha256:20b6abcb…8ed0` |
| Baked sidecar ID (`clamav_sidecar_image_id`) | `sha256:91eae57526b246da28cb370bd824c45af51e245be0093afcc316bc3fbe941f9d` (the F-P2-accepted `culvert.4`) |
| Baked sidecar archive (`clamav_baked_tar_sha256`, and the file on disk) | `6482ae8c2774b30913b69d3d26778da8005817bdfb4df051f324e74c93c3c8ad` |

A mismatch is **STOP/REPORT** (ASTRA's rule), not a rerun.

## 4. Correction: `docker-compose.ha.yml` is not shipped

Revision 2 (§2) described `docker-compose.ha.yml` as "Deploy bundle (HA, not the appliance's default)". **That was wrong.**
- `Dockerfile:191` copies only `docker-compose.yml` and `docker-compose.maint-agent.yml` into `/app/deploy`, the image's deploy bundle.
- Nothing in `appliance/build` places the HA file in the OVA.

It is a **repository file only**. Its `cap_drop: [NET_RAW]` keeps repo-based HA deployments consistent, and `TestM2Hardening_NoServiceKeepsNetRaw` pins it, but **it is neither in the replacement OVA nor in the candidate image.**

## 5. Test map: what proves each change, and where

> **Revision 3.1 (ASTRA 27 Oct 16:10).** Only the harness and documentation identities change: the lab is now `69fb5f36`, which replaces `9dcbb69d`. The candidate, source identity, epoch and sidecar constants in §1–§4 are unchanged and were not rebuilt.

**Pre-build** (done):

| Change | Evidence |
|---|---|
| M1 engine pins, sidecar `culvert.4` | Unchanged from the accepted record (`../freeze-93c83f90/BOM.md` §4) |
| `cap_drop NET_RAW` | `TestM2Hardening_NoServiceKeepsNetRaw` (fails if the drop is removed). Deep 40523416237 ran the lifecycle, maintenance-agent and real-ClamAV jobs on the new compose files. Probe controls (`../m2-mitigation/probe-control/`): with `NET_RAW` dropped, root in a default-seccomp container gets `EPERM` for AF_PACKET; with default capabilities, root **opens** it. |
| `io_uring_disabled = 2` | `TestM2Hardening_IoUringDisabledOnTheGuest`, `TestBuildOVA_CopiesEveryProvisionFilePrepareGuestInstalls`, and the build-time value check in `prepare-guest.sh`. Ordering rationale for applying it before workloads: `../m2-mitigation/RESIDUAL-DISPOSITION.md` §1a. |
| **Harness, fail-closed** (lab `69fb5f36`) | `m2-guest.sh` records every observation with its exit status, and `m2-verdict.py` refuses anything not acquired and parsed. Receipts (`../m2-mitigation/harness-receipts/`): 51 self-test cases, 0 wrong (passing fixture, valid-empty cases, one case per failure mode). Two evaluator mutations are each caught. A real sandbox run fails closed on every facility the sandbox lacks, and a run with `ip` failing and `nft` absent fails both checks. The self-test runs as the first step of every lab job. |

**Post-build, on the one replacement.** These run after the artifact exists; they are not prerequisites for creating it. Every checkpoint (`M2H <tag>`) records seven checks:

| Check | What it requires |
|---|---|
| `-transcript` | The transport exited 0; the begin and end markers are present |
| `-hardening` | `io_uring_disabled=2`; host `io_uring_setup` returns `EPERM`; a descriptor census with 0 rings and 0 live-but-unreadable processes (exits and vanished descriptors reported); no `NET_RAW`/`NET_ADMIN`/`SYS_ADMIN` and seccomp 2 for every container process; the probe refused all four requests, as root and as the container user, in both containers |
| `-ordering` | For this boot, `systemd-sysctl` was active before containerd and dockerd started; the drop-in sha256 is recorded |
| `-preconditions` | Exactly three network namespaces. In each: no VLAN link, no encap route, allowed qdisc kinds, IPv6 `forwarding`/`seg6_enabled`/`ioam6_enabled` 0 on every interface. None of 32 precondition modules loaded; unprivileged BPF off; NIC e1000 or vmxnet3. |
| `-ruleset` | Every nftables rule expression in every namespace is a source-checked form, otherwise "review required". The text ruleset is kept verbatim. |
| `-clamav` | clamd found EICAR on a stream scan (`rc=1` + `FOUND`) |
| `-clamav-ready` | The proxy's `/ready` reports clamav ok |

Where the checkpoints sit in the run:

| When (lab `69fb5f36`, matrix `candidate-0648adeb`) | Checkpoint | Regression checks already in the run |
|---|---|---|
| Build | Identity step (§3) | `build-ova.sh` closure + cold-load + bundled agent = image version |
| **First boot**, steps 1–5 | `M2H firstboot`. It runs **after** the workload and traffic steps, so the first boot's ordering evidence is the same-boot systemd timestamps, not its position. | 5 `clamav-real`, 5 `traffic`, 5 `ready-rows`, 5c category enforcement |
| **Maintenance**: 6 agent install, 6b offline restore `down`/`up`, 6c signed apply + rollback | `M2H maintenance`, on the **recreated** containers | 6 `agent-backup`/`restore-dry-run`, 6b `restore-commit` (traffic), 6c `signed-apply`/`signed-rollback` (traffic after each swap) |
| **OS update + reboot** (7, 8) | `M2H reboot`. Ordering and drop-in again on the new boot. | 7 `os-update`/`reboot`/`docker-held`, 8 `enforcement`/`ready`/`image-identity`/`stack-resumed` |
| Engine surface (E, after step 8) | E `m2-hardening` plus the existing kernel-assumption checks | E engine-version, sockets, modules denied |
| **End of run**: R, 3 power-cycle recoveries; H, history restore | `M2H final` | R `clamav-evidence` (a fresh EICAR through the proxy: blocked with clamd up, **not** with clamd stopped, blocked again after restart), R `recovery` per reboot, H `history-enforcement` |
| F-DISK-1 (separate job, same image via `SOURCE_IMAGE_*`) | — | ENOSPC behaviour of this image |

**Not gated, recorded only:** freshclam's last log lines at each checkpoint. A fresh database is not a pass condition, because the guest's mirror access depends on the runner.

**After the qualification** (each still to run): exact-byte rescans of the guest OS and host binaries, the app image and the baked sidecar, at all severities, with a check that the engine binaries equal the M1-scanned DEB contents. **No ESXi step is part of this plan.** Any ESXi import or use needs separate authorization, and the existing single VM and its custody stay as they are.

## 6. M2 conditions incorporated

`../m2-mitigation/RESIDUAL-DISPOSITION.md`, **if ASTRA accepts it**, governs the replacement's use:
- **Scope:** internal lab only.
- **Exposure:** the §5 restrictions, enforced by the checkpoints above or as operator obligations.
- **Lapse:** the §6 STOP/reassess triggers and the §7 30-day time box. **Not started:** the clock starts only on final acceptance. A trigger means stop and reassess; it never authorizes an automatic kernel patch or rebuild.

## 7. What happens next, and what does not

- **Once ASTRA accepts this closeout:** one `workflow_dispatch` of `appliance-lab.yml` on `test/appliance-lab` at the lab commit named in the handoff (now `69fb5f36` or a later lab commit ASTRA reviews). Its matrix holds exactly one entry, `candidate-0648adeb`. This is covered by the owner's existing conditional authorization (6400728126).
- **Not part of it:** a second build, ESXi action, merge, pilot, release, any copy of the OVA, or any deletion.
