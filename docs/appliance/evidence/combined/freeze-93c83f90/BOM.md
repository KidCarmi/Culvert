# Revised freeze: source, BOM and delta-to-test map for the replacement OVA (owner 6400728126, prerequisite 3)

This revises the freeze of `b9105086` (`71e3851a`, `freeze-b9105086/BOM.md`). It covers **only** the two owner-approved deltas: M1 (Docker Engine / containerd) and the sidecar libcurl fix. **ASTRA owns acceptance.** This record makes no claim about M2 or about CI acceptance; those are prerequisites 1 and 2.

## 1. Frozen build source

| | Value |
|---|---|
| **Build commit** | `93c83f903edaad7714cba21f07335aaf2f88e1c9` on `review/1528-m1-engine-pins` |
| **Tree** | `a10e9ec6abfece88cd390e53be21442ea0552516` |
| **Commit time** | `1793096442` (2026-10-27T10:20:42Z) |
| **History** | Linear children of frozen `b910508629e9d80352067bc8ec608753ddf0924e` (tree `b6b80fc5…`): `5c4c2be8` (M1 pins) → `10b46a2e`, `c1b08dbe`, `22245a12`, `2f240eaf` (docs) → `93c83f90` (sidecar fix). No merge from moving `main`; `b9105086` history is preserved. |

**Build rule:**
- Build the OVA from a checkout of **exactly `93c83f90`**, not a later docs commit.
- `build-ova.sh` then defaults `SOURCE_DATE_EPOCH` to `1793096442`; pass it explicitly as well.
- **Why the exact commit:** the epoch fixes the sidecar's identity, and a docs commit has a different timestamp. Building from one would silently change the sidecar bytes away from the F-P2-tested ones.
- **The replacement is acceptable only if its baked sidecar ID is `sha256:91eae57526b246da28cb370bd824c45af51e245be0093afcc316bc3fbe941f9d`.** `build-ova.sh` records the ID it bakes as `CLAMAV_SIDECAR_ID`, and first boot re-checks it after `docker load`. `build-ova.sh` does not compare against this value itself, so post-build gate 1 does. A different ID means F-P2 must rerun on the new bytes.

**Evidence lives on later docs-only commits** (`9d7c5fd9` and onward). `git diff 93c83f90 <evidence-head> -- . ':!docs'` is empty.

## 2. Bill of materials

| Component | Pin / identity | Changed vs `b9105086`? |
|---|---|---|
| App (proxy) binary | Built from tree `a10e9ec6` (`go1.27.3` toolchain, language `go 1.26.6`). `Dockerfile` `bdbeb96d`, `go.mod` `5381116b`, `go.sum` `76db5afe`, `internal/` `bcf606a9`: all **identical**. The only `.go` change is `appliance_ci_lane_test.go`, a test that is not shipped. | binary sources: **no** |
| App image | Rebuilt by `build-ova.sh` candidate mode; not reproducible across builds, so its identity is bound by the build receipt (`org.opencontainers.image.revision` = `93c83f90…` plus the baked image ID). | **yes**: the image's deploy bundle (`/app/deploy`) carries the compose files, which name `culvert.4` |
| Maintenance agent `culvert-maint` | `cmd/culvert-maint` tree `8b1f4c35` | no |
| Console | `cmd/culvert-console` tree `12ad87e0` | no |
| Provisioning / boot | `appliance/provision` `7fa941d2` | no |
| Build tooling | `appliance/build` `2d5988f7` → `6482b7e7`; only `manifest.env` changed (`87eda691` → `a12813ad`) | yes (pins only) |
| OS maintenance | `appliance/os-maintenance` `a91dcf9c` | no |
| Installer | `scripts/install.sh` `9eeb145e` | no |
| Packaging | `packaging/` `412b83d8` | no |
| Compose | `docker-compose.yml` `e32b2ea9` → `33141889`, `docker-compose.ha.yml` `4b43e855` → `685111e1`; the only change is the sidecar tag `culvert.3` → `culvert.4` | yes (tag only) |
| Guest OS | Ubuntu 24.04 cloud image serial `20260926`, sha256 `6a81c375…bb4d2`, signer `D2EB4462…7C81`; apt snapshot `20261002T120000Z` | no |
| Kernel | `linux-image-virtual-hwe-24.04` → `7.0.0-38-generic` | no |
| **Docker Engine / CLI** | `5:29.9.2-1~ubuntu.24.04~noble`. DEB sha256: engine `95ddf7a2…c8ae`, CLI `74747b5c…794f`. | **yes** (M1) |
| **containerd.io** | `2.4.2-3~ubuntu.24.04~noble`, DEB sha256 `f811ab57…4122`. Apt key `9DC85822…CD88` (signing subkey `D3306A01…FCD8`). | **yes** (M1) |
| Compose plugin | `5.6.1-1~ubuntu.24.04~noble` | no |
| **ClamAV sidecar** | Ref `culvert/clamav:1.5.4-culvert.4`. Dockerfile sha256 `4b08fcf3052345918cfc14fd426b90d7d8695a1cdb96364af541d8e275288234` (`appliance/clamav` tree `8d4df1d9`). Base `docker.io/clamav/clamav` index `638d9020…` / amd64 `705e0723…`. | **yes** |
| ↳ identity | **Manifest / image ID `sha256:91eae575…41f9d`**, config `sha256:3e3bef5e…d37f`, at `SOURCE_DATE_EPOCH=1793096442` | |
| ↳ archive | `clamav.tar.gz` (gzip `-n -6`) sha256 `6482ae8c…c8ad`; raw OCI `b8a413a4…3b6a`. Retained as artifact `12735025253`. | |
| ↳ packages | 41 Alpine 3.24.2 packages. Versus `culvert.3`, **only `libcurl` 8.22.0-r0 → 8.23.0-r0**. | |
| Cold-load / cosign tooling | `docker@sha256:bfec1f51…`, `cosign:v3.0.6@sha256:de9c6560…` | no |
| VM shape | 2 vCPU / 4096 MB / 40 GB, `vmx-13` | no |

### Package inventory: first boot vs after maintenance

| When | What is installed |
|---|---|
| **First boot** (verified on the `61c46d6d` disk, M2 snapshot run 40472951974) | Includes `bpftrace` 0.20.2-1ubuntu4.3, `bpfcc-tools` 0.29.1, `linux-tools-common` 6.8.0-147 and `ubuntu-kernel-accessories` 1.539.2, along with their dependents. |
| **After the first `culvert-os-update`** | Those 34 packages are autoremoved, identically on the baseline and on the M1 overlay (`m1-engine-pins/lab/README.md`). Nothing is installed or upgraded, and Docker stays held. |

The rebuilt OVA uses the same guest-OS pins, so the same split is expected. This is an expectation until the replacement's own scan confirms it.

## 3. Remaining known CVEs and their dispositions

| Area | Remaining | Status / evidence |
|---|---|---|
| Docker / containerd binaries (M1) | x/net v0.58.0 CVE-2026-78669 (HIGH) in containerd, ctr and shim; runc x/net v0.55.0 CVE-2026-78669 / 46600; GO-2026-6603/6610/6611/6612/6617; cilium/ebpf GO-2026-6238; moby/sys/user GO-2026-6686; x/crypto GO-2026-5932 (no fix). GO-2026-6809 is **removed**. | ASTRA scoped PASS on the M1 package review (`m1-engine-pins/README.md`). The rest stay residuals. |
| Compose plugin 5.6.1 | x/net CVE-2026-78669 (HIGH) and 78659/78660/78663/97032 (MEDIUM) | Unchanged existing residual (exact-OVA scan of `61c46d6d`) |
| ClamAV sidecar `91eae575…` | **None known**: 0 at any severity (lab run 40504719384) | `m1-engine-pins/sidecar-culvert4/` |
| App image | GO-2026-5932 (x/crypto openpgp), not linked into the shipped binaries | Unchanged existing disposition. The rebuilt image must be rescanned after the build. |
| Kernel 7.0.0-38 | 3 new CRITICAL: ASTRA credits observed-QEMU-state non-reachability (GUE 98621, stmmac 98571, nvmet-auth 98725). New HIGH: **open, ASTRA's M2 disposition** (prerequisite 1). | `m2-snapshot/` |
| Other guest-OS packages | Same pinned image and apt snapshot as `61c46d6d` | That OVA's accepted exact scans apply as context only. The replacement gets its own exact-VMDK rescan. |

## 4. Delta-to-test map (`b9105086` → `93c83f90`)

| Change | Shipped where | Pre-build evidence | Post-build gate on the replacement (not yet run) |
|---|---|---|---|
| **M1:** Docker 29.9.2 / containerd.io 2.4.2-3 (`manifest.env`) | Guest engine | Signed-APT provenance plus before/after `govulncheck`/Trivy on the exact DEB binaries (`m1-engine-pins/README.md`). Lab compatibility on the disposable overlay: run 40338463307, 157 PASS / 18 INFO / 0 FAIL / 1 BLOCKED (IdP). It covered offline load on the containerd snapshotter, sidecar `--no-build`, agent sudo/socket/apply/rollback, signed update and rollback, backup/restore, history, OS update and reboot, ENOSPC pressure, and the engine surface. | Exact-VMDK binary rescan (engine binaries must equal the scanned DEB contents); full QEMU qualification on the rebuilt disk |
| **Sidecar:** `libcurl=8.23.0-r0`, separate `apk add` without `--upgrade`; tag `culvert.4` (Dockerfile, `manifest.env`, both compose files) | Baked sidecar archive; compose ref | Unit/lane tests at `93c83f90`, including both mutation checks. Deep dispatch 40487749917: success, with the real `culvert.4` sidecar running scenario A. **F-P2** run 40487883047: 0 wrong-cleans on `91eae575…` (1.4.6 control: 63). **Exact all-severity scan of `91eae575…`**: run 40504719384, 0 vulnerabilities, archive retained. | The OVA's baked sidecar ID must equal `91eae575…` (or F-P2 reruns on the new bytes); exact baked-archive scan; first-boot load and `/ready clamav`; EICAR block |
| Compose tag change inside the app image's deploy bundle | App image `/app/deploy` | `TestClamAVSidecar_EveryShippedFileNamesTheSameLocalTag`; Deep lifecycle and real-ClamAV jobs | Agent refresh/apply/rollback keep the `culvert.4` binding (QEMU lifecycle) |
| Lane test (`appliance_ci_lane_test.go`) | Not shipped | Passes; both mutations fail it as intended | n/a |
| **Unchanged** (app sources, agent, console, provisioning, OS maintenance, installer, packaging, guest OS, kernel, Compose plugin) | — | `b9105086` freeze evidence; Deep dispatch 40487749917, 17 jobs successful | Standard post-build gates (below) |

### CI on `93c83f90` (dispatch)

| Gate | Result |
|---|---|
| **Deep** [40487749917](https://github.com/KidCarmi/Culvert/actions/runs/40487749917) | Success |
| **Fast** [40487754812](https://github.com/KidCarmi/Culvert/actions/runs/40487754812) | 20 success / 2 skipped / 3 failure |

The three Fast failures:
- **`gitleaks`:** the 274 history-scope findings ASTRA bounded; 0 introduced by this branch.
- **`golangci-lint`:** four diagnostics in unchanged frozen files, flagged against moving `main`.
- **The aggregate check that follows from those two.**

Neither failure is offered as a pass.

## 5. Post-build acceptance gates (after the single build, each still to run)

The replacement must pass all of the following:

1. **Exact-VMDK identity:** the build-info commit is `93c83f90`; the sidecar ID is `91eae575…`; the engine binaries equal the M1-scanned bytes.
2. **Exact-byte security rescans:** guest OS and host binaries, the app image, and the baked sidecar, at all severities.
3. **QEMU qualification:**
   - boot and lifecycle;
   - runtime image load;
   - maintenance and rollback;
   - backup, history, policy and scan;
   - F-DISK.
4. **ASTRA's independent acceptance.**

There is no rebuild series, no ESXi action, no merge, no pilot and no release.
