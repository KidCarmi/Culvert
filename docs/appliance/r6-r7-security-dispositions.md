# R6 / R7 security dispositions for the frozen candidate (ASTRA 6364575740, OPUS item b)

Prepared 2026-10-23. **Preparation only**: no build, no lab run, no VM change, no change to the PR head. Every claim below cites an evidence file under `evidence/security-r6-r7-1528/` on `review/1528-fdisk-evidence`. Each of those files was produced by a command run against the **exact bytes** named; nothing is inferred from source alone unless the text says so.

**Frozen identity:** PR head `4524311b`; OVA SHA-256 `27006cf4ad158342109b972e522438328453933df278c31b3fcf1d5301574ebd`. The OVA was re-downloaded from retained artifact `12228273676` (zip `c559f503…`, the value E1 recorded). Hashes recomputed here:
- OVA: `27006cf4…`;
- VMDK: `eb687a7d…`, matching the OVA's `.mf`.

---

## R6 — Docker Compose

### Bytes

| Binary | Where it comes from | SHA-256 | Go / x/net |
|---|---|---|---|
| **5.6.0** (shipped in `27006cf4`) | `docker-compose-plugin_5.6.0-1~ubuntu.24.04~noble`, signed Docker repository | `40343e21ca777173e69cff5dbafeb37c6f81f3b0d57d9e597f036e95eb63e76a` (byte-identical to E1/E8) | go1.26.8 / v0.58.0 |
| **5.6.1** (newer; *not* in any OVA) | `docker-compose-plugin_5.6.1-1~ubuntu.24.04~noble`, deb `9725be1d…` | `47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0` | **go1.26.10** / v0.58.0 |

**Trust chain for 5.6.1** (`r6-compose/`): Docker's key, fingerprint `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` (the value pinned in `appliance/build/manifest.env`) → good signature on `InRelease` (dated 2026-10-23T03:57Z) → `Packages` SHA-256 `18e93294…`, listed in InRelease → deb SHA-256 equals the `Packages` entry.

### Findings (govulncheck v1.8.0, binary mode, vuln DB 2026-10-21)

| | 5.6.0 (shipped) | 5.6.1 |
|---|---|---|
| Symbol-reachable advisories | **12**: GO-2026-6599, 6600, 6603, 6605, 6607, 6608, 6610, 6611, 6612, 6613 (stdlib), 6617 (x/net), 6809 (x509) | **4**: GO-2026-6603, 6611, 6612, 6617, **all in `golang.org/x/net/http2` only** |
| GO-2026-6607 (ECH, crypto/tls) | symbol-reachable | **fixed** (stdlib) |
| GO-2026-6609 (Range) | package-level only (no symbol reached) | fixed |
| Remaining non-symbol rows | — | **GO-2026-6610** (x/net, package-level) and **GO-2026-5932** (x/crypto `openpgp`, module-level, no fix). 5.6.1 is **not** a zero-finding binary |
| GO-2026-6611 (SETTINGS CPU) | stdlib and x/net | x/net only |

### Linked code (`linked-symbols.tsv`, `go tool nm`)

The same in both binaries:
- **0** symbols for x/net `http2.Server`, `serverConn`, `ClientConn` or `Transport`.
- **34** for x/net `http2.Framer`.
- grpc-go `http2Client` (54) and `http2Server` (59), and `grpc.(*Server).Serve` (6).

So Compose **contains a gRPC server**: the BuildKit session callback. "Compose has no listener" is not a sufficient dismissal, as ASTRA said.

The x/net fixes (v0.58 → v0.60) are mostly in the server/transport files, which are not linked. **But `frame.go` changed too** (`xnet-0.58-0.60-frame.go.diff`): `Framer.ReadFrame`'s meta-header path gained a separate budget for the `trailer` header (GO-2026-6603). So the Framer that is linked is part of the fix, and it cannot be dismissed as unlinked code.

### What the appliance actually makes Compose do — measured (`r6-compose/measure/`)

**Method.** Both binaries were driven through the docker CLI plugin mechanism, as on the appliance, using:
- the **exact shipped** `docker-compose.yml` and `docker-compose.maint-agent.yml`, plus the shipped `appliance/clamav` build context;
- offline stand-in images, which make no network calls (`tools/stub.go`);
- a dockerd 29.6.2 in debug mode;
- strace over every `socket`/`connect`/`bind`/`listen`;
- a logging relay in front of the daemon socket (`tools/tap.go`). It records every HTTP request line, every `Upgrade:` header, and **which side sends an HTTP/2 preface**. The client side of an h2 connection sends the preface, so a preface from the daemon means Compose is acting as an HTTP/2 **server**.

| Command (the agent's sudoers-allowlisted set) | 5.6.0 | 5.6.1 |
|---|---|---|
| `ps --format json` | HTTP/1.1 to the daemon socket only | same |
| `up -d` (images present) | HTTP/1.1 only; no `/session`, `/grpc` or h2 | same |
| `--profile cli run --rm cli --list-backups …` | HTTP/1.1 only | same |
| `down` | HTTP/1.1 only | same |
| **`up -d` with the derivative image absent** (build fallback) | **2× `POST /session` + 3× `POST /grpc`, 10× `Upgrade: h2c`, h2 prefaces in both directions** (Compose is HTTP/2 client *and* server) | same |

- No step in either version opened a TCP/UDP connection from Compose (`*.strace.net`). The only listeners are the docker CLI's own abstract Unix plugin-signal socket (`@docker_cli_…`).
- In an earlier, superseded attempt (before the relay was in place), the 5.6.0 build path showed one loopback connect (`127.0.0.1:41247`). It did not recur in the recorded run and is noted for completeness.

**Consequence, within the measured scope.** Of the cases measured, only the build fallback exercised the HTTP/2 client and server roles (and with them the `x/net/http2` Framer and grpc server code), and its peer was the local root dockerd/BuildKit. That is the same trust boundary as Compose itself, which runs as root through the agent's sudo allowlist.

What the measurement does **not** cover:
- Docker 29.6.2 with stand-in images, not the appliance's Engine 29.9.0;
- only `--list-backups` for the `cli` service, not every backup, restore or cleanup argument or error path;
- the delivered traces are filtered (network syscalls only).

This supports "only the build fallback **among the measured cases**", not "the only possible appliance HTTP/2 path".

### Privilege, environment, egress and resources (exact config)

- **Invocation:** only the maintenance agent's fixed templates, via `sudo` with a literal sudoers allowlist (`cmd/culvert-maint/internal/runner/templates_d16b.go`). Subcommands: `ps`, `up -d`, `down`, and `run --rm cli …` (backup, list, restore, cleanup). No `build`, `bake`, `watch` or `publish`. sudo's `env_reset` means `DOCKER_HOST`/`OTEL_*` cannot be injected (as recorded in E8).
- **The build fallback is reachable by design.** `docker-compose.yml` gives `clamav` a `build: context: ./appliance/clamav` with `pull_policy: never`, and `install.sh` installs that Dockerfile into `/srv/culvert`. If the baked tag `culvert/clamav:1.5.4-culvert.1` is ever missing (for example after a prune or store loss), `up -d` **builds** it. That pulls the base image by digest from docker.io and runs `apk` against Alpine mirrors. It is also an **R7 integrity concern**: the sidecar would then run fresh bytes that were never scanned.
- **Egress:** `appliance/provision/nftables.conf` sets `input` policy drop and has **no output chain**, so host egress is not filtered.
- **Resources:** `culvert-maint.service` sets `TasksMax=64` and `LimitNOFILE=4096`, with no memory or CPU cap. **Not measured:** whether a sudo'd Compose stays in the agent's cgroup or is moved into a new session scope by the PAM session stack. A bound on Compose itself is therefore **not** claimed.

### Per-CVE disposition

| CVE / GO id | 5.6.0 (frozen OVA) | 5.6.1 |
|---|---|---|
| GO-2026-6611 (CVE-2026-78669, HTTP/2 SETTINGS CPU; client **and** server) | Reached only on the build fallback; peer = local root daemon. **RESIDUAL, low exposure** | x/net Framer only, same path. **RESIDUAL, low** |
| GO-2026-6607 (ECH outer extension, crypto/tls) | TLS-server handshake code; Compose made no TLS or TCP connection on any measured path, and its gRPC server runs over h2c on a Unix socket. **NOT REACHED (measured)** | **FIXED** |
| GO-2026-6609 (Range) | Package-level only; no symbol reached. **NOT REACHED** | **FIXED** |
| GO-2026-6603 / 6612 / 6617 (HTTP/2 server: trailer memory, flow-control refund, HPACK race) | Server-role code is reached only via the build fallback; peer = local root daemon. **RESIDUAL, low** | x/net Framer (6603's trailer budget is in it) on the build path only. **RESIDUAL, low** |
| GO-2026-6599/6600/6605/6608/6610/6613/6809 (stdlib) | None reached on any measured path (no network peers besides the daemon). **NOT REACHED (measured)** | **FIXED** |

### Recommendation (for owner decision; nothing is changed here)

1. **Adopt Compose 5.6.1 in the R4 replacement.** It removes every stdlib finding, including ECH and Range, and leaves 4 x/net rows reachable only on the build fallback. Per ASTRA's R6 rule, new Compose bytes need an exact scan, offline load, apply/rollback, state/volume preservation and reboot compatibility as part of R4.
2. **Close the build fallback on the appliance.** Have the agent's `up -d` template pass `--no-build` (appliance-scoped only, because quick-start compose installs rely on the fallback). Recovery from a missing sidecar tag would then reload the scanned archive `/var/lib/culvert-appliance/images/clamav.tar.gz`, which first boot already loads, instead of building fresh bytes. This removes the one HTTP/2 path **observed in the measured cases** and the unscanned-sidecar risk. It is not proof that no other HTTP/2 path exists. It is a code change for the R4 tree, so it is proposed, not made.
3. **Residual for a limited pilot on the frozen OVA:** if the owner accepts 5.6.0 for a bounded pilot, the exposure is the build fallback with a local root peer. That needs a named owner and an end date; no dates are invented here.

---

## R7 — ClamAV sidecar binding

### Archive → image → layers (exact bytes, `r7-sidecar/`)

| Link | Evidence |
|---|---|
| OVA `27006cf4…` contains `/var/lib/culvert-appliance/images/clamav.tar.gz` | read from the VMDK with libguestfs (read-only) |
| archive SHA-256 **`a442f2dd562f609dd567f92e05634e8a18a05d3ddc981b63eb7fc99471f92517`** | equals `clamav_baked_tar_sha256` in the OVA's own `build-info.json` |
| archive OCI index → **one** manifest `sha256:ea362f9b2f7722aaaef4149ac945ebb1d182dde54e32792d8277e5126cc63bfd`, linux/amd64, ref `culvert/clamav:1.5.4-culvert.1` | `index.json`; equals `clamav_sidecar_image_id`, which is what E1 saw running |
| manifest → config `be88e79c…` + **8 layers**; all **10 blobs** hash to their names | `blob-verification.txt` |

That closes ASTRA's R7 binding gap. The image ID E1 observed is now tied, through verified content addresses, to one archive inside the exact OVA.

### Exact-byte scan of that archive (trivy 0.69.3, the lab version; DB 2026-10-23)

- OS: Alpine 3.24.2.
- **0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW.**
- **2 UNKNOWN-severity rows, one CVE:** `CVE-2026-107891` in `musl` / `musl-utils` `1.2.6-r2`, fixed in `1.2.6-r3`. Alpine secdb v3.24 lists it under `1.2.6-r3`. Impact text was **not obtainable** from this environment: NVD has no record yet and OSV is unreachable here. It is recorded as unknown impact, not as harmless.
- **Coverage limit:** trivy inventoried OS packages only. ClamAV's own C/Rust binaries carry no language-package metadata, so they are covered only by Alpine's package records.
- **Earlier evidence:** the lab's exact scan of `27006cf4` (artifact `12233103035`) did **not** include the sidecar image. This is the first scan bound to these sidecar bytes.

**Disposition:** RESIDUAL (unknown impact, fix available). Remediation: pin `musl=1.2.6-r3` alongside the existing `pcre2`/`zlib`/`nghttp2` pins in `appliance/clamav/Dockerfile` at the R4 rebuild, then re-scan and run F-P2 on the new sidecar bytes. **F-P2 (functional clamd behaviour): no reuse is claimed.**
- F-P2 was **not** re-run here.
- The earlier controlled F-P2 evidence belongs to a **different candidate's** sidecar, not to `ea362f9b…`, and version 1.5.4 alone does not carry it over.
- Reuse first needs an engine/config/library/signature delta map from that proof to `ea362f9b…`. Only unmatched or changed behaviour then needs an affected check, in the owner-selected R4.
- E1's exact-`27006cf4` content and outage passes remain credited.

---

## R7 — OS / kernel applicability on the exact disk (`r7-kernel/`)

Sources: the lab's exact scan of `27006cf4` (artifact `12233103035`, zip `8fec3080…`), plus files read here from the same VMDK: `/etc/modprobe.d/culvert-unused.conf` (`320246…`) and `modules.dep` / `modules.dep.bin` for `7.0.0-38-generic`.

### Userspace

- **Fixable HIGH rows: 4, all the Compose binary** (stdlib 1.26.8 / x/net 0.58: CVE-2026-78667, 97031, 78669), i.e. R6 above.
- **No other userspace package has a fixable HIGH or CRITICAL.**
- **The four packages E1's OS maintenance changed** (`liblzma5`, `xz-utils`, `python3-jwt`, `ca-certificates`) carry only MEDIUM rows (python3-jwt, no fix listed) in the pre-maintenance scan. Not material.

### Kernel `7.0.0-38-generic`: 201 HIGH/CRITICAL rows

| Class (scan) | CRITICAL | HIGH |
|---|---|---|
| denied: module load refused by `culvert-unused.conf` | 5 | 68 |
| absent: module not on disk | 0 | 5 |
| present: module on disk and loadable | 3 | 120 |

`linux-libc-dev` and `linux-tools-common` duplicate these rows but contain no running kernel code.

**All 8 CRITICAL rows: a conditional *static* disposition of "not reachable".** The basis is kmod dry-runs against the disk's own indexes (`modprobe-dryrun.txt`) and `modules.dep`. It holds only on two assumptions:
- the relevant dependencies are not already loaded;
- loading goes through the supported modprobe path that obeys `culvert-unused.conf`.

Disk dry-runs do **not** establish a live system's loaded-module state. Kernel config defaults (below) are not live sysctl or capability proof either.

| CVE | Subsystem | Why not reachable |
|---|---|---|
| CVE-2026-89659, 89708, 90037, 93221 | NFSD | `install nfsd /bin/false` |
| CVE-2026-90162 | ksmbd | `install ksmbd /bin/false`; it also depends on `ib_core`, which is denied |
| CVE-2026-89530 | svcrdma (`rpcrdma.ko`) | depends on `ib_core` (`install /bin/false`); the server side also needs nfsd, which is denied |
| CVE-2026-98365 | RDMA soft-RoCE (`rdma_rxe.ko`) | depends on `ib_core` and `ib_uverbs`, both `install /bin/false`. The kernel refuses a module whose dependency is not loaded (unresolved symbols), whatever modprobe does |
| CVE-2026-89652 | ceph | `ceph.ko` *can* load, but the bug is in ceph's **NFS export** `get_name`, which only nfsd calls; nfsd is denied |

The bypass is a root `insmod` of the dependency chain, and root is already the trust boundary.

**120 present HIGH rows: RESIDUAL, in two groups. They are not individually triaged here.**

- **Hardware and filesystem modules that are candidates for the denylist** (ocfs2, ntfs3, smc, Wi-Fi mt76/mac80211/cfg80211, DRM amdgpu/nouveau/vc4/v3d, f2fs, exfat, btrfs, erofs, ublk, nvme-tcp, ipvlan, slip, …). **`vmwgfx` is excluded from this list**: it is VMware's display driver, and the appliance runs on ESXi.
  - These are loadable today. Note the scan's own `kernel-review-not-holding.txt`: 41 modules an older review called "not shipped" **are on this disk**.
  - **Proposed closure:** extend `culvert-unused.conf` in the R4 build, the mechanism already used for nfsd and ksmbd. This is **not automatically safe**:
    - it must keep broad NIC support and the `MODULES=list` deferral;
    - each display, VM or storage driver needs an explicit supported-hardware impact decision before it is denied.
- **Core kernel** (BPF ×17, net core, netfilter, tls, xfrm, sched, futex, mm, …).
  - **No newer kernel exists:** `linux-image-generic-hwe-24.04` in noble-updates and noble-security is still `7.0.0-38.38~24.04.4` (checked 2026-10-23).
  - **Controls observed on these bytes:** `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` (unprivileged BPF off; the BPF rows need `CAP_BPF`/`CAP_SYS_ADMIN`), `kernel.apparmor_restrict_unprivileged_userns=1`, and `CONFIG_SECURITY_DMESG_RESTRICT=y`.
  - **Containers:** the proxy image runs as non-root user `proxy`. The compose files set **no** explicit `cap_drop`/`security_opt`, so they rely on Docker's default seccomp and capability set, which excludes `SYS_ADMIN`, `BPF` and `NET_ADMIN`. That is a default, not an appliance-enforced control.
  - **Fix path:** the appliance's OS-update path, when Ubuntu publishes a kernel.

## What this does not establish

- No new bytes were built. Compose 5.6.1, `--no-build`, the musl pin and the extended denylist are **proposals** for the R4 tree, each needing ASTRA's R4 delta checks.
- The Compose runtime measurement used Docker 29.6.2 and stand-in images, not the appliance's Engine 29.9.0. The Compose binaries, compose files and command set were the exact shipped ones.
- The 120 present kernel HIGHs are grouped, not triaged one by one. The musl CVE's impact is unknown.
- This is producer evidence (OPUS), for ASTRA's independent review. MERGE / PILOT / RELEASE remain NO-GO.
