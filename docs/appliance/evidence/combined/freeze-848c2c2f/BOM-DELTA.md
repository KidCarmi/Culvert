# Freeze revision 2: `93c83f90` → `848c2c2f` (M2 mitigation)

This is a **delta** on the freeze ASTRA accepted at 12:49 (`freeze-93c83f90/BOM.md`, with ASTRA's four provenance corrections). Everything in that record stands except what is listed here. **ASTRA owns acceptance.** The mitigation and residual reasoning are in `m2-mitigation/README.md`.

## 1. Build source (supersedes §1 of the accepted record)

| | Value |
|---|---|
| **Build commit** | `848c2c2f40f0a7beda3a7e2be7b7b396398f6d54` on `review/1528-m1-engine-pins` |
| **Tree** | `64d5c99ccdc718e402a594193a687aa893c51619` |
| **Commit time** | `1793111962`. **Not** the build epoch; see the build rule. |
| **History** | Linear: … → `93c83f90` (sidecar fix) → `9d7c5fd9`, `bca18819` (docs) → `848c2c2f` (M2 mitigation). No moving-`main` merge. |

**Build rule:**
- Build from exactly `848c2c2f`, and pass **`SOURCE_DATE_EPOCH=1793096442` explicitly**.
- **Why explicit:** `build-ova.sh` otherwise takes the checkout's commit time (`1793111962`), which would change the reproducible sidecar bytes away from the F-P2-accepted ones.
- **Why the sidecar is unchanged:** the sidecar Dockerfile is unchanged (`appliance/clamav` tree `8d4df1d9`, Dockerfile sha256 `4b08fcf3…`). With that epoch, the build reproduces manifest `91eae575…`, archive gzip `6482ae8c…` and raw `b8a413a4…`, as accepted.
- **Mismatch rule:** per ASTRA, any mismatch of baked sidecar manifest or archive hash with the accepted `91eae575…` archive is **STOP/REPORT**.

## 2. What changed (non-docs, `93c83f90` → `848c2c2f`)

| File | Blob before → after | Change | Shipped where |
|---|---|---|---|
| `docker-compose.yml` | `33141889` → `08494506` | `cap_drop: [NET_RAW]` on clamav, proxy, cli | Deploy bundle in the app image; the running stack |
| `docker-compose.ha.yml` | `685111e1` → `43f4967c` | `cap_drop: [NET_RAW]` on clamav, proxy, dp | Deploy bundle (HA, not the appliance's default) |
| `appliance/provision/sysctl-culvert-hardening.conf` | new | `kernel.io_uring_disabled = 2` | Guest `/etc/sysctl.d/99-culvert-hardening.conf` |
| `appliance/build/prepare-guest.sh` | → `1740ab98` | Installs the sysctl file; refuses a wrong value | Guest build |
| `appliance/build/build-ova.sh` | → `936cfea2` | Copies the sysctl file into the overlay | Guest build |
| `appliance_m2_hardening_test.go` | new | Pins both changes | Not shipped |

**Unchanged:** `appliance/clamav` (`8d4df1d9`), `manifest.env` and every pin, the app `Dockerfile`/`go.mod`/`go.sum`/`internal/`, agent, console, `install.sh`, packaging, guest OS, kernel and Compose plugin.

**Delta vs `b9105086`:** 9 non-docs files. These are the 5 from the accepted record, plus `sysctl-culvert-hardening.conf`, `prepare-guest.sh`, `build-ova.sh` and `appliance_m2_hardening_test.go`. Both compose files now carry two changes (the tag and `cap_drop`).

## 3. Remaining CVEs (supersedes the kernel row of §3)

| Kernel finding | New status |
|---|---|
| CVE-2026-98503 (AF_PACKET TX_RING) | **Mitigated in containers.** `NET_RAW` is dropped, and Docker's default seccomp blocks namespace creation without `CAP_SYS_ADMIN`. Host: unprivileged user namespaces get no capabilities (`apparmor_restrict_unprivileged_userns=1`); root holds full privilege anyway. |
| CVE-2026-98858 (io_uring) | **Mitigated:** containers by the default seccomp profile (io_uring not listed; default `EPERM`), the host by `io_uring_disabled = 2` |
| CVE-2026-98788 (futex private hash) | **Residual**, local code execution only; no switch available |
| IPv6/skbuff 98532/98570/98573; bridge/llc/conntrack/nftables/veth | **Residual**, network-reachable; needed by Docker networking |
| 3 new CRITICAL | Unchanged: ASTRA's observed-state credit |
| Rest of the 59 HIGH | Unchanged: ASTRA's index |

All other §3 rows (engine, Compose plugin, sidecar, app image, guest OS) are unchanged.

## 4. Delta-to-test map additions

| Change | Pre-build evidence | Post-build gate on the replacement |
|---|---|---|
| `cap_drop NET_RAW` | `TestM2Hardening_NoServiceKeepsNetRaw` (fails if the clamav drop is removed); compose/installer/agent/appliance test set green; Deep dispatch 40523416237 green (17 jobs, including the real-ClamAV scenario, lifecycle and maintenance-agent flows on the new compose files) | `CapEff`/`CapBnd` of both containers lack bit 13; `socket(AF_PACKET)` fails in each; EICAR block, freshclam update, proxy traffic and maintenance apply/rollback stay green |
| `io_uring_disabled = 2` | `TestM2Hardening_IoUringDisabledOnTheGuest` (fails on value 1); `TestBuildOVA_CopiesEveryProvisionFilePrepareGuestInstalls`; the build-time value check in `prepare-guest.sh` | `sysctl -n kernel.io_uring_disabled` = 2 on the booted guest; a host `io_uring_setup` returns `EPERM`; in each container `Seccomp: 2` and `io_uring_setup` returns `EPERM` |

## 5. CI on `0648adeb` (runtime tree = `848c2c2f`, dispatch)

| Gate | Result |
|---|---|
| **Deep** [40523416237](https://github.com/KidCarmi/Culvert/actions/runs/40523416237) | **success**, 17/17 jobs |
| **Fast** [40523421826](https://github.com/KidCarmi/Culvert/actions/runs/40523421826) | 20 success / 2 skipped / 3 failure. The failures are the same exceptions ASTRA already documented; see below. |

The two Fast failures, plus the aggregate check that follows from them:
- **`golangci-lint`:** the identical four diagnostics in unchanged frozen files (`auth_oidc_flow.go:71`, `auth_saml.go:314`, `scan_svc.go:158/168`). None in the new code.
- **`gitleaks`:** artifact `12742179218` (zip digest `sha256:39d78b7b…`, SARIF sha256 `9239eb5a…`) holds **274 results**. Comparing it by commit, path, line and rule with the adjudicated SARIF (`af60b76d…`) gives **0 added, 0 removed**.

## 6. Still not done

- No replacement OVA has been built.
- **The post-build checks above are not yet in the lab harness.** They will be added before the single build, so that build's one qualification run includes them.
- The residuals in §3 are for ASTRA and the owner to accept or reject.
