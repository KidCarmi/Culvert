# M2 kernel HIGH: mitigations + bounded residual (re ASTRA 27 Oct 12:33 HOLD)

> **Corrections (ASTRA closeout, 27 Oct).** Read this file together with `RESIDUAL-DISPOSITION.md`, which supersedes §3 and §4 below.
> - **§2 overstated io_uring.** `kernel.io_uring_disabled = 2` refuses the creation of **new** io_uring instances. It does **not** revoke a ring that already exists. The "no ring exists" half rests on two facts: the sysctl is applied early in boot, before any service, and every qualification checkpoint counts io_uring descriptors held by any process and must find 0.
> - **§3 over-generalised.** Subsystem presence (IPv6 enabled; bridge, conntrack, nftables and veth loaded) neither proves nor excludes that a given finding is reachable. Each network finding is now assessed against its own precondition.
> - **§4 is superseded** by the checkpoint and test map in `../freeze-0648adeb/BOM.md` §5. It adds in-container AF_PACKET, io_uring and namespace probes, and runs every check at first boot, after maintenance, after the OS-update reboot, and at the end of the run.

**Decision (user, in session):** mitigate what can be removed without losing a function, then record the rest as a bounded residual. **ASTRA owns acceptance**; this is the producer's proposal and evidence.

**What this commit changes:**

| Change | Files |
|---|---|
| Drop `CAP_NET_RAW` from every Culvert/ClamAV service | `docker-compose.yml`: clamav, proxy, cli. `docker-compose.ha.yml`: clamav, proxy, dp. |
| Install `kernel.io_uring_disabled = 2` on the guest, from first boot | `appliance/provision/sysctl-culvert-hardening.conf`; `prepare-guest.sh` installs it as `/etc/sysctl.d/99-culvert-hardening.conf` and checks the value; `build-ova.sh` copies it |
| Tests | `appliance_m2_hardening_test.go`; both checks verified to fail when the protection is removed |

**What it does not change:**
- **The sidecar image:** `91eae575…` is unchanged.
- **The kernel:** no kernel swap and no capability patch to application code.
- **Lab:** no new lab campaign or snapshot request.

## 1. Packet sockets: CVE-2026-98503 (AF_PACKET TX_RING)

- **Prerequisite:** `packet_create` requires `CAP_NET_RAW` in the governing user namespace (upstream `net/packet/af_packet.c` at v7.0).
- **What M2 recorded:** the ClamAV container held Docker's default capability set `a80425fb`, which includes `CAP_NET_RAW` (bit 13). Docker's default seccomp profile **allows** `socket(AF_PACKET)`: the `socket` rule admits family 17 (`seccomp-facts.txt`). In a container, the capability was therefore the only gate.

**The mitigation:**
- Every service on the Culvert/ClamAV images now runs with `cap_drop: [NET_RAW]`.
- Nothing needs raw sockets:
  - clamd and freshclam use TCP and UDP (DNS);
  - the proxy is Go `net` over TCP/UDP;
  - `cli` is the proxy image in one-shot mode;
  - healthchecks use `clamdscan --ping` and `wget`.

**Why a container cannot get the capability back:**
- **No new user namespace.** Docker's default seccomp permits `unshare`, `clone` with namespace flags, and `clone3` **only with `CAP_SYS_ADMIN`**, which the containers do not hold (`seccomp-facts.txt`).
- **No raising it inside the container.** `cap_add` is absent; the test rejects one that adds `NET_RAW`.

**Host side (not in a container):**
- The appliance's interactive logins are `culvert` and `culvert-operator`, the latter with forced command `culvert-access` (M2 snapshot).
- `kernel.apparmor_restrict_unprivileged_userns=1` (M2 snapshot): an unprivileged user namespace gets no capabilities unless an AppArmor profile grants them.
- **Root already holds `CAP_NET_RAW`.** That is a privileged-access residual, not an exposure this change claims to close.

**Remaining limits:**
- This rests on configuration and capability rules, not on an exploit attempt.
- The runtime capability set of the containers on the **replacement** guest must be observed (post-build check 2 below).

## 2. io_uring: CVE-2026-98858 (SQPOLL)

**Containers:** Docker's default seccomp profile does **not** list `io_uring_setup`, `io_uring_enter` or `io_uring_register`, and its default action is `ERRNO(EPERM)`. Inside a container, io_uring is refused.

**Evidence for that:**
- The profile is `github.com/moby/profiles/seccomp v0.2.4`, the version `dockerd` 29.9.2 records in its buildinfo. That `dockerd` is sha256 `cc8ad1a1…cb10`, from the verified DEB `95ddf7a2…`.
- The module zip hash matches `go.sum` `h1:CNKIR4jN…` and `sum.golang.org`.
- The profile file is committed as `moby-profiles-seccomp-v0.2.4-default.json`.
- The string `io_uring` occurs 0 times in that `dockerd` binary, while syscall names around it do appear.

**Host:** `kernel.io_uring_disabled = 2` refuses io_uring for **every** process, root included. Nothing on the appliance uses it: Docker/containerd and Go use epoll, and ClamAV does not link liburing.

**Result (corrected):** no process can create a new io_uring instance, in a container or on the host. A ring created before the setting took effect would keep working; the qualification shows none exists (0 io_uring descriptors at every checkpoint). On that basis, the reachability prerequisite for 98858 and any other io_uring-only finding is closed for new rings, and there are no old ones.

**Remaining limit:** the running value must be observed on the replacement guest (post-build check 1 below).

## 3. Residual (not mitigated here)

| Finding / group | Why it stays | Bound |
|---|---|---|
| **futex private hash, CVE-2026-98788** | `futex*` and `prctl` are on the default seccomp allowlist, which every program needs. No sysctl turns off `FUTEX_PRIVATE_HASH`. Ubuntu's `linux-hwe-7.0/noble` row is still Vulnerable. | Needs local code execution, in a container or on the host. The appliance runs only its own images (the proxy as non-root user `proxy` with CapEff 0, and ClamAV) and no tenant code. **Residual until Ubuntu ships a fixed HWE kernel**; the replacement keeps `7.0.0-38`. |
| **IPv6/skbuff: 98532, 98570, 98573** | *(superseded: see `RESIDUAL-DISPOSITION.md` §3, which assesses each finding against its own precondition)* | *("Reached from the network" was a generalisation from IPv6 being enabled. In fact 98532's caller is reached by any inbound IPv6 packet; 98570 and 98573 are not, on this appliance.)* |
| **bridge, llc, conntrack, nftables, veth** | *(superseded: `RESIDUAL-DISPOSITION.md` §3 lists each finding's precondition and who can create it)* | *(Loaded by design. Most of these findings need configuration that requires `CAP_NET_ADMIN`, which no container has. The exceptions are assessed individually there: 98532 is reached by inbound IPv6, and 98804 is a teardown race.)* |
| **The rest of the 59 HIGH-present** | Indexed once into seven groups by ASTRA. No claim of 59 completed exclusions is made. | ASTRA's index stands. |

These residuals are the owner's to accept or reject, as is any time-boxed condition such as moving to the next fixed HWE kernel when Ubuntu ships one.

## 4. Post-build checks the replacement must pass (added to its qualification)

1. **io_uring off:** `sysctl -n kernel.io_uring_disabled` = `2` on the booted guest, and a host `io_uring_setup` call fails with `EPERM`.
2. **No NET_RAW:** `CapEff` and `CapBnd` of `culvert-clamav` and `culvert` lack bit 13 (`NET_RAW`), read from `/proc/<pid>/status` of each container's main process; a `socket(AF_PACKET)` attempt in each container fails.
3. **Seccomp active:** in each container, `Seccomp: 2`, and `io_uring_setup` fails with `EPERM`.
4. **No regression:** the existing qualification stays green:
   - ClamAV EICAR block;
   - freshclam update;
   - proxy traffic;
   - maintenance apply/rollback, which recreates the containers from the compose files.
