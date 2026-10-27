# M2 kernel HIGH: final bounded residual disposition (ASTRA closeout item 1)

**This is the producer's proposal; ASTRA and the owner decide.** It covers the kernel the replacement INTERNAL-ONLY OVA will carry (`linux-image-virtual-hwe-24.04` → `7.0.0-38-generic`, unchanged from `61c46d6d`).

**Scope:** internal-lab use only. Any pilot, customer or production use needs a new disposition, against whatever kernel is current at that point.

**What it rests on:**

| Evidence | Where |
|---|---|
| The advisory text of each finding (Ubuntu CVE tracker, the 59 HIGH-present export) | quoted below |
| Kernel build configuration | `/boot/config-7.0.0-38-generic` from `linux-modules-7.0.0-38-generic` 7.0.0-38.38~24.04.4, deb sha256 `99536f44…7202` (snapshot `20261002T120000Z`, Packages hash verified against the signed InRelease) |
| Which modules call the two IPv6/skbuff functions | all 6900 `.ko` of that package, scanned for undefined symbols: `module-imports-7.0.0-38.txt` |
| What is loaded, which policy applies, which capabilities containers hold | M2 snapshot, run 40472951974 (`../m2-snapshot/`) |
| The shipped host firewall | `appliance/provision/nftables.conf` (installed by `prepare-guest.sh:254`) |
| Upstream v7.0 source of the consumers below | `kernel-source-v7.0/`: `SOURCES.txt` (URL + sha256 of 8 files, re-fetchable) and `EXCERPTS.txt` (the cited lines) |
| Probe controls | `probe-control/m2probe-controls.txt` |

**Limits of this evidence:**
- The source read is **upstream v7.0**, not Ubuntu's patched `7.0.0-38` tree.
- Built-in (`=y`) callers cannot be enumerated from the modules package, which carries no `System.map`. Two were checked individually (§3, 98573); **no exhaustive vmlinux enumeration was done**.
- Nothing was exploited or fuzzed. This is reachability reasoning, not a proof that something cannot be exploited.

## 1. What M2 closes, stated exactly

| Finding | Closed by | Exact claim | What the claim does **not** cover |
|---|---|---|---|
| **98503** AF_PACKET TX_RING | `cap_drop: [NET_RAW]` on every Culvert/ClamAV service, plus Docker's default seccomp (namespace creation needs `CAP_SYS_ADMIN`) | No process in either container can open an AF_PACKET socket, as root or as its own user, or create a user/network namespace to get the capability back. Controls: with `NET_RAW` kept, root in a default-seccomp container **opens** AF_PACKET; with it dropped, it gets `EPERM`. | Host root and host processes. Root already holds every capability, so this is a privileged-access residual, not a closed path. |
| **98858** io_uring SQPOLL | Inside containers: Docker's default seccomp profile (no `io_uring_*`; default `ERRNO(EPERM)`). On the host: `kernel.io_uring_disabled = 2` | **No new io_uring instance can be created** by any process: `io_uring_setup` returns `EPERM`. | **The sysctl does not revoke a ring that already exists.** It refuses `io_uring_setup` only. The claim that no ring exists rests on two facts. First, the setting is applied by `systemd-sysctl` early in boot, before Docker or any appliance service starts. Second, the qualification counts every `anon_inode:[io_uring]` descriptor held by any process at each checkpoint, and must find **0**. The earlier wording ("unavailable to container and host code alike", and the comment in the shipped `sysctl-culvert-hardening.conf`: "refused for EVERY process") is corrected here. The shipped comment is a provisioning input, so changing it would move the build off the frozen commit; it stays, and this record governs. |

## 2. futex private hash, CVE-2026-98788: residual

**What it is:** a use-after-free during private futex-hash resize. Ubuntu titles it "Privilege escalation". `CONFIG_FUTEX=y` and `CONFIG_FUTEX_PRIVATE_HASH=y`.

**Why nothing on the appliance can switch it off:**
- `futex*` and `prctl` are on Docker's default seccomp allowlist. Every threaded program needs them; no runtime would start without them.
- No sysctl disables the private hash.
- No fixed `linux-hwe-7.0` build exists for noble.

**Precondition:** local code execution in **any** process: host or container, root or not. The effect is kernel privilege, so from inside a container it means **container escape to full host control**. Neither M2 mitigation changes this; capabilities and the seccomp profile do not reach futex.

**How code could run on the appliance, and what each path is worth:**

| Path | What an attacker controls | Assessment |
|---|---|---|
| Host logins (`root`, `culvert`, `culvert-operator`; the last has forced command `culvert-access`) | — | Already an administrator, so this adds nothing new. Out of scope. |
| **clamd in `culvert-clamav`**: libclamav (C) parses every scanned body, i.e. content the proxy fetches for its clients, chosen by whoever serves it | The bytes of every scanned object | **The realistic chain.** A memory-safety bug in libclamav gives code in the ClamAV container, and 98788 turns that into host root. The sidecar is the F-P2-accepted 1.5.4 build (`91eae575…`). It has no known CVE at any severity (exact scan, run 40504719384), but a parser of hostile input with no known bug is still a parser of hostile input. |
| **freshclam in `culvert-clamav`**: parses mirror responses (signature databases) over HTTPS | A malicious or intercepted mirror | Same consequence. Needs control of the mirror or TLS interception. |
| **proxy in `culvert`**: Go, runs as user `proxy` with `CapEff=0`, parses requests and responses | Request and response bytes | Go is memory-safe, so a code-execution bug is much less likely than in C. It is not impossible, and the container's restrictions do not stop futex. |
| Supply chain (the images themselves) | — | Covered by identity gates and scans, not by this disposition. |

**What bounds it, so that this is not just a "residual" label:**
1. **The first stage must succeed.** 98788 is a second stage. Today the first stage needs an unknown code-execution bug in libclamav, freshclam or the Go proxy. All three are at versions with no known applicable CVE (the exact-byte scans of the replacement come after the build and are listed in the freeze).
2. **Who can feed the first stage is restricted by use (§5).** In the internal lab, the content clamd scans comes from lab operators, the harness and its test origins. No real users or production traffic pass through the proxy.
3. **A time box (§7) and named triggers (§6)** end the acceptance.

**What does not bound it:** container isolation. For this finding, a compromise of either container must be treated as a compromise of the host.

## 3. Network-path HIGH findings: per finding

"Present in the kernel" does **not** prove reachability, and "IPv6 is enabled" does not prove that every IPv6 finding is reachable. Each finding needs its own precondition. **"Needs `CAP_NET_ADMIN`" below means `CAP_NET_ADMIN` in the network namespace being configured:**
- Neither container holds it. Both have it out of their bounding set, and the checkpoints assert `netadmin-bnd=0` for every container process.
- Neither container can create a namespace in which it would hold it (seccomp, controls above).
- Host root holds it, which is the same privileged-access residual as in §1.

| Finding | Advisory precondition | On this kernel / appliance | Reached by an unauthenticated network peer? | Bound and checkpoint |
|---|---|---|---|---|
| **98532** `ipv6_find_hdr` returns an offset past the packet end | A caller that uses the returned transport offset. The KASAN demonstration is **openvswitch** writing a checksum there. | Module callers (`module-imports-7.0.0-38.txt`): i40e, ixgbe, mlx5_core, ip6_tables, ip6t_ah/frag/hbh/rt/srh, nf_socket_ipv6, ip_vs (+pe_sip), **nf_tables**, **nft_chain_nat**, xt_HMARK, xt_TPROXY, xt_ipvs, xt_l2tp, openvswitch, act_ct, act_pedit. **Loaded by design: nf_tables, nft_chain_nat.** openvswitch and ip_vs are denied (`install … /bin/false`). | **Yes, the call is reached.** The shipped `table inet culvert` hooks IPv6 input, so every inbound IPv6 packet runs `nft_set_pktinfo_ipv6` → `ipv6_find_hdr`, before any authentication. | The returned offset is used here only through **bounds-checked readers**: `nft_payload_eval` → `skb_copy_bits` (fails past the end → `NFT_BREAK`); `xt_tcpudp` via `nft_compat` → `skb_header_pointer` (returns NULL). The appliance's own `inet culvert` table has no payload-mangling statement. Docker's iptables-nft rules (conntrack-based NAT plus `xt` matches) are written **verbatim** into each checkpoint's evidence, so this can be checked on the booted replacement. The out-of-bounds **writers** named in the advisory (openvswitch) or able to write at that offset (act_pedit, act_ct) are denied or not loaded, and configuring tc actions needs `CAP_NET_ADMIN`. **Residual:** a consumer in Ubuntu's tree that differs from upstream v7.0, or a future ruleset that mangles payload. Checkpoint: precondition modules not loaded; ruleset has no `queue`/`flowtable`/`exthdr`/`TPROXY`/`HMARK`. |
| **98573** `skb_checksum_setup_ipv6` pull-bound underflow | A driver that calls `skb_checksum_setup` on received packets | Modules: **only xen-netback** (Xen host backend; not loaded, meaningless outside a Xen dom0). Built in: **xen-netfront** (`CONFIG_XEN_NETDEV_FRONTEND=y`) calls it in its receive path. virtio_net does not (source checked). | Only on a **Xen guest using a PV NIC**. Not on ESXi (vmxnet3/e1000) or QEMU (e1000). | **STOP trigger:** deployment on Xen. Checkpoint: NIC drivers recorded. **Limit:** no exhaustive search for other built-in callers. |
| **98570** seg6/ioam6/rpl lwtunnel: missing headroom for the MAC header | An lwtunnel **encap route** (seg6, ioam6 or rpl) **and** ingress through a VLAN device with `reorder_hdr` off | seg6 and ioam6 lwtunnel built in, rpl not set. `8021q` not loaded. | No. Both preconditions are configuration, and both need `CAP_NET_ADMIN`. | Checkpoint: 0 encap routes, 0 VLAN links, `seg6_enabled`/`ioam6_enabled` 0, `8021q` not loaded. |
| **98526** llc: headroom on stacked devices | An LLC response sent on a **VLAN** device | `llc` loaded (bridge/stp dependency); `8021q` not loaded | No VLAN device exists; creating one needs `CAP_NET_ADMIN` | Checkpoint: 0 VLAN links, `8021q` not loaded |
| **98487** bridge mdb walk after deletion | `RTM_DELMDB` flush via netlink | `bridge` loaded (Docker) | No: the request needs `CAP_NET_ADMIN` in the bridge's (host) namespace | Host-root residual only. Checkpoint: mdb entries recorded |
| **98441 / 98442** act_ct extension UAF | A tc `ct` action | `act_ct` not loaded | No: tc configuration needs `CAP_NET_ADMIN`. 98441's own text: "no practical network pipeline where we need to process both clones". | Checkpoint: `act_ct` not loaded |
| **98625 / 98792** flowtable HW_DEAD / pending race | An nftables **flowtable**, with hardware offload for the worker race | `nf_flow_table` not loaded; e1000/vmxnet3 have no flow offload | No: needs a flowtable rule (`CAP_NET_ADMIN`) | Checkpoint: no `flowtable` in the ruleset; module not loaded |
| **98624** nfnetlink_queue release vs UNBIND | An `NFQUEUE` rule and a bound queue | `nfnetlink_queue` not loaded | No (`CAP_NET_ADMIN`) | Checkpoint: no `queue`/`NFQUEUE` in the ruleset; module not loaded |
| **98567** XPS out-of-range traffic class | `num_tc` lowered (mqprio/taprio) with stale maps, plus an XPS write | XPS built in; `sch_mqprio`/`sch_taprio` not loaded | No: qdisc change needs `CAP_NET_ADMIN`; XPS sysfs writes need root | Checkpoint: qdisc kinds limited to fq_codel/noqueue/pfifo_fast/mq/fq |
| **98797** skbedit/mirred queue_mapping | `skbedit` plus a nested `mirred` xmit, onto taprio | None of these loaded | No (`CAP_NET_ADMIN`) | Checkpoint: modules not loaded; qdisc kinds |
| **98804** page_pool recycle stats after free | `CONFIG_PAGE_POOL_STATS=y` (set), and a pool destroyed while its last pages recycle | e1000 does not use page_pool. vmxnet3 (the ESXi NIC) and veth do. | Not from the advisory text: the race is in pool **teardown** (interface down or reconfiguration, driver reload, container stop for veth), not in packet contents. | Residual, timing-dependent, triggered by lifecycle events. Recorded; no switch. |
| **98588** sockmap `max_entries` > INT_MAX | Creating a SOCKMAP (`CAP_BPF`/`CAP_SYS_ADMIN`) and a 32 GiB allocation succeeding | `unprivileged_bpf_disabled=2`; guest has 4 GB | No | Checkpoint: `unprivileged_bpf_disabled=2` |
| **98641** bpf exception callback | **arm64 only** | Appliance is x86_64 | Not applicable | — |
| **Rest of the 59 HIGH-present** | — | — | — | ASTRA's seven-group index stands. **No claim of 59 completed exclusions is made here.** |

## 4. Permitted internal-lab use

The replacement OVA may be used **only** as follows:
1. **Disposable QEMU lab guests** (the `appliance-lab` workflow).
2. **ESXi qualification by ASTRA** on an **isolated lab segment**: no route from the internet to the appliance, and no other tenants on its layer-2 segment.
3. **Proxied clients are lab operators and the lab harness only.** Test origins (EICAR, example.com/org, the UT1 category sample) are allowed. **No real users, no production or customer traffic, no real user data**, and nobody browsing the internet through it as an ordinary workload.
4. **Identity providers:** test tenants only, with no credentials shared with production.
5. **Not for:** pilot, release, merge, customer handoff or any production network. Each needs separate owner approval and a new disposition.

## 5. Exposure restrictions (each is either checked automatically or an operator obligation)

| Restriction | Why | Enforced by |
|---|---|---|
| No container gains `NET_RAW`, `NET_ADMIN` or `SYS_ADMIN`, and none runs without seccomp. No `privileged`, no `cap_add`. | §1 and the `CAP_NET_ADMIN` bound in §3 | M2H `*-hardening` at every checkpoint; `TestM2Hardening_NoServiceKeepsNetRaw` |
| `kernel.io_uring_disabled = 2`, and no io_uring ring held by any process | §1 | M2H `*-hardening` |
| No VLAN interface, no lwtunnel encap route, no tc actions or extra qdiscs, no nftables flowtable/queue/exthdr/TPROXY/HMARK rules; IPv6 forwarding off; seg6/ioam6 off | §3 preconditions | M2H `*-preconditions` |
| None of the precondition modules loaded (8021q, act_ct, act_pedit, act_mirred, act_skbedit, sch_taprio, sch_mqprio, nf_flow_table, nft_flow_offload, nfnetlink_queue, openvswitch, ip6_tables, ip6t_*, nf_socket_ipv6, xt_TPROXY, xt_HMARK, xt_ipvs, xt_l2tp, ip_vs*, xen_netback, i40e, ixgbe, mlx5_core) | §3 callers | M2H `*-preconditions` |
| NIC is e1000 (QEMU) or vmxnet3 (ESXi): no Xen PV NIC, no Intel 40G/10G or Mellanox passthrough | 98573 (xen-netfront), 98532 (i40e/ixgbe/mlx5 callers) | Checkpoint records the NIC drivers. **Operator obligation for ESXi:** vmxnet3 or e1000 only, no passthrough. |
| Isolated lab segment; lab-only clients and content | §2 first stage; 98532 is reached by any IPv6 neighbour | **Operator obligation** (ASTRA, lab owner) |
| Unprivileged BPF disabled | 98588 | M2H `*-preconditions` |

## 6. STOP or reassess

Stop using the replacement for anything beyond what has already completed, and report, when **any** of these happens:
1. Any M2H checkpoint or the E `m2-hardening` check **fails** on the replacement.
2. Ubuntu publishes a `linux-hwe-7.0` (noble) build fixing **98788** or **98532**, or any finding in §3 moves to "fixed". The disposition then lapses: move to the fixed kernel.
3. A public exploit, a CISA KEV listing, or an Ubuntu priority raised to high or critical for any finding in §2 or §3.
4. A new CVE (any severity) in libclamav, freshclam, the ClamAV 1.5.4 sidecar packages or the proxy's parsing paths that allows code execution. That is the §2 first stage.
5. **Any sign of compromise:** unexplained clamd or proxy crashes or restarts, kernel oops/BUG/KASAN-style messages, an unexpected process in either container, an unexpected io_uring ring, an unexpected module load.
6. A deployment or configuration that meets a precondition: Xen hypervisor, NIC passthrough, VLAN trunking to the appliance, tc/flowtable/NFQUEUE configuration, `cap_add` or privileged containers.
7. Any use outside §4: pilot, customer, production or real-user traffic.
8. The time box below expires.

## 7. Time box

The acceptance (if granted) lapses **30 days after ASTRA accepts it**, or at the first §6 trigger, whichever comes first.

Why 30 days: Ubuntu's kernel SRU cadence is about three weeks, so a fixed HWE build is plausible inside the window. The window is short because 98788 makes either container's compromise equal to the host's.

## 8. What is checked where (pointer)

The checkpoint and test map is in `../freeze-0648adeb/BOM.md` §5. The checkpoint code is the lab harness `m2_checkpoint` and `test/e2e/appliance/lab/m2probe`, on `test/appliance-lab`.
