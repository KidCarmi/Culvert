# M2 kernel HIGH: bounded residual disposition, revision 3

**Status: the producer's proposal; not accepted.** Revision 2 answered ASTRA's 27 Oct 16:10 HOLD; revision 3 answers the two remaining gaps of 17:06 (census-loop failures, nested firewall operands: §1a, §3, §3a, §8). ASTRA and the owner decide. **The 30-day clock in §7 has not started**; it starts only if this disposition is finally accepted.

**Scope:** the kernel the one replacement INTERNAL-ONLY OVA will carry (`linux-image-virtual-hwe-24.04` → `7.0.0-38-generic`, unchanged from `61c46d6d`), for internal QEMU-lab use only (§4). It authorizes nothing: no ESXi action, pilot, customer or production use, no kernel patch, and no rebuild.

**What is being accepted:** under the restrictions in §4–§5, the risk that **code execution inside either container, or by a restricted host principal, becomes kernel privilege and therefore full host compromise**. This is a risk accepted, not a demonstrated exploit chain.

## Evidence and its limits

| Evidence | Where |
|---|---|
| Advisory text of each finding (Ubuntu CVE tracker, the 59 HIGH-present export) | quoted below |
| Kernel build configuration | `/boot/config-7.0.0-38-generic` from `linux-modules-7.0.0-38-generic` 7.0.0-38.38~24.04.4, deb sha256 `99536f44…7202` (snapshot `20261002T120000Z`, Packages hash verified against the signed InRelease) |
| Modules that call the two IPv6/skbuff functions | all 6900 `.ko` of that package, scanned for undefined symbols: `module-imports-7.0.0-38.txt` (producer scan; ASTRA did not recount it) |
| Loaded modules, policy, container capabilities on the previous OVA | M2 snapshot, run 40472951974 (`../m2-snapshot/`) |
| Shipped host firewall | `appliance/provision/nftables.conf` |
| Upstream v7.0 source of the consumers named below | `kernel-source-v7.0/`: `SOURCES.txt` (URL and sha256 of 9 files) and `EXCERPTS.txt` |
| In-container probe controls | `probe-control/m2probe-controls.txt` |
| Qualification checks on the booted replacement (post-build) | lab harness `m2-guest.sh`, `m2-verdict.py`, failure receipts in `harness-receipts/` (§8) |

**Limits:**
- The source read is **upstream v7.0**, not Ubuntu's patched `7.0.0-38` tree.
- Built-in (`=y`) callers were **checked individually, not enumerated**. Two were checked (§3, 98573). Ubuntu-specific and unenumerated built-in consumers remain an **uncertainty**.
- Nothing was exploited or fuzzed. This is reachability reasoning, not proof of non-exploitability.
- **Scanner results are point-in-time and scope-limited.** The exact all-severity Trivy scan of the sidecar `91eae575…` (run 40504719384) found 0 package findings. That does **not** establish that no applicable bug exists in any parsing component, and it is not a premise of this disposition.

## 1. What M2 changes, stated exactly

| Finding | Mitigation | Exact claim | Not covered |
|---|---|---|---|
| **98503** AF_PACKET TX_RING | `cap_drop: [NET_RAW]` on every Culvert/ClamAV service, plus Docker's default seccomp (namespace creation needs `CAP_SYS_ADMIN`) | No process in either container can open an AF_PACKET socket, as root or as the container user, or create a user/network namespace. Probed at every checkpoint (§8). Control: with `NET_RAW` kept, root in a default-seccomp container **opens** AF_PACKET. | Host processes. Host root holds every capability. Restricted host principals: see §2. |
| **98858** io_uring SQPOLL | Containers: Docker's default seccomp (no `io_uring_*`; default `ERRNO(EPERM)`). Host: `kernel.io_uring_disabled = 2` | **No process can create a new io_uring instance.** | **The sysctl does not revoke a ring that already exists.** The claim that no ring predates it rests on the ordering rationale in §1a, which is checked per boot. The descriptor census is corroboration, not proof (§1a). The comment in the shipped `sysctl-culvert-hardening.conf` ("refused for EVERY process") means new rings only; it stays unedited because it is a frozen provisioning input. |

### 1a. Why no ring predates the setting

**The setting is applied by `systemd-sysctl.service`.** It reads `/etc/sysctl.d/99-culvert-hardening.conf`, installed at build time by `prepare-guest.sh`. Upstream, that unit has `DefaultDependencies=no` and `Before=sysinit.target`.

**Every appliance workload starts after `sysinit.target`:**
- `containerd.service` and `docker.service` have default dependencies, so they start after `sysinit.target` and `basic.target`.
- The containers start from dockerd.
- `culvert-firstboot.service` and `culvert-stack-resume.service` come after `docker.service`.
- `culvert-maint.service` comes after `docker.service`.
- `culvert-console-host.service` has default dependencies.

**The only appliance units that may run alongside or before it** are the two boot-splash units, `culvert-splash-status` and `culvert-kernel-log-vt` (`DefaultDependencies=no`, `Before=sysinit.target`). Both are shell scripts with no io_uring use; the source has 0 references. Earlier processes (initramfs, PID 1, journald, udevd) are distribution components and are not claimed here.

**Checked on the finished artifact, for every boot that has a checkpoint:**
- **`<tag>-ordering`:** `systemd-sysctl`'s `ActiveEnterTimestampMonotonic` must be non-zero and earlier than the `ExecMainStartTimestampMonotonic` of both containerd and dockerd. The drop-in must be present with a recorded sha256.
- **`<tag>-hardening`:** a census of every process's descriptors finds 0 io_uring rings. Every failed read is resolved before it is counted, and each non-success is recorded on its own line:
  - an fd directory that cannot be listed is `exited` only if the process is gone (no `/proc` entry, or a zombie), otherwise `unreadable-alive`, which **fails**;
  - a descriptor whose link cannot be read is read once more, then is `fd-vanished` only if its `/proc` entry is gone, otherwise `fd-unreadable`, which **fails**;
  - the summary must carry exactly the expected counters, and each must equal its line count; a census that read no process or no descriptor fails.

  Confirmed disappearances are reported, not hidden. The census is not atomic, so it is corroboration only.

**Persistence:** the same checks at the reboot and final checkpoints show the drop-in and the value surviving the OS update, its reboot, three power-cycle recoveries and the history restore.

The `firstboot` checkpoint runs **after** steps 1–5. Its ordering evidence for the first boot comes from those same-boot timestamps, not from the checkpoint's position.

## 2. futex private hash, CVE-2026-98788: residual

**What it is:** a use-after-free during private futex-hash resize ("Privilege escalation"). `CONFIG_FUTEX=y` and `CONFIG_FUTEX_PRIVATE_HASH=y`. `futex*` and `prctl` are on Docker's default seccomp allowlist, no sysctl disables the private hash, and no fixed `linux-hwe-7.0` build is published for noble.

**Precondition:** code execution in any local process. The consequence is kernel privilege, i.e. host compromise, including from inside either container.

| How local code can run | Who controls the input | Disposition |
|---|---|---|
| `root` and `culvert` (full sudo) | Administrators | Already hold root. Nothing new. |
| **`culvert-operator`**: a **restricted** principal, SSH key only, with forced command `culvert-access` (read-only observations) | A holder of that key | **Not an administrator.** An escape from the forced command, combined with 98788, gives root. Accepted only because holders of that key are **trusted lab principals** (§4). |
| **clamd / libclamav in `culvert-clamav`** | Whoever serves content the proxy fetches and scans | Any code execution in that container, **from any cause** (unknown bug, known but unscanned bug, misconfiguration), plus 98788 = host compromise. |
| **freshclam in `culvert-clamav`** | The signature mirror, or anyone able to intercept it | Same consequence. |
| **The proxy in `culvert`** (Go; user `proxy`; `CapEff=0`) | Request and response bytes | Same consequence. Go's memory safety makes this less likely; it is not excluded. |

**What bounds it:**
1. **Who can feed the containers, and who holds credentials**, is restricted by use (§4–§5): lab principals, harness and test content only.
2. **STOP triggers (§6) and a 30-day maximum (§7).**

**What does not bound it:** container isolation and the scanner results.

## 3. Network-path HIGH findings

**No single statement covers this group.** Each row has its own precondition. Most need configuration that requires `CAP_NET_ADMIN` in the namespace concerned:
- no container process holds it in its bounding set (checked at every checkpoint);
- seccomp stops a container from creating a namespace where it would;
- host root holds it, and restricted principals fall under §2.

**Two exceptions:** 98532 is reached by inbound traffic, and 98804 is a lifecycle residual.

| Finding | Advisory precondition | On this kernel / appliance | Reached from the network? | Bound and check |
|---|---|---|---|---|
| **98532** `ipv6_find_hdr` returns an offset past the packet end | A consumer that **uses** the returned transport offset. The demonstrated write is openvswitch's checksum update. | Module callers: see `module-imports-7.0.0-38.txt`. **nf_tables and nft_chain_nat are loaded by design**; openvswitch and ip_vs are denied. | **Yes.** `table inet culvert` sends every inbound IPv6 packet through `nft_set_pktinfo_ipv6` → `ipv6_find_hdr`, before authentication. | Consumers **reviewed**: `nft_payload_eval` (`skb_copy_bits`, bounded); `xt_tcpudp` via `nft_compat` (`skb_header_pointer`, bounded); NAT, where `nf_nat_ipv6_manip_pkt` locates the L4 header itself with `ipv6_skip_exthdr` and does not use nft's offset. **Gate on the booted replacement, `<tag>-ruleset`:** every expression of every rule, in every namespace, must be one of these source-checked forms, or the gate fails as "review required". **Nested operands are classified too:** both sides of a match, NAT address/port parameters, the key and value of a metadata assignment, and statement parameters are walked recursively. Only reviewed expression kinds (payload, meta, ct, prefix, map, set, range, concat, bitwise) with their reviewed fields pass; any other kind, an unexpected field, or an expression where only a literal is reviewed fails. Before this, `ct mark set socket mark` passed: the gate classified the assignment by its key alone. It, `jhash` and `numgen` operands now fail (real `nft -j` output, receipt 01). Payload writes, queue, flowtable, exthdr, socket, tproxy and any unclassified xt match or target all fail it. The full ruleset is kept verbatim. **Residual uncertainty:** consumers in Ubuntu's tree or unenumerated built-in code paths. |
| **98573** `skb_checksum_setup_ipv6` underflow | A receive path calling `skb_checksum_setup` | Modules: only xen-netback (not loaded). Built in: **xen-netfront** calls it; virtio_net does not. | On a Xen guest with a PV NIC, yes. **Other built-in callers were not enumerated**, so "only on Xen" is not claimed. | Checkpoint: NIC drivers must be e1000 or vmxnet3. Xen is a STOP trigger. **Ubuntu status: fix pending** (§6 baseline). |
| **98570** seg6/ioam6/rpl lwtunnel MAC-header headroom | An lwtunnel encap route **and** ingress via VLAN with `reorder_hdr` off | seg6/ioam6 lwtunnel built in; rpl not set; `8021q` not loaded | No: both are configuration (`CAP_NET_ADMIN`) | Checkpoint, every namespace: 0 encap routes, 0 VLAN links, seg6/ioam6 0 on every interface |
| **98526** llc headroom on stacked devices | LLC response on a VLAN device | `llc` loaded (bridge/stp) | No VLAN device; creating one needs `CAP_NET_ADMIN` | Checkpoint: 0 VLAN links; `8021q` not loaded |
| **98487** bridge mdb walk after deletion | `RTM_DELMDB` flush (`CAP_NET_ADMIN` in the bridge's namespace) | `bridge` loaded (Docker) | No | Host-root and restricted-principal residual (§2) |
| **98441 / 98442** act_ct | tc `ct` action | `act_ct` not loaded | No (`CAP_NET_ADMIN`) | Checkpoint: module not loaded; no tc actions |
| **98625 / 98792** flowtable | nftables flowtable (+ hardware offload) | `nf_flow_table` not loaded | No (`CAP_NET_ADMIN`) | `<tag>-ruleset` fails on any flowtable; module not loaded |
| **98624** nfnetlink_queue | NFQUEUE rule + bound queue | not loaded | No (`CAP_NET_ADMIN`) | `<tag>-ruleset` fails on any queue; module not loaded |
| **98567** XPS traffic class | mqprio/taprio `num_tc` change + XPS write | built in; qdisc modules not loaded | No | Checkpoint: qdisc kinds within fq_codel/noqueue/pfifo_fast/mq/fq |
| **98797** skbedit/mirred queue_mapping | tc actions onto taprio | not loaded | No (`CAP_NET_ADMIN`) | Checkpoint: modules not loaded; qdisc kinds |
| **98804** page_pool recycle stats after free | `PAGE_POOL_STATS=y` (set); a pool torn down while pages recycle | e1000 has no page_pool; vmxnet3 and veth do | Not by packet content: a **lifecycle** race on pool teardown (interface reconfiguration, driver reload, container stop for veth). The lab itself performs container recreation and reboots. | **Lifecycle residual**, timing-dependent, no switch. Accepted under §4–§7. |
| **98588** sockmap `max_entries` | SOCKMAP creation (`CAP_BPF`/`CAP_SYS_ADMIN`) and a 32 GiB allocation | `unprivileged_bpf_disabled=2`; 4 GB guest | No | Checkpoint: `unprivileged_bpf_disabled=2` |
| **98641** | arm64 only | x86_64 | Not applicable | — |
| **The rest of the 59 HIGH-present** | — | — | — | ASTRA's seven-group index stands. **No claim of 59 completed exclusions.** |

### 3a. Which network namespaces the argument covers

**The argument depends on exactly three network namespaces:** the host's, `culvert`'s, and `culvert-clamav`'s. At every checkpoint the harness:
- takes a census of every process's network namespace, with one outcome per process: read, `exited` (confirmed gone) or `unreadable-alive`, which **fails**. The summary must agree with the lines;
- acquires the three expected namespaces separately: the host's directly, each container's from `docker inspect` (recorded; a failed read fails the check by name);
- **reconciles the two in both directions:** a namespace outside the three fails, and an expected one absent from the census fails. If fewer than three contexts were acquired, the check fails as "coverage not reconciled" instead of claiming coverage;
- in each of the three, reads links, the IPv4 and IPv6 routes (`table all`), qdiscs, the nftables ruleset (JSON for the gate, text for review) and **every interface's** IPv6 `forwarding`, `seg6_enabled`, `ioam6_enabled` and `disable_ipv6`. It does not read only the `all`/`default` entries.

**Not covered:** a namespace created and destroyed between two checkpoints. Containers cannot create one (seccomp), so that is again a host-root or restricted-principal residual under §2.

## 4. Permitted use (internal lab only)

1. **Only the disposable QEMU guests of the `appliance-lab` workflow** that qualify the one replacement build.
2. **Proxied clients are the lab harness only.** Content comes from the harness's test origins (EICAR, example.com/org, the UT1 category sample). No real users, no production or customer traffic, no real user data.
3. **Credentials:** `culvert`, `culvert-operator` and console credentials are per-run disposable secrets held by the harness. Identity providers are test tenants only.
4. **Not permitted under this document:**
   - **ESXi:** any ESXi import or use, including ASTRA's earlier ESXi qualification pattern. Neither this document nor the conditional replacement-build approval authorizes it, and the existing single VM and its custody stay as they are.
   - pilot, release, merge, customer handoff or any network beyond the lab runner.

## 5. Exposure restrictions

| Restriction | Why | Enforced by |
|---|---|---|
| No container gains `NET_RAW`/`NET_ADMIN`/`SYS_ADMIN` or runs without seccomp; no privileged or `cap_add` | §1, §3 | `<tag>-hardening` at each checkpoint; `TestM2Hardening_NoServiceKeepsNetRaw` |
| `io_uring_disabled = 2` applied before workloads; no ring held | §1, §1a | `<tag>-hardening`, `<tag>-ordering` |
| Exactly three network namespaces | §3a | `<tag>-preconditions` |
| In each of them: no VLAN link, no lwtunnel encap route, qdiscs within the allowed set, IPv6 forwarding/seg6/ioam6 0 on every interface | §3 | `<tag>-preconditions` |
| Every rule expression in every namespace is a source-checked form | 98532 and the queue/flowtable findings | `<tag>-ruleset` |
| None of the 32 precondition modules loaded; unprivileged BPF off | §3 | `<tag>-preconditions` |
| NIC e1000 (QEMU) or vmxnet3 | 98573, 98532 driver callers | `<tag>-preconditions` |
| Lab-only clients, content and credentials | §2 | Operator obligation (the harness by construction) |

**Every check above fails closed.** An observation that could not be acquired or parsed fails its check; it is never read as "nothing found" (§8).

## 6. STOP and reassess

**STOP and reassess means:** stop using the replacement beyond what has completed, report, and wait for a decision. **It never authorizes an automatic kernel patch, rebuild or second build.**

**Baseline for the triggers** (retrieved by the producer on 27 Oct 2026):
- **98532 and 98573: Ubuntu priority high; `linux-hwe-7.0` noble status *pending*, fix `7.0.0-42.42~24.04.1`** (tracker updated 2026-10-26 and 2026-10-22). Raw values: `ubuntu-status-baseline.txt`.
- 98788: the tracker returned HTTP 504 twice; not retrieved. Its baseline is the High rating already accepted in ASTRA's index and the status ASTRA links.

**Triggers:**
1. Any M2H check or E `m2-hardening` **fails** on the replacement.
2. Ubuntu publishes a **released** `linux-hwe-7.0` noble build fixing 98788, 98532 or 98573. **98532 and 98573 are already pending in `7.0.0-42.42~24.04.1`, so this trigger is expected soon; it means stop and reassess, not an automatic kernel change.**
3. Any listed finding's Ubuntu priority rises **above High** (to Critical); a CVSS ≥ 9.0 rating; a CISA KEV listing; or a public exploit.
4. A new code-execution CVE in libclamav, freshclam, the sidecar's packages or the proxy's input paths.
5. **Any sign of compromise:** unexplained clamd or proxy crashes or restarts, kernel oops/BUG messages, an unexpected process, ring, module or namespace.
6. A configuration that meets a precondition: Xen, NIC passthrough, VLAN trunking, tc/flowtable/NFQUEUE, `cap_add`, privileged containers, an added network namespace.
7. Any use outside §4.
8. The §7 time box expires.

## 7. Time box

**30 days from ASTRA's final acceptance of this disposition**, or the first §6 trigger, whichever is earlier. **Not started.**

## 8. Checks and receipts

**The checkpoint map** is in `../freeze-0648adeb/BOM.md` §5: first boot, after maintenance, after the OS-update reboot, at the end of the run.

**The fail-closed contract and its receipts** (`harness-receipts/`):
- **Self-test:** the evaluator is exercised against a passing fixture plus one mutation per failure mode. **87 cases, 0 wrong**, including the valid-empty and confirmed-disappearance cases. It runs in `appliance-lab.sh selftest`, the first step of every lab job.
- **Mutation evidence:** each of nine evaluator mutations is caught by the self-test. They include removing the expected-namespace reconciliation, accepting unreadable state as vanished, removing the docker-top reconciliation, and removing nested-operand validation. The guest script is also run with a failing `ip` and an absent `nft`; both are recorded as failures and fail their checks.
- **Real collector outcomes** (producer sandbox, not the guest):
  - The sandbox's PID 1 still exists and cannot be read, so the run records `fd-unreadable` ×21 and `unreadable-alive`, and both checks fail.
  - With Docker stopped, the container pid reads fail by name, and the check reports "coverage not reconciled: only 1 of 3".
  - Three real processes are killed at the moment the census reaches them. They are recorded as `exited` / `fd-vanished`, not as failures.
