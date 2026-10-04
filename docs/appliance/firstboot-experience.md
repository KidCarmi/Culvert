# First-boot experience and boot-time work

This is design rationale, not a claim that boot-time optimizations or a host
self-updater have shipped. Source review is pinned to
`36b5407e5bd3ff3c883bf855c269b8b7675013ed`; the measured ESXi candidate used
2 vCPUs and 4 GiB configured RAM. Runtime `nproc`/`MemTotal` were not retained.

## What the measured reboot tells us

The retained `esxi-run-36b5407e/evidence/post-reboot-observation.json` records
monotonic timestamps since guest boot:

| Observation | Time since boot | Meaning |
|---|---:|---|
| Console worker process started | 202.95 s | Process launch, not first visible console frame |
| Docker main process started | 302.08 s | Docker **started at** 302 s; this is not its startup duration |
| Maintenance agent process started | 367.02 s | Does not establish when its socket became usable |
| Stack-resume command started / finished | 367.02 / 476.28 s | About 109 s executing the resume command |
| First-boot unit | Never started | Condition false, start timestamp zero; no completed provisioning steps in the full current-boot journal |

The harness reported SSH and proxy `/health` reachable 552 s after the reboot
command. That interval includes shutdown, boot, forwarding recovery and polling;
it is neither first-boot installation time nor an exact proxy-ready timestamp.

Retained `08-stack-resume.txt` narrows the resume interval: command start
11:54:30, both maintenance locks held 11:54:31, Compose start 11:54:33,
ClamAV starting 11:54:54, started/waiting 11:55:06, healthy 11:56:11,
proxy starting 11:56:11, started and resume finished 11:56:19. The reboot
request was logged at 11:47:56. ClamAV therefore accounts for a measured
65-second health wait in this sequence; it does not explain the entire
552 seconds. Proxy creation completed 503 seconds after the request; its exact
subsequent health transition was not captured. This VM has been deleted, so
missing timing evidence requires another controlled run.

Preinstalling more first-boot components cannot by itself remove this reboot's
delay: provisioning did not run. Before changing dependency ordering, collect
`systemd-analyze time`, `critical-chain`, `plot`, unit activation timestamps and
monotonic journals for Docker/containerd, network-online, cloud-init and resume.
Also record ESXi CPU scheduling and datastore latency, Docker container
start/health transitions, and timestamps for management versus enforcement
readiness. These distinguish queued dependencies, resource contention and
application initialization. `blame` alone omits queued jobs and `Type=simple`
initialization; critical-chain also has parallelism and activation limitations.
See the [upstream systemd analysis manual](https://github.com/systemd/systemd/blob/v255/man/systemd-analyze.xml).

## What is already baked, and what first boot still does

| Component | Current artifact / first-boot behavior |
|---|---|
| Docker, Compose and OS packages | Installed in the guest disk during build; Docker versions pinned and held. |
| Go console and local recovery worker | One static `culvert-console` executable, built before disk customization; console units and helpers already installed. |
| Culvert proxy and CLI | Same precompiled image, shipped as a compressed image archive; first boot imports it into Docker. |
| Maintenance agent | Static Go binary already compiled into the proxy image's deploy bundle. First boot verifies its source, extracts and installs its host files, then configures access and starts it. This candidate did not need an on-guest Go build. |
| ClamAV | Image archive shipped; first boot imports it and waits for service health. Actual signature download/initialization costs need phase measurements. |
| Instance state | Network/hostname, login credentials, setup token, CA/session material and application state are initialized for each VM. They must not be cloned from a running template. |

The implementation is in
[guest preparation](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/appliance/build/prepare-guest.sh),
[first-boot image/install steps](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/appliance/provision/culvert-firstboot.sh#L219),
and the [compiled deploy bundle](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/Dockerfile#L93).

## Incremental changes with the lowest risk

1. **Show observed progress first.** Keep the console available independently
   of Docker. Distinguish management access, provisioning and traffic readiness;
   use actual completed steps and current observations, with elapsed time and a
   recovery action when blocked. Do not manufacture percentages or treat a
   usable setup URL as enforcement readiness.
2. **Measure, then separate agent packaging from activation.** Stage the
   verified host binary, unit and templates during OVA build. Add an explicit
   offline installation mode: the current packaging installer performs Docker
   checks and `daemon-reload`, while `prepare-guest.sh` has no running systemd.
   Finalize per-instance configuration and verify the pinned image's proxy UID,
   group/socket access and sudoers binding before starting services. Keep the
   privileged-operation smoke test and version checks.
3. **Avoid a second proxy creation where evidence justifies it.** Today
   `wire_release_agent_for_compose` observes the running proxy UID, configures
   the agent and recreates the proxy with its socket override. Prepare that
   binding before the first proxy start, preserving the same authorization
   checks. This can avoid repeated application initialization, but its saving
   has not been measured. See [installer wiring](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/scripts/install.sh#L2326).
4. **Evaluate image-store seeding separately.** Shipping image tars already
   removes registry pulls, but still requires decompression/import on the VM.
   Docker supports loading compressed archives and restores their tags;
   it does not promise zero startup work. A later builder could import into a
   disposable guest using the pinned engine, then shut it down cleanly and
   scrub identities. Do not copy a developer's live Docker data directory.
   Compare disk/OVA size, load time and clone correctness before adopting this.
   See [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/).

Follow existing Go boundaries for new runtime logic: the root module owns
`cmd/culvert-console` and `internal/applianceconsole`; `cmd/culvert-maint` is a
separate module. Use the compiler pinned by root `go.mod`, static Linux/amd64
appliance builds, typed operations with bounded inputs, and deterministic
failure/recovery tests. Keep privileged command templates aligned with their
sudoers rules. Moving lifecycle logic to Go does not require moving the proxy
out of its container or creating another daemon.

## Three different meanings of “fence”

**HA write fencing is already inside the Go proxy binary.** It uses
`ha_fencing.go`, `ha_lease.go` and `internal/halease`; `armHALease` runs before
HA role selection. There is no separate Culvert HA-fencing executable to bake.

**etcd is the external lease authority.** Compose includes an optional `ha`
profile with a single-member etcd container, explicitly marked for a local lab.
Both control planes must use the same authority; automatically enabling an
independent local witness on every cloned appliance would not provide shared
arbitration. Production needs separately managed failure domains, TLS and
durable etcd state. Three etcd members can tolerate one member failure; one
cannot tolerate any. This is a witness deployment choice, not three Culvert
control planes. See [Culvert's Compose contract](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/docker-compose.yml#L191)
and [etcd's quorum/failure-domain guidance](https://etcd.io/docs/v3.6/faq/#what-is-failure-tolerance).

**The host maintenance shutdown fence is local coordination.** The console,
OS-maintenance helper and maintenance agent share locks and a durable
`host-shutdown.pending` protocol. This prevents maintenance overlapping a
shutdown or bypassing interrupted work; it does not arbitrate HA leadership.
Faster startup must preserve both protocols. Witness state must not be
reset/cloned during a host update, and HA failover still has the documented
[bounded replication-loss window](../adr/0005-ha-lease-witness-failover.md).

## Upgrade gap and qualification prerequisites

The agent currently upgrades the pinned **proxy image**, with preflight,
backup, health verification and rollback. It does not update its own host
binary or the host console. Rerunning the installer can replace the agent,
but that is not a transactional host self-update API. See the
[current upgrade operation](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/cmd/culvert-maint/internal/server/handlers_upgrade_apply.go#L1).

Such an API needs a separately reviewed, signed and versioned compatible host
bundle: agent, console, helpers, units and protocol requirements. Stage and
verify it before mutation; publish atomically, retain the previous version,
and recover interrupted transitions from a durable journal. A bounded
privileged helper must own activation and rollback across the agent's own
restart. Preserve operator configuration, instance secrets, socket directory
identity and both maintenance locks/fences. An unsigned candidate exception
must not become the production trust path. These are requirements, not
implemented capabilities.

| Qualification slice | Evidence required before claiming improvement |
|---|---|
| Boot progress only | Fresh default/key/static-network imports; unavailable network; interrupted provisioning; management and enforcement states remain distinct. |
| Agent preinstallation / initial wiring | Signed artifact and exact versions; wrong-architecture/tamper rejection before mutation; real socket-authorized privileged operation; no proxy restart needed solely to add wiring. |
| Preloaded images / boot tuning | Fresh clones have distinct credentials/IDs; cold first boot, ordinary reboot and maintenance reboot measured separately; slow DNS/network/storage cases stay recoverable. |
| Host bundle updates | Old/new compatibility, failure before/after activation, lost power, failed health check, rollback, concurrent maintenance and same-boot shutdown refusal. |
| HA changes | Separate multi-node lab: witness loss, partition, paused leader, rolling restart and retained epochs; the single-VM ESXi run provides no HA qualification. |

Prerequisites for speed claims are a phase-timed baseline on the same VM
resources and a separate disposable candidate. HA work additionally requires
two control planes and an approved witness topology. Publish measured changes
for each boot scenario; do not infer a saving from upstream examples or the
presence of a prebuilt binary.
