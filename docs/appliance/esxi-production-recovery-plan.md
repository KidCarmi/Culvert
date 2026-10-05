# ESXi production recovery acceptance

Owner instruction on 2026-10-05 supersedes the previous product freeze for
confirmed production blockers. PR #1528 is not merge-ready. ASTRA owns controlled
ESXi reproduction; Opus owns product, provisioning and build fixes. No merge or
release until the blockers are closed and reviewed.

## Budget declared before evaluating fixes

Every one of at least three consecutive maintenance reboots must complete within
**120 seconds**, from authenticated privileged acceptance immediately before
invoking the existing maintenance reboot command to the third consecutive good
external sample, sampled at five-second intervals. Include graceful shutdown;
exclude keyboard login and initial installation. Never substitute controller
intent, open TCP ports or a successful Compose invocation for service readiness.
This is an engineering acceptance budget, not an established customer SLA.
Do not relax it after observing a result.
The initial 180-second ASTRA proposal was superseded by this stricter limit to
match Opus comment 5998912770 before any new baseline or fix was evaluated.

A good sample requires actual allowed proxy traffic (200), blocked traffic (403),
truthful ready/health status, real enabled and connected ClamAV, the expected
maintenance agent and persisted policy/CA. All three samples must follow the
observed outage and belong to the new boot. Authenticated postboot evidence binds
boot identity and guest monotonic/realtime clocks to controller timestamps;
ambiguous clock mapping blocks the timing claim. Record observed readiness and
later controller confirmation separately.

The first post-ready product backup listing must succeed within **five seconds**,
with the expected archive. A timeout remains a failure; a later result cannot
replace it. Every reboot must preserve administrator access, CA, policy,
categories, backup, image/version, both maintenance locks and the access boundary.
Final acceptance includes the existing security and lifecycle regression suite.

## Baseline and measurements

Retained baseline source: `b579ca28c9d936e9141292ce5ec564a26feeae86`.
OVA SHA256: `1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775`.
The earlier source and replacement VMs were deleted. Import a new owned VM from
those exact retained bytes, establish authenticated access, restore the same
fixture using its separately retained secrets, then prepare the OS once. Record
kernel/package/signature/data identities before comparisons. Do not mix an OS
update, feed update or different resource allocation into an unlabelled reboot
comparison. First-install duration is a separate measurement.

Approved placement and limits remain those of the lab scope: one owned VM at a
time, two vCPU, 4096 MiB RAM, 40 GiB disk, existing datastore/network and capacity
reserves. Do not stop or modify unrelated workloads to manufacture a result.

Freeze the committed controller and all helpers before execution. Use a separate
checkout for subsequent fixes. Diagnostic guest additions are identified by
content hashes, bounded, root-only, outside the deliverable OVA, and constant
across compared runs. Record their overhead and remove them before final
uninstrumented confirmation when needed to substantiate that comparison.

Collect:

- authenticated maintenance acceptance and independent external samples;
- early-boot monotonic/realtime, CPU/iowait, PSI, diskstats, selected process
  CPU/fault/read/write/wait-channel observations in bounded tmpfs;
- effective systemd dependency/order and main/pre-start timestamps, full relevant
  journals, process/container and health events, and maintenance-lock evidence;
- matching owned-VM ESXi disk latency/throughput and CPU/memory sample windows;
- first ClamAV PING success versus Docker health transition, and application
  listener/readiness initialization timestamps.

Keep raw material private; public evidence contains measured assertions and
hashes, not credentials, recovery secrets, private keys or trust fixtures.

## Causal comparisons

The recorded baseline has separate problems: pre-containerd 0–193.436 seconds,
containerd 193.436–273.686, Docker 273.692–335.967, stack resume
335.973–463.145, and observed readiness approximately 497 seconds after kernel
boot. Containerd and Docker have substantial pre-log intervals. Stack resume
acquired both locks in approximately one second, then spent approximately
34 seconds before container startup and 83 seconds waiting for ClamAV health.
These observations do not prove storage causation or justify removing gates.

Use one explicit intervention per comparison, with matched resources, data,
kernel and signature identities. Repeat or reverse a reversible intervention
where possible; report host-load variation and missing metrics. Candidate
experiments follow the measured bottleneck: remove unnecessary startup work in
a reviewed appliance variant; distinguish executable loading/I/O from CPU
initialization; distinguish ClamAV database initialization from health polling.
An infrastructure cause requires a demonstrated corrective change and its
recovery effect on approved placement, not merely elevated latency.

If product or provisioning bytes change, Opus integrates and builds a new retained
OVA. Final qualification names its full hash, source/image identities and frozen
controller. Three successful diagnostic reboots on an altered guest do not
qualify an untested deliverable artifact.

## Other production blockers

Track F-DISK-1 active-write disk exhaustion, ClamAV remediation and outage
semantics, usable authenticated recovery-secret custody, and scanner dispositions
to concrete resolution with evidence. Existing fresh restore proves recovery of
the supported archive and separately retained secrets; it does not recover
historical logs excluded by that archive. Historical availability failures and
incomplete diagnoses remain in the record. Risk acceptance is not the default
resolution.
