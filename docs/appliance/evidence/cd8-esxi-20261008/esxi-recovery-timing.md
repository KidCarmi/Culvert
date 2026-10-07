# cd8 ESXi recovery timing — three maintenance cycles

All three measured maintenance cycles passed the existing strict recovery
oracle on candidate `cd8e44505bd329e5de675592ad4c23f92a534d55`, under authenticated
controller `7acb405c4e18e8fa8d77734e812b11bb91483208`. This report covers those
cycles only. It does not claim that visual, fresh recovery, scanner or other
release gates are complete.

The sanitized numerical evidence and original evidence hashes are in
[esxi-recovery-timing.json](esxi-recovery-timing.json). The analysis reads retained
private evidence offline; it does not replay requests, logins, backup creation
or maintenance. No raw application output, credentials, cookies, host/device
identifiers, process arguments or environment contents are included.

## External recovery and backup

These times start at the authenticated maintenance acceptance, before the
unchanged product reboot command acquires its locks and stops the stack. They
therefore include graceful shutdown and reboot, rather than starting at Docker
startup or a guessed guest boot time.

| Observation, seconds after acceptance | Cycle 1 | Cycle 2 | Cycle 3 |
| --- | ---: | ---: | ---: |
| First healthy sample starts | 58.812 | 57.000 | 61.359 |
| First healthy sample completes | 61.265 | 57.578 | 61.969 |
| Third consecutive healthy sample completes | **69.094** | **69.078** | **71.625** |
| Fresh login before the one first-ready backup, duration | 0.110 | 0.078 | 0.094 |
| Actual first-ready backup, duration | **1.453** | **0.859** | **0.765** |

All three confirmation times are within 120s and all actual backup durations
are within 5s. The backup is triggered on the first healthy completion and runs
separately from the continuing five-second sample cadence. The extra interval
between first healthy completion and final confirmation is 7.829, 11.500 and 9.656s
respectively; it is confirmation/polling time, not another guest boot phase.
A sample's start and completion differ because its actual checks take time.

Cycle 1 initially produced **BLOCKED**, because its first authenticated sampler
snapshot stopped 0.436s before the strict PONG coverage window ended. That
original summary remains unchanged. A later read-only snapshot of the **same
boot** supplied the missing tail. Independent offline inspection confirmed the
original 128,284 decompressed sampler bytes are an exact prefix of the 360,215-byte
supplement. The original observer rows and clock correlation were retained;
there was no second reboot, request replay or relaxed PONG oracle. The separate
supplement summary is PASS 69.094s; its hashes and the original BLOCKED summary
hash are retained in the companion JSON. The initial evidence-collection defect
is not erased by the effective result.

## Guest startup phases

The following values are seconds on the guest's boot-monotonic clock from
`systemctl show`, not controller elapsed time. Containerd/Docker activation
is distinct from application readiness and from the first emitted journal line.

| Guest phase | Cycle 1 | Cycle 2 | Cycle 3 |
| --- | ---: | ---: | ---: |
| Local filesystems active | 9.480 | 10.661 | 9.886 |
| Containerd process start | 15.363 | 16.528 | 15.563 |
| First retained containerd journal line | 17.213 | 18.813 | 17.948 |
| Containerd active | 21.989 | 21.534 | 22.811 |
| Docker process start | 21.995 | 21.543 | 22.815 |
| First retained dockerd journal line | 25.541 | 24.236 | 26.327 |
| Docker active | 29.311 | 30.097 | 30.169 |
| Maintenance agent process start | 29.322 | 30.108 | 30.176 |
| Stack resume starts | 29.323 | 30.109 | 30.177 |
| First direct ClamAV PONG sample | 44.449 | 45.414 | 45.388 |
| Stack resume finishes successfully | 45.478 | 46.757 | 45.914 |

The systemd containerd start-to-active intervals are 6.626, 5.006 and 7.248s;
Docker intervals are 7.316, 8.553 and 7.354s; resume intervals are 16.155, 16.648 and
15.737s. Firstboot has no execution timestamp and remains inactive on all three
maintenance boots. The agent and resume start immediately after Docker becomes
active. A first PONG is a sampled observation, not the exact instant clamd became
ready; the PASS oracle independently requires direct PONG coverage throughout
the selected healthy window, bound to the current container identity/endpoint.

Do not subtract guest timestamps directly from controller elapsed times. The
conservative controller estimates for guest boot origin, relative to maintenance
acceptance, are [-1.291, 5.568]s, [1.057, 4.979]s and [0.181, 9.400]s. The negative
endpoint in cycle 1 reflects measurement uncertainty; it is not evidence that
this reboot began before acceptance. Those bounds are too wide to attribute a
precise shutdown or application-to-polling delay. They still permit separating
the guest phase sequence from the external confirmation budget. Docker active
and resume complete do not alone prove the public API and traffic checks were
already healthy; the first external complete healthy samples are listed above.

## Sampler and storage observations

For comparability, each aggregate runs from the first retained two-second
sampler observation through the first sample at/after the strict proof's
conservative healthy-window end. Sampling starts after local filesystems; it
cannot explain firmware/initramfs time or all pre-containerd work.

| Guest sampled interval / aggregate | Cycle 1 | Cycle 2 | Cycle 3 |
| --- | ---: | ---: | ---: |
| Guest time window, seconds | 14.449–74.449 | 15.414–71.414 | 15.388–75.388 |
| Samples in aggregate | 31 | 29 | 31 |
| CPU time accounted as iowait | 31.843% | 31.286% | 29.380% |
| I/O PSI some, cumulative stall / wall interval | 38.230% | 38.124% | 35.176% |
| I/O PSI full, cumulative stall / wall interval | 36.212% | 36.389% | 33.578% |
| CPU PSI some, cumulative stall / wall interval | 2.124% | 2.278% | 2.050% |
| Memory PSI some/full | 0% / 0% | 0% / 0% | 0% / 0% |
| Maximum sampler invocation duration, milliseconds | 794.030 | 358.555 | 599.694 |

Iowait is the delta of `/proc/stat` iowait divided by the sum of the first eight
CPU-counter deltas, avoiding guest-time double counting. PSI uses cumulative
`total` deltas, not an average of the decaying avg10 values. These are whole-guest
window aggregates, not exclusive measurements of Docker or application threads.
No sampler errors or truncated process scans were recorded in these windows.
The sampler itself has finite overhead and its first observation begins several
seconds after its service process starts.

Both maintenance locks were observed held together for eight consecutive
samples: 30.449–44.449s, 31.414–45.414s and 31.388–45.388s. These are first/last
sampled held points, not exact acquisition/release times. The OS-update lock was
unavailable in the first eight samples of each window; unavailable is not
counted as unlocked. The agent lock was observable throughout. Lock holder PIDs
remain private. This is direct sampled lock evidence during resume, rather than
inferring locking merely from successful service exit.

| ESXi 20-second counter aggregates | Cycle 1 | Cycle 2 | Cycle 3 |
| --- | ---: | ---: | ---: |
| Requested telemetry window, seconds / selected samples | 160 / 8 | 109.078 / 5 | 111.625 / 6 |
| Host device read latency: mean / maximum sample, ms | 14.75 / 55 | 20.20 / 56 | 20.83 / 71 |
| Host read queue latency: mean / maximum sample, ms | 0.25 / 2 | 0 / 0 | 0 / 0 |
| Host write queue latency: mean / maximum sample, ms | 6.25 / 34 | 3.40 / 9 | 2 / 5 |
| VM virtual-disk read latency: mean / maximum sample, ms | 8.83 / 39 | 11.67 / 31 | 11 / 22 |
| VM virtual-disk write latency: mean / maximum sample, ms | 3.83 / 9 | 6 / 8 | 3.25 / 6 |
| Aggregate VM CPU ready: mean / maximum sample, ms per interval | 81.63 / 129 | 95.60 / 135 | 93.83 / 123 |

Host and VM counter collection completed for each requested window. Cycle 1
used the collector's longer 160s fallback window because its original verdict was
BLOCKED; cycles 2/3 used 109.078/111.625s windows. The telemetry averages therefore
cover different spans, including shutdown and post-startup time, and must not be
treated as directly comparable per-service startup costs. The virtual
read/write latency metrics each contain two missing samples; their means use
valid samples only. Exact selected/valid/missing counts are in the JSON. Counter
maxima are maxima of 20-second aggregate samples, not instantaneous maxima or
latency percentiles. Host device counters cover the device, so other workload
contributions are not excluded. CPU co-stop, CPU maximum-limit time, ballooning
and swap-in counters were zero in the returned samples; this does not establish
the absence of every possible transient outside those observations.

The combination of substantial guest I/O wait/PSI, measured device latency and
small CPU scheduling-wait counters is consistent with I/O-heavy startup in these
three runs. It does not identify a unique defective device or establish the
cause of the historical 597-second boot. That earlier diagnosis and evidence
remain separate. No hypothetical CPU, network, storage or scanner cause is
presented as proven here.
