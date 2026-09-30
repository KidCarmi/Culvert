# Shutdown package-isolation pilot evidence

Baseline: `1f7f42c6937847c26f29387dcaae6685e356a9b0`, Go 1.26.8,
Linux amd64, 4-vCPU cgroup, 32 GiB RAM; GOMAXPROCS=4, Go build parallelism 4.
Design and exact migration: [roadmap](../../roadmap/PACKAGE-ISOLATION.md),
[ADR-0037](../adr/0037-shutdown-registry-package-isolation.md).

## Initial checks

- Package race + shuffle: `go test -race -count=2 -shuffle=20260930 ./internal/shutdown` passed.
- Production shutdown integration: selected registry/wiring, CHAOS-56, audit-close
  and cluster-flush tests passed (16.9 s root package execution).
- Rootshard source/binary inventory agreement: 6,742 root entries; 17 moved to
  the new package, 2 added to root, no lost entries. New package: 24 entries.
- The existing per-file coverage table names no moved shutdown source. No floor
  or workflow edits are needed; global coverage still includes the new package.

## Baseline limitations being compared

The first full baseline root run used the machine's default umask 0077, warm
compiler cache, no race/coverage, no result cache, and completed in 357.1 s:
6,682 top-level entries passed, 16 failed, 59 skipped. This is a diagnostic
run, **not a clean performance baseline**. Four failure families were identified:

- File-mode fixtures expect standard umask 0022 (backup/restore and KEK-mode
  checks). Subsequent validation uses that mask, scoped to the test process.
- `getent ahostsv4 example.com` fails in this cloud machine; IdP URL validation
  correctly refuses unresolved external fixtures. No security guard is bypassed.
- The real-Docker installer fixture calls `sudo docker`; Docker/Compose work,
  but `sudo` is absent. The installer conservatively answers NOTFRESH.
- An upstream portability audit assertion fails during the full root run;
  isolated reproduction and matched candidate results are recorded below.

These are outside the shutdown change. Failures, skips and unrun checks must not
be relabeled as passing. Full-module race, determinism, coverage, measurements
and live PR results will be appended as they complete.

## Existing CI evidence (not an equivalent candidate pair)

The PR that produced baseline main is #1490, head
`349ecf6410994731edb1a98010662a060cd77b92`:

- [Fast 36264359485](https://github.com/KidCarmi/Culvert/actions/runs/36264359485):
  attempt 1 success, 765 s from first job start to last completion, 3,537 summed
  job runner-seconds. Root compile 118 s; slowest root shard 486 s; non-root lane
  681 s. The non-root lane, not this pilot's ~1 s of movable tests, bounds Fast.
- [Deep 36264359560](https://github.com/KidCarmi/Culvert/actions/runs/36264359560):
  attempt 2 success; successful determinism job 781 s. Its 7,880 s job-span
  includes rerun delay; it must not be called execution cost or compared with
  a single-attempt candidate as a speedup.

CI-REDESIGN §18.5/§19.1 gives broader historical evidence that Deep determinism
often bounds both-gates completion. Its Go/toolchain, source revision, queue and
attempt cohorts differ; preserve that qualification when choosing follow-ups.
