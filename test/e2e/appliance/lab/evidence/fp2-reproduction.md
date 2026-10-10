# F-P2 — EICAR delivered during a disk fill: reproduced and attributed

**Run 38013626508** (lab commit `8ce1e3fd`), both RETAINED OVAs, same harness,
same runner class: boot, qualify, then 14 cycles of root-filesystem fill →
10 EICAR + clean pairs → release, with every clamd conversation recorded on the
ClamAV container's host veth into tmpfs (`clamd-tap.py`).

| OVA | at-fill samples | EICAR delivered | clamd `OK` to an EICAR stream | EICAR stream replies | evidence |
|---|---|---|---|---|---|
| dc57bd76 `855b4a09…` (artifact 11655543954) | 140 | **1** | **1** | FOUND 89, ERROR+OK 52, ERROR 13, **OK 1** | `fp2-dc57bd76-clamd-streams.jsonl` |
| 91e05872 `060a3dc6…` (artifact 11655439556) | 140 | 0 | 0 | FOUND 106, ERROR+OK 41, ERROR 8 | `fp2-91e05872-clamd-streams.jsonl` |

Both legs passed their preconditions: a fresh EICAR drew the ClamAV block
before any fill, and the tap recorded that conversation with its FOUND reply.

## The stream that decides it (dc57bd76, 01:44:28.929Z)

```
01:44:28.486  zINSTREAM  66 B        'Error writing to temporary file ERROR\0stream: OK\0'
01:44:28.681  zINSTREAM 142 B EICAR  'stream: Eicar-Signature FOUND\0'   8 ms
01:44:28.929  zINSTREAM 142 B EICAR  'stream: OK\0'                      2 ms   <- delivered (sample c14.7)
01:44:29.190  zINSTREAM 142 B EICAR  'stream: Eicar-Signature FOUND\0'   8 ms
```

* **Culvert sent the whole body.** 142 bytes is `zINSTREAM\0` (10) + chunk
  length (4) + the 124-byte EICAR body + terminator (4), the same size as the
  streams clamd detected 250 ms before and after.
* **clamd answered a bare `stream: OK`** with no `ERROR` reply attached, in
  2 ms against 8–11 ms for a detection: it scanned less than it received.
* **Culvert behaved as specified.** Its parser treats only a single `OK` reply
  as clean (`parseRawClamResponse`), and that is exactly what it got.
  Every ERROR form in this data was a fault and was refused.

## What is and is not established

* **Attribution: clamd (ClamAV 1.4.6 in the sidecar).** It returns an unqualified
  clean verdict for content it did not scan, during temp-filesystem exhaustion.
  Reading clamd 1.4.6 did not find this path: a failed temp write answers
  `ERROR` (`server-th.c`), a failed per-scan mkdir answers `ERROR`
  (`scanners.c`), a failed reload keeps the old engine. The in-library cause is
  **not yet identified**.
* **91e05872 is NOT shown to be unaffected.** 0/140 against 1/140 is not a
  meaningful difference, and both OVAs ship the same clamd spool path.
* **"Headroom" did not vary.** Every fill stopped at 16 MiB free: ext4's
  reserved clusters, which even root cannot allocate. All 14 cycles were the
  same full-disk state.

## Root cause (2026-10-10, owner follow-up 6097484537)

**libclamav 1.4.6 returns CLEAN for a file it never scanned when it cannot
create its per-scan temp directory.** `scan_common()` (`libclamav/scanners.c`)
sets `status = CL_EACCES` when `mkdir(ctx.sub_tmpdir)` fails and jumps to
`done`; the done-path filter `result_should_goto_done()` does not list
`CL_EACCES` among the halting codes and rewrites it to `CL_SUCCESS`, so
clamd replies `stream: OK`. The client receives no error.

* **Deterministic and fault-free** (`fp2-isolated-bad788e5/`, run 38053156677):
  the exact sidecar from the retained bad788e5 OVA, stock clamd.conf,
  scripted client, clamd's /tmp alone on a 256 MiB ext4. With exactly
  4096 bytes free — room for the spooled body, none for the directory —
  every EICAR (40/40, serial) was answered a bare OK in a median 0.61 ms
  (FOUND: 4.45 ms) with NO earlier error in its cycle; clamd logged 118
  "Can't create temporary directory for scan". With 8-way concurrency the
  same happens at 16–64 KiB free (concurrent spools consume the headroom).
* **Causal** (`fp2-source-1.4.6/`, run 38053729565): 1.4.6 built from the
  release source twice; stock answers 60/60 EICAR OK at the edge, the
  one-line patch (`CL_EACCES` → `CL_ETMPDIR`) answers 60/60 ERROR. Controls
  40/40 FOUND on both.
* **Attribution:** scanner, not Culvert's client (scripted client), not
  concurrency (serial), not the harness (both builds, same harness).

**Consequence for the product:** the Culvert quarantine is armed by a fault
reply; this failure emits none, so the quarantine cannot catch it. In the
appliance the edge is reachable by host-disk pressure (clamd's /tmp is on
the guest root filesystem) and, with concurrency, from more headroom than a
single request needs. F-P2 stays OPEN and blocks production readiness.

## Disposition: MITIGATED on the product (reactive), root cause FOUND upstream (report not filed)

Owner decision (2026-10-10): options 2 + 3 below; option 1 not taken without
lab-proven size caps.

* **Option 2 shipped** on PR #1528 as commit `72c827b7`: a 60 s clean-verdict
  quarantine after any clamd engine fault. It would have refused this instance.
  It does **not** cover a wrong `OK` before the first fault of an episode, so
  the risk is narrowed, not closed.
* **Verified on the corrected candidate, run 38036111516** (retained 72c827b7
  OVA `76769f86…`, same 14-cycle fill reproduction, same tap). The upstream
  defect recurred **3 times in 140 at-fill samples**: complete 142-byte EICAR
  streams answered a bare `stream: OK` in 1–2 ms, each 0.19 s, 0.95 s and
  1.70 s after a clamd fault. **Culvert delivered none of them**: every
  clean verdict inside the window was refused (`clam_clean_quarantined=101`).
  Check `F2 eicar-never-delivered` PASS; `F2 clamd-ok-to-eicar` records the
  upstream evidence. Streams: `fp2-72c827b7-clamd-streams.jsonl`.
  Margin: the latest wrong OK came 1.7 s after a fault against a 60 s window.
  This does not bound the residual (a wrong OK BEFORE an episode's first
  fault): in 4 observed instances (1 on dc57bd76, 3 here) none was first.
* **72c827b7 had a cache bypass (owner review, P1).** A clean verdict cached
  BEFORE the fault was served from the hash cache without consulting the
  quarantine, so a body already judged clean kept passing during the outage.
  The run above could not see it: its EICAR bodies were never cached clean.
  The pressure phases did see it, and the harness accepted it: under inode
  exhaustion the "allowed" request answered 200 from the cache. Fixed in
  `bad788e5`: every clean verdict is bound to the clamd fault generation at
  scan start, and a fault invalidates every clean verdict cached before it
  (cached blocks are kept). 72c827b7 is superseded.
* **Verified on the replacement candidate, run 38045099843** (retained
  bad788e5 OVA `87c8ae61…`, same reproduction, same tap). The defect recurred
  **2 times in 140 at-fill samples**: complete 142-byte EICAR streams answered
  a bare `stream: OK` in 1 ms, 1.48 s and 0.47 s respectively after a clamd
  fault.
  **Culvert delivered none** (`clam_clean_quarantined=190`). Check
  `F2 eicar-never-delivered` PASS. Streams: `fp2-bad788e5-clamd-streams.jsonl`.
  In the pressure phases the allowed request is now refused as
  AV-unavailable under inode exhaustion (403/403), where 72c827b7 served it
  200 from the cache (run 38045091498, judge `p_enforced`). 6 instances
  observed in total; none was first in its episode. The residual stands and
  F-P2 stays OPEN.
* **Option 3 drafted**: `fp2-clamav-upstream-report.md`, for the owner to file
  through ClamAV's private security channel.

### Original options (for the record)

The risk is open on both candidates. The remediation needs an owner decision
(see the PR #1528 handoff), because each option trades something:

1. **clamd temp directory on a bounded tmpfs.** Host-disk exhaustion can then
   no longer reach clamd's spool. But a small tmpfs is easier to fill with
   crafted archive content, so it needs clamd's MaxScanSize/MaxFileSize capped
   below its size, or it may widen the trigger.
2. **Culvert-side quarantine.** Under `av_unavailable=closed`, no clean
   verdict is trusted for a window after any clamd spool error. This is
   mechanism-independent and would have refused this instance (an ERROR reply
   came 0.44 s earlier). It is reactive: a silent OK before any error in an
   episode is not caught.
3. **Upstream report to ClamAV**, with this reproduction and the stream
   record, to find the in-library cause.
