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

## Disposition: MITIGATED on the product (reactive), root cause OPEN upstream

Owner decision (2026-10-10): options 2 + 3 below; option 1 not taken without
lab-proven size caps.

* **Option 2 shipped** on PR #1528 as commit `72c827b7`: a 60 s clean-verdict
  quarantine after any clamd engine fault. It would have refused this instance.
  It does **not** cover a wrong `OK` before the first fault of an episode, so
  the risk is narrowed, not closed. It is not yet in any qualified candidate.
  The next candidate must re-run this reproduction expecting 0 delivered.
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
