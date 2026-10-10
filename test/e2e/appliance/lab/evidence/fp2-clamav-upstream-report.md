# Draft upstream report to ClamAV — clean verdict for an unscanned INSTREAM under temp-filesystem exhaustion

**Status: DRAFT, not filed.** Filing is the owner's action. Recommended channel:
ClamAV's private security reporting route (see `SECURITY.md` in
`Cisco-Talos/clamav`), not a public issue, because the effect is a detection
bypass an attacker could try to induce by filling the scanner's disk.

---

## Summary

During root-filesystem exhaustion, clamd 1.4.6 answered a bare `stream: OK`
to a complete INSTREAM carrying the EICAR test file. The streams 250 ms before
and after, with identical bytes, were answered `Eicar-Signature FOUND`. The
`OK` came 2 ms after the stream was sent, against 8–11 ms for every detection
in the same run, so it looks as if the content was not scanned. 0.44 s
earlier, clamd had failed a different stream with
`Error writing to temporary file`.

We could not find this path by reading 1.4.6. A failed temp write answers
`ERROR` (`clamd/server-th.c`), and a failed per-scan mkdir answers `ERROR`
(`libclamav/scanners.c`). We are asking for help locating it.

## Environment

* clamd **1.4.6**, official image
  `docker.io/clamav/clamav@sha256:57deb108fc4c72778aa83eafbca7bb7153e28c3f57c005afd38d31f16da86f23`.
  Our derivative only upgrades the Alpine packages pcre2 10.49, zlib 1.3.2-r1
  and nghttp2-libs 1.70.0-r0. The image's **stock `clamd.conf`** is used
  unchanged: temporary directory `/tmp` inside the container, which is on the
  overlay root filesystem of the host.
* Host: Ubuntu 24.04 VM, ext4 root, Docker 29.x. freshclam running
  (`CLAMAV_NO_FRESHCLAMD=false`).
* Client: TCP INSTREAM (`zINSTREAM\0`, one 4-byte big-endian length-prefixed
  chunk, zero-length terminator), one connection per scan.

## Reproduction

The run was automated: 14 cycles × 10 EICAR + 10 clean scans, each cycle at a
full root filesystem. The steps:

1. Fill the host root filesystem until `fallocate` fails. On ext4 this
   stops at about 16 MiB free (reserved clusters), so every cycle reached the
   same state.
2. While full, send INSTREAM scans alternating between EICAR (124-byte body,
   142 bytes on the wire) and a small clean body. Record every conversation on
   the container's host-side veth.
3. Release the fill, then repeat.

**Result:** 1 of 140 EICAR streams answered `stream: OK` in the first run,
**3 of 140** in a second run on a newer build of the same image, and **2 of
140** in a third (6 in 560 samples across four runs). All six were complete
142-byte streams, answered in 1–2 ms, each 0.19–1.70 s after clamd failed
another stream (`Error writing to temporary file` or `Can't write to file`). The other image gave 0 of 140, which we do NOT read as evidence
of absence. Every other EICAR reply was `FOUND`, `ERROR`, or
`<error> ERROR\0stream: OK\0` (an error reply followed by an OK in the same
response).

## The decisive sequence (UTC, one connection per line)

```
01:44:28.486  INSTREAM  66 B        'Error writing to temporary file ERROR\0stream: OK\0'
01:44:28.681  INSTREAM 142 B EICAR  'stream: Eicar-Signature FOUND\0'   8 ms
01:44:28.929  INSTREAM 142 B EICAR  'stream: OK\0'                      2 ms
01:44:29.190  INSTREAM 142 B EICAR  'stream: Eicar-Signature FOUND\0'   8 ms
```

* The client sent the whole stream: 142 B = command (10) + length (4) +
  body (124) + terminator (4), byte-for-byte the same as the detected streams.
* The reply carried no `ERROR`.

## Two side observations

1. **A combined response.** The first line above contains an error reply AND
   `stream: OK` in one response. A client that reads only the last NUL-delimited
   token would treat that as clean. Is this response shape intended?
2. **No reply at all.** The temp-file-creation failure path in 1.4.6 appears
   to close the connection without any reply.

## What we ask

* Where in 1.4.6 an INSTREAM can complete with `OK` without the scan having
  run, under ENOSPC on the temp directory.
* Whether an ENOSPC during spooling or scanning can be reported to the client
  as anything other than `ERROR`.

## Attachments

* `fp2-dc57bd76-clamd-streams.jsonl`: the 366 recorded conversations of the
  run containing the event. Each line has the close time, command, bytes up,
  an EICAR flag, the verbatim reply and which side closed. It contains no
  customer data: only test bodies.
* `fp2-91e05872-clamd-streams.jsonl`: the same for the second image, with no
  event.
* `fp2-72c827b7-clamd-streams.jsonl`: the second run with events (3).
* `fp2-bad788e5-clamd-streams.jsonl`: the third run with events (2).

## Our mitigation, for context

The client (Culvert) now distrusts clean verdicts for 60 s after any clamd
engine fault, including verdicts it cached before the fault. In the second
and third runs it refused all five wrong `OK`s; nothing was delivered. It cannot catch a wrong `OK` that comes before the first fault of an episode,
which is why we are reporting.
