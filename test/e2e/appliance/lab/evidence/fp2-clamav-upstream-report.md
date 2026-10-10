# Draft upstream report to ClamAV — INSTREAM answers "OK" for a file it never scanned when the per-scan temp directory cannot be created

**Status: DRAFT, not filed.** Filing is the owner's action. Recommended channel:
ClamAV's private security reporting route (see `SECURITY.md` in
`Cisco-Talos/clamav`), not a public issue: the effect is a detection bypass
that a remote party may be able to induce by filling the scanner's temp
directory (for example with concurrent large uploads to a scanning gateway).

---

## Summary

In libclamav 1.4.6, when `scan_common()` cannot create its per-scan
temporary directory, the scan returns `CL_CLEAN` without scanning anything,
and clamd answers `stream: OK` to INSTREAM. No error reaches the client.

`libclamav/scanners.c`, `scan_common()`:

```c
    if (mkdir(ctx.sub_tmpdir, 0700)) {
        cli_errmsg("Can't create temporary directory for scan: %s.\n", ctx.sub_tmpdir);
        status = CL_EACCES;
        goto done;
    }
    ...
done:
    // Filter the result from the post-scan hooks and stuff, so we don't propagate non-fatal errors.
    (void)result_should_goto_done(&ctx, status, &status);
```

`result_should_goto_done()` halts and keeps the code only for `CL_VIRUS`,
`CL_EUNLINK`, `CL_ESTAT`, `CL_ESEEK`, `CL_EWRITE`, `CL_EDUP`, `CL_ETMPFILE`,
`CL_ETMPDIR` and `CL_EMEM`. `CL_EACCES` falls to `default:`, which sets the
result to `CL_SUCCESS` (== `CL_CLEAN`). `clamd/scanner.c` `scanfd()` then
replies `OK` because the result is `CL_CLEAN`. `cli_magic_scan()` never ran.

Suggested fix: report the failure as a halting error (for example
`status = CL_ETMPDIR;`), so clamd replies `... ERROR`. The same
`CL_EACCES` pattern exists in `cli_magic_scan()` for the per-layer directory
(line ~4290), reachable only with `keeptmp` enabled.

## Reproduction (deterministic)

* Official image `docker.io/clamav/clamav:1.4` (1.4.6) with Alpine package
  upgrades only (pcre2, zlib, nghttp2), **stock `clamd.conf`**
  (`TemporaryDirectory` = `/tmp`), freshclam off, signatures
  `ClamAV 1.4.6/28136`.
* clamd's `/tmp` is a 256 MiB ext4 filesystem of its own (`-m 0`), so the
  test exhausts only the spool.
* Fill it until exactly **4096 bytes** are free (one ext4 block). Send one
  INSTREAM per connection: `zINSTREAM\0`, one 4-byte big-endian length,
  the 124-byte EICAR test file (the 68-byte string plus 56 bytes of
  space/tab padding), the zero terminator. 142 bytes on the wire.

Result: the body fits in the last free block; the per-scan `mkdir` then
fails with ENOSPC. **Every** EICAR is answered `stream: OK` (40 of 40 over
four fills), in a median 0.61 ms against 4.45 ms for a real detection.
clamd logs `Can't create temporary directory for scan` each time and sends
the client no error. With 0 bytes free, the write fails and the reply is
`... ERROR\0stream: OK\0`. From 16 KiB free up, every EICAR is `FOUND`.
With 8 concurrent clients the same bare `OK` also occurs at 16–64 KiB free,
because concurrent spools consume the headroom.

## Second, related observation

When the body write itself fails (`handle_stream()` in
`clamd/server-th.c`), clamd sends `Error writing to temporary file ERROR`
and, if the terminator is already in the buffer, still dispatches
`INSTREAMSCAN` on the short temp file. The client gets
`... ERROR\0stream: OK\0` in one response. A client that reads only the last
NUL-delimited token sees a clean result.

## How we found it

In a full-disk test of an appliance, clamd answered `stream: OK` to complete
EICAR streams 6 times in 560 samples across four runs, each 0.19–1.70 s
after another stream failed with a temp-file write error. An isolated
reproduction then showed it is deterministic at the edge described above
and does NOT need an earlier error.

## Causal confirmation

ClamAV 1.4.6 built from the release source twice on one host, stock and
with only the line above changed to `CL_ETMPDIR`, with the same config, a
one-signature database and the same 4 KiB edge state. Result: PENDING
(`fp2-source-1.4.6/verdict.txt` once the run completes).

## Attachments

* `fp2-isolated-bad788e5/`: every conversation (sha256 of the full bytes
  sent, verbatim reply, timing, temp free space before and after), the
  clamd log errors, the clamd.conf hash, the signature set, the image
  binding.
* `fp2-source-1.4.6/`: the stock-vs-patched control.
* Earlier appliance runs: `fp2-dc57bd76-`, `fp2-72c827b7-`,
  `fp2-bad788e5-clamd-streams.jsonl`.

All bodies are test files; no customer data.
