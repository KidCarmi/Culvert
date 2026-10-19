# Preallocate badger's writable mmapped files (F-DISK-1)

This directory is the complete `github.com/dgraph-io/ristretto/v2 v2.2.0` Go
module (tag commit `47ceb3b6852000bc497437af816dd68d4c5fa114`), the version
`github.com/dgraph-io/badger/v4 v4.9.6` resolves. Upstream files and notices
are retained; nothing about licensing changes (Apache-2.0, `LICENSE`).

## Why

Badger stores its memtable write-ahead log, value log and new tables through
`z.OpenMmapFile`, which sizes a new file with `ftruncate`: the file is
**sparse**, and its blocks are allocated only when a page of the mapping is
first stored into. On a full filesystem that allocation fails inside the page
fault, and the kernel answers with **SIGBUS** — a Go program cannot recover
that, so the proxy died mid-write (`fatal error: fault` in
`logFile.zeroNextEntry` / `writeEntry` ← `memTable.Put` ← `writeToLSM`;
reproduced four times on CI runners, F-DISK-1 in
`docs/appliance/readiness-report.md`). No badger option preallocates. The
latest upstream release (v2.4.2) still truncates sparse.

## What changed (and nothing else)

| File | Change |
|---|---|
| `z/file.go` | `OpenMmapFileUsing` reserves the whole mapped size with `fallocate` for every **writable** mapping (new files, and existing files a sparse earlier build left behind). On failure the error is returned and a file this call created is removed (as badger's own bootstrap failure does; an empty file would be refused by badger's next open). `OpenMmapFile` now closes the descriptor it opened when it returns an error. |
| `z/file_linux.go` | `(*MmapFile).Truncate` reserves the added range when **growing**; on failure the file returns to its old size and the existing mapping is untouched. Shrinking is unchanged. |
| `z/prealloc_linux.go` (new) | `preallocate`: `fallocate(fd, 0, off, len)`, retried on `EINTR`. A filesystem without `fallocate` (`EOPNOTSUPP`/`ENOSYS`) is NOT left sparse (that kept the SIGBUS, ASTRA review of d943a9a1): it gets glibc's `posix_fallocate` emulation — a zero byte written into every block whose probed byte reads zero — which allocates the blocks, turns a shortage into an error, and never changes existing data (the same call covers existing files an earlier sparse build left behind). One stderr line per process names the emulation. |
| `z/prealloc_linux_test.go` (new) | Forces `EOPNOTSUPP`/`ENOSYS` through the `fallocate` variable: the range must end fully allocated (`st_blocks`) with existing bytes intact, and a failing emulated write must be an error. Both fail against the old sparse fallback. |
| `z/prealloc_other.go` (new) | no-op off Linux. |

Effect: a full filesystem is reported as `ENOSPC` when badger creates or grows
a file — badger already propagates those errors (`cannot create new mem table`,
table build retry) — instead of a fatal fault at the first store. Disk usage is
honest from the start: a mapped file occupies its full size while open (catdb
and logstore cap the value log at 128 MiB: 256 MiB mapped; a memtable WAL is
2 × 64 MiB). Badger still truncates files to their used size on close.

Not covered: badger's discard-stats file grows with `y.Check(...)` (a panic on
error instead of a fault); it grows only past 65k value-log files, which these
stores never reach.

## Verification

```text
python3 appliance/artifact-audit/verify_dependency_forks.py      # upstream bytes + exact patches (both forks)
go test ./internal/catdb -run 'TestStoreFilesAreFullyAllocated|TestFullFilesystemWriteReturnsErrorNotSIGBUS'
(cd third_party/ristretto && go test ./z/...)                    # upstream z tests on the patched code
```

`TestFullFilesystemWriteReturnsErrorNotSIGBUS` (root: mounts a size-capped
tmpfs) bulk-writes the real category store until the filesystem is full, in a
child process: it fails on a fault, requires the write to return ENOSPC, then
frees space and requires a clean reopen with the committed data. Against
upstream v2.2.0 it reproduces the CI crash (`fatal error: fault`, same stack).
The end-to-end gate is the midwrite scenario
(`test/e2e/appliance/upgrade-enospc-qualify.sh`, `QUAL_ENOSPC_SCENARIO=midwrite`).

## Maintenance obligation

Upgrading ristretto (or a badger upgrade that moves it) must replace the full
upstream tree, re-check whether upstream preallocates, re-apply this patch,
regenerate `CULVERT-PROVENANCE.json`, and run the three checks above. The local
replacement is recorded in Go build info; SBOM consumers must retain the
upstream version plus this provenance.

## Supported data filesystems

The guarantee — a write into a reserved range never needs a new block — holds on
filesystems that allocate in place: ext4 (the appliance's `/data`), XFS, and any
filesystem without `fallocate` through the emulation above. Copy-on-write
filesystems (btrfs, ZFS) allocate a new block on every overwrite, so no
preallocation can make a full one safe; a host that keeps Docker volumes on
one is outside the F-DISK-1 guarantee.
