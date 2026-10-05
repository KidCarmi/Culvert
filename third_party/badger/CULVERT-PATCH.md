# Survive a failed memtable / value-log allocation (F-DISK-1)

This directory is the complete `github.com/dgraph-io/badger/v4 v4.9.6` Go
module (tag commit `fbd8d2eefad8be8757249767255faf989945b599`, module sum and
zip sha256 in `CULVERT-PROVENANCE.json`). Upstream files and notices are
retained; nothing about licensing changes (Apache-2.0, `LICENSE`). It is the
companion of `third_party/ristretto`, which preallocates badger's writable
mmapped files so a full filesystem returns `ENOSPC` instead of faulting.

## Why

Once allocation can FAIL with an error (the ristretto fork), badger has to
survive that error. It did not, in one place that matters:
`ensureRoomForWrite` handed the full memtable to the flusher and only then
called `newMemTable()`. When that allocation failed, `db.mt` was left `nil`,
this write returned the error — and the NEXT write died on
`y.AssertTrue(db.mt != nil)`, which is `log.Fatalf`. On a full disk the
proxy therefore still exited, one write later than the SIGBUS it replaced.
Reproduced by `TestFullFilesystemWriteReturnsErrorNotSIGBUS/retry`
(`Assert failed`) before this patch. `dropAll` / `dropPrefixes` (reached by
the request-history store's `PurgeAll`) had the same nil-on-failure shape.

## What changed (and nothing else)

| File | Change |
|---|---|
| `db.go` `ensureRoomForWrite` | Allocate the replacement memtable FIRST. On failure the full memtable stays current, nothing is retired, the write is refused with the error, and a later write retries. The spare is kept across the flush-wait loop and discarded (`DecrRef`, which deletes its WAL) if the DB closes while waiting. |
| `db.go` `dropAll`, `dropPrefixes` | Allocate the replacement before tearing the old memtables down; a failed allocation changes nothing. `dropPrefixes` discards the spare if a flush fails. |
| `value.go` `write` | When the grow of the current value log fails, return the offset reserved for the entry (`writableLogOffset`) before returning the error. Measured: upstream's kept offset leaves an unused hole and does NOT lose acknowledged values in `TestFullFilesystemWriteReturnsErrorNotSIGBUS/vlog-grow` (values are read by pointer), so this is hygiene, not a demonstrated data-loss fix. |

Already safe without a badger change, and why:
- `flushMemtable` retries a failed L0 table build once a second. A failed
  `O_EXCL` table or value-log creation leaves no file and no descriptor
  behind (the ristretto fork closes the descriptor and removes a file it
  created but could not reserve), so the retry cannot hit "file exists".
  While the flusher cannot build a table, writes that need a new memtable are
  refused at the allocation above; a write that finds `flushChan` full waits
  for the flusher, as upstream does.
- `Close` on a full disk returns (bounded) and the store reopens once space
  is back: `TestFullFilesystemWriteReturnsErrorNotSIGBUS/close-full`.

## Verification

```text
python3 appliance/artifact-audit/verify_dependency_forks.py      # upstream bytes + exact patches (both forks)
go test ./internal/catdb -run 'TestStoreFilesAreFullyAllocated|TestFullFilesystemWriteReturnsErrorNotSIGBUS'   # as root for the tmpfs cases
```

The `retry` case writes the real category store into a full tmpfs, then
writes again three times in the same process (each must be refused, not
fatal), frees space and writes again in the same process, closes within a
bound, reopens and checks every acknowledged batch.

Badger's own suite, measured: the root package (`go test -short .`, 289 s)
passes on this patch built against UPSTREAM ristretto, and `table`, `skl`
and `y` pass on this patch built against the ristretto fork. The root
package cannot run against the ristretto fork on a small disk, and why is
worth knowing: several upstream tests leave a DB open while their directory
is deleted, and with the default 1 GiB value log each leaked handle now holds
a real 2 GiB reservation until the process exits (sparse upstream files cost
nothing). The product stores cap the value log at 128 MiB and close their
handles.

## Maintenance obligation

Upgrading badger must replace the full upstream tree, re-check whether
upstream fixed the allocate-after-retire order, re-apply this patch,
regenerate `CULVERT-PROVENANCE.json` and run the checks above. The local
replacement is recorded in Go build info; SBOM consumers must retain the
upstream version plus this provenance.
