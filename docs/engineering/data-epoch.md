# Data epoch: which images can read this data

Contract: UPG-003. Design: ADR-0062, slice 6a (owner decision 2026-11-28: add
this contract before runtime recovery may put an earlier image back).
Code: `internal/dataepoch`, `data_epoch.go`, the `LABEL` in `Dockerfile`.

## What it is

A **data epoch** is a whole number for the form of the persisted state under
`/data`. It changes only when a release migrates that state into a form an
older build cannot read.

| Fact | Where | Rule |
|---|---|---|
| The data's epoch | `<dataDir>/.data-epoch`, `{"schema":1,"epoch":N}` | Only rises. A proxy boot raises it to the build's epoch before any store loads; nothing lowers it. Absent in an existing data directory means epoch 1. |
| The epochs an image reads | image labels `io.culvert.data-epoch.min` / `.max` | Equal to `dataepoch.OldestReadable` / `dataepoch.Current` (drift test). |

An image may run on data whose epoch is within its `[min, max]`. An image with
no labels (every image built before this change) says nothing, and the
maintenance agent never puts it back on data.

`culvert --print-data-epoch` prints the data's epoch and the build's range as
JSON. It reads only. An unreadable marker, or a data directory an interrupted
restore moved aside, is an error, never epoch 1.

## Why an absent marker is epoch 1

Every build released before this change read and wrote epoch 1, and every
build of this change is at epoch 1 and writes no marker. The first build that
raises the epoch writes the marker before it writes anything in the new form,
so from then on the marker is present.

## Raising the epoch (obligations)

Raise `dataepoch.Current` only in the release whose migration an older build
cannot read, and only together with all of the following. A tripwire test
(`TestDataEpoch_BumpObligationsTripwire`) fails until they are done.

1. **Backup carries the marker.** Add `.data-epoch` to the backup artifacts.
2. **Restore never lowers it.** After a restore commits, the marker must name
   the higher of the restored backup's epoch (absent: 1) and the epoch the data
   had before the restore. A partial restore mode leaves files of both.
3. **The migration happens after the raise.** `checkDataEpochAtBoot` raises the
   marker before any store loads and refuses the boot if it cannot. Keep every
   migrating store after it in `main()`.
4. **`OldestReadable` stays as low as the build can read.** Lower it only when
   the build drops support for reading the older form.
5. **Release notes** say which epoch the release writes and that earlier
   images will no longer be put back by the maintenance agent.

`prepare-downgrade` rewrites some stores into a form an earlier build reads. If
a future downgrade path lowers the data back to an earlier epoch, it must also
lower the marker, as its own decision with its own tests.
