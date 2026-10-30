# FB-1 T4: network lane evidence

| | |
|---|---|
| Lab run | [41111194290](https://github.com/KidCarmi/Culvert/actions/runs/41111194290) (`test/appliance-lab` at `da7dabc7`, workflow `snapshot-pin-check.yml`) |
| Source checked out | `d452d50dda9943bafaa4e03d3f77e542dd6d97dd` (the FB-1 implementation) |
| Runner | Ubuntu 24.04.5 LTS, APT 2.8.3 (the guest's APT) |
| Artifact | `fb1-snapshot-pin-check-d452d50d…`, id 13002859346, zip sha256 `0e891941017bd0848d49e68be696a3be7ff2dd05a71b3ae3313e083f30a238bf` |

These files are copied from the artifact (`SHA256SUMS`). `c2.log` keeps only APT's non-progress lines.

| Case | Result |
|---|---|
| C1 pinned update + pins | PASS: all four snapshot InRelease files equal the manifest pins. The systemd candidate is 255.4-1ubuntu8.17 from the snapshot; the live candidate is 8.18. |
| C2 future ID `20991231T000000Z` | PASS on both layers. The guard refuses it. With the guard bypassed, APT accepts it (rc 0) and serves noble-updates InRelease `3e30429b…`, which is the **live** archive's file (E6). The pin check refuses it. |
| C3 `Snapshot: yes` on Docker's repository | PASS: rc 100, `E: Snapshots not supported`. |
| C4 unreachable index | PASS: plain update rc 0 with `W:`; pinned update (`--error-on=any`) rc 100 with `E:`. |
| build-ova.sh fetch block (extracted verbatim; `fetch-block.sha256`) | PASS. A wrong pin stops it. With the manifest pins it fetches and verifies all 16 indexes and Docker's signed index. |
| Reconciliation on the fetched real indexes | PASS. The 325c142a inventory is refused on **exactly the recorded 57** (`got-57.tsv` = `../../esxi-325c142a/kernel-42/provenance-nonsnapshot-57.tsv`). Without them, 623 reconcile (619 snapshot + 4 Docker), byte-identical to the local reconciliation against the independently fetched kernel-42 indexes. |
