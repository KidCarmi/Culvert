# ESXi early-initrd read-ahead experiment — 2026-10-05

**Result: FAIL for recovery repeatability; PASS for exact original-initrd restoration.** The 1024 KiB intervention was validly applied before root mount, but its three consecutive recovery results were FAIL/PASS/PASS. This experiment does not qualify the appliance for production or establish storage as the cause of slow recovery.

The [sanitized aggregate](evidence/esxi-early-initrd-v4-20261005.json) contains the six boot results, controller and artifact identities, phase observations, and 128 independently checked file references. Raw authenticated captures remain private; this report contains no credentials or raw configuration.

## Scope and provenance

This was an unchanged Culvert product image with a deliberately altered guest initrd, followed by restoration of the exact original initrd. One owned VM on DataStore2 retained 2 vCPU, 4096 MiB RAM and a 40 GiB disk. The comparison was A0 (128 KiB), B1–B3 (1024 KiB), return A1 (128 KiB), then original restoration. Kernel, package, Compose, image and ClamAV signature evidence remained equal across all six captures.

| Identity | Exact value |
|---|---|
| Measured source | `b579ca28c9d936e9141292ce5ec564a26feeae86` |
| OVA SHA-256 | `1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775` |
| Product image | `sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47` |
| Campaign | `13222c13-21fb-4ad3-ad38-48d0acf84778` |
| A0 measurement controller | `34e69951648f886fb8f8fe034345e7b5480d12cf` |
| A0 freeze SHA-256 | `0bad4c489327f6c610a445d7376ad0c9e7a83c3628c30eb862542789747f8169` |
| Later measurements and all supplemental proofs | `ff0d0151cc39ac98718ca979e8ed70160a100e66` |
| Later freeze SHA-256 | `edd16c9d224c2f12603be61fa9f19017879c2c9461556adaafbeb4c413903ee8` |

The later controller added a journal verifier and tests. All 105 inherited manifest files were verified byte-identical. The original measurement helper, probe, collector and sampler did not change.

## Acceptance and results

The frozen gate required recovery within 120 seconds of authenticated maintenance acceptance, ending with three consecutive healthy samples at the five-second sampling cadence. It also required three consecutive B passes and the first post-ready backup within five seconds. Systemd activation or a direct ClamAV PONG alone does not satisfy authenticated readiness.

| Cycle | Effective read-ahead | Recovery seconds | Timing | First backup seconds |
|---|---:|---:|---|---:|
| A0 | 128 KiB | 95.187 | PASS | 0.922 |
| B1 | 1024 KiB | 165.781 | **FAIL** | 0.766 |
| B2 | 1024 KiB | 114.406 | PASS | 1.094 |
| B3 | 1024 KiB | 80.922 | PASS | 1.250 |
| Return A1 | 128 KiB | 132.453 | **FAIL** | 2.218 |
| Original restored | 128 KiB | 97.515 | PASS | 0.797 |

All six strict backup checks, independently evaluated direct-PONG coverage and persistence checks passed. The backup recheck includes boot and first-ready sample association, dispatch cadence, recorded baseline archive equality and measured duration. Original API listing/archive bytes were not retained: equality relies on the frozen recorded filename/size/encryption predicate, not an independent content-integrity check. Later backup and state passes do not replace B1 or A1 timing failures.

## Where elapsed time varied

These timestamps are seconds since the guest kernel boot, not seconds since maintenance acceptance.

| Phase | A0 | B1 | B2 | B3 | A1 | Original |
|---|---:|---:|---:|---:|---:|---:|
| Local filesystems active | 12.328 | 11.059 | 24.878 | 11.488 | 17.539 | 12.659 |
| containerd start | 24.470 | 22.206 | 39.276 | 21.168 | 39.184 | 24.172 |
| containerd active | 38.227 | 49.271 | 47.852 | 28.534 | 57.534 | 39.156 |
| Docker active | 46.886 | 65.222 | 57.508 | 36.185 | 75.817 | 50.838 |
| Stack resume finished | 68.008 | 115.769 | 76.515 | 56.672 | 96.218 | 71.308 |

B1 spent 27.065 seconds starting containerd and 50.539 seconds resuming the stack. B2/B3 containerd pre-log intervals were 4.329/4.348 seconds versus A0's 13.398 seconds, but B1 took 23.225 seconds. A1's unit-log collector timed out after 15 seconds (exit −9, zero bytes); its pre-log interval is unknown. This does not demonstrate a consistent, reversible binary-load improvement.

Clock correlation places acceptance-to-next-kernel origin within 22.991–29.850 seconds for B1, versus 1.102–7.024 for A0. These are uncertainty intervals, not isolated shutdown durations. Early sampler coverage starts after the initrd/root transition, so it cannot directly attribute all earlier I/O.

B1 also coincided with heavier shared-device activity: mean read latency was 90.727 ms versus A0's 11.125 ms, and mean write-queue latency was 147 ms versus 0.75 ms. These are means of 20-second samples over different observation windows, not I/O-weighted latency. Device counters include unrelated workloads. Observed VM CPU-ready maxima were 97–112 ms per 20-second interval for B1 through A1, with zero observed co-stop, maximum-limit, balloon and swap-in counters; this does not eliminate every host scheduling or cache confound. No matching kernel I/O-error, EXT4-error or disk-timeout indicator was found in the retained first-five kernel captures.

An alternate-datastore control remains capacity-blocked: the 19:53:33Z read-only check found 68.6728515625 GiB free on SSD datastore1, below the frozen 110 GiB import guard. The guard was not relaxed and unrelated workloads were not changed. Capacity is not causal evidence or risk acceptance.

## Verification, restoration and remaining limits

The built-in v4 verifier failed because `dmesg --raw` and `--color` were mutually exclusive. That diagnostic failure remains recorded. The additive verifier independently checked the current boot, ownership, active initrd hash, receipt, preserved boot files and effective setting before and after reading the complete kernel journal. All five comparison boots showed the intended hook before root mount; for example A0 applied at 2.902043 seconds before mount at 2.999911 seconds. Thus the intervention was valid despite the retained built-in verifier error.

Normal restoration and a final reboot verified the original 37,347,640-byte initrd for kernel `6.8.0-146-generic`, SHA-256 `d22af6fa8e3b0c609ae3227b7e036b1262b3054b4f395ced2a4d3beedf32bf54`, effective 128 KiB and absence of the experimental hook marker. The final supplemental result SHA-256 is `706837efdbc0c0e7adfc2a6ac76a95be0841d01c66a3f6f0ac2e42ad39bd8c21`.

Earlier E0 and rootfs-udev repeatability failures, the invalid v3 hook experiment, the v4 verifier and A1 collector errors, and the historical 597-second recovery/10-second backup timeout remain preserved. Their causes are not closed by this comparison. Source fixes reviewed at `4dba8b9b516cccfda369d582396d4210f942df9f` are separate from the measured b579 artifact. They still require their own integrated artifact qualification; this experiment closes no other production blocker and grants no risk acceptance.
