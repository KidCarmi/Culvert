# cd8 ESXi qualification plan — declared before VM operations

This plan selects only source `cd8e44505bd329e5de675592ad4c23f92a534d55`, OVA SHA256 `46cb60078eb2adbc2f8704046268f68e56798bc2b37cd824ba70f8a919bd2ab1`, and application image `sha256:659258eee3fc609a8e95e0bc22c89cb57849887b0dcf2b92708ddbff0fb69b42`. Artifact 11512150120 from run 37684926209 must be retained and its outer and internal manifests verified before boot. The baked ClamAV image is `sha256:7d4e1087e7b94ac37971d35bc831321ebb3e891d6b7d4af8524b7a45e7f1efc3`, tag `culvert/clamav:1.4.6-culvert.2`.

The shared lifecycle is reconciled to lab revision `dcbe2f4026f46e394023d5aa68b52686758523dc`; only the existing ESXi hooks and Windows transport refusal differ as recorded in shared-harness-provenance.json. QEMU console/adoption entrypoints are retained but not invoked by this ESXi campaign. Historical mutation continuations remain pinned to their original candidate and shared source. All controller helpers and external inputs must be frozen before import; the execution checkout will not be edited while qualification runs.

## Acceptance

- Three independent maintenance reboots must each reach three joint healthy samples within **120 seconds** of the accepted maintenance request. Sampled evidence includes real allowed/blocked proxy traffic, EICAR enforcement, ClamAV readiness, administrator access, preserved policy/CA/image/agent and first backup-list availability. First-install timing is separate. A timeout/failure remains a failure even if a later observation succeeds.
- Correlate guest monotonic service times with controller observations and ESXi realtime storage/VM metrics. Wait for the requested trailing sample window to publish; missing counters remain missing. Do not infer storage causation from correlation.
- Default console bootstrap, forced password change, read-only operator SSH and refusal regressions, setup/auth, actual restore, real-verifier signed update/rollback, OS update, static-network failure rollback with usable networking after reboot, and identity reset/power-off/fresh identities with superseded-credential refusal.
- Export encrypted backup and separately retain recovery secrets. Preserve evidence before source deletion. Fresh-appliance restoration requires the source VM and its backing disks to be absent; validate recovered admin, CA, policy, categories, agent and real traffic.
- Capture ESXi VGA frames from an armed pre-power-on observer through cold boot and maintenance. Inspect centering, mode stability, truthful status, menu URL and clean handoff. Perform explicit Esc, Alt+F12 and Alt+F1 observations only outside credential entry, plus authenticated bounded `/dev/console` and inherited getty diagnostics. The Ubuntu text splash does not promise a second-Esc toggle. Credentials/screenshots remain private unless a frame is individually cleared for publication.
- Keep F-DISK, scanner, ClamAV remediation/adoption, recovery-secret custody and IdP limitations explicit in the integrated closeout. QEMU evidence does not substitute for ESXi results. No merge or release authorization.

## Scope

One owned disposable VM at most, 2 vCPU, 4096 MiB RAM, 40 GiB disk; 64 GiB datastore reserve, 4096 MiB host memory reserve and 2000 MHz CPU reserve. Existing non-lab workloads are not changed. Privileged guest work uses the existing authenticated local recovery procedure. Fixture keys and test trust remain outside the deliverable OVA.
