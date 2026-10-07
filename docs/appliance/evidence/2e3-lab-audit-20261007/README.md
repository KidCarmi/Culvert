# Replacement 2e3 evidence audit

Read-only independent audit of PR #1528 source `2e3bcc2a1095f3e26e4f0b73a6a5515bdd069ee2`, handoff [6036306585](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6036306585), lab [37606237892](https://github.com/KidCarmi/Culvert/actions/runs/37606237892), controller `e96895c4b5ba4e4254f92d89038a57023daf365b`.

**PASS for exact-image binding and the recorded QEMU/F-DISK scenarios. Full production closure is not established.** No live ESXi, VM, registry, or destructive operations were performed.

| Evidence | Independent disposition |
|---|---|
| Artifact archives | QEMU 11477120696, F-DISK 11474899905 and image 11475570320 downloaded and SHA256-verified against handoff/GitHub metadata. |
| Image identity | Tar `db4f5ce8784e2a8e5145fdf59126a8e675a27f6628ac3b70e0d2ac16daf5ffff`; manifest `sha256:536403fc9ba8a4bc15d229a12a7586ce6ccc35ba99148b71869a81596e0ea940`; config `sha256:7b3c98273c372b2875c140d4c678f415f3dda681e185e290c6b9b7234e1f1714`. Manifest/config/all 12 layers and all 12 uncompressed rootfs hashes verified. |
| Source | CI merge 6b33ccf6 and head 2e3bcc2a have identical tree `55d2a7019bca847db52707866e5b66b2d6043887`. Build-info names 2e3 for image/provisioning/console with no drift. |
| QEMU |79 PASS, 5 INFO, 2 BLOCKED, 0 FAIL. Independently parsed final three consecutive joint samples in each trial: readiness, real allow/block, ClamAV EICAR and operator phase all pass. Recovery 100.610/100.477/100.524 s versus 120 s. |
| F-DISK |19 PASS, 1 SURVIVED, 1 INFO, 0 FAIL/inconclusive/known-failure. Write-in-flight fill led to memtable fallocate ENOSPC; proxy remained running with 0 restarts. Free space plus compose up restored serving, preserved user/CA state and 200/403 enforcement. |
| Category recovery |Store available 1, recovered 0, quarantined copies 0. Fresh retry reports complete 2,576,609 domains **963 s after serving recovery**. This is eventual category recovery, not immediate complete coverage. |
| Scanner CI |Active Trivy/govulncheck/gosec jobs pass their configured scopes. Snyk status success. CodeQL execution succeeds but retains one medium annotation; zero-alert wording is inaccurate. |
| Overall CI |100 listed checks: 59 success, 41 skipped, 0 failed. All four aggregate gates approved; skipped legacy jobs are not counted as executed tests. |

## Remaining boundaries

- QEMU 4b portal-cookie replay needs an IdP; 6c signed update lacks its fixture. Both are explicitly **BLOCKED**, not passed. Their separate CI tests do not replace this appliance-level qualification.
- The recovery profile injects 12 ms reads/3 ms writes under KVM QEMU. It is not physical ESXi timing evidence.
- F-DISK current/predecessor are the same image. This proves the recorded mid-write recovery case, not a cross-version upgrade. Category convergence is certified by the fresh successful sync marker/count, not an independent comparison of every domain.
- The backup fixture is **unencrypted**, 11,607 bytes; first listing 1.419/1.428/1.422 s. Actual offline restore passed, but this is not encrypted-backup restore qualification.
- The generic lab harness still has weaker assertions: dry-run banners without captured command RC; firstboot journal limited to tail 20 with swallowed transport errors; ready-row assertion does not reject missing named rows. Actual retained JSON has all 11 readiness rows OK and the journal records a condition-based firstboot skip, supporting this run without curing those general oracle weaknesses.
- The apparent `[F] guest-content` failure is intentionally a diagnostic against superseded 4c4b772 in a separate `LAB_DIR=fpcmp`. Controller source confirms it is not a hidden failure from the active qualification verdict.
- OVA SHA `55e98116ba2c020789b3f5de4eabab7e29af611c83b9c972b82a6319a19f145e` is recorded by build/qualification evidence; this reviewer did not download or recompute the OVA. Parent owns that verification.
- Candidate is an unsigned CI artifact. No release-signing or production-readiness claim is made.

## CodeQL disposition

[Check 112737290301](https://github.com/KidCarmi/Culvert/runs/112737290301) reports one medium `go/log-injection` annotation at `proxy_tunnel.go:832`, columns 27–39: numeric `firstByte[0]`. It is formatted as `%02x`, not raw input. The hostname is sanitized and quoted; protocol is a fixed enum and sanitized. The source files are unchanged from d698, whose comparison with main 3fcc07e7 and exhaustive 256-byte formatting test were retained in the prior audit. This remains a **source-backed existing false positive**, not a new dependency issue. No alert was dismissed or risk accepted.

Trivy scans only HIGH/CRITICAL, ignores unfixed and ignorefile entries, and reports 0 selected findings for Alpine/app/agent. Image-build job 112736271369 records the same 7b3c9827 config and uploads artifact 11474785430 ZIP `6a4f6cbd92b609e7f99c21716797c1aa7fbed5ee3b2fdeca333fdf6e452f0064`, downloaded by scanner 112737194810. This binds the scan to the candidate content despite differing export/registry manifest wrappers. govulncheck reports 0 called vulnerabilities and 1 uncalled required-module vulnerability. Do not summarize those scopes as no vulnerabilities anywhere.

## Reproducibility and publication

`audit.json` contains IDs, digests, source references and findings. `verify-offline.py` verifies the local tar and sample traces; `inspect-binaries.go` reads ELF metadata only. The two binaries retain real Rekor/Sigstore verification functions and no grpc-gateway/runtime functions.

Executed locally:
```
python -B .tools/2e3-review/verify-offline.py
go run .tools/2e3-review/inspect-binaries.go .tools/2e3-review/private-binaries/culvert .tools/2e3-review/private-binaries/culvert-maint
```
Both exited 0. The Python verifier had an initial syntax typo, corrected before its successful run; no live actions occurred.

**Publish only this sanitized directory.** Sibling archive/extracted directories retain original lab transcripts and are not reviewed for wholesale publication. Selected excerpts here omit credentials and signed download URLs. `SHA256SUMS` fixes this bundle's contents.
