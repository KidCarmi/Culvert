# cd8e4450 independent handoff audit

**PASS for exact-image intake and the recorded scenarios. This is not an ESXi or full production-readiness verdict.** Review date: 2026-10-08. Source `cd8e44505bd329e5de675592ad4c23f92a534d55`; main lab run `37684926209`, controller `dcbe2f4026f46e394023d5aa68b52686758523dc`.

| Area | Result |
|---|---|
| Artifacts | All five requested ZIPs downloaded and SHA256-verified. Exact application tar, manifest/config, all 12 layer blobs and all 12 uncompressed filesystem hashes verified locally. |
| Source | CI merge `b5f00355` and head `cd8e4450` share tree `b15344b9e44843feae9e2cdfe0de8ef8c9bc6278`. |
| Fresh QEMU | **83 PASS, 5 INFO, 1 BLOCKED, 0 FAIL.** Three independently parsed sample traces end with three consecutive joint readiness/allow-block/ClamAV EICAR/operator-ready passes: **103.279 / 103.210 / 103.192 seconds**, below 120 seconds. |
| Signed fixture | Unsigned apply refused; signed apply and rollback succeed, and baseline digest/enforcement return. Retained operation JSON independently confirms both terminal states. Uses a test key and a label-only target, not a vendor release or cross-version migration. |
| F-DISK | **19 PASS, 1 SURVIVED, 1 INFO.** Active-write ENOSPC refused without restart. State and enforcement persist; category import completes 2,579,670 domains **873 seconds after serving recovery**. Current/predecessor are the same cd8 image. |
| Adoption | **74 PASS, 4 INFO, 2 BLOCKED.** Starts from the retained 2e3 OVA. Application-only upgrade preserves host components; offline refresh preserves current serving; online refresh adopts the updated sidecar; reboot retains it. |
| Exact baked sidecar | **PASS binding/SBOM/scan.** Separate scan run `37693602079`, job `113039591853`, extracted the retained archive rather than rebuilding. Trivy and SBOM ImageID/DiffIDs match the binding. Full vulnerability JSON: **41 packages, 0 reported vulnerabilities**; CycloneDX: **42 components**. |
| CI | **61 successful, 41 skipped, 0 failed** across both API pages. All four aggregate gates approved. Snyk status success. CodeQL still retains one previously reviewed medium false positive. |

## Identity

- OVA: `46cb60078eb2adbc2f8704046268f68e56798bc2b37cd824ba70f8a919bd2ab1`. This review reads the retained build/qualification/scan evidence; the parent owns the independent OVA download/hash.
- Application tar: `8a19dfce4562e0f15eb607229ae37153c1a21bdb839e5c4206a3f68cd0795819`.
- Application manifest: `sha256:659258eee3fc609a8e95e0bc22c89cb57849887b0dcf2b92708ddbff0fb69b42`.
- Application config: `sha256:7afa4f49cc0d6c31d9a0b2a5a171862e6a618fb407ca6ca94f451d02efe6e3e9`.
- Baked sidecar: `culvert/clamav:1.4.6-culvert.2`; index `sha256:7d4e1087e7b94ac37971d35bc831321ebb3e891d6b7d4af8524b7a45e7f1efc3`; config `sha256:7d422f7c7dba76221399dfc8a8e290390f59fe5b2d1641e4cf704d20c733674a`.
- Sidecar archive: `359cde5ff4265d223dd030abd73f45526e8af24bf562dd2ae216f97ccc260564`.

The exact scan records pcre2 `10.49-r0`, zlib `1.3.2-r1`, nghttp2-libs `1.70.0-r0`, libcurl `8.22.0-r0`. Trivy 0.69.3 uses database updated **2026-10-07 07:38:55 UTC**; scan created **2026-10-07 22:04:58 UTC**. Its full JSON command has no explicit severity/unfixed filter; the separate gate selects fixable HIGH/CRITICAL. Zero reported findings is limited to that database and scanner coverage.

## Remaining boundaries

- Fresh-QEMU IdP portal-cookie replay remains **BLOCKED**. Adoption also lacks its signed-update fixture; the separate fresh-cd8 signed fixture passes.
- The adoption run builds sidecar `0f241eee...`, not the baked `7d4e1087...` image. Its functional and reboot results do not transfer the exact baked-image scan to those separately built bytes. Offline refresh proves continued current serving, not an offline reboot.
- QEMU's synthetic I/O delay is not real ESXi performance. The backup fixture is unencrypted, not encrypted-backup qualification.
- Generic readiness presence, dry-run exit-status and complete firstboot-journal oracles remain weaker than desired. Actual retained readiness has all 11 rows OK, actual offline restore passes, and retained journal records a condition-based firstboot skip. These observations do not cure the general harness limitations.
- CodeQL check `112939932917` annotates `proxy_tunnel.go:832`, numeric `firstByte[0]` rendered with `%02x`. Those source files are unchanged from the previously verified d698 source. Successful execution is not zero annotations; no alert dismissal or risk acceptance occurred.
- Main-application Trivy is HIGH/CRITICAL with unfixed/ignorefile filtering. govulncheck reports zero called vulnerabilities but one uncalled required-module vulnerability. Neither is an unrestricted clean claim.

## Evidence and handling

`audit.json` contains exact IDs, hashes, checks and limits. `exact-sidecar/` retains the bound SBOM and scanner evidence. `github-evidence.json` includes both pages of checks and the separate scan-job result. `verify-offline.py` is the locally authored verifier, not a downloaded script; it exited 0. No live VM operations, fault injection, product changes or PR posting occurred.

**Publish only this sanitized directory.** Original archive/extracted directories contain unreviewed console transcripts and stay outside the public subset. `SHA256SUMS` covers every payload file.
