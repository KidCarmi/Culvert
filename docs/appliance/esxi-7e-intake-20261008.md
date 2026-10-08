# 7e53720d OVA intake and evidence review

**PASS: local artifact integrity, complete internal manifest, hardware and recorded provenance/evidence review. Independent ESXi NOT RUN. Production closeout remains blocked. No merge/release.** Retained locally before any boot; declared2vCPU/4096MiB/40GiB hardware matches the approved limits.

Selected [OVA artifact11562703124](https://github.com/KidCarmi/Culvert/actions/runs/37805385811/artifacts/11562703124), build run37805385811, lab revision `442cb87420c2d9dc523a536afe5878e6d2bb5a9d`. This replaces98cf41c0 for the next qualification; earlier artifacts and failed attempts remain evidence.

| Identity | Value |
|---|---|
| Product source | `7e53720d06f525f4e5fdbfec42f52840d5b734e2` |
| OVA SHA256 | `578ea6b83b450b91bccc10ac80058db42d157e2161a45aa23fc8a23a2def7c65` |
| OVA bytes | 1,308,221,440 |
| ZIP SHA256 | `2a7830e6fa8c7d868e2775e03eea53380060f02476cf9ca8b5a11fcd97a22e63` |
| Application image | `sha256:2a355d7a8930b12581c0f42c273bc3357cbefa36d9382ab7071d2c187dda0554` |
| Source image tar | `1e29ed3117c382c3e5a19067e66d58ddfbafcf6e310cf24302251737fdd31c11` |
| Console binary | `8d30bbf5af9f43438129429ba77971eebb4e5f055c7a937f171da65547dbbe1d` |
| Baked sidecar image | `sha256:1cf6b7e347c2b14b14cbcdf5d9e5de1cb8de8e3b97c44508874178315b563787` |
| Baked sidecar archive | `ae9c66c28ce7272ceeafc0e652ede4b704c3fa85ee89000ccc8267c2eae8d161` |

## Independent audit

All seven small evidence ZIPs were downloaded and checked against GitHub's SHA256 and byte counts. Source7e is available locally and the actual49-line reproducibility block matches the probe byte-for-byte exactly once in `appliance/build/build-ova.sh`; block SHA256 `1f3d39adc77bb003e47d3e4efadb0cfd913d60a10abe24c376a55b06ed0789cc`. All16 queried source workflows completed successfully. Green workflows do not replace the remaining runtime checks.

| Result | Evidence and limits |
|---|---|
| PASS: measured sidecar reproducibility | Probe37803364047/artifact11561921555 records two invocations, each with two no-cache builds, identical manifest/loaded identity and compressed archive. OVA build logs record another independent pair with the same identity/archive. Source removes APK time-bearing log/cache, sets the epoch, rewrites timestamps and bakes the compared OCI archive itself. These six measured builds establish sidecar reproduction for those inputs, not full-OVA reproducibility. |
| PASS: exact baked/adopted scan binding | Baked scan37812196453/artifact11565403005 binds this exact OVA, OCI archive, config and all8 DiffIDs to Trivy. Adopted scan11564024137 binds its separately built running image `9decfc48...` and matches adoption A5's binding. Each reports0 vulnerabilities,41 packages/42 SBOM components against recorded Oct8 15:33UTC DB. Do not transfer one image's scan to the other. |
| PASS: QEMU subset | Candidate artifact11564133828 has94PASS/5INFO/1BLOCKED/0FAIL. Injected-I/O maintenance recovery103.335339/103.109104/103.112884s <=120s, with consecutive readiness/allow-block/EICAR/operator samples. First backup listings1.705/1.789/1.677s. Not ESXi results. |
| PASS: history recovery subset | Source data volume deleted, restored into a new volume on the same VM, log key rotated, wrong-passphrase/live-lock refusals matched, all12 records recovered identically. This does not establish source-VM-unavailable fresh-appliance recovery. |
| PASS: signed fixture subset | Real verifier signed apply/rollback, baseline image after reboot, secret root-reveal boundary and enforcement recorded. Disposable lab trust and label-only target remain distinct from release dispatch and cross-version migration. |
| PASS: bounded F-DISK-1 | Artifact11563538114 binds candidate source tar/config/image; active-write exhaustion survived with zero restarts and200/403 enforcement. Category import converged978s after recovery. 2GiB nested-Docker fixture; predecessor equals current image. No whole-datastore/full-appliance or migration claim. The generic QEMU footer calling F-DISK-1 OPEN is not the separate bounded result. |
| PARTIAL: boot appearance | Inspected QEMU graphical capture11565211681 at8.00s: centered cyan Culvert on black, no log overlap. No exact7e ESXi graphical proof yet. |
| BLOCKED/NOT RUN: remaining production gates | QEMU still blocks portal-cookie replay for absent IdP. Exact ESXi bootstrap, access/auth/SSH refusals, network/identity P1 regressions, three <=120s maintenance reboots with traffic/scanner/state, fresh-appliance recovery and history/secret custody, HTTPS/IdP browser journey, boot console and app/OS scanner dispositions remain open. |

The scan's `nghttp2 files: none` probe must not be used to assert library absence: its package is in the inventory. `nghttpx_present=no` is the narrower recorded observation.

Original98 attempt1 recovery failures126.875651/120.065958s remain. The retained A-B-B-A comparison showed no material artifact effect on its runner; it did not isolate the old runner's specific condition. Keep the120s ESXi budget and evidence boundaries unchanged.

## Local state and next qualification

No7e VM imported or booted during this intake. The retained cd8 fresh-recovery VM remains the last independently tested ESXi guest; its UI and credentials do not describe this new OVA. Read-only operator SSH and authenticated local PAM/sudo remain required. Reconcile the shared harness and commit/freeze all helpers before running; preserve private evidence before retiring the retained VM. Stay within one owned VM,2vCPU,4GiB RAM,40GiB disk and approved reserves. Do not edit a running qualification checkout.

No new confirmed product blocker was found in this focused intake/evidence audit. This candidate is suitable to enter independent ESXi qualification with intake verification complete; it is not production-approved. Do not expand features or re-baseline unexplained guest-content drift. No merge/release.
