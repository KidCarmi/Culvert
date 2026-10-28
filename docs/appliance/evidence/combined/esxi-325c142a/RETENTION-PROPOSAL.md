# Artifact retention proposal (deadline 2026-11-10T18:12:40Z)

**Status:** proposal only. Nothing has been copied, uploaded, deleted or changed in access. Executing it is O1 in `CUSTODY-AND-AUTHORIZATION.md`.

## 1. What expires, and when

| Artifact | ID | Size (bytes) | ZIP SHA-256 | Expires (UTC) | Already held privately? |
|---|---|---|---|---|---|
| **OVA** `appliance-lab-ova-candidate-0648adeb` | 12756793569 | 2,079,718,929 | `124fcc372cfa1953f05be8e3c640504a4b546b8abd1a532e89d819cce9ebf903` | **2026-11-10 18:12:40** | **No.** ASTRA did not download the OVA. |
| Qualification evidence `appliance-lab-evidence-candidate-0648adeb` | 12760932320 | 874,776 | `efcda68be338f9f1ef19fc0c631360316b3fc12e15021189dffb2d13bdc938bc` | 2026-11-26 18:43:03 | ASTRA parsed it; ASTRA to confirm it is retained |
| F-DISK evidence `appliance-lab-fdisk1-evidence` | 12757059994 | 9,752 | `382518bba814d170751504b43c4d8dce972e49966db434ce9fceb7a83fe5e2e6` | 2026-11-26 18:17:10 | ASTRA to confirm |
| Exact-scan evidence `appliance-lab-exact-scan-0648adeb` | 12770110434 | 10,889,306 | `80ba03334e3e730931d7a8a9fce5fa16da854dc2e0b873ecf19e1fbf95ee3687` | 2026-11-26 20:43:49 | Yes (ASTRA, "retained once") |
| Sidecar-scan evidence `appliance-lab-sidecar-scan-0648adeb` | 12768554394 | 21,794 | `7de7114ce9c4347b7438cee925b30f4a84ec0901334a83f8074b50f56ce34871` | 2027-01-25 20:35:56 | Yes (ASTRA) |
| Candidate image tar (preserved) | 12747932343 | — | (tar `770c295c…de4e7`) | 2027-01-25 | Actions-retained |

**Expiry deletes; it cannot be extended.** GitHub fixes an artifact's retention at upload; it cannot be lengthened afterwards.

**The OVA is the only item that is both unheld and expiring before the residual window ends (2026-11-26).** Losing it means the qualified bytes are gone: any rebuild is a different artifact and restarts the identity, scan and qualification chain.

**Visibility today:** the repository is **public**. "Internal-only" is the intended use, not access control. Any signed-in GitHub user can download Actions artifacts of a public repository until they expire. This proposal does not change that (see §4).

## 2. Recommended solution: one sealed private copy, held by ASTRA

1. **When:** by **2026-11-07** (three days of margin).
2. **Who:** ASTRA, which already keeps the project's sealed custody store (DPAPI-encrypted, hash-verified collections from earlier ESXi campaigns). This adds no new holder or location.
3. **Download once**, authenticated:
   ```bash
   gh api repos/KidCarmi/Culvert/actions/artifacts/12756793569/zip > ova-12756793569.zip
   ```
4. **Verify before anything else.** Any mismatch is STOP: keep nothing, report.
   ```bash
   test "$(stat -c %s ova-12756793569.zip)" = 2079718929
   echo "124fcc372cfa1953f05be8e3c640504a4b546b8abd1a532e89d819cce9ebf903  ova-12756793569.zip" | sha256sum -c -
   unzip -q ova-12756793569.zip -d ova && cd ova
   echo "325c142a7df441eb97dd5a5e688e0fb89979b8ee29680175d627fcf8556df96f  culvert-appliance-1.0.360-candidate.g0648adeba52e-ubuntu-24.04.ova" | sha256sum -c -
   mkdir x && tar -xf *.ova -C x && (cd x && python3 -I -c "
   import hashlib,re,sys
   bad=[m.group(1) for l in open([f for f in __import__('os').listdir('.') if f.endswith('.mf')][0])
        for m in [re.match(r'SHA256\((.+)\)= ([0-9a-f]{64})', l.strip())] if m and hashlib.sha256(open(m.group(1),'rb').read()).hexdigest()!=m.group(2)]
   sys.exit('mf mismatch: '+','.join(bad) if bad else print('mf ok'))") && rm -rf x
   ```
   Re-hashing the actual OVA bytes at download time also gives ASTRA the independent OVA hash it has not yet taken (its ruling: "ASTRA did not download/mount/hash the ~2 GB OVA").
5. **Seal:** store the ZIP (not re-packed) encrypted in the existing custody store, plus a custody manifest. Keep the evidence ZIPs not yet held (12760932320, 12757059994) in the same bundle.
   - **Manifest contents:** artifact ID, run 40555901182, ZIP bytes and SHA-256, OVA SHA-256, `.mf` result, holder, location label, UTC time, and the verifier's identity.
6. **Second verification:** the owner (or a second person) re-checks the two SHA-256 values against the manifest and this file. Publish only the manifest's hashes and timestamp on #1528.
7. **Use:** this sealed copy is also the ESXi import source (O2). No further copy is kept.
8. **Leave the GitHub artifact alone.** It expires by itself on 2026-11-10. **Do not delete it early** (O10, separate decision).

**Re-verify on every use:** before import, re-run step 4 against the custody copy. A custody copy is trusted only by its hash, never by its location.

## 3. Alternatives considered (not recommended)

| Option | Why not |
|---|---|
| Workflow job that re-uploads the OVA with a longer retention | Creates **another public** copy; GitHub's maximum is 90 days anyway; changes nothing about access |
| Private repository release asset, or new private object storage | New hosting location and access grants for an unsigned candidate; more access change than needed; the owner would also have to administer it |
| Do nothing and rebuild later if needed | A rebuild is a new artifact: identity, scans, QEMU and ESXi would all restart. This contradicts "finish qualification of this exact appliance". |

## 4. Access, deliberately unchanged

- **Not proposed:** shortening public availability (deleting the artifact before expiry) or making the repository private. Both are irreversible or broad access changes and need their own owner decision (O10).
- **Impact if left as is:** the OVA stays publicly downloadable until 2026-11-10. It holds no secrets: the setup token, CA and log passphrases are minted at first boot, not baked in.
