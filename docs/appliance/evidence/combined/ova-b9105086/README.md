# Internal OVA from frozen b9105086: identity chain + qualification

**Unsigned candidate, internal evaluation only.**
- Owner decisions 6387402372 + 6389524853 allow ONE internal OVA plus non-destructive QEMU checks.
- ASTRA SOURCE-INTEGRATION PASS for b9105086 / tree b6b80fc5: 2026-10-24 21:55Z.
- Confirmed in session before dispatch.

No ESXi operation, merge, pilot or release.

## 1. Identity chain (source → image → OVA)

| hop | identity | evidence |
|---|---|---|
| frozen source | commit `b910508629e9d80352067bc8ec608753ddf0924e`, tree `b6b80fc5628b14c3489b20d970f5c81f038c087f` | `../freeze-b9105086/` |
| CI build of the app image | Deep PR Gate run 40133521510, job 120990134925. It checked out synthetic merge `76856bd8`, **tree `b6b80fc5`** (= frozen). VERSION build-arg `v1.0.327-candidate.gb910508629e9` | `../freeze-b9105086/ci-job-checkouts.tsv` + the archived job log |
| image artifact | `deep-gate-image` id 12576270570, zip sha256 `bdc56bf4…c940`, `culvert-image.tar` sha256 `1db620abbf4fe34424749e64a4e8b96861a945a201583ab386d47926cd7ec7fb` | re-hashed locally from the downloaded artifact |
| image identity | manifest digest (the running `.Id` in the containerd store) `sha256:ca27cf9a645431ed77255efa0897daabb63bbed9c6b4acd6ac574820422d186c`; config blob `sha256:75dd735cebbfe312e7f15c2e86f82bf66493853d707c6d2b3d664e03f6e47779` | `index.json` / `manifest.json` of the tar |
| OVA build | lab run 40185226897 (lab commit `735f1a24`). Provisioning checkout = `b9105086` (`git_dirty: false`, `provisioning_drift: false`). `SOURCE_DATE_EPOCH=1792855424`. Baked `install.sh` sha256 `d5f3cff0…a69f6a` = `git show b9105086:scripts/install.sh` | `qualify/build-info.json` |
| identity gate (stops before boot) | app index digest `ca27cf9a…`, ClamAV sidecar `sha256:4c365e4047f948e909bfda5a7d5bf06408f2fab68e59fc513c71681ccec65ebc` (the F-P2-tested image), sidecar archive `ce011ffc6c1a2cfa5496156a44efac27c977e0fcaf38786362be9c02fce4d059` (recorded and on disk): **all equal** | `identity-gate-output.txt` |
| OVA | `culvert-appliance-1.0.327-candidate.gb910508629e9-ubuntu-24.04.ova` sha256 **`61c46d6db6603d76edbb0d64327bed85e76bea86d24457e9f3ae36e71bd5854a`**, artifact `appliance-lab-ova-candidate-b9105086` id 12595618495 (retained until 2026-11-08) | `qualify/*.ova.sha256` |
| running guest | after every reboot the container runs `ca27cf9a…`; agent and proxy both `v1.0.327-candidate.gb910508629e9` | `qualify/checks.jsonl` steps 6/8 |

**Correction to the BOM** (`../freeze-b9105086/BOM.md` §1): it said the app image "must carry revision `b9105086…`". The CI image carries **no labels at all**. Its source binding is the four facts above:
- the CI build log's checkout tree;
- the tar sha256;
- the manifest/config digests;
- the VERSION stamp, which build-ova.sh's candidate guard checks against the provisioning HEAD.

## 2. Results

Raw artifacts are archived as `raw.tar.gz` per job. The downloaded zips matched GitHub's recorded artifact digests:
- qualify `47a4d9a9…`
- F-DISK `fca3ebb0…`
- boot-console `7e9c129a…`

| job | verdict | counts |
|---|---|---|
| QEMU qualify, run 40185226897 | 1 harness defect, below | 112 checks: 104 pass, 6 info, 1 blocked, 1 fail |
| F-DISK-1, run 40185226897 | PASS | 25 checks: 23 pass, 1 SURVIVED (the known failure did NOT reproduce), 1 info |
| boot console, run 40189552918 (retained OVA, no rebuild) | PASS | 30 checks: 24 pass, 6 info |

- **The 1 fail is a defect in the new harness step 6d, not the appliance.** `POST /api/support/bundles/{id}/approve` answers **204** on success, and the check wanted 200. Step 8 proves the approval took effect: `support-persisted` passes, with the bundle listed after the reboot as `state=ready`, `case=lab-persist`. The harness now accepts any 2xx (lab commit `521fe5c2`). The qualification was **not** re-run for this: the effect is already proven and only one build is authorized.
- **The 1 blocked** is the standing IdP limitation: `4b portal-cookie-replay` needs an identity provider, and none exists in this lab.
- **New checks for this candidate:**
  - `8 ca-encrypted-at-rest`: `/data/ca.bundle` begins with `PSCA`, contains no PEM private key, and `.env` has a non-empty `CULVERT_CA_PASSPHRASE`. This exercises main's `secret_already_set` fix on a real first boot.
  - `8 support-persisted`: the bundle survives the reboot.
- **Recovery:** three maintenance reboots recovered in 36.8 s, 41.5 s and 41.6 s (budget 60 s).
- **Boot console:**
  - healthy splash control;
  - the live splash names a failed unit;
  - Esc is one-way;
  - tty1 stays text after the splash;
  - no splash without a display;
  - the console banner and Build line name the booted OVA's version.
- **Not repeated:** F-P2. The baked sidecar is byte-identical to the tested `4c365e40`.
