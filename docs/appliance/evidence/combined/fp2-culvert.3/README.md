# F-P2 isolated — ClamAV sidecar culvert.3 (owner decision 6387402372 §1)

- **Run:** Appliance Lab 40117446508, `test/appliance-lab` @ `11036032dd334293e1b0cc9aa0f85613d6681cab`, `[fp2-isolated]` only.
- **Artifacts:** both are copied here verbatim, unzipped, and their zips hash to the API digests.
  - `12570451604`, zip sha256 `3ccae8c70cd00b68028fb73083cbbbd77bd1f14eb3f5839f9dd3624d4d375358` (candidate)
  - `12569276879`, zip sha256 `813bb68770bcb142e761c94a036f3bed67aef7dba82771321569fb862c3c1a36` (control)
- **Tested identity:**
  - image ID `sha256:4c365e4047f948e909bfda5a7d5bf06408f2fab68e59fc513c71681ccec65ebc` (both builds gave the same manifest);
  - built from `appliance/clamav/Dockerfile` sha256 `dccebff1c328b80d6134e5160c00f763e40c1cc72a26009a389a8d859174afc7` @ `52463785`, with `SOURCE_DATE_EPOCH=1792855424`;
  - baked-form archive `clamav.tar.gz` sha256 `ce011ffc6c1a2cfa5496156a44efac27c977e0fcaf38786362be9c02fce4d059`.
- **Result:**

  | | wrong cleans (EICAR → bare OK) | requests | EICAR sent at ≤ 64 KiB temp free | no-pressure control |
  |---|---|---|---|---|
  | candidate `culvert.3` | **0** | 1672 | 520 | 100/100 FOUND, 100/100 clean OK |
  | control 1.4.6 (upstream `57deb108`) | **56** | 1672 | 520 | 100/100 FOUND, 100/100 clean OK |

- **OVA binding:** an OVA is covered by this evidence only if it bakes image ID `sha256:4c365e40…`, which needs `build-ova.sh` run with `SOURCE_DATE_EPOCH=1792855424`. Any other ID means F-P2 reruns on those bytes.
- **Limits:**
  - The control is the upstream 1.4.6 image: the old derivative's OVA artifact `11666266481` expired (410).
  - One run is samples, not proof that the defect cannot occur.
  - ASTRA reviews this independently; this file is producer evidence only.
- Full write-up: #1528 comment 6387817964.
