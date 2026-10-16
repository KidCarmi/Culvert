# Candidate 6aa900cd — equivalence + requalification decision (F-P2 fix)

**Candidate source:** `6aa900cdbb964f8b79c4eaba8fad62148e4a0322` (PR #1528 head).
**Prior qualified candidate:** `bad788e54ffef2a2f8490ba27ebfe027a2a6eb11`.
**Change:** owner-approved ClamAV sidecar engine bump 1.4.6 → 1.5.4, closing
F-P2 (the detection bypass reported to Cisco PSIRT as PSIRT-0035161972).

## Candidate ↔ PR head

`candidate-6aa900cd-equivalence-pr1528head.md`: **0 files differ** between the
candidate and PR #1528's head. The candidate IS the PR head, so the qualified
bytes correspond to the exact source under review — no "the PR moved on" gap.
(Re-run whenever the PR head advances; the record is the identity only while
the head stays at 6aa900cd.)

## Why a full rebuild + requalification, not an equivalence claim

`candidate-6aa900cd-delta-from-bad788e5.md`: 54 files differ from the prior
qualified candidate; **4 are build inputs**, and all four are the sidecar
engine bump itself:

| file | why it ships |
|---|---|
| `appliance/clamav/Dockerfile` | the sidecar derivative — FROM digest now the official 1.5.4 image |
| `appliance/build/manifest.env` | CLAMAV_IMAGE_* digests + CLAMAV_SIDECAR_REF `culvert/clamav:1.5.4-culvert.1` |
| `docker-compose.yml` | sidecar `image:` tag baked into the OVA |
| `docker-compose.ha.yml` | same sidecar tag on the HA compose baked into the OVA |

Because shipped build inputs changed, the prior OVA's qualification does NOT
carry over (`candidate-equivalence.py` exits 1). This candidate is therefore
built and qualified from scratch rather than certified by equivalence:

- build the candidate OVA from 6aa900cd using that head's own Deep PR Gate
  image (run 38873584208, tar `ede6e067…`, image id `sha256:11fc13cd…` — all
  three verified against the artifact before the build), then
  preflight → up → qualify → recovery → history (lab guest-boot);
- `[cache-bypass]`: re-prove the 60s clean-verdict quarantine on the 1.5.4
  engine against this build's retained OVA;
- `[fp2-isolated]`: re-run the F-P2 reproduction against this build's baked
  1.5.4 sidecar — must deliver 0, where the 1.4.6 sidecar delivered > 0;
- exact-byte Trivy scan of the sidecar archive extracted from this OVA;
- ASTRA ESXi handoff under the NEW candidate identity (recovery/reboot timing
  is re-measured on the new OVA; the sidecar engine bump does not touch the
  restore/recovery path, but the handoff carries the new identity regardless).

## Byte-identity caveat (owner note)

`candidate-equivalence.py` proves only that a rebuild would consume the same
SOURCE inputs; it is not a byte-identity claim (the Go build stamps the VCS
revision, the OVA name carries the commit, and the image/OVA builds fetch
external content — GeoLite, apt — at build time). "Only the embedded commit
stamp changes" is NOT proof a future rebuild is byte-identical. The qualified
OVA is evidence for its own sha256 only; a release must ship those exact bytes
or requalify the rebuild.

## Trigger note (lab mechanics)

The guest-boot build runs only when the push's HEAD COMMIT MESSAGE contains
no bracketed job tag — the workflow's `contains()` matches a tag anywhere in
the message, body included. A first attempt put the words cache-bypass and
fp2-isolated (in brackets) in the body; that matched the fp2-isolated job's
gate and disabled guest-boot, so run 38878259116 re-ran the 1.4.6 isolated
control instead of building the candidate. The build is re-triggered with a
bracket-free message. The Phase 2 scanner legs are launched by their own
single-tag pushes once this build records the new OVA artifact id + baked
sidecar digest.
