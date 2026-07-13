# Culvert Edge-Case Lab — Evidence Retention & Sanitization (R6)

## Principle
Raw successful-run evidence is **not** committed to git. The repository keeps only small, stable,
source-of-truth artifacts; full runtime evidence lives as CI artifacts / release attachments.

## What stays IN git

| Artifact | Path | Why |
|---|---|---|
| Scenario schema | `EDGE-CASE-SCENARIO-SCHEMA.json` | contract, stable |
| Canonical behavior registry | `EDGE-CASE-CANONICAL-BEHAVIORS.json` | coverage baseline (49 behaviors) |
| Scenario→behavior mapping | `EDGE-CASE-SCENARIO-MAPPING.json` | traceability + quarantine status |
| Aggregated summaries | `reports/*.json` (results summary, canonical-summary, uniqueness, mutation-gate) | counts only, change rarely |
| Deterministic fixtures | `fixtures/origin_server.py`, `fixtures/certs/*.crt` | reproducibility (cert only, **no private key** committed) |
| Representative reproductions | `representative_evidence/` | a few sanitized confirmed-finding manifests |
| Harness + docs | `harness/**`, `EDGE-CASE-*.md` | the lab itself |

## What is REMOVED from git (regenerated each run)

`edge-case-lab/evidence/` (645 raw files/run) and `edge-case-lab/scenarios/` (215 per-run
manifests) are now **git-ignored** and were removed from the index (`git rm --cached`, kept on
disk). Also ignored: `reports/mutation-raw.jsonl`, `/tmp/culvert.log`. This removed ~13 MB / 861
files of per-run churn from the branch.

## CI artifact retention

| Tier | Evidence | Retention |
|---|---|---|
| PR smoke | pass/fail summary only (no raw evidence) | 14 days |
| Nightly canonical | per-behavior results + any non-PASS manifests | 30 days |
| Full campaign | complete `evidence/` + manifests bundle (`.tar.gz`) | 90 days |
| Release certification | immutable summary + full evidence bundle, **attached to the GitHub Release** | permanent (release asset) |
| Confirmed security findings | minimal sanitized reproduction (`representative_evidence/` + `repro_one.py`) committed | permanent |

## Sanitization gate (`harness/sanitize_check.py`)

Runs before any commit of representative evidence and before any CI artifact upload. Fails the step
(exit 1) if it finds, outside allow-listed empty/redacted forms:
- `Authorization: Basic|Bearer …` headers and inline Basic credential blobs
- `Cookie` / `Set-Cookie` / `ps_ui_session` / `SessionHMAC` session material
- `-----BEGIN … PRIVATE KEY-----`
- the lab's own credentials/passphrases (`LabPass123!`, `labtest123`)
- generic `"password"/"secret"/"token"/"api_key": "<value>"` pairs

Verified: `sanitize_check.py edge-case-lab/scenarios edge-case-lab/evidence` → **OK, no secrets**
(the admin-API logs record request bodies/paths/status, not `Authorization` headers; the
configured-mode setup password is sent via a non-logged path). The fixture **private key**
(`fixtures/certs/fixture.key`) is git-ignored and never committed.

## Operational notes
- `git status` after a run is clean except the committed summary JSON (raw evidence is ignored).
- To publish evidence from CI: `tar czf evidence.tgz edge-case-lab/evidence edge-case-lab/scenarios`
  **after** `sanitize_check.py` passes, then upload as an artifact — never `git add` it.
- `representative_evidence/` is refreshed only when a confirmed finding changes; each file is
  sanitized before commit.
