# Release-Catalog Weekly Re-sign — Operator Runbook (M1-4)

The served catalog carries a 180-day freshness window (`expires_at`). With no
releases, the window would lapse and every enforce-mode appliance would degrade
to `available:false`. The weekly re-sign keeps the window sliding without
changing WHAT is released: same `catalog_version`, same `created_at`,
byte-identical manifests — only `generated_at`/`expires_at` move.

## ⚠ Hard activation precondition (owner action — SEC-F7)

Before relying on the weekly cron, the **`v-tag-protection` ruleset MUST
restrict tag CREATION** (`creation=true`) with `bypass_actors` set to the
GitHub Actions bot. Once a tag dispatch is a signing event, an attacker who can
create a `v*` tag can mint a signing context; the ruleset is the backstop.
This cannot be enforced from inside the repository — confirm it in
Settings → Rules before the first production re-sign.

### Enabling the tag-creation restriction without breaking releases (RELEASE_TAG_PAT)

The `auto-tag` job (`ci.yml`) creates each `v*` release tag by pushing as
`github-actions[bot]`, which **Restrict creations blocks** — and a
repository-level ruleset cannot add the Actions bot as a bypass actor. So the
job pushes the tag authenticated as **`RELEASE_TAG_PAT`** instead: a
fine-grained PAT (single-repo, `Contents: read and write`) owned by a
Repository-admin, stored as an Actions secret. Do this IN ORDER so releases
never break:

1. Create the fine-grained PAT (owner = the repo admin; repo = this repo only;
   `Contents: read and write`) and add it as the repo secret `RELEASE_TAG_PAT`.
2. Merge the `ci.yml` change that pushes the tag with that PAT (already wired;
   `auto-tag` fails loudly if the secret is missing). Restrict creations is
   still OFF here, so nothing is blocked yet.
3. In the ruleset: **Bypass list → Add bypass → Repository admin** (Always
   allow), then tick **Restrict creations**, Save.

Validate: the next merge to `main` auto-tags fine (the PAT owner bypasses); a
manual `git tag v9.9.9 && git push origin v9.9.9` from a normal clone is
rejected. If the PAT expires it silently breaks releases — the `auto-tag`
preflight then fails with a clear message; rotate the secret. (A GitHub App
installation token is the no-expiry upgrade if you prefer.)

**First production run — one-time verification:** the scheduler locates each
dispatched run via `gh run list --branch <ref>`; for the ci.yml dispatch the
ref is the TAG. Confirm on the first run that the scheduler finds and watches
the ci.yml run (its log prints `watching ci.yml run <id>`). A mismatch is
fail-closed (FATAL after the bounded wait), not silent — but fix it before
relying on the unattended weekly cron.

The appliance-side backstop for same-version replays is the SEC-F4
`(catalog_version, generated_at)` ratchet in `release_catalog_state.json` —
shipped with this milestone; no operator action needed (legacy state files
migrate on the first post-upgrade install).

## The weekly flow (all automatic)

| When (UTC, Mon) | What | Where |
| --- | --- | --- |
| 03:00 | `resign-catalog.yml` resolves the latest `v*` tag and dispatches `ci.yml` at that tag with `resign=true`; polls to success (fail-closed) | scheduler (signs nothing; `actions:write` only) |
| — | `catalog-resign` job: latest-tag assert (SEC-F2a) → download the ORIGINAL bundle by exact name → **verify it through the baked root + pinned identity BEFORE reading anything** (SEC-F1, in the gate binary) → rebuild (same version/created_at, +180d window) → keyless sign → end-to-end verify → prune superseded `-r*` assets → attach `culvert-release-catalog-<tag>-rYYYYMMDD.tar.gz` | ci.yml at the tag ref |
| — | R2 publish (resign input): stage to the NEW `history/stable/<tag>-rYYYYMMDD/` prefix → staged-bytes verify → **monotonic live binding** (SEC-F2b: staged `catalog_version` ≥ live; equality ⇒ identical entries + strictly newer `generated_at`) → promote → purge → confirm | publish-catalog-r2.yml |
| — | Pages publish (same tag; picks the newest resign bundle) + dual-origin verify | publish-catalog-pages.yml, verify-dual-publish.yml |
| 09:00 | **Freshness canary** (SEC-F5): live `generated_at` age must be ≤ 14d, else RED | verify-dual-publish.yml (cron) |

## What failure looks like / what to do

- **Scheduler run RED** — a dispatch, poll, or downstream run failed or timed
  out. The live catalog is UNTOUCHED (every step fails closed). Re-run the
  scheduler manually (`Actions → Re-sign Release Catalog → Run workflow`); the
  flow is idempotent (same-day re-run reuses the `-rYYYYMMDD` name, `--clobber`).
- **Canary RED (age > 14d)** — the re-sign has been failing silently for ≥2
  weeks. Investigate the scheduler runs; you have until the appliance-side
  `release_catalog_stale` alert (30d remaining) plus the rest of the 180-day
  window before customers degrade.
- **Appliance `release_catalog_stale` alert** — the last-line backstop (~4-5
  weekly retries left). Same investigation; a manual scheduler run is the fix.
- **Never** hand-edit or re-upload catalog assets: the original release asset is
  immutable by contract, and every publish path verifies signatures before
  promoting — an unsigned or foreign-signed bundle cannot go live.

## Manual re-sign (break-glass)

1. `Actions → CI → Run workflow` → select the LATEST `v*` tag → check `resign`.
   (A bare tag dispatch without `resign` fails by design; an old tag fails the
   latest-tag assert.)
2. After it's green: `Actions → Publish Release Catalog (R2) → Run workflow`
   with `tag` and the exact `resign_asset` name from the release's assets.
3. Same for Pages (`tag` only), then dispatch `Verify Dual Publish`.
