# Recommended GitHub Repository Settings (documentation only)

**These are recommendations to apply by hand.** Per the migration constraints,
this migration does **not** change any GitHub repository settings automatically,
and does **not** enable or disable any paid GitHub feature. Nothing below has been
applied — treat this as a checklist for the repository owner.

Applies to the two new repositories `KidCarmi/tac-platform` and
`KidCarmi/tac-infrastructure` (and, where noted, confirms the existing
`KidCarmi/Culvert` posture — no change requested).

---

## 1. Branch protection (default branch `main`)

| Setting | Recommended | Rationale |
|---|---|---|
| Require a pull request before merging | **on** | no direct pushes to `main` |
| Required approvals | **≥ 1** (owner review) | second set of eyes |
| Dismiss stale approvals on new commits | **on** | re-review after changes |
| Require review from Code Owners | **on** | `CODEOWNERS` (`* @KidCarmi`) is honoured |
| Require status checks to pass | **on** | see §2 |
| Require branches up to date before merge | **on** | test against the target tip |
| Require conversation resolution | **on** | no unresolved review threads |
| Require linear history | **on** | matches the squash/rebase merge strategy (§5) |
| Require signed commits | **on** (see §6) | provenance |
| Include administrators | **on** | rules apply to the owner too |
| Restrict force pushes / deletions | **on** | protect history |

## 2. Required status checks

- **tac-platform:** the `ci.yml` job that runs `go vet` + `go build ./...` +
  `go test -race -count=1 ./...` against PostgreSQL. Mark it required once it has
  reported at least once.
- **tac-infrastructure:** the `ci.yml` job that runs `tofu fmt -check` +
  `validate` + the `no-mutable-tags` guard.
- Do **not** mark the scheduled cross-repo compatibility lane as a required PR
  check (it is intentionally off the per-PR critical path — see `CROSS-REPO-CI.md`).

## 3. Secret scanning & push protection (GitHub Advanced Security / free for public repos)

| Setting | Recommended |
|---|---|
| Secret scanning | **on** |
| Push protection (block commits containing secrets) | **on** |
| Dependency graph | **on** |
| Dependabot alerts | **on** |
| Dependabot security updates | **on** |

> Availability depends on repo visibility/plan. **Do not enable a paid feature on
> the owner's behalf** — this row is a recommendation to review in repo settings.

## 4. Dependabot (version updates)

- Both repos ship `.github/dependabot.yml` (weekly). tac-platform covers Go
  modules + GitHub Actions; tac-infrastructure covers GitHub Actions (+ Terraform
  once a real provider is added). Confirm Dependabot is enabled in **Settings →
  Code security**.

## 5. Merge strategy

- **Squash-merge only** (disable merge commits and rebase-merge), matching the
  "require linear history" rule. Keeps `main` a clean, one-commit-per-change log.
- **Auto-delete head branches** after merge: **on**.

## 6. Signed commits / verified provenance

- Enable **Require signed commits** on `main` (§1). Contributors sign with GPG,
  SSH, or S/MIME so commits show **Verified**.
- **tac-platform release provenance:** when release CI is added, publish images
  **by digest** with an SBOM and (recommended) cosign/SLSA provenance — mirroring
  Culvert's existing signed-release posture. The infra repo already consumes
  **digests only**.

## 7. Environments & deployment approvals (tac-infrastructure)

- Define a GitHub **Environment** per deployment target (e.g. `staging`) with a
  **required reviewer** (owner) so any future deploy workflow pauses for manual
  approval.
- Keep deploy workflows **manual/`workflow_dispatch`** — no push-to-deploy. (This
  migration deploys nothing and connects no model to a mutation tool.)

## 8. Actions permissions

| Setting | Recommended |
|---|---|
| Actions allowed | this repo + verified/marketplace actions you pin by SHA |
| Default `GITHUB_TOKEN` permissions | **read-only**, elevate per-job as needed |
| Allow Actions to create/approve PRs | **off** unless required |
| Fork PR workflows | require approval before running |

CI workflows in both repos already request least-privilege token scopes; keep the
repo default read-only.

## 9. Release permissions

- Restrict who can publish releases/tags to the owner (or a protected tag
  ruleset). Mirror Culvert's tag-protection posture (`v-tag-protection`-style
  ruleset restricting tag creation) once tac-platform starts cutting `v*` tags.

## 10. CODEOWNERS

- Both repos include `CODEOWNERS` (`* @KidCarmi`). Combined with "Require review
  from Code Owners" (§1) this makes owner review mandatory on every path.

---

### Not changed by this migration
No branch protection, status check, secret-scanning, Dependabot, signing,
environment, Actions, or release setting was modified programmatically. No paid
feature was toggled. Apply the above manually in each repo's **Settings**.
