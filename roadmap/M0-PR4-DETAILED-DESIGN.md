# M0-PR4 — Legacy update-path retirement (default-off) — Detailed Design (v1)

**Milestone:** M0 (Foundation & Safety) — PR 4 of 5.
**Single objective:** make the legacy **unauthenticated GitHub-tags** update fallback
(`checkGitHubLatestTag`) **off by default**, behind a read-once break-glass env
`CULVERT_LEGACY_GH_TAG_CHECK`, so a private-repo build makes **no unauthenticated
GitHub API call** on the update path (no private-repo 404 brick). The code is
**retained** for the compat window; a loud one-line startup log states the mode.

Authority: `roadmap/M0-DETAILED-DESIGN.md` §4.5 (E5) + §6/§7. Independent of PR3
(CI surface) and PR5 (IaC/docs). No production Go behavior changes beyond gating this
one fallback off by default.

## 1. Scope

| In scope | Out of scope |
|---|---|
| Gate the `checkGitHubLatestTag` fallback in `checkUpdateNow` (update.go) behind read-once `CULVERT_LEGACY_GH_TAG_CHECK` (default OFF) | Removing `checkGitHubLatestTag` (kept for the compat window) |
| Pure resolver `resolveLegacyGhTagCheck` + loud one-line startup note | `saasfeed`/`install.sh` raw GitHub fetches (**M2**, per §4.5) |
| Extract a unit-testable fallback helper + a dial seam; tests | Any R2 / repo-private / IaC work |

## 2. Repository evidence

- `checkUpdateNow` (`update.go:357`) decodes the updater's `/api/update/check`
  result, then at **`update.go:404-419`** unconditionally calls
  `checkGitHubLatestTag()` when the registry reports no newer version. That function
  (`update.go:309`) does an **unauthenticated** `GET https://api.github.com/repos/
  KidCarmi/Culvert/tags` — which, once the repo is private (M2), returns 404 and (per
  §4.5) can brick the update-visibility path for a public/misconfigured token.
- The canonical read-once break-glass pattern is `resolveCatalogVerifyMode`
  (`release_wiring.go:166`): a **pure** resolver returning the value **plus a loud
  one-line note** the caller logs at startup. This PR mirrors it exactly.
- `startUpdateChecker` (`update.go:195`) is the single startup entry (wired from
  `background_services_startup.go:48`) — the place to emit the mode note once.
- `checkGitHubLatestTag` has **no client seam** (uses `http.DefaultClient`), so the
  test is at the caller (TEST-M4).

## 3. Design

### 3.1 Read-once resolver (mirrors `resolveCatalogVerifyMode`)

```go
// resolveLegacyGhTagCheck decides whether the legacy unauthenticated GitHub-tags
// update fallback runs. DEFAULT OFF: no GitHub API call on the update path, so a
// private-repo build cannot 404-brick here. Returns the decision + a loud one-line
// note to log once at startup. Enabled ONLY by an explicit truthy env value —
// break-glass for the compat window.
func resolveLegacyGhTagCheck(v string) (enabled bool, note string)
```

- truthy (`1`/`true`/`yes`/`on`, case/space-insensitive) → `(true, "…ENABLED via
  CULVERT_LEGACY_GH_TAG_CHECK (compat window; makes an unauthenticated GitHub API
  call)…")`.
- anything else incl. unset/typo → `(false, "…DISABLED (default); no unauthenticated
  GitHub API call; set CULVERT_LEGACY_GH_TAG_CHECK=true to re-enable during the compat
  window")`. A typo never silently enables (fail-safe toward OFF).

Read once into a package var: `var legacyGhTagCheck, legacyGhTagCheckNote =
resolveLegacyGhTagCheck(os.Getenv(envLegacyGhTagCheck))`. `startUpdateChecker` logs
`legacyGhTagCheckNote` once (guarded `if logger != nil`) before the first check.

### 3.2 Gated, unit-testable fallback helper (TEST-M4)

Extract the `update.go:404-419` block so the caller path is testable without a live
updater, and add a **dial seam** so a test can assert **no GitHub call** when off:

```go
// checkGitHubLatestTagFn is the dial seam (default = the real call); tests replace
// it with a counting spy to prove the default build never dials GitHub.
var checkGitHubLatestTagFn = checkGitHubLatestTag

// maybeGitHubTagFallback consults the legacy gate and only then dials GitHub. It
// returns the (possibly updated) latest/available and whether the fallback fired.
func maybeGitHubTagFallback(curLatest string, curAvailable bool, cleanVer string) (latest string, available, used bool) {
	latest, available = curLatest, curAvailable
	if curAvailable || cleanVer == "dev" || !legacyGhTagCheck {
		return latest, available, false // no dial
	}
	if gh := checkGitHubLatestTagFn(); gh != "" && semverGreater(gh, cleanVer) {
		return gh, true, true
	}
	return latest, available, false
}
```

`checkUpdateNow` replaces the inline block with a call to the helper and logs the
existing "Docker registry had no newer semver tag, but GitHub has …" line only when
`used` is true. Behavior when the gate is ON is **byte-identical** to today.

### 3.3 Behavior-change note (REL-M4)

The fallback also papered over a Docker-registry-vs-git-tag semver gap for **public**
users (the v0.0.16–v0.0.19 CI issue in the code comment). Default-off may reduce
update *visibility* for that narrow case. This is documented in an `update.go`
comment + the PR body; the authoritative fix is the R2/catalog path (M1+), and the
break-glass env restores the old behavior meanwhile. `saasfeed`/`install.sh` raw
fetches are **M2**.

### 3.4 GUI parity

`CULVERT_LEGACY_GH_TAG_CHECK` is an **env-only, read-once break-glass** compat flag
for a temporary window — GUI-parity deferral, matching the established
`CULVERT_RELEASE_*` precedent (env-only, documented). No admin API/UI surface.

## 4. Failure / behavior matrix

| Condition | Behavior |
|---|---|
| env unset (default) | fallback OFF; no GitHub dial; loud one-line startup log |
| env truthy | fallback ON (byte-identical to today); startup log states ENABLED |
| env typo/garbage | OFF (fail-safe); startup log states DISABLED |
| registry already reports update, or `dev` build | fallback short-circuits (no dial) regardless of gate |

## 5. Test strategy

- `TestResolveLegacyGhTagCheck` — table: unset→off, `true/1/yes/on/ TRUE `→on,
  `false/no/0/garbage`→off; note non-empty and mentions the env var in both modes.
- `TestMaybeGitHubTagFallback_DefaultNoDial` — gate off ⇒ `used=false` AND the dial
  seam counter stays **0** (proves no unauthenticated GitHub call by default).
- `TestMaybeGitHubTagFallback_EnabledUsesGitHub` — gate on + spy returns a higher
  tag ⇒ `used=true`, latest/available updated.
- `TestMaybeGitHubTagFallback_ShortCircuits` — registry already has an update, and
  `dev` build ⇒ no dial even when the gate is on.
- Regression: `update_test.go` stays green; `go test ./...`, `-race` on update
  surface, `go vet`, `gofmt`.

## 6. Rollback

Revert the commit → the inline fallback returns (default-on). Fully additive/local;
`checkGitHubLatestTag` is untouched. The env restores old behavior without a rebuild.

## 7. Open questions for planning review

1. Startup-note placement — `startUpdateChecker` (chosen) vs an init/startup slice.
2. Should the "reduced visibility" behavior-change also emit a runtime hint when the
   registry reports no update AND the gate is off (vs. the single startup note only)?
3. Truthy-set — is `1/true/yes/on` the right accept-set (matches `CULVERT_C2_ENFORCE`
   negation semantics inverted)? Anything else must stay OFF.

## 8. Planning-review findings & resolutions

Two independent planning reviews (correctness/testability; behavior/scope). Both
**approve-with-fixes**; all resolved in the implementation:

| Finding | Sev | Resolution |
|---|---|---|
| Package-var `= resolve(os.Getenv())` freezes at package-LOAD, before any test runs ⇒ env→gate wiring untestable | **HIGH** | Resolver stays pure; the env is read at STARTUP via `applyLegacyGhTagCheckEnv(getenv)` (called from `startUpdateChecker`), with `getenv` injected as a test seam. `TestApplyLegacyGhTagCheckEnv` drives it. |
| Test mutation of `legacyGhTagCheck`/`checkGitHubLatestTagFn` leaks across `-count=2 -shuffle=on` | **HIGH** | Every mutating test save/restores via `t.Cleanup` (`withFallbackSpy` helper) and none call `t.Parallel`. |
| Spy-at-helper proves "no dial" only if extraction is total | MED | Added `TestCheckUpdateNow_NoDirectGitHubCall` source-scan: `checkUpdateNow` body has no `checkGitHubLatestTag(` / `api.github.com`, only `maybeGitHubTagFallback`. |
| Must preserve `used → pullTag="latest"` wiring (not just the log line) | MED | `checkUpdateNow` sets `ghFallback = used` and keeps `if ghFallback { pullTag = "latest" }`; the ON path is byte-identical. |
| Discoverability: an operator who stops seeing updates has only a boot log | MED | Gate state surfaced in `/api/update/status` (`legacy_gh_tag_check`); env added to CLAUDE.md; a one-shot runtime hint fires when the disabled fallback could have mattered. |
| "Reduced visibility" overstated — registry path untouched + ci.yml now publishes semver image tags | LOW | Code comment + PR body now state the Docker-registry check remains the live path; default-off covers only a CI-regression edge case. |
| Objective is the runtime update path, not install scripts (`internal/bootstrap` still curls api.github.com) | LOW | Scoped explicitly in CLAUDE.md + the PR body; install-script fetches are M2. |
| Truthy accept-set / concurrency / retain-posture / rollback | LOW/confirm | `1/true/yes/on` (fail-safe OFF otherwise); write-once-at-startup read is race-free; retain+break-glass and rollback confirmed sound. |
