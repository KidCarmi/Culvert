# ADR-0050: The embedded frontend artifact validator is owned by internal/frontendbundle

- Status: Proposed for review with the implementation PR (IM-017, 2026-11-20).
- Numbering: ADR-0047 is the highest merged. ADR-0040 is reserved by open
  PR #1526, ADR-0048 by open PR #1965 (IM-013) and ADR-0049 by open PR #1966
  (IM-015). No other open PR adds a file under `docs/adr/` (checked against
  every open PR head on 2026-11-20).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-017.
  Related: ADR-0002 (lists `ui_*.go` as main-owned), ADR-FE-001 (frontend
  platform), ADR-0042..0049.

## Context

`ui_frontend_v2.go` (727 lines, package main) held two responsibilities:

1. **A validator.** `validateFrontendV2(dist fs.FS)` and 17 helpers, about 450
   lines: the Vite manifest decode with a duplicate-key pre-scan, the
   asset-path trust boundary (relative, canonical, under `assets/`, allowlisted
   extension, content-hash suffix, conservative alphabet), the import-graph
   check, the exact manifest/tree cross-check, and the shell-to-manifest
   binding. It read only the `fs.FS` it was handed. Its two root references
   were `sanitizeLog` (manifest strings quoted in error text) and the
   `frontendV2MIME` table, which only the validator read.
2. **Composition and serving.** The `//go:embed all:frontend/dist` artifact,
   the `CULVERT_EXPERIMENTAL_UI` gate, the resolved-once
   `atomic.Pointer[frontendV2State]`, the three routes, the response headers
   (route-scoped CSP, cache policy), the 503 degradation and the `/ready` row.

The validator is a security decision ("is this tree safe to serve, and which
files"), and it could only be tested by compiling the whole application.

ADR-0002 lists `ui_*.go` as main-owned. That holds for (2): routes, handlers
and published state are composition. It does not describe (1), which has no
route, no state and no caller other than `resolveFrontendV2`. This ADR narrows
ADR-0002 for this file only and does not supersede it.

## Decision

Move (1) to `internal/frontendbundle` with three exported identifiers:
`Validate(dist fs.FS) (shell []byte, assets map[string]Asset, err error)`,
`Asset` (`ContentType`, `Size`) and `ManifestEntry`. Keep (2) in main.

- Root keeps `validateFrontendV2` as a one-line binding and
  `frontendV2Asset` as an alias of `frontendbundle.Asset`, so the caller
  (`resolveFrontendV2`), the handlers and the remaining root tests are
  unchanged apart from one field spelling (`asset.ContentType`).
- The MIME table becomes `contentTypeFor`, a switch, so the package has no
  mutable table. Its values are pinned against a frozen copy of the root map.
- Manifest strings quoted in error text are sanitized with `obs.Sanitize`,
  the internal owner's CWE-117 barrier, whose algorithm is the same as
  `sanitizeLog`. Main still wraps the whole error with `sanitizeLog` before
  logging it, as before.
- The package's only package-level variables are four compiled regular
  expressions (immutable, safe for concurrent use).

Lifecycle, in one sentence: main owns the embedded artifact, calls `Validate`
once at admin-UI construction and publishes the result; the package holds no
state, starts no goroutines, does no logging and reads only the `fs.FS` it is
given.

Unchanged, byte for byte: every error message (it reaches the server log and
decides ready versus 503), the accepted and rejected sets, the returned shell
bytes, each asset's content type and size, the route behavior and the default-
off gate.

## CI

`pr-fast-gate.yml` classifies `ui_frontend_v2*` as frontend surface so the
frontend verification job runs when the serving code changes. The moved
validator would have left that classifier. This PR adds
`internal/frontendbundle/*` to the same `case`, so the gate's trigger surface
is the same as before the move. Nothing is removed from any gate. The package
enters the non-root race lane and the coverage universe through
`go list ./...`.

## Tests

Seven validator tests moved with their names unchanged, with the `fe1bShell`
and `fe1bFixture` helpers: `TestFE1B_ValidatorAdversarialFixtures`,
`TestFE1B_AmbiguousCaseCollision`, `TestFE1B_ImportGraph`,
`TestFE1B_HashedNameContract`, `TestFE1B_HashRuleMatchesBundleScan`,
`TestFE1B_ShellManifestBinding` and `TestFE1B_DuplicateManifestKeysRejected`.
`TestFE1B_ShellManifestBinding` also asserted that the real committed dist
validates; that half needs the embed, so a root test of the same name keeps
it.

New in the package: a differential test whose 53 trees were run against
unmodified main (`5333aab`) and whose verdicts (error text, or shell length
plus asset set with content type and size) are recorded verbatim, with a
mutation control; the content-type oracle; result shape, nothing-to-serve on
rejection, control-byte-free error text, and concurrent independent calls; and
a boundary test (no application import except `internal/obs`; no `log`, `os`,
`sync`, `embed`, `time` or `net`; no `init`; no package variable except a
directly compiled regexp; exactly three exported names) with a negative
control for each rule.

New in root: `TestFE1B_ValidatorBindingFailsClosed`, which pins that the root
name returns the package's error and nothing to serve.

Every serving, gating, CSP, readiness and legacy-isolation test stays in root.

## Consequences

The decision that gates what the admin UI serves can be tested and fuzzed
without compiling the application, and `ui_frontend_v2.go` drops from 727 to
273 lines that are all composition. Two follow-ups are recorded, not done
here: the validator has no fuzz target, and `fuzz-nightly.yml` is a
hand-maintained matrix that the owner edits.
