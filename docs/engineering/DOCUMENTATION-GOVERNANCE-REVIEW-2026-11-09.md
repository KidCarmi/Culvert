# Documentation governance review 2026-11-09

Scope: checked-out `main` at `d11ed3a`. Point-in-time record; not a source of truth for behavior.

## Result

No documentation governance changes are required.

## Checks performed

- `python3 docs/agent-context/check.py` passes (static integrity of the agent guidance).
- Environment variables read by non-test Go code (68 names) were each searched for in all tracked Markdown. Every name with no mention is test, CI, release-harness or e2e scaffolding (`CULVERT_E2E_*`, `CULVERT_RELEASE_SPEC_*`, `*_CHILD`, `FAKE_*`, `CULVERT_*_PPROF`, Keycloak/OpenLDAP/SimpleSAML fixtures); none is an operator-facing setting.
- Four `CULVERT_FEED_GEN_*` inputs (`DATASET`, `GENERATED_AT`, `PREV_VERSION`, `VALIDITY_HRS`) are read only by a feed-generation tool, not the runtime; left undocumented.
- Relative Markdown links across 594 tracked files: no broken link except one in `docs/agent-context/history/conventions.md`, a deliberately preserved verbatim historical file (not edited).

## Not assessed

Per-option configuration-reference completeness and best-practice coverage were not re-audited this run; no evidence of drift was found in the checks above.
