# Observe Acceptance example specs

This directory holds a copyable acceptance-spec template for the artifact-bound
Observe Acceptance Harness (`cmd/mcp-observe-acceptance`, QUAL-6). The template is
documentation and safe example configuration only. It contains no secrets, no keys,
no credentials, and no signed-artifact claims.

## Files

- `mcp-observe-acceptance-authoritative.json` - an authoritative-mode spec template.
  Every value an operator must decide is an obvious `<DECISION_REQUIRED_...>`
  placeholder. The schema and field names mirror `internal/mcpacceptance/spec.go`
  on the current main branch.

## How to use the template

1. Copy the template to an operator-owned working location outside this repository.
2. Fill every `<DECISION_REQUIRED_...>` placeholder with a real, operator-decided
   value. The decision worksheet at `docs/operator/mcp-observe-acceptance-decisions.md`
   enumerates each value and its source of truth.
3. Follow `docs/operator/mcp-observe-acceptance-runbook.md` in order. The runbook is
   the executable procedure; this template is only its spec input.

## Placeholder and secret rules

- Secret-bearing material (TLS keys, the mTLS client key, the token-signing key) is
  referenced by file path only. The template carries file-path placeholders such as
  `<DECISION_REQUIRED_SIGNING_KEY_FILE>`; it never embeds key bytes, a bearer token,
  or a fake credential. The harness reads those files at run time and never copies
  their bytes into the evidence bundle.
- The digest placeholders are strings. Before an authoritative run the operator
  replaces them with a real `sha256:<hex>` digest. `expected_digest` and
  `provenance.verified_digest` must both equal the SHA-256 of the exact binary at
  `binary_path`, or the harness aborts before any traffic.
- The `run` durations are pre-filled with safe bounded defaults, not operator
  secrets. Leave them or tune within the harness maxima documented in
  `internal/mcpacceptance/spec.go`.

## Mode notes

- `mode` is `authoritative` in this template. Authoritative evidence is the only
  evidence a qualification decision may rely on. It requires a matching
  `expected_digest`, a `provenance.verified_digest` equal to the hashed binary, and
  an explicit `environment`.
- `mode` `dev` is the CI and self-test path against a locally built binary. Dev
  evidence is always marked `authoritative: false` and can never be accepted as
  qualification evidence. A locally built development binary is not authoritative
  qualification evidence. Do not use dev mode for an acceptance decision.

## Schema stability

`internal/mcpacceptance/docs_pack_test.go` loads this template through the real
`LoadSpec` on every test run. `LoadSpec` rejects unknown fields, so if the spec
schema changes and this template is not updated, that test fails. The template is
therefore kept in lockstep with the code, not by hand.

## Authoritative controls consumed (QUAL-6.1)

In authoritative mode the primary process consumes the operator-selected environment
and proves each control at runtime: `bind_host` + `gateway_port` (the listener binds
them; loopback proven absent when non-loopback), `qualification_policy_file` (passed
verbatim; preflight-gated; digest + runtime revision recorded), `telemetry.*`
(operator-owned data/KEK/archive, preserved on cleanup, reused across the restart), and
`supervision.*` (operator-accessible Admin + metrics listeners + credentials, with a
safe `supervision.json` descriptor for live external supervision). Credentials are
supplied by file PATH only, never inline, and never re-emitted into evidence.

The second tenant process and the negative-control auxiliaries remain harness-owned
(ephemeral ports, isolated telemetry). See "Harness scope and current limitations" in
`docs/operator/mcp-observe-acceptance-runbook.md` for the full boundary.

## What this template is not

Filling the placeholders does not authorize an acceptance run. A run is authorized
only by a green Observe Acceptance Preflight against the exact signed artifact,
environment, monitoring, runbook, and named ownership. A passing acceptance run does
not authorize Observe, Shadow, Canary, or Production.
