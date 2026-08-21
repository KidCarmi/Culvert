# MCP Observe Acceptance Harness (QUAL-6)

The Observe Acceptance Harness runs a bounded, deterministic acceptance against a
BUILT Culvert artifact and writes a tamper-evident, secret-free evidence bundle.
It drives the real production boundaries of the MCP Gateway: a real TLS/mTLS
listener, real OAuth authentication, the real Admin HTTP API, real `/metrics`, and
the real on-disk encrypted telemetry spool and archive.

This harness is an ACCEPTANCE TEST tool. It does not begin Observe, does not start
any qualification-duration window, does not promote a Catalog tool, does not enable
execution, and does not change rollout mode or unlock Production. A PASS bundle is
evidence for an Observe acceptance decision. It is NOT authorization to transition
rollout.

> This document covers the acceptance harness only. It is NOT the complete Observe
> operational runbook. The broader Observe runbook (prerequisites, monitoring
> dashboards, incident escalation, abort criteria, and named ownership) remains an
> operational prerequisite tracked separately.

## Command

```
mcp-observe-acceptance -spec acceptance.json [-source-sha <sha>] [-timeout 15m]
```

Build it from the module: `go build -o mcp-observe-acceptance ./cmd/mcp-observe-acceptance`.

Exit codes: `0` overall PASS, `1` overall FAIL, `2` usage or run error.

## Modes

The spec `mode` selects the artifact-verification policy:

- `authoritative`: the run requires a matching `expected_digest` and a provenance
  block whose `verified_digest` equals the hashed binary, plus an explicit
  environment. Its evidence is marked `authoritative: true`. Authoritative
  verification is bound to the exact hashed binary before any traffic begins.
- `dev`: the CI / self-test path against a locally built binary. Its evidence is
  marked `authoritative: false` and can never be accepted as qualification
  evidence. A dev run never silently satisfies an authoritative run, and a flag
  can never turn a dev binary into authoritative evidence.

## Artifact identity

Before any scenario runs, the harness computes the SHA-256 of the binary and,
after the first listener is up, records the binary version from `GET /healthz`.

For an authoritative run:

- `artifact.expected_digest` MUST equal the hashed binary (checked before spawn).
- `artifact.provenance.verified_digest` MUST equal the hashed binary. The operator
  performs signature and provenance verification out of band with the accepted
  verifier (cosign keyless against the pinned identity in `release_identity.env`).
  The harness does not re-implement a Sigstore verifier; it binds the operator's
  verified digest to the exact hashed binary. A missing or mismatched provenance
  block fails the authoritative run. There is no silent downgrade.
- `artifact.expected_source_commit` MUST be present and unambiguous.

## Spec input

The spec is a JSON file. Secrets are referenced by file path and never inlined.

```json
{
  "mode": "dev",
  "artifact": { "binary_path": "/path/to/culvert" },
  "evidence_dir": "/path/to/evidence",
  "run": {
    "startup_timeout": "60s",
    "request_timeout": "15s",
    "shutdown_timeout": "20s",
    "restart_timeout": "45s"
  }
}
```

An authoritative spec adds the artifact verification material and an environment:

```json
{
  "mode": "authoritative",
  "artifact": {
    "binary_path": "/opt/culvert/culvert",
    "expected_digest": "sha256:<hex>",
    "expected_version": "v1.2.3",
    "expected_source_commit": "<commit>",
    "provenance": {
      "verifier": "cosign-keyless",
      "identity": "<pinned issuer/SAN>",
      "verified_digest": "sha256:<hex>"
    }
  },
  "environment": {
    "bind_host": "127.0.0.1",
    "oauth_issuer": "<issuer>",
    "canonical_resource": "<resource>",
    "required_scopes": ["gateway.tools.call"],
    "accepted_client_ids": ["<client id>"],
    "tenant_a": "<tenant A>",
    "tenant_b": "<tenant B>",
    "server_a": "<server A id>",
    "server_b": "<server B id>",
    "tls_cert_file": "<path>",
    "tls_key_file": "<path>",
    "server_ca_file": "<path>",
    "client_ca_file": "<path>",
    "client_cert_file": "<path>",
    "client_key_file": "<path>",
    "trusted_jwks_file": "<path>",
    "signing_key_file": "<path>",
    "signing_kid": "<kid>"
  },
  "evidence_dir": "/var/lib/culvert/acceptance"
}
```

Every environment value is an operator decision. The harness never invents hosts,
issuers, tenants, thresholds, or paths.

## Two-tenant environment

The harness launches two processes of the same artifact. Each is a genuine
single-tenant fleet (tenant A owns server A, tenant B owns server B) sharing the
issuer, canonical resource, JWKS, scopes, and client ids. A valid token for either
tenant therefore authenticates on either process, so the four-cell matrix (A to A,
B to B, A to B, B to A) exercises real cross-tenant admission against a genuinely
foreign-owned, really-seeded server. This uses the production single-tenant
inventory schema unchanged.

## Evidence bundle

The harness writes to `evidence_dir`:

- `summary.json`: the top-level result. Fields include `authoritative`, the tested
  `artifact` identity (digest, version, source commit, verification status),
  `acceptance_config_hash`, `run_id`, the acceptance run start and end timestamps,
  `overall`, the per-criterion `criteria`, the `tenant_matrix`, the
  `telemetry_summary`, and the restart, emergency-disable, and non-execution
  results.
- `logs/proc-*.stderr.log`: bounded copies of each process's stderr.
- `manifest.json`: a per-file SHA-256 manifest plus an overall manifest digest.
  This makes accidental mutation detectable. It is not a signature and confers no
  authorization.
- `secret_scan_violations.json`: present only if the secret scan tripped (a bounded
  classification, never the offending value); its presence forces `overall: FAIL`.

The acceptance run start and end timestamps are TEST-RUN timestamps only. They are
not an Observe window, a Shadow window, a Canary window, soak time, or a
qualification duration. The harness never calls `BeginWindow`.

## PASS / FAIL semantics

`overall` is PASS only when every required criterion is present and passed, the
artifact identity is authoritative when the mode demands it, the secret scan is
clean, no execution was detected, and no qualification window was created. A
required criterion that fails or does not run makes the overall result FAIL. There
is no best-effort PASS. Advisory (non-required) criteria that skip do not fail the
run.

## Known limitation

All seeded tools remain Quarantined in Observe, so a live user-rule ALLOW on a
`tools/call` is not exercisable. The harness proves the ALLOW-class decision path
through `tools/list` discovery and proves the quarantine hard-override on
`tools/call`. Catalog promotion is out of scope and is primarily a Shadow
prerequisite.

## Cleanup

After every run, success or failure, the harness terminates its child processes,
closes the tripwire servers, releases ports, and removes its own temporary work
root (fixtures and secrets). It preserves the evidence bundle and never deletes
operator-owned state outside the harness work root.

## Expected next step

A PASS from this harness does not authorize Shadow, Canary, or Production. After
QUAL-6 merges, run one final Observe Acceptance Preflight against the exact signed
qualification artifact, the exact qualification environment, configured monitoring,
an executable runbook, and named ownership. If preflight is green, run the live
Observe Acceptance with this harness.
