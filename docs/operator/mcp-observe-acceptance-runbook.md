# MCP Observe Acceptance runbook

This is the executable operator runbook for a bounded, authoritative Observe
Acceptance run of the Culvert MCP Gateway. It wraps the artifact-bound acceptance
harness (`cmd/mcp-observe-acceptance`, QUAL-6) with the operator procedure the
harness does not itself perform: prerequisites, artifact verification, environment
and ownership confirmation, live supervision, abort criteria, evidence preservation,
incident escalation, and cleanup.

For harness implementation detail (modes, evidence-bundle shape, PASS/FAIL
semantics, the two-tenant strategy) see
`docs/operator/mcp-observe-acceptance-harness.md`. This runbook does not duplicate
that material; it references it. For the value-by-value decisions the run needs see
`docs/operator/mcp-observe-acceptance-decisions.md`. For a copyable spec see
`docs/operator/examples/mcp-observe-acceptance-authoritative.json`.

## Scope and non-goals

This runbook covers a single bounded acceptance run and ends after the evidence
bundle is collected and reviewed. It contains no Observe rollout transition. A
passing acceptance run does not begin Observe, does not start any
qualification-duration window, does not promote a Catalog tool, does not enable
execution, does not change rollout mode, and does not unlock Production.

An acceptance PASS is evidence for a later, separate Post-Acceptance Observe
Readiness Decision. It is not that decision.

## Harness scope and current limitations (read before section 1)

QUAL-6.1 closed the four QUAL-6 authoritative-mode gaps: in authoritative mode the
harness now tests the operator-selected qualification environment on the PRIMARY
process rather than substituting internal fixtures. Read what it consumes from the
operator versus what remains harness-owned negative-control scratch, so this runbook
is not misread. Every item below is confirmed against the harness source
(`internal/mcpacceptance/fixture.go`, `authoritative.go`, `harness.go`).

Authoritative mode consumes the operator identity material (`tls_cert_file`,
`tls_key_file`, `server_ca_file`, `client_ca_file`, `client_cert_file`,
`client_key_file`, `trusted_jwks_file`, `signing_key_file`, `signing_kid`,
`oauth_issuer`, `canonical_resource`, `required_scopes`, `accepted_client_ids`,
`tenant_a`, `tenant_b`, `server_a`, `server_b`) AND, new in QUAL-6.1, the following
operator-selected controls, each consumed by the primary and PROVEN at runtime:

- Policy. `environment.qualification_policy_file` is passed into the primary's
  `mcp.gateway.qualification_policy_file` verbatim (never rewritten, never replaced by
  a fixture). A preflight rejects a policy that cannot support the required scenarios
  (`POLICY_SCENARIO_REQUIREMENT_UNSATISFIED`). The `operator_policy_digest`, the
  runtime `policy_revision`, and `policy_snapshot_hash` describe THIS policy; the
  `environment.policy_operator_selected` criterion proves the runtime revision equals
  the operator file's declared revision.
- Network boundary. `environment.bind_host` is the interface the Gateway binds
  (`mcp.gateway.bind_address`); `gateway_port` is the operator-selected port. The MCP
  clients connect to that host, and `environment.bind_host_effective` proves the
  listener bound it (and that loopback does not serve when the host is non-loopback).
  A wildcard or invalid host fails before traffic.
- Telemetry storage and KEK. `environment.telemetry.{node_id,data_dir,kek_file,
  archive_dir}` are consumed by the primary EXACTLY. They are classified
  operator-owned, are NEVER auto-deleted on cleanup, and are reused across the real
  restart to prove durable persistence. The harness never generates or reads the KEK;
  the binary owns it at the operator path. `environment.telemetry_operator_owned`
  proves consumption and ownership.
- Admin and metrics supervision. `environment.supervision.{admin_port,metrics_port,
  admin_user,admin_password_file,metrics_token_file}` select the operator-accessible
  Admin and metrics listeners + credentials (credentials by PATH only, never inline).
  `supervision.admin_reachable` and `supervision.metrics_reachable` prove the
  advertised endpoints are reachable AND enforce their auth. A safe supervision
  descriptor (`supervision.json`, and a stdout line) exposes the reachable URLs, the
  admin user, the credential FILE references, and the run id, so an operator can
  supervise the run live. No secret value is printed or written to evidence.

The two-tenant matrix uses a second process (tenant B) and several negative-control
auxiliaries (mtls, disabled, deny-only, emergency). These remain harness-owned: they
bind the operator host on ephemeral ports with isolated harness telemetry, because
concurrent processes cannot share one encrypted spool. Every authoritative process
reads the operator policy EXCEPT the deny-only default-deny probe, which uses a
harness policy under the work root by construction and never claims or mutates the
operator policy.

Transport-security note: the Admin UI and proxy/metrics listeners bind all interfaces
(existing product behavior) and are protected by their own auth (basic auth / bearer)
plus the optional `-ui-allow-ip` allowlist. For external supervision over an untrusted
network, front them with operator TLS termination or restrict them to a trusted
management network; the harness proves reachability and auth enforcement, not
transport confidentiality.

## Phase order

Run the phases in this exact order. Do not proceed to a phase until the previous
phase is true.

1. Preflight
2. Artifact verification
3. Environment verification
4. Ownership confirmation
5. Evidence destination confirmation
6. Acceptance spec validation
7. Acceptance invocation
8. Active supervision
9. PASS / FAIL review
10. Evidence preservation
11. Cleanup

The numbered sections below expand this order into the sixteen required operator
sections. Sections 5 through 12 describe criteria and signals that the single
acceptance invocation produces and that the operator watches and reviews; they are
not separate commands.

## 1. Prerequisites

Confirm all of the following before doing anything else. Any unmet prerequisite is a
STOP, not a workaround.

- A green Observe Acceptance Preflight for this exact artifact and environment. Only
  a green preflight authorizes invoking the live acceptance harness.
- The decision worksheet (`docs/operator/mcp-observe-acceptance-decisions.md`) is
  complete: no row reads `DECISION REQUIRED`.
- The acceptance harness binary is built from the same source under test:
  `go build -o mcp-observe-acceptance ./cmd/mcp-observe-acceptance`.
- The five operational owners are named (section 14).
- The evidence destination is prepared (section 13 and the evidence destination
  contract below).
- The qualification node clock is synchronized.
- The acceptance host is operator-controlled with no untrusted local users. The
  harness passes the operator admin password and metrics token to the spawned process
  via the product's own `-pass` / `-metrics-token` flags, so those values are visible
  to a local user on the acceptance host (via `ps` or `/proc`) for the duration of the
  run, exactly as they would be for any direct product launch. They never enter the
  evidence bundle. The admin password must satisfy the product complexity policy
  (upper, lower, digit) and should be at least eight characters so the evidence
  secret-scan registers it.
- Production is qualification-locked and stays locked throughout (see Production
  lock below).

## 2. Artifact verification

The acceptance must test one exact, verified artifact. A locally built development
binary is not authoritative qualification evidence. Authoritative harness mode
requires a verified artifact identity. Verification failure is an immediate ABORT.

Use the existing accepted Culvert release and signing path. Do not create a second
Sigstore or cosign trust model, and do not invent issuer or SAN values. The pinned
keyless identity lives in `release_identity.env` and is pinned byte-equal to the
in-binary constants; the release image and catalog are signed keyless on the tag
path by `ci.yml`. Verify against that identity, not a new one.

Obtain and record, into the worksheet and the evidence record:

- Release version / tag.
- Source commit (must contain QUAL-1 through QUAL-6).
- Artifact or image digest.
- Architecture and platform (must match the qualification node).
- Signature verification result (cosign keyless verify against the pinned identity
  in `release_identity.env`).
- Provenance verification result.
- SBOM identity attached to the release.
- Release-catalog binding where applicable (the signed catalog resolves the channel
  to a verified `repo@sha256` digest).

Record the verified digest as `<DECISION_REQUIRED_OPERATOR_VERIFIED_SHA256_DIGEST>`
in the spec `artifact.provenance.verified_digest`, and the same digest as
`artifact.expected_digest`. The harness recomputes the SHA-256 of the binary at
`binary_path` and aborts before any traffic if either does not match. The harness
does not re-implement signature verification; it binds your out-of-band verified
digest to the exact hashed binary.

ABORT if: the signature does not verify, provenance does not verify, the digest does
not match, the platform does not match, or the source commit does not contain
QUAL-1 through QUAL-6.

## 3. Environment inventory

Confirm every environment value is decided and correct. The harness never invents
hosts, issuers, tenants, thresholds, or paths. Use the decision worksheet as the
checklist. Confirm, at minimum:

- Node: host, OS, architecture, telemetry node ID, clock synchronization.
- Gateway: canonical resource (`environment.canonical_resource`) and accepted
  protocol versions are consumed. `environment.bind_host` is the interface the primary
  Gateway binds and `environment.gateway_port` is its port; the MCP clients connect
  there and the run proves the selected network boundary (`environment
  .bind_host_effective`). A wildcard or invalid host fails before traffic.
- TLS and mTLS: server certificate and key, client CA, server CA the harness
  trusts, and the Model-A client certificate and key. All are file-path references.
  `environment.tls_server_name` (optional) is the name the harness validates the
  listener cert against; the operator's server cert SAN must cover it (defaults to the
  bind host).
- OAuth: issuer, JWKS file, accepted client ids, required scopes, audience or
  resource, sender-constraint posture, and the token signing key file and kid.
- Tenant A and tenant B: tenant ids, ServerIDs, OwnerScopes, and that seeded tools
  remain Quarantined.
- Policy: `environment.qualification_policy_file` is the operator-owned qualification
  policy file (production format). It is consumed by the primary verbatim and gated by
  a preflight scenario-requirement check. Its digest and the runtime revision are
  recorded and matched.
- Telemetry: `environment.telemetry.{node_id,data_dir,kek_file,archive_dir}` are the
  operator-owned QUAL-3 custody boundary. They are consumed exactly, preserved on
  cleanup, and reused across the restart. The harness never generates or reads the KEK.
- Supervision: `environment.supervision.{admin_port,metrics_port,admin_user,
  admin_password_file,metrics_token_file}` select the operator-accessible Admin and
  metrics listeners and credentials (credentials by PATH only).

Secret-bearing files are referenced by path only and their bytes never enter the
evidence bundle. Confirm the harness process can read each referenced file.

ABORT if: any environment value is missing, or a referenced file is unreadable, or
the platform of the artifact does not match the node.

## 4. Startup configuration

Build the acceptance spec from the template
(`docs/operator/examples/mcp-observe-acceptance-authoritative.json`). Set
`mode` to `authoritative`. Fill every `<DECISION_REQUIRED_...>` placeholder with the
decided value. Set `evidence_dir` to the prepared, empty, operator-owned evidence
directory. Leave the `run` durations at their bounded defaults or tune them within
the harness maxima.

Do not embed secrets in the spec. TLS keys, the mTLS client key, and the token
signing key are file paths.

## 5. Startup validation

The harness starts the artifact and waits for readiness at the production boundary
before running any scenario. Readiness is health-based, not process-alive. The
harness polls `GET /api/mcp/health` and proceeds only when all of the following are
true on the gateway runtime:

- `gateway.runtime.state` is `ready`.
- `gateway.runtime.listener_ready` is `true`.
- `gateway.runtime.posture` is `observe`.
- `gateway.runtime.execution_enabled` is `false`.

The harness also records the binary version from `GET /healthz` and records
`gateway.policy_revision` and `gateway.policy_snapshot_hash` for the evidence. In
authoritative mode these describe the OPERATOR-selected qualification policy: the
`environment.policy_operator_selected` criterion proves the runtime revision equals
the revision declared in the operator policy file, and `operator_policy_digest` binds
the source file. In dev mode they describe the fixture policy.

The startup criteria in the bundle are `startup.ready`, `startup.tls_reachable`,
`startup.oauth_metadata`, and `startup.disabled_binds_nothing` (a disabled Gateway
config binds no MCP listener).

ABORT if: the gateway never reaches the ready and observe and execution-disabled
state within the startup timeout, or the recorded posture is anything other than
observe, or execution is enabled.

## 6. Known-good request

The harness proves a same-tenant known-good path reaches a real ALLOW-class
decision. It initializes an MCP session for tenant A against server A and performs a
`tools/list` discovery that reaches a real ALLOW-class policy rule. The
corresponding criteria are `policy.discovery_allow` and `policy.loaded` and
`policy.shared_snapshot`.

Note the accepted limitation: all seeded tools remain Quarantined in Observe, so a
live user-rule ALLOW on a `tools/call` is not exercisable. `tools/list` discovery is
the live ALLOW-class scenario. `tools/call` is expected to remain hard Quarantined.

ABORT if: the known-good `tools/list` does not reach the expected ALLOW-class
decision.

## 7. Tenant-isolation validation

The harness runs the full four-cell tenant matrix at the binary boundary using two
processes of the same artifact, each a genuine single-tenant fleet:

- A to A and B to B reach policy (same-owner).
- A to B and B to A hit a real `TENANT_MISMATCH` against a genuinely foreign-owned,
  really-seeded server.

The criteria are `tenant.aa`, `tenant.bb`, `tenant.ab`, `tenant.ba`,
`tenant.spoof_ignored` (a spoofed tenant header is ignored), and `tenant.no_leak`.
A broad ALLOW must never override a tenant mismatch; the criterion
`policy.quarantine_beats_allow` and the cross-tenant cells prove the isolation is
not weakened by a permissive user rule.

ABORT if: any cross-tenant cell is admitted, a spoofed tenant identity is honored,
tenant data leaks across the boundary, or a broad ALLOW overrides a tenant mismatch.

## 8. Authentication and hard-failure validation

The harness exercises the authentication boundary and the hard-failure paths at the
binary boundary. The criteria include `oauth.valid`, `oauth.missing`,
`oauth.malformed`, `oauth.expired`, `oauth.wrong_issuer`, `oauth.wrong_audience`,
`oauth.missing_scope`, the TLS and mTLS accept and reject criteria (`tls.mtls_accept`,
`tls.mtls_reject`), the Host and Origin checks (`host.allowed`, `host.bad`,
`origin.bad`), and the protocol checks (`protocol.lifecycle`, `protocol.malformed`,
`protocol.bad_version`, `protocol.oversized`). Inventory behavior is proven by
`inventory.known`, `inventory.unknown`, `inventory.admin_list`,
`inventory.cross_tenant_enum`, and `inventory.quarantined`.

ABORT if: a valid credential is rejected, an invalid credential is admitted, an mTLS
reject is accepted, or any hard-failure boundary regresses.

## 9. Durable evidence validation

The harness proves a decision is durably committed through the real encrypted
telemetry spool and readable back through the Admin HTTP API. The criterion
`evidence.allow_committed` commits a decision before the restart; `metrics.telemetry_ready`
confirms telemetry is ready. Durability is further proven by the restart criterion
(section 12), which asserts the committed decision persists and is readable after a
real process restart.

ABORT if: a committed decision is not durably readable, or telemetry never reports
ready, or a critical durability signal fails (see the watch-list).

## 10. Monitoring supervision

The signals below are present on current main. In authoritative mode (QUAL-6.1) the
primary process now exposes the operator-selected Admin and metrics listeners
(`environment.supervision.admin_port` / `metrics_port`) protected by the
operator-supplied credentials, so live external scraping of `/metrics` and the Admin
API IS available during the run. The harness writes a safe supervision descriptor
(`supervision.json` in the evidence directory, and a stdout line at startup) carrying
the reachable Gateway/Admin/metrics URLs, the admin user, the credential FILE
references, and the run id; no secret value is printed or written. Use those URLs plus
the credential files you supplied to supervise the run. The `supervision.admin_reachable`
and `supervision.metrics_reachable` criteria prove the endpoints are reachable and
enforce their auth.

The harness ALSO polls the health and metrics signals internally and folds the
durability outcome into `summary.json` (`telemetry_summary`, the `metrics.*`
criteria, restart and non-execution results), so the harness remains the authoritative
PASS/FAIL engine; external supervision is an additional operator view, not a second
acceptance decision. The auxiliary/negative-control processes still use ephemeral
loopback ports and are not externally supervised. This is not sustained Observe
monitoring: dashboards, alert rules, and numeric thresholds remain a later
sustained-Observe requirement and are not delivered by this runbook. For external
exposure over an untrusted network, front the plain-HTTP Admin/metrics listeners with
operator TLS termination or restrict them to a trusted management network.

The table documents what the harness asserts internally on your behalf and the exact
fields and metric names you can scrape live at the advertised endpoints.

Numeric thresholds are operator decisions and are marked `DECISION REQUIRED`. The
fail-closed direction for the critical durability signals is that they do not
degrade during the bounded run.

| Signal | Source endpoint | Exact field or metric | Expected healthy state | Abort significance | Threshold |
| --- | --- | --- | --- | --- | --- |
| Gateway readiness | `GET /api/mcp/health` | `gateway.runtime.state`, `gateway.runtime.listener_ready`, `gateway.runtime.posture`, `gateway.runtime.execution_enabled` | `ready`, `true`, `observe`, `false` | Not ready, wrong posture, or execution enabled aborts | DECISION REQUIRED |
| Policy posture | `GET /api/mcp/health` | `gateway.policy_revision`, `gateway.policy_snapshot_hash` | Matches expected from worksheet | Unexpected revision or hash aborts | DECISION REQUIRED |
| Auth failures | acceptance evidence | `oauth.*` criteria in `summary.json`, process stderr in `logs/` | Every `oauth.*` criterion PASS | A valid reject or invalid admit aborts | No dedicated counter exists; watch via criteria |
| Tenant mismatch | acceptance evidence | `tenant_matrix` and `tenant.*` criteria in `summary.json` | Cross-tenant cells report `TENANT_MISMATCH` | Any cross-tenant admission aborts | No dedicated counter exists; watch via criteria |
| Telemetry readiness | `/metrics` | `culvert_mcp_telemetry_ready` | 1 (ready) | Not ready aborts durable evidence | DECISION REQUIRED |
| Critical event failures / degraded | `/metrics` | `culvert_mcp_degraded`, `culvert_mcp_event_commits_total` | `degraded` 0; commits advance | Degraded or stalled commits aborts | DECISION REQUIRED |
| Ordinary loss | `/metrics` | `culvert_mcp_ordinary_loss_total` | Does not increase during the run | Increase indicates loss | DECISION REQUIRED |
| Denial loss / aggregation | `/metrics` | `culvert_mcp_denial_loss_total`, `culvert_mcp_denial_aggregates_total` | Denial loss does not increase | Denial loss increase aborts | DECISION REQUIRED |
| Spool records / bytes / quota | `/metrics` | `culvert_mcp_spool_records`, `culvert_mcp_spool_bytes`, `culvert_mcp_spool_quota_bytes` | Bytes below quota | Spool at quota risks loss | DECISION REQUIRED |
| Critical reserve | `/metrics` | `culvert_mcp_critical_reserve_free_bytes` | Above zero | Reserve exhaustion aborts | DECISION REQUIRED |
| Exporter success / failure | `/metrics` | `culvert_mcp_export_batches_total`, `culvert_mcp_export_events_total` | Advance while data flows | Stalled export with backlog aborts | DECISION REQUIRED |
| Archive saturation | `/metrics` | `culvert_mcp_export_saturated` | 0 (not saturated) | Saturation risks loss | DECISION REQUIRED |
| Export lag | `/metrics` | `culvert_mcp_export_lag` | Bounded | Growing lag with backlog aborts | DECISION REQUIRED |
| Last successful export | `/metrics` | `culvert_mcp_last_export_timestamp_seconds` | Recent relative to run start | Stale timestamp with backlog aborts | DECISION REQUIRED |
| High-cardinality guard | `/metrics` | any `culvert_mcp_*` series labels | No banned label (`tenant`, `principal`, `server`, `tool`, `event_id`, `path`, `subject`, `client`) | A banned label present aborts (`metrics.no_high_cardinality`) | Not numeric |
| Process health | `GET /healthz`, `GET /api/mcp/overview` | liveness and version; overview `execution_state` | Alive; `execution_state` is `not_implemented` | Process death or execution advance aborts | DECISION REQUIRED |

## 11. Emergency disable

The harness proves the accepted emergency-disable behavior as a criterion
(`emergency.disable`): disabling the Gateway config and restarting the artifact stops
MCP admission while the SWG forward proxy stays up and rollout is unchanged. During a
live run, if the operator must stop MCP admission, use the accepted config-disable
mechanism and restart; the SWG proxy remains available. Confirm afterward that MCP no
longer admits, the SWG proxy `/health` is up, and `/api/mcp/overview` still reports
`execution_state` `not_implemented`.

ABORT the acceptance if: disabling MCP also takes down the SWG proxy, or rollout
advanced, or execution state changed.

## 12. Restart / recovery

The harness proves recovery across a real process restart (`restart.recovery`): it
stops and restarts the same artifact, then asserts that a decision committed before
the restart remains readable and non-empty afterward. This proves the durable spool
persisted the decision, not merely that the endpoint recovered.

ABORT if: post-restart the committed decision is not persisted and readable within
the restart timeout, or the restart fails.

## 13. Evidence collection

The harness writes to `evidence_dir`:

- `summary.json`: the top-level result, including `authoritative`, the tested
  `artifact` identity, `acceptance_config_hash`, `run_id`, the acceptance run start
  and end timestamps, `overall`, the per-criterion `criteria`, the `tenant_matrix`,
  the `telemetry_summary`, and the restart, emergency-disable, and non-execution
  results.
- `manifest.json`: a per-file SHA-256 manifest plus an overall manifest digest. It
  makes accidental mutation detectable. It is not a signature and confers no
  authorization.
- `logs/proc-*.stderr.log`: bounded per-process stderr.
- `secret_scan_violations.json`: present only if the secret scan tripped. Its
  presence forces `overall: FAIL` and carries only a bounded classification, never
  the offending value.

Preserve the whole bundle together with the artifact-verification evidence and the
completed decision worksheet.

## 14. Incident escalation

Escalate by role. Do not invent people; record the real identity of each role in the
worksheet and here as a placeholder until decided.

Escalation chain:

1. Acceptance operator: `<DECISION_REQUIRED_ACCEPTANCE_OPERATOR>`
2. Qualification run owner: `<DECISION_REQUIRED_QUALIFICATION_RUN_OWNER>`
3. Security owner or on-call responder:
   `<DECISION_REQUIRED_SECURITY_OWNER>` / `<DECISION_REQUIRED_ONCALL_RESPONDER>`
4. Release / artifact owner (when the incident is artifact-related):
   `<DECISION_REQUIRED_RELEASE_ARTIFACT_OWNER>`
5. KEK custodian (when the incident is telemetry-encryption-related):
   `<DECISION_REQUIRED_KEK_CUSTODIAN>`

For the bounded acceptance run, an incident commander may remain a later
Observe-phase assignment per the accepted design. The bounded run uses the simpler
escalation path above; a standing incident commander is an Observe-phase role, not a
bounded-run blocker. Record that distinction explicitly.

## 15. Abort criteria

Abort the acceptance immediately on any condition below. On abort: stop the run,
preserve whatever evidence exists, record the abort reason, and escalate per section
14. A required criterion that cannot run means acceptance FAIL.

Required criterion SKIP == acceptance FAIL, unless the criterion is explicitly marked
Shadow-plus or not applicable by the accepted Observe contract (for example, a live
user-rule ALLOW on `tools/call`, which is not exercisable while all seeded tools
remain Quarantined).

Immediate-abort conditions:

- Artifact digest, signature, or provenance mismatch.
- Wrong artifact or wrong source identity.
- TLS or mTLS regression.
- OAuth or authentication boundary regression.
- Tenant-isolation failure.
- A broad ALLOW overriding a tenant mismatch.
- Unexpected tool execution.
- Tripwire inbound request count greater than zero.
- Credential materialization.
- Token passthrough indication.
- Critical telemetry durability failure.
- Evidence secret leak (`secret_scan_violations.json` present).
- Evidence manifest or integrity failure.
- Management activation.
- Qualification-window creation.
- Rollout-mode change.
- Production unlock indication.
- Inability to cleanly control or stop the spawned process.
- Any required acceptance criterion that cannot run.

The harness enforces most of these fail-closed automatically: artifact binding fails
before spawn, a required criterion that fails or is absent forces `overall: FAIL`,
the non-execution tripwire fails on any inbound request, and the secret scan forces
FAIL on any hit. Management activation, qualification-window creation, rollout
change, and Production unlock are structurally absent from the harness by
construction.

## 16. Final cleanup

Distinguish harness-owned ephemeral material from operator-owned material.

The harness, on success or failure, terminates its child processes, closes the
tripwire servers, releases ports, and removes its own temporary work root (its
generated fixtures, temporary keys, temporary tripwire state, and temporary process
state). It preserves the evidence bundle and never deletes operator-owned state
outside its work root.

In the current harness the telemetry data directory, archive, and KEK are created
under the harness temporary work root and are removed by `Harness.cleanup`; they are
harness-owned ephemeral state, not operator-owned artifacts (see Harness scope and
current limitations). There is no operator KEK to preserve today. Operator-owned
telemetry, archive, and KEK preservation becomes applicable only after a harness change
places them under operator-owned locations.

The operator must preserve, and must not auto-delete:

- The authoritative evidence bundle (`summary.json`, `manifest.json`, the bounded
  `logs/`) in `evidence_dir`, which the harness does not delete.
- The artifact-verification evidence.
- The completed decision worksheet.
- The signed artifact.
- The evidence destination.

The operator may safely remove or rotate ephemeral material that the operator created
outside the harness work root: any operator-generated temporary tokens, temporary
private keys, temporary fixture files, and temporary process state created for the run.
Do not remove the signed artifact or the evidence destination unless the runbook has an
explicit, operator-approved retention action for that item. Once a harness change
introduces operator-owned telemetry, archive, and KEK locations, add them to this
preserve list.

Record any cleanup failure with the evidence. Cleanup failure is itself an item to
escalate.

## Harness invocation

Re-checked against current source (`cmd/mcp-observe-acceptance/main.go`).

```
mcp-observe-acceptance -spec <ACCEPTANCE_SPEC.json> [-source-sha <HARNESS_SRC_SHA>] [-timeout 15m]
```

- `-spec` is the required path to the acceptance spec JSON.
- `-source-sha` optionally records the harness source commit in the bundle.
- `-timeout` bounds the whole run (default 15m).

Authoritative mode is selected by `"mode": "authoritative"` in the spec, not by a CLI
flag. There is no CLI switch that can turn a dev binary into authoritative evidence.

Exit codes (exact, from current code): `0` overall PASS, `1` overall FAIL, `2` usage
or run error.

## Acceptance result interpretation

- Exit `0` and `overall: PASS`: every required criterion is present and passed, the
  artifact identity is authoritative when the mode demands it, the secret scan is
  clean, no execution was detected, and no qualification window was created.
- Exit `1` and `overall: FAIL`: at least one required criterion failed or did not
  run, or the run is not authoritative when required, or the secret scan tripped, or
  execution was detected. There is no best-effort PASS.
- Exit `2`: a usage or run error (bad spec, unreadable input, harness error). This is
  not an acceptance result; fix the input and re-run.
- `authoritative: true` only when the mode is authoritative and the digest and
  provenance binding held. `authoritative: false` evidence is never qualification
  evidence.
- Required criterion semantics: a required criterion that is absent makes the overall
  result FAIL. Advisory (non-required) criteria that skip do not fail the run.
- Verify the evidence manifest: recompute the per-file SHA-256 set and confirm it
  matches `manifest.json`. The manifest is tamper-evidence, not a signature, and
  confers no authorization.

An acceptance PASS does not mean READY TO BEGIN OBSERVE, does not mean Shadow
approved, does not mean Canary approved, and does not mean Production approved. After
a future authoritative PASS, the next step is a separate Post-Acceptance Observe
Readiness Decision.

## Evidence destination contract

The evidence directory (`evidence_dir`) must be:

- Operator-owned.
- Empty before the run, as the harness requires.
- Access-restricted.
- Backed by adequate storage.
- Retention decided in advance.
- Backup decision made in advance.
- Final reviewer or recipient decided in advance.
- Kept separate from fixture secrets (which never enter the bundle and live only in
  the harness work root).

Do not hard-code a path. Use `<DECISION_REQUIRED_EVIDENCE_DIR>` in the worksheet and
spec until decided.

## Catalog boundary

- Catalog promotion is not required for Observe acceptance.
- Seeded tools remain Quarantined throughout.
- `tools/list` is the live user-policy ALLOW-class scenario.
- `tools/call` remains hard Quarantined.
- No tool is to be promoted during acceptance.

Do not add a Catalog promotion step to this run.

## Qualification-clock guard

The acceptance harness must NOT call `BeginWindow`, must not invoke the qualification
issuer, must not create a Production receipt, and must not transition rollout state.

Acceptance run timestamps (`acceptance_run_start_utc`, `acceptance_run_end_utc`) are
test-run timestamps only. They are not an Observe window, a Shadow window, a Canary
window, soak time, or a qualification duration. Do not describe them as Observe
evidence duration.

## Production lock

Production remains qualification-locked throughout the entire acceptance procedure.
This procedure contains no Production unlock action. Any indication of a Production
unlock during the run is an immediate abort.
