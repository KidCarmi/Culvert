# Observe Acceptance decision worksheet

This worksheet enumerates every value an operator must decide before an authoritative
Observe Acceptance run, and the source of truth for each. It is a companion to
`docs/operator/mcp-observe-acceptance-runbook.md` and the spec template at
`docs/operator/examples/mcp-observe-acceptance-authoritative.json`.

No value here is pre-filled. Every unresolved row reads `DECISION REQUIRED`. This
repository does not invent artifact identities, hosts, IPs, issuers, client ids,
scopes, tenant ids, owners, thresholds, credentials, or a KEK. Filling a row is an
operator or release action, not a documentation action.

How to use it: copy this table into your qualification record, replace each
`DECISION REQUIRED` with the decided value (or a reference to where it is stored),
and keep the completed worksheet with the acceptance evidence bundle.

The right-hand column names where the value is authoritative, not a suggested value.

## Artifact

| Value | Spec field | Status | Source of truth |
| --- | --- | --- | --- |
| Release version / tag | `artifact.expected_version` | DECISION REQUIRED | Signed release tag produced by `ci.yml` |
| Accepted source commit | `artifact.expected_source_commit` | DECISION REQUIRED | The tagged commit; must contain QUAL-1 through QUAL-6 |
| Binary / image | `artifact.binary_path` | DECISION REQUIRED | The pulled, verified release artifact on the qualification node |
| SHA-256 digest | `artifact.expected_digest` | DECISION REQUIRED | `sha256` of the exact binary at `binary_path` |
| Signature verification evidence | `artifact.provenance.identity` | DECISION REQUIRED | cosign keyless verify against the pinned identity in `release_identity.env` |
| Provenance evidence | `artifact.provenance.verified_digest` | DECISION REQUIRED | Operator out-of-band verification; must equal the hashed binary |
| SBOM identity | not in spec | DECISION REQUIRED | Release SBOM attached to the tagged release |

## Node

| Value | Status | Source of truth |
| --- | --- | --- |
| Host / node identity | DECISION REQUIRED | Qualification environment definition |
| OS | DECISION REQUIRED | Qualification environment definition |
| Architecture | DECISION REQUIRED | Must match the artifact platform |
| Telemetry node ID | DECISION REQUIRED | Node configuration used for the run |
| Clock synchronization source / state | DECISION REQUIRED | Node time source (NTP or equivalent) |

## Gateway

| Value | Spec field | Status | Source of truth |
| --- | --- | --- | --- |
| Bind address | `environment.bind_host` | DECISION REQUIRED | Qualification environment definition |
| Port | derived by the harness per process | DECISION REQUIRED | Harness assigns bounded local ports; operator confirms no conflict |
| Canonical resource | `environment.canonical_resource` | DECISION REQUIRED | Gateway resource identifier for the run |
| Accepted MCP protocol versions | fixed by the artifact | DECISION REQUIRED (confirm) | Product build under test |

## TLS / mTLS

| Value | Spec field | Status | Source of truth |
| --- | --- | --- | --- |
| Server certificate identity | `environment.tls_cert_file` | DECISION REQUIRED | Operator PKI |
| Server key reference | `environment.tls_key_file` | DECISION REQUIRED | Operator PKI (file path only) |
| Client CA | `environment.client_ca_file` | DECISION REQUIRED | Operator PKI |
| Server CA the harness trusts | `environment.server_ca_file` | DECISION REQUIRED | Operator PKI |
| Model-A client certificate identity | `environment.client_cert_file` | DECISION REQUIRED | Operator PKI |
| Model-A client key reference | `environment.client_key_file` | DECISION REQUIRED | Operator PKI (file path only) |

## OAuth

| Value | Spec field | Status | Source of truth |
| --- | --- | --- | --- |
| Issuer | `environment.oauth_issuer` | DECISION REQUIRED | Identity provider for the run |
| JWKS source | `environment.trusted_jwks_file` | DECISION REQUIRED | Identity provider JWKS (file path) |
| Accepted client IDs | `environment.accepted_client_ids` | DECISION REQUIRED | Identity provider registration |
| Required scopes | `environment.required_scopes` | DECISION REQUIRED | Gateway policy contract for the run |
| Audience / resource | `environment.canonical_resource` | DECISION REQUIRED | Gateway resource identifier |
| Sender-constraint posture | fixed by the artifact | DECISION REQUIRED (confirm) | Product build under test |
| Token signing key | `environment.signing_key_file` | DECISION REQUIRED | Operator-held ES256 key (file path only) |
| Token signing key id | `environment.signing_kid` | DECISION REQUIRED | Matches the JWKS entry |

## Tenant A

| Value | Spec field | Status | Source of truth |
| --- | --- | --- | --- |
| Tenant ID | `environment.tenant_a` | DECISION REQUIRED | Qualification environment definition |
| Model-A identity for A | minted from `signing_key_file` | DECISION REQUIRED | Operator identity material |
| ServerID | `environment.server_a` | DECISION REQUIRED | Qualification inventory |
| OwnerScope | bound to tenant A | DECISION REQUIRED | Qualification inventory |
| Endpoint | seeded by the harness fixture | DECISION REQUIRED (confirm) | Qualification inventory |
| Expected seeded tools | remain Quarantined in Observe | DECISION REQUIRED (confirm) | Qualification inventory |

## Tenant B

| Value | Spec field | Status | Source of truth |
| --- | --- | --- | --- |
| Tenant ID | `environment.tenant_b` | DECISION REQUIRED | Qualification environment definition |
| Model-A identity for B | minted from `signing_key_file` | DECISION REQUIRED | Operator identity material |
| ServerID | `environment.server_b` | DECISION REQUIRED | Qualification inventory |
| OwnerScope | bound to tenant B | DECISION REQUIRED | Qualification inventory |
| Endpoint | seeded by the harness fixture | DECISION REQUIRED (confirm) | Qualification inventory |
| Expected seeded tools | remain Quarantined in Observe | DECISION REQUIRED (confirm) | Qualification inventory |

## Policy

| Value | Status | Source of truth |
| --- | --- | --- |
| Source file | DECISION REQUIRED | Qualification policy selection; see `docs/operator/mcp-qualification-policy.md` |
| Intended ALLOW discovery rule | DECISION REQUIRED | Qualification policy; proven live via `tools/list` |
| Expected deny case | DECISION REQUIRED | Qualification policy; default-deny or explicit deny |
| Expected snapshot revision / hash after startup | DECISION REQUIRED | Read from `gateway.policy_revision` and `gateway.policy_snapshot_hash` on `/api/mcp/health` after startup |

## Telemetry

| Value | Status | Source of truth |
| --- | --- | --- |
| Data root | DECISION REQUIRED | Node configuration; see `docs/operator/mcp-qualification-telemetry.md` |
| KEK file / provider | DECISION REQUIRED | Operator key custody |
| Archive root | DECISION REQUIRED | Node configuration |
| Retention | DECISION REQUIRED | Operator retention policy |
| Quota | DECISION REQUIRED | Node configuration |
| Backup / custody boundary | DECISION REQUIRED | Operator custody policy |

## Evidence

| Value | Spec field | Status | Source of truth |
| --- | --- | --- | --- |
| Evidence directory | `evidence_dir` | DECISION REQUIRED | Operator-owned location, empty before the run |
| Directory owner | not in spec | DECISION REQUIRED | Operator |
| Access control | not in spec | DECISION REQUIRED | Operator |
| Retention | not in spec | DECISION REQUIRED | Operator retention policy |
| Backup | not in spec | DECISION REQUIRED | Operator backup policy |
| Final recipient / reviewer | not in spec | DECISION REQUIRED | Qualification run owner |

## Ownership

| Role | Status | Source of truth |
| --- | --- | --- |
| Qualification run owner | DECISION REQUIRED | Operator organization |
| Security owner | DECISION REQUIRED | Operator organization |
| On-call responder | DECISION REQUIRED | Operator organization |
| Release / artifact owner | DECISION REQUIRED | Operator organization |
| KEK custodian | DECISION REQUIRED | Operator organization |
| Incident commander (Observe phase) | DECISION REQUIRED (Observe-phase, not a bounded-run blocker) | Operator organization |

## Completion gate

The worksheet is complete only when no row reads `DECISION REQUIRED`. A complete
worksheet does not by itself authorize a run. Re-run the Observe Acceptance Preflight
after completing this worksheet; only a green preflight authorizes invoking the live
acceptance harness.
