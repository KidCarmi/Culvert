// Package mcperr defines the stable, sanitized error model shared by every
// package of the MCP protocol kernel (PR-1). It is a leaf package with no
// intra-kernel dependencies so that jsonrpc, protocol, session and limits can
// all return the same typed error without an import cycle.
//
// Two properties are load-bearing and are asserted by tests:
//
//   - Stable reason codes. Every kernel rejection carries a Reason whose numeric
//     value and machine string ("malformed_json", "unsupported_method", …) are
//     part of the package contract. Callers branch on Reason, never on free-form
//     message text.
//   - No hostile input in errors (MCP-PROTO-013). An Error never embeds raw,
//     attacker-controlled payload bytes. Detail is a fixed, developer-authored
//     string; any variable token that must appear is passed through Sanitize,
//     which strips control bytes and hard-bounds the length. This keeps a
//     malformed-input rejection from becoming a log-injection or memory vector.
package mcperr

import (
	"strconv"
	"strings"
)

// Reason is the stable category of a kernel rejection. The zero value,
// ReasonNone, means "not a kernel error".
type Reason int

const (
	// ReasonNone is the zero value: no kernel error.
	ReasonNone Reason = iota
	// ReasonMalformedJSON — the bytes are not well-formed strict JSON, or violate
	// a strict-decode rule (duplicate object key, invalid UTF-8, trailing bytes /
	// multiple top-level values, excessive nesting depth).
	ReasonMalformedJSON
	// ReasonInvalidJSONRPC — structurally valid JSON that is not a valid JSON-RPC
	// 2.0 envelope (bad "jsonrpc", invalid id shape, request without id,
	// notification with id, response with both result and error or neither,
	// ambiguous request/response shape).
	ReasonInvalidJSONRPC
	// ReasonUnsupportedBatch — a top-level JSON-RPC batch array. Rejected whole in
	// V1 — never split or partially processed.
	ReasonUnsupportedBatch
	// ReasonUnsupportedVersion — a protocol version outside the supported set, or a
	// sessionless first request missing the MCP-Protocol-Version identification.
	ReasonUnsupportedVersion
	// ReasonUnsupportedMethod — a method absent from the reviewed admitted registry
	// (every non-admitted method, including a method valid in the negotiated spec
	// version but not in Culvert's V1 set).
	ReasonUnsupportedMethod
	// ReasonResourceLimit — a structural or resource bound was exceeded (frame
	// bytes, depth, member/element counts, string/method/id/error-data bytes,
	// session or outstanding-request caps).
	ReasonResourceLimit
	// ReasonInvalidLifecycle — an operation illegal in the current lifecycle state.
	ReasonInvalidLifecycle
	// ReasonUncorrelatedResponse — a response whose (session, direction, id) matches
	// no outstanding request owned by this side.
	ReasonUncorrelatedResponse
	// ReasonDuplicateCompletion — a second completion for an already-resolved
	// request (distinct from a tolerated late cancellation).
	ReasonDuplicateCompletion
	// ReasonInvalidCancellation — a cancellation violating ownership, direction or
	// target rules (wrong owner, opposite direction, or naming initialize).
	ReasonInvalidCancellation
	// ReasonLateCancellation — a cancellation that arrives after its target already
	// completed. Tolerated per the spec — NOT a fault and NOT a duplicate
	// completion; surfaced as a distinct reason so callers can no-op it.
	ReasonLateCancellation

	// --- PR-2 (registry & catalog) reasons ---------------------------------
	// These extend the shared model for the server-registry and tool-catalog
	// packages. They are appended (never reordered) so every PR-1 numeric value is
	// unchanged. Byte/depth/element structural bounds keep using ReasonResourceLimit
	// (shared with the decoder); ReasonCapacityExceeded is reserved for entity-count
	// capacity (registered servers, tools, catalog entries).

	// ReasonInvalidRegistration — a server registration that fails validation:
	// empty/malformed id, malformed or non-canonical endpoint, missing pinned
	// identity, a Gateway record placed in the wrong capability namespace, a
	// duplicate id, or an already-registered canonical endpoint. Distinct from a
	// live-identity MISMATCH (ReasonServerIdentityMismatch) and from ingestion of an
	// UNREGISTERED server (ReasonUnregisteredServer).
	ReasonInvalidRegistration
	// ReasonUnregisteredServer — discovery/ingestion was attempted for a server id
	// that is not present (and enabled) in the registry snapshot. An unregistered
	// server is never eligible for tool ingestion.
	ReasonUnregisteredServer
	// ReasonServerIdentityMismatch — the caller-supplied verified identity does not
	// exactly match the server's pinned identity. A server-level fault that disables
	// the server; it can never be downgraded to tool-schema drift.
	ReasonServerIdentityMismatch
	// ReasonMalformedDiscovery — a tools/list discovery result that is structurally
	// invalid against the supported V1 contract (bad top-level shape, missing/typed
	// tool name, missing input schema, unknown envelope member) — distinct from raw
	// JSON malformation (ReasonMalformedJSON).
	ReasonMalformedDiscovery
	// ReasonDuplicateTool — two tools with the same name in one server's discovery
	// result. Never silently collapsed (no map/last-write-wins).
	ReasonDuplicateTool
	// ReasonCanonicalizationFailed — a value could not be canonicalized for hashing
	// (invalid UTF-8, duplicate key, trailing data, over-bound) when the failure is
	// not already a plain ReasonMalformedJSON at the byte layer.
	ReasonCanonicalizationFailed
	// ReasonCapacityExceeded — an entity-count capacity was exceeded (registered
	// servers, tools-per-server, or total catalog entries). Distinct from the
	// byte/structural ReasonResourceLimit.
	ReasonCapacityExceeded
	// ReasonUnknownTool — an observation for a (server,tool) with no prior catalog
	// record. Classified as quarantine-required; PR-2 never converts it to allowed.
	ReasonUnknownTool
	// ReasonPrivilegeExpansion — an observation that broadens a tool's capability
	// (proven, or conservatively-classified ambiguous security-relevant broadening).
	// Classified as quarantine-required.
	ReasonPrivilegeExpansion
	// ReasonSemanticDrift — a behavioral/description change that is neither proven
	// safe narrowing nor proven privilege expansion. Classified as review-required.
	ReasonSemanticDrift
	// ReasonStaleSnapshot — an optimistic publish whose base revision no longer
	// matches the current snapshot (a concurrent publish won). The caller re-reads
	// and retries; the current snapshot is left unchanged.
	ReasonStaleSnapshot

	// --- PR-3 (identity, token validation, sender constraint) reasons ------
	// Appended (never reordered). Every reason is a DETERMINISTIC negative-auth
	// outcome; none ever carries a raw token, proof JWT, private key, full claim
	// set, subject email or tenant free-text (Detail is fixed developer text).

	// ReasonCredentialMissing — no credential was presented.
	ReasonCredentialMissing
	// ReasonCredentialInQuery — a bearer token presented in the query string; a
	// forbidden location, rejected before any normal validation.
	ReasonCredentialInQuery
	// ReasonMalformedToken — a token that is not well-formed for its declared type
	// (bad compact JWT shape, undecodable segment, malformed introspection metadata).
	ReasonMalformedToken
	// ReasonUnsupportedTokenType — a credential of a type PR-3 does not validate.
	ReasonUnsupportedTokenType
	// ReasonUnsupportedAlgorithm — a JWS alg outside the allowlist, missing, or
	// `none`; also an algorithm-confusion attempt (a key type that cannot serve the
	// declared alg).
	ReasonUnsupportedAlgorithm
	// ReasonSignatureInvalid — the JWS signature did not verify against the trusted key.
	ReasonSignatureInvalid
	// ReasonIssuerRejected — the token issuer is absent or not in the capability's
	// trusted-issuer allowlist.
	ReasonIssuerRejected
	// ReasonAudienceMissing — the token carries no effective audience/resource.
	ReasonAudienceMissing
	// ReasonAudienceRejected — the effective audience is not the capability's
	// canonical Culvert resource (foreign aud, upstream URL, SWG client id, etc.).
	ReasonAudienceRejected
	// ReasonResourceMismatch — the audience is a Culvert resource but for the wrong
	// capability or a different ServerID.
	ReasonResourceMismatch
	// ReasonTokenExpired — the token/metadata is past its expiry (with skew).
	ReasonTokenExpired
	// ReasonTokenNotYetValid — nbf is in the future beyond the permitted skew.
	ReasonTokenNotYetValid
	// ReasonTokenTTLExceeded — the token's lifetime exceeds the configured maximum,
	// or its future nbf / authentication age exceeds the configured bound.
	ReasonTokenTTLExceeded
	// ReasonScopeMissing — a required scope is absent, or a presented scope is
	// malformed / a forbidden blanket-or-wildcard scope.
	ReasonScopeMissing
	// ReasonCapabilityMismatch — a credential/scope/resource for the other capability.
	ReasonCapabilityMismatch
	// ReasonTenantMismatch — conflicting tenant ids in the chain, or a cross-tenant
	// resource reference.
	ReasonTenantMismatch
	// ReasonDelegationChainInvalid — an ambiguous or inconsistent principal chain
	// (both/neither Human and Workload subject, agent owner mismatch, tool not under
	// the selected server, Management carrying Gateway authority, etc.).
	ReasonDelegationChainInvalid
	// ReasonSenderConstraintRequired — the deployment profile requires a sender
	// constraint (DPoP/mTLS) that is absent.
	ReasonSenderConstraintRequired
	// ReasonDPoPMalformed — a DPoP proof that is not a well-formed proof JWT (bad
	// type, missing JWK, private JWK material, undecodable).
	ReasonDPoPMalformed
	// ReasonDPoPBindingMismatch — the proof's htm/htu/ath/cnf thumbprint does not
	// match the request or the access token.
	ReasonDPoPBindingMismatch
	// ReasonDPoPReplay — a DPoP proof jti already seen within its bounded partition.
	ReasonDPoPReplay
	// ReasonDPoPNonce — a required server nonce is missing or does not match.
	ReasonDPoPNonce
	// ReasonMTLSBindingMismatch — the observed certificate thumbprint does not match
	// the token's cnf.x5t#S256 (or the binding is missing/malformed).
	ReasonMTLSBindingMismatch
	// ReasonInactiveToken — an opaque introspection result marked inactive.
	ReasonInactiveToken
	// ReasonSessionIdentityBound — an attempt to read/derive where a session already
	// carries a (different) bound identity in a context that forbids it.
	ReasonSessionIdentityBound
	// ReasonSessionIdentityRebind — an attempt to bind a DIFFERENT identity to a
	// session that already has one (subject/tenant/client/agent/capability/resource
	// change). The existing binding is retained.
	ReasonSessionIdentityRebind
	// ReasonRegistryServerUnavailable — the Gateway resource names a ServerID that is
	// not registered or not enabled in the live registry snapshot.
	ReasonRegistryServerUnavailable

	// ── PR-4 credential-broker reasons ────────────────────────────────────────

	// ReasonCredentialProfileMissing — no credential profile resolves for the plan.
	ReasonCredentialProfileMissing
	// ReasonCredentialProfileDisabled — the selected profile exists but is disabled.
	ReasonCredentialProfileDisabled
	// ReasonCredentialProfileAmbiguous — more than one profile matches; selection is
	// not mechanically unique, so the broker fails closed rather than guessing.
	ReasonCredentialProfileAmbiguous
	// ReasonProviderUnavailable — the credential provider could not be reached or
	// returned a transient failure (sanitized; no provider error text).
	ReasonProviderUnavailable
	// ReasonProviderUnsupportedOperation — the provider does not support the
	// requested operation (rotate/revoke/inspect).
	ReasonProviderUnsupportedOperation
	// ReasonProviderInvalidMaterial — the provider returned material or lease
	// metadata that is malformed or fails structural validation.
	ReasonProviderInvalidMaterial
	// ReasonCredentialScopeMismatch — the provider-returned effective scope exceeds
	// or does not match the plan's server/tool/resource/tenant/environment scope.
	ReasonCredentialScopeMismatch
	// ReasonCredentialPowerExceeded — the credential's effective power exceeds the
	// profile/plan ceiling (e.g. write/admin material for a read-only plan).
	ReasonCredentialPowerExceeded
	// ReasonCredentialExpired — the credential lease is past its expiry.
	ReasonCredentialExpired
	// ReasonCredentialRevoked — the credential version/profile is revoked.
	ReasonCredentialRevoked
	// ReasonCredentialVersionStale — the plan's profile revision or credential
	// version is older than the live one.
	ReasonCredentialVersionStale
	// ReasonCacheMiss — no cache entry for the requested key (fail closed for
	// high-risk; fail closed for low-risk unless explicit fallback is enabled).
	ReasonCacheMiss
	// ReasonCacheFull — the encrypted cache is at capacity and no room can be
	// reclaimed; the broker fails closed rather than growing unbounded.
	ReasonCacheFull
	// ReasonCacheIntegrityFailure — a cached envelope failed to decrypt/authenticate.
	ReasonCacheIntegrityFailure
	// ReasonRotationInProgress — a concurrent rotation for the profile is underway
	// and the request cannot be serviced (serialized/rejected).
	ReasonRotationInProgress
	// ReasonRotationFailed — a rotation could not validate a successor; the current
	// version stays active.
	ReasonRotationFailed
	// ReasonRevocationFailed — a provider-side revoke failed; local use stays blocked.
	ReasonRevocationFailed
	// ReasonMaterializationGateDenied — the pre-materialization gate denied the plan.
	ReasonMaterializationGateDenied
	// ReasonMaterializationGateUnavailable — the pre-materialization gate could not
	// render a decision (fail closed; provider not called, cache not decrypted).
	ReasonMaterializationGateUnavailable
	// ReasonMaterialAlreadyConsumed — a single-use material handle was consumed twice.
	ReasonMaterialAlreadyConsumed
	// ReasonCredentialKindUnsupported — the plan's credential kind is not supported.
	ReasonCredentialKindUnsupported

	// ── PR-5 runtime / listener reasons ───────────────────────────────────────

	// ReasonListenerDisabled — an MCP listener is disabled (off by default).
	ReasonListenerDisabled
	// ReasonHTTPMethodRejected — an HTTP method is not accepted (terminal 405: GET
	// without a negotiated session, DELETE, or any unsupported method). No stream is
	// allocated and no session state is mutated.
	ReasonHTTPMethodRejected
	// ReasonHostRejected — the request Host / :authority is not on the listener's
	// allowlist (evaluated per request and per HTTP/2 stream).
	ReasonHostRejected
	// ReasonOriginRejected — the request Origin is missing (where required), malformed,
	// or not allowlisted.
	ReasonOriginRejected
	// ReasonAdmissionRejected — the listener refused admission before expensive work
	// (connection / concurrency / queue / session / rate budget exhausted).
	ReasonAdmissionRejected
	// ReasonObserveOnly — a decision-point method (tools/list, tools/call) reached a
	// listener that runs in observe mode only: no policy engine, credential broker or
	// upstream exists yet, so the request is deterministically rejected (never a
	// fabricated success).
	ReasonObserveOnly
	// ReasonTLSRequired — a non-test deployment requires TLS but none was configured,
	// or an mTLS-required listener did not receive a verified peer certificate.
	ReasonTLSRequired
	// ReasonListenerConfigInvalid — a listener configuration is unsafe (zero/negative/
	// wildcard/conflicting address or port, shared mutable limits, missing TLS).
	ReasonListenerConfigInvalid
	// ReasonRequestDeadlineExceeded — a request exceeded its bounded deadline
	// (slowloris / trickle / handshake stall defense).
	ReasonRequestDeadlineExceeded

	// ── PR-6 policy-engine reasons ────────────────────────────────────────────

	// ReasonPolicySnapshotInvalid — a policy snapshot failed strict parsing or
	// structural validation (bad schema version, duplicate key, unknown field,
	// over-limit size, mixed-capability rule set).
	ReasonPolicySnapshotInvalid
	// ReasonPolicyRuleInvalid — a policy rule failed compilation (malformed action,
	// reason/remediation code, duplicate RuleID/priority, bad condition).
	ReasonPolicyRuleInvalid
	// ReasonPolicyConditionInvalid — a rule condition matcher is malformed (unknown
	// matcher/field, bad glob, over-limit set, invalid time window).
	ReasonPolicyConditionInvalid
	// ReasonPolicyObligationInvalid — an obligation is invalid for its action
	// (credential profile on DENY, missing one-call for ALLOW_ONCE, etc.).
	ReasonPolicyObligationInvalid
	// ReasonPolicyInputInvalid — a decision tuple is structurally invalid (missing
	// capability/revision, conflicting tenants, cross-capability authority, raw
	// token/body supplied, unknown enum). Distinct from a valid no-match default deny.
	ReasonPolicyInputInvalid
	// ReasonPolicyNamespaceMismatch — a snapshot mixes Gateway and Management rules,
	// or a rule/input crosses the capability namespace.
	ReasonPolicyNamespaceMismatch
	// ReasonPolicyStaleRevision — a snapshot publication used a stale base revision
	// (a concurrent publish won); nothing is published.
	ReasonPolicyStaleRevision
	// ReasonPolicyLimitExceeded — a policy structural/evaluation bound was exceeded
	// (rules/conditions/values/trace/simulator cases/compile work).
	ReasonPolicyLimitExceeded

	// ── PR-7 inspection reasons ───────────────────────────────────────────────
	// Appended (never reordered). Every reason is a DETERMINISTIC inspection
	// outcome; none ever carries a raw argument, raw output, matched secret,
	// bearer token, private key or full URL (Detail is fixed developer text). The
	// inspection layer translates any provider/resolver/parser error string into
	// one of these without embedding the untrusted external text.

	// ReasonSchemaInvalid — tool-call arguments (or a registered output) failed
	// SEMANTIC schema validation against the exact catalog input/output schema
	// (type/required/enum/bounds/format/additionalProperties). Distinct from the
	// PR-1 structural ReasonMalformedJSON: the bytes decoded, the VALUE is wrong.
	ReasonSchemaInvalid
	// ReasonSchemaUnsupported — the compiled schema (or the value under it) uses a
	// security-relevant keyword outside the closed supported V1 subset. Fails
	// conservative: an unsupported keyword on a decision-point tool is never
	// silently ignored.
	ReasonSchemaUnsupported
	// ReasonSchemaLimitExceeded — a schema compile/validation bound was exceeded
	// (schema nodes, alternatives, validation operations, argument nodes).
	ReasonSchemaLimitExceeded
	// ReasonOutputTooLarge — a structured output exceeded the security byte/node
	// bound. Structured over-limit output is BLOCKED (never blindly truncated).
	ReasonOutputTooLarge
	// ReasonOutputSchemaInvalid — an output failed validation against the tool's
	// registered output schema (or was not the required JSON type).
	ReasonOutputSchemaInvalid
	// ReasonSecretDetected — a secret/credential shape was found and the profile
	// disposition for that classification is BLOCK. The raw secret is never
	// carried in the error.
	ReasonSecretDetected
	// ReasonPIIDetected — a PII classification was found and the profile
	// disposition for it is BLOCK.
	ReasonPIIDetected
	// ReasonRedactionFailed — a MANDATORY redaction could not be produced or the
	// transformed copy failed re-validation (schema revalidation, residual secret,
	// broadened destination, missing/stale profile). Fails closed: no partial
	// transform is published.
	ReasonRedactionFailed
	// ReasonDestinationMalformed — a destination URL/host/IP failed canonicalization
	// (bad host syntax, malformed port, userinfo, control chars, ambiguous percent
	// encoding, non-canonical numeric-IP, IPv6 zone id, fragment-as-policy).
	ReasonDestinationMalformed
	// ReasonDestinationSchemeRejected — the destination scheme is not on the narrow
	// allowlist (file/data/javascript/gopher/ftp/unix/unknown rejected).
	ReasonDestinationSchemeRejected
	// ReasonSSRFBlocked — a destination resolved (or was verified at connect) to a
	// private/link-local/metadata/reserved/multicast/prohibited address. Wraps the
	// authoritative internal/ssrf table; never a second divergent private table.
	ReasonSSRFBlocked
	// ReasonDNSResolutionFailed — bounded DNS resolution timed out, returned an
	// empty answer, a malformed address, or overflowed the address-count bound.
	ReasonDNSResolutionFailed
	// ReasonDNSAnswerMixed — a DNS answer mixed public and private addresses. The
	// whole answer fails closed (a single private address poisons the answer).
	ReasonDNSAnswerMixed
	// ReasonDNSPinMismatch — the actual connect-time peer is not a member of the
	// immutable PinnedDestination address set, or the pin is stale/expired. The
	// rebinding TOCTOU guard.
	ReasonDNSPinMismatch
	// ReasonRedirectRejected — a redirect hop was refused (scheme downgrade,
	// userinfo, cross-origin without opt-in, public→private/metadata, credential
	// URL, malformed relative target, or a re-run destination/SSRF failure).
	ReasonRedirectRejected
	// ReasonRedirectLimitExceeded — the bounded redirect hop count was exceeded or
	// a redirect loop was detected.
	ReasonRedirectLimitExceeded
	// ReasonInjectionSuspected — best-effort deterministic labeling flagged output
	// content that attempts to instruct/manipulate the agent, and the profile
	// treats that label as a hard block (lower-confidence labels are reported, not
	// blocked).
	ReasonInjectionSuspected
	// ReasonInspectionUnavailable — a rule/operation required inspection evidence
	// that no inspector is wired to supply (fail closed for a high-risk operation;
	// never a silent pass).
	ReasonInspectionUnavailable
	// ReasonInspectionLimitExceeded — a general inspection bound was exceeded
	// (findings, redactions, extracted destinations, bytes scanned, safe-result
	// bytes) on a high-risk operation. Fails closed.
	ReasonInspectionLimitExceeded

	// ── PR-8 durable decision-event reasons ─────────────────────────────────
	// Appended at the end; every value above is frozen. These name the ways a
	// decision event can be rejected before persistence, a durable commit can
	// fail, a receipt can be forged/mismatched, and an export can be refused.

	// ReasonEventInvalid — a decision event failed structural validation before
	// persistence for a reason without a more specific code below (malformed
	// envelope, phase/category mismatch, unknown enum). Fails closed; no
	// malformed event ever partially publishes.
	ReasonEventInvalid
	// ReasonEventSchemaVersion — the event envelope carried an unknown or
	// unsupported schema version. Fails closed (no forward-guessing of an
	// unrecognised layout).
	ReasonEventSchemaVersion
	// ReasonEventPartitionMismatch — the event's partition does not match its
	// category/criticality: a critical operation routed outside P-CRIT, or an
	// authentication/authorization denial routed into P-CRIT. Fails closed.
	ReasonEventPartitionMismatch
	// ReasonEventTenantConflict — the event mixes tenants, or mixes Management
	// and Gateway capability fields, in a way that would break tenant/capability
	// isolation. Fails closed.
	ReasonEventTenantConflict
	// ReasonEventSecretPresent — the event carried raw token, credential,
	// private-key or other secret-classified material. Structural exclusion
	// rejects it before it can reach the spool; never redacted-in-place.
	ReasonEventSecretPresent
	// ReasonEventEvidenceMissing — a required revision or decision-evidence field
	// was absent (e.g. a critical decision with no action-class binding, an
	// outcome event referencing no committed decision). Fails closed.
	ReasonEventEvidenceMissing
	// ReasonEventTooLarge — the encoded event, or one of its bounded fields,
	// exceeded the configured event/metadata byte bound. Fails closed.
	ReasonEventTooLarge
	// ReasonEventCorrelationMalformed — an event ID, replay ID or correlation ID
	// was malformed or out of the accepted shape/bounds. Fails closed.
	ReasonEventCorrelationMalformed
	// ReasonEventReplayConflict — a second, DIFFERING critical event was appended
	// under a replay identity already bound to a different committed event within
	// the retained window. Deterministic duplicate rejection; never two differing
	// committed critical events under one replay identity.
	ReasonEventReplayConflict
	// ReasonEventQueueSaturated — bounded-queue admission failed. For a critical
	// event this is a critical commit FAILURE (fail closed), not an invitation to
	// drop the event.
	ReasonEventQueueSaturated
	// ReasonEventCommitFailed — a durable commit failed after admission (short
	// write, append error, fsync/dir-sync error, checkpoint-metadata failure,
	// rotation failure). Admission is not durability; the record is not
	// acknowledged and the triggering critical operation fails closed.
	ReasonEventCommitFailed
	// ReasonEventEncryptionUnavailable — the spool encryption key/provider was
	// unavailable at commit time. Treated as a commit FAILURE, never a plaintext
	// fallback. Fails closed.
	ReasonEventEncryptionUnavailable
	// ReasonEventEncryptionFailed — authenticated encryption (or its inverse on
	// recovery) failed. Treated as a commit/integrity FAILURE, never a plaintext
	// fallback. Fails closed.
	ReasonEventEncryptionFailed
	// ReasonEventStorageFull — storage returned ENOSPC and deterministic
	// reclamation could not free space without reclaiming unexported critical
	// evidence. Fails closed; the domain enters critical-durability-degraded.
	ReasonEventStorageFull
	// ReasonEventSpoolCorrupt — segment/record/checkpoint integrity verification
	// failed, or recovery metadata was ambiguous/corrupt. Fails toward the narrow
	// local critical-durability-degraded state, never toward normal.
	ReasonEventSpoolCorrupt
	// ReasonEventDurabilityDegraded — the durability domain is in
	// critical-durability-degraded, so a new critical operation in that domain
	// fails closed until the bounded recovery criteria are met.
	ReasonEventDurabilityDegraded
	// ReasonEventDenialLaneDegraded — a coalesced denial aggregate could not be
	// committed, or P-DEN reached its quota. Recorded on the DISTINCT denial-loss
	// counter; the request stays denied; NEVER blocks authenticated work and
	// NEVER enters critical-durability-degraded.
	ReasonEventDenialLaneDegraded
	// ReasonEventReceiptInvalid — a commit receipt was forged, mismatched against
	// its decision digest, or presented for a different request/tenant/capability
	// than it was bound to. Fails closed.
	ReasonEventReceiptInvalid
	// ReasonEventExportUnauthorized — an export/read request failed tenant,
	// capability or partition-scope authorization (including any cross-tenant
	// read). Fails closed.
	ReasonEventExportUnauthorized
	// ReasonEventExportRangeExceeded — an export/read request exceeded its bounded
	// range, record count or byte budget. Fails closed.
	ReasonEventExportRangeExceeded

	// ── PR-9 admin API / Management MCP / approval / publication reasons ──

	// ReasonAdminRequestInvalid — a malformed admin/Management request: a bad
	// cursor, identifier, enum value, sort direction or filter. Fails closed.
	ReasonAdminRequestInvalid
	// ReasonAdminRangeExceeded — an admin/Management request exceeded a bounded
	// page size, time range, simulation corpus, comparison sample or record/byte
	// budget. Fails closed.
	ReasonAdminRangeExceeded
	// ReasonAdminUnknownField — an admin/Management request carried an unknown
	// query parameter or body field under the strict-decode contract. Fails closed.
	ReasonAdminUnknownField
	// ReasonAdminNotFound — the addressed admin/Management resource does not exist
	// within the caller's authorized tenant scope. Returned uniformly so a caller
	// cannot distinguish "absent" from "exists in another tenant".
	ReasonAdminNotFound
	// ReasonAdminForbidden — the resolved administrative or Management identity is
	// not authorized for the requested operation (role, scope or tenant). Fails
	// closed; never leaks the existence of the target.
	ReasonAdminForbidden
	// ReasonAdminTenantScope — a request attempted to read or act across a tenant
	// boundary, or supplied a tenant hint not backed by the authenticated identity.
	// Fails closed; no cross-tenant record, count, range or existence is revealed.
	ReasonAdminTenantScope

	// ReasonApprovalNotFound — the addressed approval or publication request does
	// not exist within the caller's authorized tenant scope. Uniform not-found.
	ReasonApprovalNotFound
	// ReasonApprovalSelfApproval — four-eyes violation: the approver is the same
	// authenticated principal as the requester. Rejected.
	ReasonApprovalSelfApproval
	// ReasonApprovalExpired — the approval/publication request is past its TTL and
	// can no longer be approved. Rejected.
	ReasonApprovalExpired
	// ReasonApprovalStaleRevision — a bound policy, catalog, tool or credential
	// revision changed since the request was created, invalidating it. Rejected.
	ReasonApprovalStaleRevision
	// ReasonApprovalTerminalState — the request is already in a terminal
	// (approved/rejected) state; terminal states are immutable. A conflicting
	// transition is rejected; an identical repeat is idempotent.
	ReasonApprovalTerminalState
	// ReasonApprovalBindingMismatch — the presented candidate/decision digest,
	// tenant, capability, base revision or expiry does not match the immutable
	// request binding (a TOCTOU guard). Rejected.
	ReasonApprovalBindingMismatch

	// ReasonPublicationValidationFailed — a candidate policy document failed
	// compilation/validation and must not be published. Fails closed.
	ReasonPublicationValidationFailed
	// ReasonPublicationStaleBase — the expected base revision does not match the
	// active local revision at publish time (optimistic-concurrency guard).
	ReasonPublicationStaleBase
	// ReasonPublicationNotApproved — a local publication was attempted without a
	// matching four-eyes approval bound to the exact candidate. Fails closed.
	ReasonPublicationNotApproved
	// ReasonPublicationDurabilityRequired — the required PR-8 P-CRIT publication
	// event did not durably commit, so nothing is published and the active policy
	// is retained. Fails closed.
	ReasonPublicationDurabilityRequired

	// ReasonManagementToolUnknown — a tools/call named a tool outside the fixed
	// Management catalog, or one the resolved identity was never authorized to see.
	// A remembered-but-unauthorized name gains no authority. Fails closed.
	ReasonManagementToolUnknown
	// ReasonManagementToolUnauthorized — the resolved Management identity is not
	// authorized for the selected tool (scope, role, capability or tenant). Each
	// tools/call is re-authorized independently of any prior tools/list. Fails closed.
	ReasonManagementToolUnauthorized
	// ReasonManagementResultTooLarge — a Management result exceeded the bounded
	// safe-result byte budget and could not be safely returned; the caller must
	// page. Fails closed rather than truncating unsafely.
	ReasonManagementResultTooLarge

	// ReasonConfigInvalid — a candidate PR-9 listener/access configuration failed
	// validation (missing reference, bad value, or Gateway/Management overlap of
	// address, port, OAuth resource, client or scope). Current runtime retained.
	ReasonConfigInvalid
	// ReasonConfigApplyFailed — a validated local configuration could not be
	// applied/bound; the previous running configuration is retained unchanged and
	// no CP→DP propagation is claimed. Fails closed.
	ReasonConfigApplyFailed

	// ── PR-10 signed CP→DP snapshot / fencing / rollback reasons ──

	// ReasonSnapshotMalformed — the snapshot envelope is structurally invalid:
	// undecodable, truncated, a duplicate canonical field, or a bounded header
	// field could not be located. Rejected whole; no partial apply.
	ReasonSnapshotMalformed
	// ReasonSnapshotSchemaUnknown — the snapshot declares a schema version outside
	// the supported set (a newer/unknown schema a DP must not partially interpret).
	// Rejected whole.
	ReasonSnapshotSchemaUnknown
	// ReasonSnapshotCapabilityMismatch — the snapshot's signed capability does not
	// match the target store, or the payload carries a field belonging to the other
	// capability (Gateway↔Management isolation). Fails closed.
	ReasonSnapshotCapabilityMismatch
	// ReasonSnapshotAlgUnknown — the signature algorithm identifier is not the one
	// supported algorithm (ed25519). An unknown alg is never treated as ed25519.
	ReasonSnapshotAlgUnknown
	// ReasonSnapshotKeyUntrusted — the signing key ID is not present in the DP's
	// trust store. A key carried inside the snapshot never authorizes itself.
	ReasonSnapshotKeyUntrusted
	// ReasonSnapshotHashMismatch — the recomputed content hash over the canonical
	// unsigned manifest+payload does not equal the declared content_hash.
	ReasonSnapshotHashMismatch
	// ReasonSnapshotSignatureInvalid — the Ed25519 signature did not verify against
	// the trusted public key over the domain-separated signing input.
	ReasonSnapshotSignatureInvalid
	// ReasonSnapshotTooLarge — an envelope, payload section, or aggregate byte/entry
	// bound was exceeded. Rejected before any state mutation.
	ReasonSnapshotTooLarge
	// ReasonSnapshotRevisionInvalid — a revision in the tuple is negative, missing,
	// out of bounds, or inconsistent with the payload actually included.
	ReasonSnapshotRevisionInvalid
	// ReasonSnapshotRevisionRegression — a lower revision arrived in the same or a
	// lower epoch, or the same revision arrived with a different content hash.
	// Rejected (never silently regresses component state).
	ReasonSnapshotRevisionRegression
	// ReasonSnapshotEpochStale — the snapshot's configuration epoch is below the
	// DP's last-seen trusted epoch (a stale/zombie Control Plane). Rejected without
	// ratcheting; the DP keeps serving its last valid snapshot.
	ReasonSnapshotEpochStale
	// ReasonSnapshotEpochInvalid — an unfenced/zero epoch after a positive epoch was
	// already observed, or a higher epoch whose authenticity did not pass (so it
	// must not ratchet the trusted epoch). Fails closed.
	ReasonSnapshotEpochInvalid
	// ReasonSnapshotMinVersionUnmet — the receiving DP's compatibility version is
	// below the snapshot's minimum_dp_version; it must not apply semantics it cannot
	// interpret. The DP keeps its prior valid snapshot.
	ReasonSnapshotMinVersionUnmet
	// ReasonSnapshotMinVersionMalformed — the minimum_dp_version is absent or not a
	// valid monotonic compatibility value for a PR-10 MCP snapshot. Rejected.
	ReasonSnapshotMinVersionMalformed
	// ReasonSnapshotValidationFailed — a whole-snapshot semantic validation failed
	// (registry/catalog/policy/credential/inspection consistency, required
	// references, safe configuration). Rejected whole; active state unchanged.
	ReasonSnapshotValidationFailed
	// ReasonSnapshotPersistFailed — the DP could not durably persist the validated
	// candidate before the atomic swap; activation is aborted and the current active
	// snapshot is retained byte-unchanged. Fails closed.
	ReasonSnapshotPersistFailed
	// ReasonSnapshotSignerUnavailable — signing is required but the CP signer is
	// unavailable; nothing is signed or published. Fails closed.
	ReasonSnapshotSignerUnavailable
	// ReasonDistributionWriteAuthority — the CP is not the write-authoritative
	// lease holder at the irreversible publication boundary (lost/never-held lease
	// or a fenced-out generation). Publication is refused.
	ReasonDistributionWriteAuthority
	// ReasonAckInvalid — a DP acknowledgement is malformed or does not bind to a
	// known snapshot: wrong node identity, wrong capability, or an unknown content
	// hash. An acknowledgement for one snapshot never satisfies another.
	ReasonAckInvalid
	// ReasonAckUnauthenticated — an acknowledgement arrived over an unauthenticated
	// channel (no enrolled-node identity). Rejected.
	ReasonAckUnauthenticated
	// ReasonRollbackTargetMissing — the rollback directive references a retained
	// target snapshot the DP does not hold. Refused; current snapshot retained.
	ReasonRollbackTargetMissing
	// ReasonRollbackTargetCorrupt — the retained rollback target failed
	// re-verification (hash/signature) at rollback time. Refused; current retained.
	ReasonRollbackTargetCorrupt
	// ReasonRollbackDirectiveInvalid — the signed rollback directive is invalid:
	// bad signature, expired, wrong current hash, or a capability/epoch mismatch.
	ReasonRollbackDirectiveInvalid

	// ─── PR-11 · guarded execution, shadow/canary rollout, upstream client ───
	// These are appended (never reordered); the iota order above is frozen.

	// ReasonRolloutModeInvalid — a rollout mode value is unknown/unparseable, or a
	// zero/unset mode reached a place that requires a concrete mode. Fails closed
	// (treated as Disabled — no execution).
	ReasonRolloutModeInvalid
	// ReasonRolloutTransitionInvalid — an illegal mode transition: a promotion that
	// skips a stage (e.g. Disabled→Shadow, Observe→Canary), an unknown/future target
	// mode, or a same-revision transition with different rollout content. Rejected.
	ReasonRolloutTransitionInvalid
	// ReasonRolloutProductionLocked — a transition into Production was attempted
	// without a valid Production Qualification receipt. Production is fail-closed and
	// unreachable in this build; no env/flag/API/snapshot field bypasses this.
	ReasonRolloutProductionLocked
	// ReasonRolloutQualificationInvalid — a supplied Production Qualification receipt
	// failed verification, or is not bound to the exact target scope + snapshot hash.
	// Rejected; Production stays locked.
	ReasonRolloutQualificationInvalid
	// ReasonRolloutScopeInvalid — a rollout scope is malformed: a wildcard "all"
	// default, an over-limit selector/expansion count, a percentage bucket without a
	// stable bound salt, or a non-deterministic selector. Fails closed (empty scope).
	ReasonRolloutScopeInvalid
	// ReasonRolloutScopeStaleBase — a scope/mode change was submitted against a base
	// revision that is no longer current (optimistic-concurrency loss). Rejected.
	ReasonRolloutScopeStaleBase
	// ReasonRolloutConnectorModeRejected — a connector mode other than "local-client"
	// (Model A) was supplied — "outbound-connector" (Model B) and "dmz-endpoint"
	// (Model C) are reserved, unimplemented, and rejected on every surface in V1.
	ReasonRolloutConnectorModeRejected
	// ReasonRolloutEvidenceInsufficient — a promotion's evidence window (shadow/canary
	// duration, soak, zero-open-defects) is not yet satisfied. Reporting-only gate;
	// the promotion is not published until the evidence is present.
	ReasonRolloutEvidenceInsufficient
	// ReasonRolloutEmergencyActive — a capability-local kill switch (emergency disable)
	// is engaged; new admission for that capability is refused until it is cleared.
	ReasonRolloutEmergencyActive
	// ReasonRolloutOutOfScope — a request is outside the active rollout scope for its
	// capability. Informational disposition (Observe/Shadow behavior applies); never a
	// hard failure by itself.
	ReasonRolloutOutOfScope
	// ReasonExecutionNotPermitted — real upstream execution is not permitted for this
	// request in the current mode/scope (Disabled/Observe, or out-of-scope). The
	// decision is recorded; no upstream call is made.
	ReasonExecutionNotPermitted
	// ReasonConfirmationRequired — the policy action is REQUIRE_CONFIRMATION and no
	// valid exact-call confirmation obligation was satisfied. No execution.
	ReasonConfirmationRequired
	// ReasonApprovalRequired — the policy action is REQUIRE_APPROVAL and no valid exact
	// approval receipt was satisfied (four-eyes). No execution.
	ReasonApprovalRequired
	// ReasonObligationReceiptInvalid — a confirmation/approval receipt is stale,
	// expired, or does not bind the exact tenant/tool/args/destination/revisions/
	// snapshot. Rejected; the allowance is not consumed.
	ReasonObligationReceiptInvalid
	// ReasonAllowanceConsumed — an ALLOW_ONCE grant was already consumed, or an
	// ALLOW_FOR_SESSION grant exceeded its bound call count / TTL / session. No
	// execution; a failed pre-execution hard control never consumes an allowance.
	ReasonAllowanceConsumed
	// ReasonAllowanceInvalid — an allowance grant is malformed or not bound to this
	// exact session/call. Fails closed.
	ReasonAllowanceInvalid
	// ReasonUpstreamEndpointInvalid — the upstream endpoint was not resolved from the
	// registered server record (e.g. a request-supplied arbitrary URL). Refused; no
	// dial is attempted.
	ReasonUpstreamEndpointInvalid
	// ReasonUpstreamServerUnusable — the target server is unregistered, disabled, or
	// its pinned identity no longer verifies. Refused before any connection.
	ReasonUpstreamServerUnusable
	// ReasonUpstreamVersionUnsupported — no mutually supported MCP protocol version
	// could be negotiated with the upstream server (no legacy/downgrade path).
	ReasonUpstreamVersionUnsupported
	// ReasonUpstreamTransportRejected — the upstream leg attempted a rejected
	// transport: legacy HTTP+SSE, a JSON-RPC batch, an automatic downgrade, or an
	// arbitrary/extension method outside the admitted V1 set. Refused.
	ReasonUpstreamTransportRejected
	// ReasonUpstreamResponseInvalid — the upstream response failed strict kernel
	// decoding or admitted-shape validation. The whole response is rejected.
	ReasonUpstreamResponseInvalid
	// ReasonUpstreamResponseTooLarge — the upstream response exceeded the configured
	// header/body/result byte bound. Rejected before buffering the remainder.
	ReasonUpstreamResponseTooLarge
	// ReasonUpstreamConnectFailed — the connection to the upstream server could not be
	// established (dial/TLS handshake failure). Sanitized; no raw network error text.
	ReasonUpstreamConnectFailed
	// ReasonUpstreamTLSIdentity — the connected upstream peer's TLS/workload identity
	// did not match the server record's pinned identity (connect-time verification).
	ReasonUpstreamTLSIdentity
	// ReasonUpstreamTimeout — a connect, TLS-handshake, or response deadline/budget was
	// exceeded on the upstream leg. Fails closed.
	ReasonUpstreamTimeout
	// ReasonUpstreamPoolExhausted — the bounded per-server connection pool or request
	// queue was exhausted. Refused (availability bound), never unbounded.
	ReasonUpstreamPoolExhausted
	// ReasonUpstreamCancelled — the client cancelled or the request context was
	// cancelled; cancellation was propagated to the upstream leg. Not a server fault.
	ReasonUpstreamCancelled
	// ReasonUpstreamRetryDenied — an ambiguous transport outcome on a write/destructive
	// tools/call is never auto-retried (at-most-once). Refused rather than duplicated.
	ReasonUpstreamRetryDenied
	// ReasonUpstreamCallFailed — a generic, sanitized upstream tools/call failure that
	// is not one of the more specific classes above. No raw upstream error is exposed.
	ReasonUpstreamCallFailed
	// ReasonUpstreamDiscoveryFailed — an upstream tools/list discovery failed (fetch,
	// decode, or ingestion). The previous known-good catalog is retained unchanged.
	ReasonUpstreamDiscoveryFailed

	// ── transport anti-ambiguity ──────────────────────────────────────────────

	// ReasonAmbiguousRequestHeader — a SINGLETON security-relevant request header
	// (Origin, DPoP, Mcp-Session-Id, MCP-Protocol-Version, Authorization) was
	// presented more than once. Culvert never resolves such a conflict by picking a
	// value: an intermediary and the gateway could pick differently, so the request
	// is rejected whole. Appended at the END of the enum so no existing ordinal moves.
	ReasonAmbiguousRequestHeader

	// ReasonDecisionSnapshotStale — the tool a policy decision was made ABOUT is no
	// longer the tool the live catalog reports (its fingerprint moved, or it is
	// gone). The decision is stale and must not authorize the call. Appended at the
	// END of the enum so no existing ordinal moves.
	ReasonDecisionSnapshotStale

	// ─── tool-trust approval / promotion (ADR-0034) ───
	// Appended at the END of the enum; every ordinal above is frozen. These name
	// the ways a tool-trust (catalog Usable promotion) decision is refused. None
	// carries a token, credential, raw schema/body, or private identity material —
	// Detail is fixed developer text.

	// ReasonToolNotApprovable — the addressed tool is not in a state a trust grant
	// can promote (e.g. its server identity changed and it is ServerDisabled, or it
	// is already the target of a live grant). Fails closed; never promotes.
	ReasonToolNotApprovable
	// ReasonToolApprovalStale — the catalog advanced under the decision (a concurrent
	// ingest won the optimistic CAS), so the exact reviewed target can no longer be
	// promoted atomically. The caller re-reads and re-decides; nothing is promoted.
	ReasonToolApprovalStale
	// ReasonToolFingerprintMismatch — the tool's CURRENT observed fingerprint does
	// not exactly match the reviewed digest the approval binds to (the rug-pull
	// guard). A trust decision never authorizes a different fingerprint. Fails closed.
	ReasonToolFingerprintMismatch
	// ReasonServerNotUsable — the tool's server is unregistered, disabled, or its
	// pinned identity no longer verifies, so no tool behind it can be promoted.
	ReasonServerNotUsable
	// ReasonToolNotFound — the addressed tool does not exist in the live catalog
	// within the caller's authorized tenant scope. Uniform not-found.
	ReasonToolNotFound
	// ReasonApprovalRevoked — the approval was revoked (terminal). A revoked grant
	// never re-activates from a later identical discovery; a fresh decision is
	// required. Rejected.
	ReasonApprovalRevoked
	// ReasonApprovalTenantConflict — the approval's tenant does not match the target
	// server's ownership scope, or a cross-tenant approval action was attempted.
	// Fails closed; no cross-tenant existence is revealed.
	ReasonApprovalTenantConflict
	// ReasonApprovalPurposeUnsupported — an approval purpose that is not issuable in
	// this build was requested (only shadow_evaluation is issuable; live_execution is
	// refused at issue). The live-execution firewall's negative half. Fails closed.
	ReasonApprovalPurposeUnsupported
	// ReasonApprovalNotAuthorized — the actor is not authorized for the requested
	// trust operation (role, scope, or an empty/over-bound actor). Fails closed.
	ReasonApprovalNotAuthorized
	// ReasonApprovalStoreUnavailable — the durable approval store could not be written
	// (a full or read-only disk, an I/O error). The in-memory state is left unchanged and
	// the unchanged mutation is RETRYABLE once storage recovers, so it maps to 503 (service
	// unavailable), never 400 — the caller's input was valid. Distinct from
	// ReasonConfigInvalid, which is reserved for a corrupt/marshal/decode fault.
	ReasonApprovalStoreUnavailable
	// ReasonRolloutBudgetExhausted — the Canary blast-radius budget denied a live execution
	// (whole-Canary total/window/concurrency/rate spent, or a per-identity blast-radius cap
	// exceeded). No upstream call is made. Distinct from an emergency kill and from a trust
	// failure so §14 evidence can tell "approved + budget-aborted" apart from the others.
	ReasonRolloutBudgetExhausted
	// ReasonLiveTrustRevalidationFailed — the runtime live-execution trust revalidation at the
	// side-effect boundary found no currently-valid live_execution approval binding the exact
	// tenant/server/tool/fingerprint (revoked, expired, tool drifted, or never approved). No
	// upstream call is made. Distinct from ReasonApprovalRequired (a policy-level obligation) so
	// evidence can tell a runtime trust withdrawal apart from a decision-time approval gap.
	ReasonLiveTrustRevalidationFailed
)

// reasonCode maps each Reason to its stable machine string. The strings are part
// of the package contract and MUST NOT change without a coordinated update.
//
//nolint:gosec // G101: these are stable machine-readable error codes, not credentials.
var reasonCode = map[Reason]string{ // #nosec G101 -- stable machine-readable error-code strings (e.g. "token_expired"), not hardcoded credentials
	ReasonNone:                 "none",
	ReasonMalformedJSON:        "malformed_json",
	ReasonInvalidJSONRPC:       "invalid_jsonrpc",
	ReasonUnsupportedBatch:     "unsupported_batch",
	ReasonUnsupportedVersion:   "unsupported_version",
	ReasonUnsupportedMethod:    "unsupported_method",
	ReasonResourceLimit:        "resource_limit",
	ReasonInvalidLifecycle:     "invalid_lifecycle",
	ReasonUncorrelatedResponse: "uncorrelated_response",
	ReasonDuplicateCompletion:  "duplicate_completion",
	ReasonInvalidCancellation:  "invalid_cancellation",
	ReasonLateCancellation:     "late_cancellation",

	ReasonInvalidRegistration:    "invalid_registration",
	ReasonUnregisteredServer:     "unregistered_server",
	ReasonServerIdentityMismatch: "server_identity_mismatch",
	ReasonMalformedDiscovery:     "malformed_discovery",
	ReasonDuplicateTool:          "duplicate_tool",
	ReasonCanonicalizationFailed: "canonicalization_failed",
	ReasonCapacityExceeded:       "capacity_exceeded",
	ReasonUnknownTool:            "unknown_tool",
	ReasonPrivilegeExpansion:     "privilege_expansion",
	ReasonSemanticDrift:          "semantic_drift",
	ReasonStaleSnapshot:          "stale_snapshot",

	ReasonCredentialMissing:         "credential_missing",
	ReasonCredentialInQuery:         "credential_in_query",
	ReasonMalformedToken:            "malformed_token",
	ReasonUnsupportedTokenType:      "unsupported_token_type",
	ReasonUnsupportedAlgorithm:      "unsupported_algorithm",
	ReasonSignatureInvalid:          "signature_invalid",
	ReasonIssuerRejected:            "issuer_rejected",
	ReasonAudienceMissing:           "audience_missing",
	ReasonAudienceRejected:          "audience_rejected",
	ReasonResourceMismatch:          "resource_mismatch",
	ReasonTokenExpired:              "token_expired",
	ReasonTokenNotYetValid:          "token_not_yet_valid",
	ReasonTokenTTLExceeded:          "token_ttl_exceeded",
	ReasonScopeMissing:              "scope_missing",
	ReasonCapabilityMismatch:        "capability_mismatch",
	ReasonTenantMismatch:            "tenant_mismatch",
	ReasonDelegationChainInvalid:    "delegation_chain_invalid",
	ReasonSenderConstraintRequired:  "sender_constraint_required",
	ReasonDPoPMalformed:             "dpop_malformed",
	ReasonDPoPBindingMismatch:       "dpop_binding_mismatch",
	ReasonDPoPReplay:                "dpop_replay",
	ReasonDPoPNonce:                 "dpop_nonce",
	ReasonMTLSBindingMismatch:       "mtls_binding_mismatch",
	ReasonInactiveToken:             "inactive_token",
	ReasonSessionIdentityBound:      "session_identity_bound",
	ReasonSessionIdentityRebind:     "session_identity_rebind",
	ReasonRegistryServerUnavailable: "registry_server_unavailable",

	ReasonCredentialProfileMissing:       "credential_profile_missing",
	ReasonCredentialProfileDisabled:      "credential_profile_disabled",
	ReasonCredentialProfileAmbiguous:     "credential_profile_ambiguous",
	ReasonProviderUnavailable:            "provider_unavailable",
	ReasonProviderUnsupportedOperation:   "provider_unsupported_operation",
	ReasonProviderInvalidMaterial:        "provider_invalid_material",
	ReasonCredentialScopeMismatch:        "credential_scope_mismatch",
	ReasonCredentialPowerExceeded:        "credential_power_exceeded",
	ReasonCredentialExpired:              "credential_expired",
	ReasonCredentialRevoked:              "credential_revoked",
	ReasonCredentialVersionStale:         "credential_version_stale",
	ReasonCacheMiss:                      "cache_miss",
	ReasonCacheFull:                      "cache_full",
	ReasonCacheIntegrityFailure:          "cache_integrity_failure",
	ReasonRotationInProgress:             "rotation_in_progress",
	ReasonRotationFailed:                 "rotation_failed",
	ReasonRevocationFailed:               "revocation_failed",
	ReasonMaterializationGateDenied:      "materialization_gate_denied",
	ReasonMaterializationGateUnavailable: "materialization_gate_unavailable",
	ReasonMaterialAlreadyConsumed:        "material_already_consumed",
	ReasonCredentialKindUnsupported:      "credential_kind_unsupported",

	ReasonListenerDisabled:        "listener_disabled",
	ReasonHTTPMethodRejected:      "http_method_rejected",
	ReasonHostRejected:            "host_rejected",
	ReasonOriginRejected:          "origin_rejected",
	ReasonAdmissionRejected:       "admission_rejected",
	ReasonObserveOnly:             "observe_only",
	ReasonTLSRequired:             "tls_required",
	ReasonListenerConfigInvalid:   "listener_config_invalid",
	ReasonRequestDeadlineExceeded: "request_deadline_exceeded",

	ReasonPolicySnapshotInvalid:   "policy_snapshot_invalid",
	ReasonPolicyRuleInvalid:       "policy_rule_invalid",
	ReasonPolicyConditionInvalid:  "policy_condition_invalid",
	ReasonPolicyObligationInvalid: "policy_obligation_invalid",
	ReasonPolicyInputInvalid:      "policy_input_invalid",
	ReasonPolicyNamespaceMismatch: "policy_namespace_mismatch",
	ReasonPolicyStaleRevision:     "policy_stale_revision",
	ReasonPolicyLimitExceeded:     "policy_limit_exceeded",

	ReasonSchemaInvalid:             "schema_invalid",
	ReasonSchemaUnsupported:         "schema_unsupported",
	ReasonSchemaLimitExceeded:       "schema_limit_exceeded",
	ReasonOutputTooLarge:            "output_too_large",
	ReasonOutputSchemaInvalid:       "output_schema_invalid",
	ReasonSecretDetected:            "secret_detected",
	ReasonPIIDetected:               "pii_detected",
	ReasonRedactionFailed:           "redaction_failed",
	ReasonDestinationMalformed:      "destination_malformed",
	ReasonDestinationSchemeRejected: "destination_scheme_rejected",
	ReasonSSRFBlocked:               "ssrf_blocked",
	ReasonDNSResolutionFailed:       "dns_resolution_failed",
	ReasonDNSAnswerMixed:            "dns_answer_mixed",
	ReasonDNSPinMismatch:            "dns_pin_mismatch",
	ReasonRedirectRejected:          "redirect_rejected",
	ReasonRedirectLimitExceeded:     "redirect_limit_exceeded",
	ReasonInjectionSuspected:        "injection_suspected",
	ReasonInspectionUnavailable:     "inspection_unavailable",
	ReasonInspectionLimitExceeded:   "inspection_limit_exceeded",

	// ── PR-8 durable decision-event reasons ──
	ReasonEventInvalid:               "event_invalid",
	ReasonEventSchemaVersion:         "event_schema_version",
	ReasonEventPartitionMismatch:     "event_partition_mismatch",
	ReasonEventTenantConflict:        "event_tenant_conflict",
	ReasonEventSecretPresent:         "event_secret_present",
	ReasonEventEvidenceMissing:       "event_evidence_missing",
	ReasonEventTooLarge:              "event_too_large",
	ReasonEventCorrelationMalformed:  "event_correlation_malformed",
	ReasonEventReplayConflict:        "event_replay_conflict",
	ReasonEventQueueSaturated:        "event_queue_saturated",
	ReasonEventCommitFailed:          "event_commit_failed",
	ReasonEventEncryptionUnavailable: "event_encryption_unavailable",
	ReasonEventEncryptionFailed:      "event_encryption_failed",
	ReasonEventStorageFull:           "event_storage_full",
	ReasonEventSpoolCorrupt:          "event_spool_corrupt",
	ReasonEventDurabilityDegraded:    "event_durability_degraded",
	ReasonEventDenialLaneDegraded:    "event_denial_lane_degraded",
	ReasonEventReceiptInvalid:        "event_receipt_invalid",
	ReasonEventExportUnauthorized:    "event_export_unauthorized",
	ReasonEventExportRangeExceeded:   "event_export_range_exceeded",

	// ── PR-9 admin API / Management MCP / approval / publication reasons ──
	ReasonAdminRequestInvalid: "admin_request_invalid",
	ReasonAdminRangeExceeded:  "admin_range_exceeded",
	ReasonAdminUnknownField:   "admin_unknown_field",
	ReasonAdminNotFound:       "admin_not_found",
	ReasonAdminForbidden:      "admin_forbidden",
	ReasonAdminTenantScope:    "admin_tenant_scope",

	ReasonApprovalNotFound:        "approval_not_found",
	ReasonApprovalSelfApproval:    "approval_self_approval",
	ReasonApprovalExpired:         "approval_expired",
	ReasonApprovalStaleRevision:   "approval_stale_revision",
	ReasonApprovalTerminalState:   "approval_terminal_state",
	ReasonApprovalBindingMismatch: "approval_binding_mismatch",

	ReasonPublicationValidationFailed:   "publication_validation_failed",
	ReasonPublicationStaleBase:          "publication_stale_base",
	ReasonPublicationNotApproved:        "publication_not_approved",
	ReasonPublicationDurabilityRequired: "publication_durability_required",

	ReasonManagementToolUnknown:      "management_tool_unknown",
	ReasonManagementToolUnauthorized: "management_tool_unauthorized",
	ReasonManagementResultTooLarge:   "management_result_too_large",

	ReasonConfigInvalid:     "config_invalid",
	ReasonConfigApplyFailed: "config_apply_failed",

	// ── PR-10 signed CP→DP snapshot / fencing / rollback reasons ──
	ReasonSnapshotMalformed:           "snapshot_malformed",
	ReasonSnapshotSchemaUnknown:       "snapshot_schema_unknown",
	ReasonSnapshotCapabilityMismatch:  "snapshot_capability_mismatch",
	ReasonSnapshotAlgUnknown:          "snapshot_alg_unknown",
	ReasonSnapshotKeyUntrusted:        "snapshot_key_untrusted",
	ReasonSnapshotHashMismatch:        "snapshot_hash_mismatch",
	ReasonSnapshotSignatureInvalid:    "snapshot_signature_invalid",
	ReasonSnapshotTooLarge:            "snapshot_too_large",
	ReasonSnapshotRevisionInvalid:     "snapshot_revision_invalid",
	ReasonSnapshotRevisionRegression:  "snapshot_revision_regression",
	ReasonSnapshotEpochStale:          "snapshot_epoch_stale",
	ReasonSnapshotEpochInvalid:        "snapshot_epoch_invalid",
	ReasonSnapshotMinVersionUnmet:     "snapshot_min_version_unmet",
	ReasonSnapshotMinVersionMalformed: "snapshot_min_version_malformed",
	ReasonSnapshotValidationFailed:    "snapshot_validation_failed",
	ReasonSnapshotPersistFailed:       "snapshot_persist_failed",
	ReasonSnapshotSignerUnavailable:   "snapshot_signer_unavailable",
	ReasonDistributionWriteAuthority:  "distribution_write_authority",
	ReasonAckInvalid:                  "ack_invalid",
	ReasonAckUnauthenticated:          "ack_unauthenticated",
	ReasonRollbackTargetMissing:       "rollback_target_missing",
	ReasonRollbackTargetCorrupt:       "rollback_target_corrupt",
	ReasonRollbackDirectiveInvalid:    "rollback_directive_invalid",

	// PR-11 — guarded execution, shadow/canary rollout, upstream client
	ReasonRolloutModeInvalid:           "rollout_mode_invalid",
	ReasonRolloutTransitionInvalid:     "rollout_transition_invalid",
	ReasonRolloutProductionLocked:      "rollout_production_locked",
	ReasonRolloutQualificationInvalid:  "rollout_qualification_invalid",
	ReasonRolloutScopeInvalid:          "rollout_scope_invalid",
	ReasonRolloutScopeStaleBase:        "rollout_scope_stale_base",
	ReasonRolloutConnectorModeRejected: "rollout_connector_mode_rejected",
	ReasonRolloutEvidenceInsufficient:  "rollout_evidence_insufficient",
	ReasonRolloutEmergencyActive:       "rollout_emergency_active",
	ReasonRolloutOutOfScope:            "rollout_out_of_scope",
	ReasonExecutionNotPermitted:        "execution_not_permitted",
	ReasonConfirmationRequired:         "confirmation_required",
	ReasonApprovalRequired:             "approval_required",
	ReasonObligationReceiptInvalid:     "obligation_receipt_invalid",
	ReasonAllowanceConsumed:            "allowance_consumed",
	ReasonAllowanceInvalid:             "allowance_invalid",
	ReasonUpstreamEndpointInvalid:      "upstream_endpoint_invalid",
	ReasonUpstreamServerUnusable:       "upstream_server_unusable",
	ReasonUpstreamVersionUnsupported:   "upstream_version_unsupported",
	ReasonUpstreamTransportRejected:    "upstream_transport_rejected",
	ReasonUpstreamResponseInvalid:      "upstream_response_invalid",
	ReasonUpstreamResponseTooLarge:     "upstream_response_too_large",
	ReasonUpstreamConnectFailed:        "upstream_connect_failed",
	ReasonUpstreamTLSIdentity:          "upstream_tls_identity",
	ReasonUpstreamTimeout:              "upstream_timeout",
	ReasonUpstreamPoolExhausted:        "upstream_pool_exhausted",
	ReasonUpstreamCancelled:            "upstream_cancelled",
	ReasonUpstreamRetryDenied:          "upstream_retry_denied",
	ReasonUpstreamCallFailed:           "upstream_call_failed",
	ReasonUpstreamDiscoveryFailed:      "upstream_discovery_failed",
	ReasonAmbiguousRequestHeader:       "ambiguous_request_header",
	ReasonDecisionSnapshotStale:        "decision_snapshot_stale",

	// ─── tool-trust approval / promotion (ADR-0034) ───
	ReasonToolNotApprovable:           "tool_not_approvable",
	ReasonToolApprovalStale:           "tool_approval_stale",
	ReasonToolFingerprintMismatch:     "tool_fingerprint_mismatch",
	ReasonServerNotUsable:             "server_not_usable",
	ReasonToolNotFound:                "tool_not_found",
	ReasonApprovalRevoked:             "approval_revoked",
	ReasonApprovalTenantConflict:      "approval_tenant_conflict",
	ReasonApprovalPurposeUnsupported:  "approval_purpose_unsupported",
	ReasonApprovalNotAuthorized:       "approval_not_authorized",
	ReasonApprovalStoreUnavailable:    "approval_store_unavailable",
	ReasonRolloutBudgetExhausted:      "rollout_budget_exhausted",
	ReasonLiveTrustRevalidationFailed: "live_trust_revalidation_failed",
}

// Code returns the stable machine string for the reason (e.g. "malformed_json").
// An unknown reason returns "unknown(<n>)" rather than panicking.
func (r Reason) Code() string {
	if s, ok := reasonCode[r]; ok {
		return s
	}
	return "unknown(" + strconv.Itoa(int(r)) + ")"
}

// String implements fmt.Stringer with the stable machine code.
func (r Reason) String() string { return r.Code() }

// Error is the single typed error returned by the MCP kernel. It carries a
// stable Reason, a fixed developer-authored Op/Detail (never raw hostile input),
// and an optional wrapped cause.
type Error struct {
	Reason  Reason
	Op      string // kernel operation, e.g. "decode", "classify", "admit"
	Detail  string // fixed, developer-authored description (no hostile bytes)
	wrapped error
}

// New builds a kernel Error. op and detail MUST be fixed, developer-authored
// strings. To include a variable token (e.g. an offending method name), the
// caller must pass it through Sanitize first.
func New(r Reason, op, detail string) *Error {
	return &Error{Reason: r, Op: op, Detail: detail}
}

// Wrap builds a kernel Error that wraps a lower-level cause. The cause is used
// only for errors.Is/As and Error() text; callers must ensure it too carries no
// raw hostile bytes (stdlib json errors are safe — they do not echo the input).
func Wrap(r Reason, op, detail string, cause error) *Error {
	return &Error{Reason: r, Op: op, Detail: detail, wrapped: cause}
}

// Error implements the error interface with a stable, sanitized message shape:
// "mcp: <op>: <code>: <detail>". It never prints raw payload bytes.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("mcp: ")
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(": ")
	}
	b.WriteString(e.Reason.Code())
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	return b.String()
}

// Unwrap exposes the wrapped cause for errors.Is/As.
func (e *Error) Unwrap() error { return e.wrapped }

// Is matches by Reason so callers can write errors.Is(err, mcperr.ErrX-style)
// checks via a sentinel, and also matches another *Error with the same Reason.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Reason == e.Reason && (t.Op == "" || t.Op == e.Op)
}

// ReasonOf extracts the kernel Reason from an error chain, or ReasonNone if the
// error is not (and does not wrap) a kernel Error.
func ReasonOf(err error) Reason {
	for err != nil {
		if e, ok := err.(*Error); ok {
			return e.Reason
		}
		switch u := err.(type) {
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		case interface{ Unwrap() []error }:
			// A multi-error tree (e.g. fmt.Errorf with more than one %w verb). errors.As/errors.Is
			// traverse these; ReasonOf must too, or a bounded reason wrapped alongside another cause
			// would read as ReasonNone. Return the FIRST bounded reason found across the branches,
			// mirroring the single-chain "first wrapped reason wins" semantics.
			for _, branch := range u.Unwrap() {
				if r := ReasonOf(branch); r != ReasonNone {
					return r
				}
			}
			return ReasonNone
		default:
			return ReasonNone
		}
	}
	return ReasonNone
}

// Sanitize renders an untrusted token safe to embed in an error/log message: it
// replaces every byte that is not a printable ASCII graphic (0x20–0x7E, excl.
// backslash and quote to keep CWE-117 scanners happy) with '.', and truncates to
// max bytes with a trailing "…" marker. It never returns the raw input. A
// non-positive maxLen defaults to 64.
func Sanitize(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 64
	}
	truncated := false
	if len(s) > maxLen {
		s = s[:maxLen]
		truncated = true
	}
	var b strings.Builder
	b.Grow(len(s) + 1)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '\\' || c == '"' {
			b.WriteByte('.')
			continue
		}
		b.WriteByte(c)
	}
	if truncated {
		b.WriteString("~")
	}
	return b.String()
}
