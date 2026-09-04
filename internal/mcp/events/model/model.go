// Package model defines the immutable, versioned decision-event envelope that
// the PR-8 durable event pipeline persists. It is a LEAF package: it imports
// only the shared error model (internal/mcp/mcperr) and the standard library,
// so the event schema, its validation, and its canonical digest carry no
// dependency on the runtime, policy, inspection or identity engines. The runtime
// adapter (internal/mcp/events) maps a live policy.Decision / inspection.Summary
// / identity.ResolvedContext into this envelope's TYPED SAFE FIELDS — the model
// never embeds those types, never holds a map[string]any, and by construction
// cannot carry a raw token, credential, private key, complete argument or
// complete output.
//
// Two properties are load-bearing (EVENT-MODEL.md §1/§3, MCP-EVENT-003/004/005):
//
//   - Secret-free by construction. Every field is a typed scalar, enum, hash or
//     bounded string; a field not promoted into this schema by design DOES NOT
//     EXIST in the event, rather than existing in redacted form. There is no
//     open map a caller could smuggle a secret through.
//   - Deterministic canonical digest. The event's identity hash is computed over
//     a fixed-field-order canonical encoding with NO map serialization, so a
//     canonically-equivalent event always yields an identical digest, and the
//     digest is stable across nodes and restarts (canonical.go).
//
// Sequence and prior-chain digest are NOT part of the model: they are assigned by
// the spool at commit time and authenticated in the segment record framing
// (internal/mcp/events/spool), which is where per-partition monotonicity and
// reorder/tamper evidence live. The model owns the event's intrinsic content and
// its intrinsic digest.
package model

// Event-envelope schema versions. An event carrying an UNSUPPORTED schema version
// is rejected at validation AND at recovery (fail closed; no forward-guessing of an
// unrecognised layout).
//
// v1 is the original envelope. v2 is ADDITIVE: it introduces the durable Shadow
// sub-facts (ShadowEvidence) and is stamped ONLY on a Shadow decision event — the
// only event that carries ShadowEvidence. Every non-shadow event stays v1, so its
// canonical digest is byte-identical across this change (SHADOW-EVIDENCE-ROUTING-1).
const (
	// SchemaVersionV1 is the original envelope (no Shadow sub-facts).
	SchemaVersionV1 = 1
	// SchemaVersionV2 adds durable ShadowEvidence; stamped only on Shadow events.
	SchemaVersionV2 = 2
	// SchemaVersion is the DEFAULT version stamped on an event that carries no Shadow
	// sub-facts. It is deliberately kept at v1 so every non-shadow writer's events, and
	// their digests, are unchanged. A Shadow decision event is stamped SchemaVersionV2
	// by the adapter when it carries ShadowEvidence.
	SchemaVersion = SchemaVersionV1
)

// SupportedSchemaVersion reports whether THIS build can interpret an event carrying
// schema version v. A Shadow-capable (v2) build supports v1 AND v2; any other version
// is rejected as an unknown schema (fail closed) at validation and at recovery. A
// pre-v2 build supports only v1, so it rejects a v2 event — the documented downgrade
// posture (SHADOW-EVIDENCE-ROUTING-1): a v1 binary must refuse v2 evidence, never
// partially interpret it as v1.
func SupportedSchemaVersion(v int) bool {
	return v == SchemaVersionV1 || v == SchemaVersionV2
}

// Phase is the lifecycle phase of an event. The zero value is invalid.
type Phase uint8

const (
	// PhaseNone is the zero value: not a valid phase.
	PhaseNone Phase = iota
	// PhaseDecision — a pre-execution decision event. For a critical class this
	// is the event that MUST be durably committed BEFORE that class's own
	// irreversible action.
	PhaseDecision
	// PhaseOutcome — a post-execution outcome event, emitted SEPARATELY after
	// execution. It never replaces the pre-execution decision commit and must
	// reference a committed decision (DecisionRef).
	PhaseOutcome
	// PhaseDenialAggregate — a coalesced authentication-failure / authorization-
	// denial aggregate. Attacker-mintable; lives only in P-DEN.
	PhaseDenialAggregate
	// PhaseRecoveryMarker — a durability-recovery/health marker committed and read
	// back as part of the critical-durability-degraded exit criteria.
	PhaseRecoveryMarker
	// PhaseHealth — a health/degradation-transition marker.
	PhaseHealth
	// PhaseSendIntent — a DURABLE SEND INTENT committed immediately before the
	// final boundary guards and the irreversible upstream call. It names the exact
	// physical attempt (AttemptID) and the reservation and activation generation
	// that authorized it, so a process that dies after the peer received the bytes
	// still leaves proof that the attempt EXISTED. Without it, a post-send crash is
	// indistinguishable from "never sent" — which is the one inference that must
	// never be made (see PhysicalSendState).
	PhaseSendIntent
)

// String returns the stable machine string for the phase.
func (p Phase) String() string {
	switch p {
	case PhaseDecision:
		return "decision"
	case PhaseOutcome:
		return "outcome"
	case PhaseDenialAggregate:
		return "denial_aggregate"
	case PhaseRecoveryMarker:
		return "recovery_marker"
	case PhaseHealth:
		return "health"
	case PhaseSendIntent:
		return "send_intent"
	default:
		return "none"
	}
}

// Valid reports whether the phase is a real phase.
func (p Phase) Valid() bool { return p >= PhaseDecision && p <= PhaseSendIntent }

// Criticality is the durability class of an event. It selects the partition and
// governs the fail-closed / degraded posture. The zero value is invalid.
type Criticality uint8

const (
	// CritNone is the zero value: not a valid criticality.
	CritNone Criticality = iota
	// CritOrdinary — an ordinary authenticated decision or outcome event (low-risk
	// allow/monitor). Lives in P-ORD.
	CritOrdinary
	// CritCritical — an authenticated critical decision event (write, destructive,
	// configuration publication, credential materialization gate, state-affecting
	// Management). Lives in P-CRIT and owns the reserved capacity.
	CritCritical
	// CritDenial — a coalesced attacker-mintable denial aggregate. Lives in P-DEN.
	CritDenial
)

// String returns the stable machine string for the criticality.
func (c Criticality) String() string {
	switch c {
	case CritOrdinary:
		return "ordinary"
	case CritCritical:
		return "critical"
	case CritDenial:
		return "denial"
	default:
		return "none"
	}
}

// Valid reports whether the criticality is real.
func (c Criticality) Valid() bool { return c >= CritOrdinary && c <= CritDenial }

// Partition is the logical durable partition an event is routed to. The zero
// value is invalid. The three partitions are logically separate even when one
// physical spool directory is shared (EVENT-MODEL.md §4b.4).
type Partition uint8

const (
	// PartNone is the zero value: not a valid partition.
	PartNone Partition = iota
	// PartCrit — P-CRIT: authenticated critical events; reserved capacity that
	// P-ORD and P-DEN MUST NOT consume.
	PartCrit
	// PartOrd — P-ORD: ordinary authenticated events; shares the non-reserved
	// remainder.
	PartOrd
	// PartDen — P-DEN: coalesced denial aggregates; own quota, cannot consume the
	// P-CRIT reserve.
	PartDen
)

// String returns the stable machine string for the partition.
func (p Partition) String() string {
	switch p {
	case PartCrit:
		return "P-CRIT"
	case PartOrd:
		return "P-ORD"
	case PartDen:
		return "P-DEN"
	default:
		return "none"
	}
}

// Valid reports whether the partition is real.
func (p Partition) Valid() bool { return p >= PartCrit && p <= PartDen }

// ExpectedPartition returns the partition a given criticality MUST route to.
// The (criticality, partition) binding is mechanically enforced in Validate so a
// critical event can never be routed outside P-CRIT and a denial can never be
// routed into P-CRIT.
func (c Criticality) ExpectedPartition() Partition {
	switch c {
	case CritOrdinary:
		return PartOrd
	case CritCritical:
		return PartCrit
	case CritDenial:
		return PartDen
	default:
		return PartNone
	}
}

// Capability is the MCP capability that owns the event. Model-local (so the model
// stays a leaf); the runtime adapter maps protocol.Capability into this. The zero
// value is invalid. Gateway and Management events are never mixed in one event.
type Capability uint8

const (
	// CapNone is the zero value: not a valid capability.
	CapNone Capability = iota
	// CapGateway — the Gateway (business tool traffic) capability.
	CapGateway
	// CapManagement — the Management (configuration) capability.
	CapManagement
)

// String returns the stable machine string for the capability.
func (c Capability) String() string {
	switch c {
	case CapGateway:
		return "gateway"
	case CapManagement:
		return "management"
	default:
		return "none"
	}
}

// Valid reports whether the capability is real.
func (c Capability) Valid() bool { return c == CapGateway || c == CapManagement }

// ActionClass names the irreversible-action class a critical decision gates. Each
// class is gated at ITS OWN side effect (EVENT-MODEL.md §4a). The zero value,
// ActionClassNone, is used by ordinary/denial events and by reads. A critical
// event MUST carry a non-None action class (the action-class binding).
type ActionClass uint8

const (
	// ActionClassNone is the zero value: no critical action-class binding
	// (ordinary reads, monitors, denials).
	ActionClassNone ActionClass = iota
	// ActionClassRead — a low-risk read/monitor (ordinary, not a critical gate).
	ActionClassRead
	// ActionClassWrite — a write whose irreversible action is the upstream call.
	ActionClassWrite
	// ActionClassDestructive — a destructive/production action; upstream call.
	ActionClassDestructive
	// ActionClassConfigPublication — signing/pushing/applying a config snapshot.
	ActionClassConfigPublication
	// ActionClassCredentialIssue — broker-side credential minting.
	ActionClassCredentialIssue
	// ActionClassCredentialRotate — broker-side credential rotation.
	ActionClassCredentialRotate
	// ActionClassCredentialRevoke — broker-side credential revocation.
	ActionClassCredentialRevoke
	// ActionClassCredentialSelect — high-risk credential selection/materialization.
	ActionClassCredentialSelect
	// ActionClassManagementMutation — a state-affecting Management operation and
	// the signed snapshot it publishes (no V1 mechanism; PR-8 stubs it).
	ActionClassManagementMutation
)

// String returns the stable machine string for the action class.
func (a ActionClass) String() string {
	switch a {
	case ActionClassRead:
		return "read"
	case ActionClassWrite:
		return "write"
	case ActionClassDestructive:
		return "destructive"
	case ActionClassConfigPublication:
		return "config_publication"
	case ActionClassCredentialIssue:
		return "credential_issue"
	case ActionClassCredentialRotate:
		return "credential_rotate"
	case ActionClassCredentialRevoke:
		return "credential_revoke"
	case ActionClassCredentialSelect:
		return "credential_select"
	case ActionClassManagementMutation:
		return "management_mutation"
	default:
		return "none"
	}
}

// Valid reports whether the action class is a real class.
func (a ActionClass) Valid() bool {
	return a >= ActionClassRead && a <= ActionClassManagementMutation
}

// IsCritical reports whether the action class denotes a critical irreversible
// action (everything except None and Read). A critical event MUST carry an
// IsCritical action class; an ordinary event MUST NOT.
func (a ActionClass) IsCritical() bool {
	return a >= ActionClassWrite && a <= ActionClassManagementMutation
}

// ChainLink is one safe typed reference in the PR-3 causal delegation chain
// (human/agent/client → capability → server → tool → resource). It carries a
// kind and an opaque id — never a display name, email or secret.
type ChainLink struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// IdentityEvidence records the PR-3 causal identity chain WITHOUT secrets
// (MCP-ID-004). Every field is a safe principal id, tenant, capability-scoped id,
// hash or one-way session-correlation digest. There is no bearer token, DPoP
// proof, certificate private material, raw subject email or raw session token.
type IdentityEvidence struct {
	Tenant          string `json:"tenant"`
	PrincipalID     string `json:"principal_id"`
	PrincipalType   string `json:"principal_type"` // human / agent / workload
	AgentID         string `json:"agent_id,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ServerID        string `json:"server_id,omitempty"`
	ToolName        string `json:"tool_name,omitempty"`
	ToolFingerprint string `json:"tool_fingerprint,omitempty"`
	ResourceRef     string `json:"resource_ref,omitempty"`
	ResourceHash    string `json:"resource_hash,omitempty"`
	Assurance       string `json:"assurance,omitempty"`
	// SenderBinding is the VERIFIED proof-of-possession binding for the request
	// ("none" / "dpop" / "mtls"). It is recorded SEPARATELY from Assurance because
	// they are different properties (OVN-05): a DPoP proof shows the presenter
	// controls the token's key, not that a human authenticated strongly. Without
	// it an auditor reading `assurance:"high"` under the documented NIST-AAL
	// labels would conclude something the product never observed.
	SenderBinding      string      `json:"sender_binding,omitempty"`
	SessionCorrelation string      `json:"session_correlation,omitempty"` // TokenDigest / fingerprint, never a token
	Chain              []ChainLink `json:"chain,omitempty"`
}

// DecisionEvidence records the policy decision WITHOUT the raw request. Every
// field is a stable code, id, revision, hash or bounded label.
type DecisionEvidence struct {
	Action              string   `json:"action"`
	ReasonCode          string   `json:"reason_code"`
	MatchedRuleID       string   `json:"matched_rule_id,omitempty"`
	DecisiveConditionID string   `json:"decisive_condition_id,omitempty"`
	Remediation         string   `json:"remediation,omitempty"`
	PolicyRevision      uint64   `json:"policy_revision"`
	CatalogRevision     uint64   `json:"catalog_revision"`
	RegistryRevision    uint64   `json:"registry_revision,omitempty"`
	InspectionRevision  uint64   `json:"inspection_revision,omitempty"`
	RuntimeRevision     uint64   `json:"runtime_revision,omitempty"`
	ConfigEpoch         uint64   `json:"config_epoch,omitempty"`
	PolicySnapshotHash  string   `json:"policy_snapshot_hash,omitempty"`
	Obligations         []string `json:"obligations,omitempty"`
	OperationClass      string   `json:"operation_class,omitempty"`
	RiskClass           string   `json:"risk_class,omitempty"`
	ExecutionState      string   `json:"execution_state,omitempty"`
	// NOTE: the Shadow enforcement-prediction sub-facts are NOT stored inline on
	// DecisionEvidence. Adding them here as digest-covered v1 fields would be a rollback
	// hazard — a pre-change binary reading a shadow event drops the unknown fields on
	// unmarshal, recomputes CanonicalBytes without them, and misreports the valid record
	// as corrupted. They live in a SEPARATE typed sub-evidence pointer, Event.Shadow, on a
	// v2 envelope with explicit v1/v2 recovery (SHADOW-EVIDENCE-ROUTING-1, closed). The raw
	// evaluated policy action stays in Action above (its existing home); ExecutionState
	// carries "shadow_evaluated" for a shadow event. See ShadowEvidence.
}

// ShadowEvidence records the durable, per-request Shadow enforcement prediction — the
// full ShadowDecision an operator uses to judge Canary readiness. It is a typed,
// secret-free sub-evidence (like Outcome/Denial/Marker): present ONLY on a
// SchemaVersionV2 Shadow decision event (ExecutionState "shadow_evaluated") and nil
// otherwise. It carries the SAME facts returned to the client in the transient Shadow
// response body (execution.shadowResult), so the durable record reconstructs exactly
// what the caller saw at request time.
//
// The raw/evaluated policy action is NOT duplicated here — it lives in
// DecisionEvidence.Action (single source of truth). Every field below is a bounded enum
// (validated in Validate); no secret, argument, output or credential value appears.
type ShadowEvidence struct {
	// Outcome is the Model-1 enforcement prediction (would_execute, would_block,
	// would_require_approval, would_require_confirmation, would_fail_credential_readiness,
	// would_fail_inspection, would_fail_stale_decision, would_fail_hard_control).
	Outcome string `json:"outcome"`
	// Override is true when the policy verdict itself is restrictive (non-allow-class),
	// so a policy DENY/APPROVAL/CONFIRMATION is never laundered into a plain would_execute.
	Override bool `json:"override"`
	// CredentialPlan is the credential-readiness sub-fact derived from Plan metadata only
	// (no_credential_profile, credential_plan_valid, credential_plan_invalid,
	// no_planner_composed). Shadow never materializes a credential.
	CredentialPlan string `json:"credential_plan"`
	// MaterializationReadiness is ALWAYS "not_evaluated": Shadow never evaluates
	// materialization (it holds no materialize-capable broker). Any other value is invalid.
	MaterializationReadiness string `json:"materialization_readiness"`
	// RequestInspection is the pre-executor inspection sub-fact (would_pass, would_fail,
	// not_evaluated). not_evaluated means no inspection ran — never a false would_pass.
	RequestInspection string `json:"request_inspection"`
	// ResponseInspection is ALWAYS "not_evaluated": a Shadow evaluation makes no upstream
	// call, so no upstream response exists to inspect. Any other value is invalid.
	ResponseInspection string `json:"response_inspection"`
}

// InspectionEvidence records only sanitized inspection facts (MCP-INSP-*). No
// matched secret and no complete argument or output body ever appear here.
type InspectionEvidence struct {
	SchemaStatus       string   `json:"schema_status,omitempty"`
	OutputSchemaStatus string   `json:"output_schema_status,omitempty"`
	FindingClasses     []string `json:"finding_classes,omitempty"`
	MaxSeverity        string   `json:"max_severity,omitempty"`
	DLPDisposition     string   `json:"dlp_disposition,omitempty"`
	DestinationClass   string   `json:"destination_class,omitempty"`
	PinEvidenceHash    string   `json:"pin_evidence_hash,omitempty"`
	RedirectStatus     string   `json:"redirect_status,omitempty"`
	InjectionLabels    []string `json:"injection_labels,omitempty"`
	OriginalHash       string   `json:"original_hash,omitempty"`
	TransformedHash    string   `json:"transformed_hash,omitempty"`
	RedactionCount     int      `json:"redaction_count,omitempty"`
	RedactionProfile   string   `json:"redaction_profile,omitempty"`
	RedactionRevision  uint64   `json:"redaction_revision,omitempty"`
}

// CredentialEvidence records only safe credential references (MCP-CRED-004
// redaction leg). No secret, no client token, no sensitive provider-secret path.
type CredentialEvidence struct {
	ProfileID    string `json:"profile_id,omitempty"`
	ProviderID   string `json:"provider_id,omitempty"`
	PlannedKind  string `json:"planned_kind,omitempty"`
	PowerCeiling string `json:"power_ceiling,omitempty"`
	PlanID       string `json:"plan_id,omitempty"`
	Version      uint64 `json:"version,omitempty"`
	CacheState   string `json:"cache_state,omitempty"` // hit / miss metadata, never a value
}

// PhysicalSendState is the TRUTH about whether request bytes for one physical tool
// invocation could have reached the peer. It is deliberately NOT a boolean.
//
// "Executed" is a statement about Culvert's own control flow; it cannot answer the
// question that matters after a transport fault or a crash, which is whether the
// PEER may already have acted. Collapsing that into a bool forces every ambiguous
// case to be recorded as one of two lies. This enum keeps uncertainty explicit and
// conservative: an unknown outcome is never downgraded to "not sent".
type PhysicalSendState string

const (
	// SendStateUnset is the zero value and is INVALID on a committed outcome.
	SendStateUnset PhysicalSendState = ""
	// SendDefinitelyNotSent may be used ONLY when it is mechanically provable that
	// no request byte could have reached the peer — in practice, when a guard denied
	// BEFORE the physical call began. It must never be inferred from a missing
	// record or from an error observed after the call started.
	SendDefinitelyNotSent PhysicalSendState = "definitely_not_sent"
	// SendMayHaveBeenSent is the conservative state for every ambiguous transport
	// outcome once the physical call has begun: connection reset, timeout, context
	// cancellation, or a crash with no terminal record. Reconciliation against an
	// independent witness is required to resolve it.
	SendMayHaveBeenSent PhysicalSendState = "may_have_been_sent"
	// SendPeerResponseReceived means the peer returned a response, so the invocation
	// demonstrably reached it. This says nothing about whether the response was
	// later blocked by inspection.
	SendPeerResponseReceived PhysicalSendState = "peer_response_received"
	// SendReconciledReceived resolves an ambiguous attempt against an authoritative
	// independent witness that HAS the attempt.
	SendReconciledReceived PhysicalSendState = "reconciled_received"
	// SendReconciledNotReceived resolves an ambiguous attempt against an
	// authoritative independent witness that definitively does NOT have it.
	SendReconciledNotReceived PhysicalSendState = "reconciled_not_received"
)

// Valid reports whether the state is one of the defined non-zero states.
func (s PhysicalSendState) Valid() bool {
	switch s {
	case SendDefinitelyNotSent, SendMayHaveBeenSent, SendPeerResponseReceived,
		SendReconciledReceived, SendReconciledNotReceived:
		return true
	default:
		return false
	}
}

// MayHaveReachedPeer is the CONSERVATIVE predicate: it answers false only for the
// two states that positively prove the peer did not act. Everything else — including
// an unset/unknown state — answers true, so budget accounting and reconciliation
// can never treat uncertainty as a non-event.
func (s PhysicalSendState) MayHaveReachedPeer() bool {
	return s != SendDefinitelyNotSent && s != SendReconciledNotReceived
}

// ReconciliationRequired reports whether this attempt still needs an authoritative
// independent witness to reach a final answer.
func (s PhysicalSendState) ReconciliationRequired() bool {
	return s == SendMayHaveBeenSent || s == SendStateUnset
}

// OutcomeEvidence records a post-execution outcome. It does not replace the
// pre-execution decision commit. An outcome event MUST reference a committed
// decision via DecisionRef.
//
// The attempt-identity and physical-send fields exist so the record can answer the
// First-Canary question — "did Culvert cause exactly the tool effects it
// authorized, and does it know what happened to each one?" — WITHOUT consulting
// anything mutable. They are an immutable snapshot at outcome time, bound to the
// activation generation and reservation that authorized the effect, so an orphan
// from a superseded generation can be recognized as such after a restart.
type OutcomeEvidence struct {
	DecisionRef           string `json:"decision_ref"`
	Executed              bool   `json:"executed"`
	StatusClass           string `json:"status_class,omitempty"`
	DurationMs            int64  `json:"duration_ms,omitempty"`
	UpstreamResponseClass string `json:"upstream_response_class,omitempty"`
	InspectionResult      string `json:"inspection_result,omitempty"`
	FailureReason         string `json:"failure_reason,omitempty"`

	// AttemptID names ONE potential physical tool invocation. It is not an
	// execution id, a server id, or a JSON-RPC wire id: exactly one AttemptID
	// corresponds to at most one side-effect-bearing tool send, which is what makes
	// independent witness correlation possible.
	AttemptID string `json:"attempt_id,omitempty"`
	// ReservationID binds the attempt to the budget slot that authorized it, so a
	// physical effect can never be attributed to an unauthorized reservation.
	ReservationID string `json:"reservation_id,omitempty"`
	// ActivationGeneration is the Canary generation in force when the attempt was
	// authorized. An orphan carrying generation G must remain visible under G+1 and
	// must never become fresh execution allowance.
	ActivationGeneration uint64 `json:"activation_generation,omitempty"`
	// PhysicalSendState is the conservative truth about peer reachability.
	PhysicalSendState PhysicalSendState `json:"physical_send_state,omitempty"`
}

// DenialEvidence records a coalesced denial aggregate (P-DEN). It retains count,
// first-seen and last-seen so evidence is preserved while volume is not. Tenant
// and principal appear ONLY where verified identity existed; before identity
// exists they are empty (never invented from an attacker hint).
type DenialEvidence struct {
	DenialReason      string `json:"denial_reason"`
	ListenerID        string `json:"listener_id,omitempty"`
	SourceBucket      string `json:"source_bucket"`
	Count             uint64 `json:"count"`
	FirstSeenUnixNano int64  `json:"first_seen_unix_nano"`
	LastSeenUnixNano  int64  `json:"last_seen_unix_nano"`
}

// MarkerEvidence records a recovery/health-transition marker (PhaseRecoveryMarker
// / PhaseHealth). It carries the degraded state name, its scope and an entry
// reason — never a secret.
type MarkerEvidence struct {
	State  string `json:"state"`
	Scope  string `json:"scope"`
	Reason string `json:"reason,omitempty"`
}

// Event is the immutable, versioned decision-event envelope. It is a struct of
// TYPED SAFE FIELDS only — no map[string]any — so it is deterministically
// canonicalizable (canonical.go) and secret-free by construction. Sub-evidence
// that applies to only one phase is a pointer and nil otherwise.
//
// EventDigest is the intrinsic content digest, computed by ComputeDigest over the
// canonical encoding with the digest field itself zeroed. It is set by the
// pipeline before commit and verified on recovery/export.
type Event struct {
	SchemaVersion int         `json:"schema_version"`
	EventID       string      `json:"event_id"`
	Phase         Phase       `json:"phase"`
	Criticality   Criticality `json:"criticality"`
	Partition     Partition   `json:"partition"`
	Capability    Capability  `json:"capability"`
	ActionClass   ActionClass `json:"action_class"`
	NodeID        string      `json:"node_id"`
	DomainID      string      `json:"domain_id"`
	TimeUnixNano  int64       `json:"time_unix_nano"`
	ReplayID      string      `json:"replay_id"`
	CorrelationID string      `json:"correlation_id"`
	SnapshotHash  string      `json:"snapshot_hash,omitempty"`

	Identity   IdentityEvidence   `json:"identity"`
	Decision   DecisionEvidence   `json:"decision"`
	Inspection InspectionEvidence `json:"inspection"`
	Credential CredentialEvidence `json:"credential"`
	Outcome    *OutcomeEvidence   `json:"outcome,omitempty"`
	Denial     *DenialEvidence    `json:"denial,omitempty"`
	Marker     *MarkerEvidence    `json:"marker,omitempty"`
	// Shadow is the durable Shadow enforcement prediction, present ONLY on a
	// SchemaVersionV2 Shadow decision event and nil otherwise. Because it is a nil
	// pointer with omitempty on every non-shadow (v1) event, it is OMITTED from the
	// canonical encoding of those events, so their digest is byte-identical to the
	// pre-v2 encoding (SHADOW-EVIDENCE-ROUTING-1 digest-compatibility invariant).
	Shadow *ShadowEvidence `json:"shadow,omitempty"`

	// EventDigest is the intrinsic content digest (hex sha256). It is excluded
	// from the canonical encoding used to compute it.
	EventDigest string `json:"event_digest"`
}
