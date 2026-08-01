package policy

// This file holds the policy-local, self-contained domain enumerations. They
// MIRROR the value semantics of the upstream engines (protocol/identity/registry/
// catalog) but are defined here so the evaluator imports none of them: every fact
// is translated into these bounded enums by the caller, keeping the evaluation
// path pure and the decision contract stable. Every enum's ZERO VALUE is an
// explicit "unset/invalid" that fails closed.

// Capability is the policy namespace. Gateway and Management are completely
// separate; a rule of one namespace can never match an input of the other.
type Capability uint8

const (
	// CapabilityUnset — zero value; rejected by input/snapshot validation.
	CapabilityUnset Capability = iota
	// CapGateway — the business MCP Security Gateway surface.
	CapGateway
	// CapManagement — the read-only + draft/validate/simulate surface.
	CapManagement
)

// String returns the capability label.
func (c Capability) String() string {
	switch c {
	case CapGateway:
		return "gateway"
	case CapManagement:
		return "management"
	default:
		return "unset"
	}
}

// Valid reports whether the capability is one of the two real namespaces.
func (c Capability) Valid() bool { return c == CapGateway || c == CapManagement }

// OperationClass is the coarse effect class of the operation being evaluated.
type OperationClass uint8

const (
	// OpUnset — zero value; rejected by input validation.
	OpUnset OperationClass = iota
	// OpRead — a read-only operation.
	OpRead
	// OpWrite — a state-changing but reversible operation.
	OpWrite
	// OpDestructive — an irreversible/destructive operation (never implicitly allowed).
	OpDestructive
	// OpDiscovery — a discovery operation (e.g. tools/list).
	OpDiscovery
	// OpControl — a control-plane operation.
	OpControl
)

// String returns the operation-class label.
func (o OperationClass) String() string {
	switch o {
	case OpRead:
		return "read"
	case OpWrite:
		return "write"
	case OpDestructive:
		return "destructive"
	case OpDiscovery:
		return "discovery"
	case OpControl:
		return "control"
	default:
		return "unset"
	}
}

// Valid reports whether the operation class is a real class.
func (o OperationClass) Valid() bool { return o >= OpRead && o <= OpControl }

// OperationNamespace distinguishes a Gateway tool operation from a Management
// operation. It must be consistent with the Capability.
type OperationNamespace uint8

const (
	// NamespaceUnset — zero value; rejected by input validation.
	NamespaceUnset OperationNamespace = iota
	// NamespaceGatewayTool — a Gateway tool operation.
	NamespaceGatewayTool
	// NamespaceManagementOperation — a Management operation.
	NamespaceManagementOperation
)

// String returns the namespace label.
func (n OperationNamespace) String() string {
	switch n {
	case NamespaceGatewayTool:
		return "gateway_tool"
	case NamespaceManagementOperation:
		return "management_operation"
	default:
		return "unset"
	}
}

// SubjectKind is the authenticated subject type.
type SubjectKind uint8

const (
	// SubjectUnset — zero value; rejected by input validation.
	SubjectUnset SubjectKind = iota
	// SubjectHuman — a human subject.
	SubjectHuman
	// SubjectWorkload — a non-human workload subject.
	SubjectWorkload
)

// String returns the subject-kind label.
func (s SubjectKind) String() string {
	switch s {
	case SubjectHuman:
		return "human"
	case SubjectWorkload:
		return "workload"
	default:
		return "unset"
	}
}

// Assurance is the authentication assurance of the subject (loosely NIST AAL).
// Higher is stronger; the zero value is Unknown (the floor).
type Assurance uint8

const (
	// AssuranceUnknown — no assurance asserted (the floor).
	AssuranceUnknown Assurance = iota
	// AssuranceLow — single-factor / basic.
	AssuranceLow
	// AssuranceMedium — multi-factor.
	AssuranceMedium
	// AssuranceHigh — hardware-backed / phishing-resistant.
	AssuranceHigh
)

// String returns the assurance label.
func (a Assurance) String() string {
	switch a {
	case AssuranceLow:
		return "low"
	case AssuranceMedium:
		return "medium"
	case AssuranceHigh:
		return "high"
	default:
		return "unknown"
	}
}

// Disposition mirrors the catalog eligibility of the resolved tool.
type Disposition uint8

const (
	// DispUnset — zero value; a Gateway tool input without a disposition is invalid.
	DispUnset Disposition = iota
	// DispQuarantined — quarantined (unknown tool or privilege expansion).
	DispQuarantined
	// DispReviewRequired — semantic drift; routed to human review.
	DispReviewRequired
	// DispPendingNarrowing — safe narrowing pending disposition.
	DispPendingNarrowing
	// DispServerDisabled — the server's identity changed; every tool behind it is unusable.
	DispServerDisabled
	// DispUsable — an approved, known tool with no material change.
	DispUsable
)

// String returns the disposition label.
func (d Disposition) String() string {
	switch d {
	case DispQuarantined:
		return "quarantined"
	case DispReviewRequired:
		return "review_required"
	case DispPendingNarrowing:
		return "pending_narrowing"
	case DispServerDisabled:
		return "server_disabled"
	case DispUsable:
		return "usable"
	default:
		return "unset"
	}
}

// DriftClass mirrors the catalog drift classification of the resolved tool.
type DriftClass uint8

const (
	// DriftUnset — zero value; a Gateway tool input without a drift class is invalid.
	DriftUnset DriftClass = iota
	// DriftNoMaterialChange — the canonical fingerprint is unchanged.
	DriftNoMaterialChange
	// DriftSafeNarrowing — every change is mechanically proven restrictive.
	DriftSafeNarrowing
	// DriftPrivilegeExpansion — a proven/ambiguous security-relevant broadening.
	DriftPrivilegeExpansion
	// DriftSemanticDrift — a behavioral change neither proven narrowing nor expansion.
	DriftSemanticDrift
	// DriftIdentityChange — the observed identity differs from the recorded one.
	DriftIdentityChange
	// DriftUnknownTool — no prior record for this (server, tool).
	DriftUnknownTool
)

// String returns the drift-class label.
func (d DriftClass) String() string {
	switch d {
	case DriftNoMaterialChange:
		return "no_material_change"
	case DriftSafeNarrowing:
		return "safe_narrowing"
	case DriftPrivilegeExpansion:
		return "privilege_expansion"
	case DriftSemanticDrift:
		return "semantic_drift"
	case DriftIdentityChange:
		return "identity_change"
	case DriftUnknownTool:
		return "unknown_tool"
	default:
		return "unset"
	}
}

// Destination is the observed network/resource breadth of the tool (ordered, with
// DestinationUnknown outside the order).
type Destination uint8

const (
	// DestinationUnknown — not observed (outside the ordering).
	DestinationUnknown Destination = iota
	// DestinationNone — no external destination.
	DestinationNone
	// DestinationApproved — a single approved upstream service.
	DestinationApproved
	// DestinationInternal — the internal network.
	DestinationInternal
	// DestinationArbitrary — arbitrary network / any URL (the broadest).
	DestinationArbitrary
)

// String returns the destination label.
func (d Destination) String() string {
	switch d {
	case DestinationNone:
		return "none"
	case DestinationApproved:
		return "approved"
	case DestinationInternal:
		return "internal"
	case DestinationArbitrary:
		return "arbitrary"
	default:
		return "unknown"
	}
}

// CredentialPower is the ordered privilege ceiling of a credential/tool. Higher is
// more powerful; the zero value is Unset.
type CredentialPower uint8

const (
	// PowerUnset — zero value; unset.
	PowerUnset CredentialPower = iota
	// PowerReadOnly — read-only power.
	PowerReadOnly
	// PowerWrite — write power.
	PowerWrite
	// PowerAdmin — administrative power (the broadest).
	PowerAdmin
)

// String returns the credential-power label.
func (p CredentialPower) String() string {
	switch p {
	case PowerReadOnly:
		return "read_only"
	case PowerWrite:
		return "write"
	case PowerAdmin:
		return "admin"
	default:
		return "unset"
	}
}

// Reversibility is whether the tool operation can be undone.
type Reversibility uint8

const (
	// ReversibilityUnset — zero value; unset.
	ReversibilityUnset Reversibility = iota
	// Reversible — the operation can be undone.
	Reversible
	// Irreversible — the operation cannot be undone.
	Irreversible
)

// String returns the reversibility label.
func (r Reversibility) String() string {
	switch r {
	case Reversible:
		return "reversible"
	case Irreversible:
		return "irreversible"
	default:
		return "unset"
	}
}

// TrustClass is a supplied trust/risk classification for an agent or client.
type TrustClass uint8

const (
	// TrustUnknown — no classification supplied.
	TrustUnknown TrustClass = iota
	// TrustUntrusted — explicitly untrusted.
	TrustUntrusted
	// TrustLow — low trust.
	TrustLow
	// TrustHigh — high trust.
	TrustHigh
)

// String returns the trust-class label.
func (t TrustClass) String() string {
	switch t {
	case TrustUntrusted:
		return "untrusted"
	case TrustLow:
		return "low"
	case TrustHigh:
		return "high"
	default:
		return "unknown"
	}
}

// ManagedState is whether an agent runs under managed control.
type ManagedState uint8

const (
	// ManagedUnknown — not asserted.
	ManagedUnknown ManagedState = iota
	// Managed — centrally managed.
	Managed
	// Unmanaged — not centrally managed.
	Unmanaged
)

// String returns the managed-state label.
func (m ManagedState) String() string {
	switch m {
	case Managed:
		return "managed"
	case Unmanaged:
		return "unmanaged"
	default:
		return "unknown"
	}
}

// ServerVerification is the server's verified-identity state (mirrors registry).
type ServerVerification uint8

const (
	// ServerVerifyUnset — zero value; a Gateway server input without it is invalid.
	ServerVerifyUnset ServerVerification = iota
	// ServerVerified — the pinned identity is the current trusted baseline.
	ServerVerified
	// ServerIdentityMismatch — a later verified identity did not match the pin.
	ServerIdentityMismatch
)

// String returns the server-verification label.
func (s ServerVerification) String() string {
	switch s {
	case ServerVerified:
		return "verified"
	case ServerIdentityMismatch:
		return "identity_mismatch"
	default:
		return "unset"
	}
}
