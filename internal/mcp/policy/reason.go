package policy

import "strings"

// ReasonCode is a stable, structured machine reason for a decision — never
// unbounded free-form text. Its shape is PREFIX.TOKEN(.TOKEN)* where PREFIX is one
// of the accepted MCP.* domains and every TOKEN is bounded UPPER_SNAKE. Callers
// branch on the exact code; humans render it elsewhere (Management/UI).
type ReasonCode string

// Accepted reason-code prefixes (the closed domain set, MCP-POLICY-MODEL §reasons).
const (
	prefixAuth       = "MCP.AUTH"
	prefixServer     = "MCP.SERVER"
	prefixTool       = "MCP.TOOL"
	prefixPolicy     = "MCP.POLICY"
	prefixCredential = "MCP.CREDENTIAL" // #nosec G101 -- reason-code domain prefix, not a credential
	prefixInspection = "MCP.INSPECTION"
	prefixRate       = "MCP.RATE"
	prefixSystem     = "MCP.SYSTEM"
	prefixManagement = "MCP.MANAGEMENT"
)

// acceptedPrefixes is the closed set a reason code's domain must belong to.
var acceptedPrefixes = map[string]struct{}{
	prefixAuth: {}, prefixServer: {}, prefixTool: {}, prefixPolicy: {},
	prefixCredential: {}, prefixInspection: {}, prefixRate: {}, prefixSystem: {},
	prefixManagement: {},
}

// Engine-emitted reason codes. These are the codes the hard-override and
// default-deny paths stamp themselves; rule authors supply their own (validated)
// codes for ordinary matches. Every string here is part of the package contract.
// Engine-emitted + doc-taxonomy reason codes (MCP-POLICY-MODEL §5). The
// hard-override / default-deny paths stamp the engine codes themselves; rule
// authors supply their own (validated) codes. Every string here is contract.
const (
	// ReasonNoMatchDefaultDeny — a valid tuple that no enabled rule matched.
	ReasonNoMatchDefaultDeny ReasonCode = "MCP.POLICY.NO_MATCH_DEFAULT_DENY"
	// ReasonSnapshotUnavailable — no valid policy snapshot exists for the capability
	// at a decision point (runtime fail-closed). Distinct from SNAPSHOT_INVALID
	// (an integrity failure): here nothing is published yet.
	ReasonSnapshotUnavailable ReasonCode = "MCP.POLICY.SNAPSHOT_UNAVAILABLE"
	// ReasonSnapshotInvalid — a snapshot failed integrity/HA validation (§5 taxonomy).
	ReasonSnapshotInvalid ReasonCode = "MCP.SYSTEM.SNAPSHOT_INVALID"
	// ReasonResourceScope — the resource scope did not match (§5).
	ReasonResourceScope ReasonCode = "MCP.POLICY.RESOURCE_SCOPE"
	// ReasonTimeWindow — outside the permitted time window (§5).
	ReasonTimeWindow ReasonCode = "MCP.POLICY.TIME_WINDOW"
	// ReasonApprovalRequired — the matched rule requires approval (§5).
	ReasonApprovalRequired ReasonCode = "MCP.POLICY.APPROVAL_REQUIRED"

	// ReasonToolUnknown — hard override: an unknown tool (no catalog record).
	ReasonToolUnknown ReasonCode = "MCP.TOOL.UNKNOWN"
	// ReasonToolPrivilegeExpansion — hard override: privilege-expansion drift.
	ReasonToolPrivilegeExpansion ReasonCode = "MCP.TOOL.PRIVILEGE_EXPANSION"
	// ReasonToolSchemaChanged — a tool schema change (§5 / §6 worked example).
	ReasonToolSchemaChanged ReasonCode = "MCP.TOOL.SCHEMA_CHANGED"
	// ReasonToolSemanticDrift — a tool semantic drift (§5).
	ReasonToolSemanticDrift ReasonCode = "MCP.TOOL.SEMANTIC_DRIFT"

	// ReasonServerIdentityChanged — hard override: the server's verified identity changed.
	ReasonServerIdentityChanged ReasonCode = "MCP.SERVER.IDENTITY_CHANGED"
	// ReasonServerDisabled — hard override: the Gateway server is disabled.
	ReasonServerDisabled ReasonCode = "MCP.SERVER.DISABLED"
	// ReasonServerUnregistered — hard override: the Gateway server is unregistered (§5).
	ReasonServerUnregistered ReasonCode = "MCP.SERVER.UNREGISTERED"

	// ReasonIdentityAmbiguous — missing/ambiguous identity on a write/high-risk op
	// (MCP-ID-005; §5 MCP.AUTH.IDENTITY_AMBIGUOUS).
	ReasonIdentityAmbiguous ReasonCode = "MCP.AUTH.IDENTITY_AMBIGUOUS"
	// ReasonTenantMismatch — hard override: conflicting/cross-tenant reference (MCP-ID-007).
	ReasonTenantMismatch ReasonCode = "MCP.AUTH.TENANT_MISMATCH"
	// ReasonCapabilityMismatch — hard override: input crosses the capability namespace.
	ReasonCapabilityMismatch ReasonCode = "MCP.AUTH.CAPABILITY_MISMATCH"

	// ReasonManagementMutationNotApproved — hard override: a forbidden Management
	// activation/publication/mutation/state-affecting operation class (V1 boundary; §5).
	ReasonManagementMutationNotApproved ReasonCode = "MCP.MANAGEMENT.MUTATION_NOT_APPROVED"

	// ReasonInvalidInput — the decision tuple is structurally invalid (distinct from
	// a valid tuple that simply did not match).
	ReasonInvalidInput ReasonCode = "MCP.SYSTEM.INVALID_INPUT"
	// ReasonMissingOperand — a required decision operand is absent (input/model failure).
	ReasonMissingOperand ReasonCode = "MCP.SYSTEM.MISSING_OPERAND"
	// ReasonInspectionUnavailable — a rule required inspection evidence that PR-7 has
	// not yet supplied; the requirement must NOT silently pass.
	ReasonInspectionUnavailable ReasonCode = "MCP.INSPECTION.UNAVAILABLE"
)

const (
	maxReasonBytes    = 128
	maxReasonSegments = 8
	maxSegmentBytes   = 48
)

// Valid reports whether the reason code is well-formed: an accepted MCP.* prefix
// followed by at least one bounded UPPER_SNAKE token, within the size bounds. It
// never accepts free-form text.
func (r ReasonCode) Valid() bool {
	s := string(r)
	if s == "" || len(s) > maxReasonBytes {
		return false
	}
	// The prefix is the first TWO dotted segments ("MCP" + domain).
	first := strings.IndexByte(s, '.')
	if first < 0 {
		return false
	}
	second := strings.IndexByte(s[first+1:], '.')
	if second < 0 {
		return false // needs a prefix AND at least one code token
	}
	prefixEnd := first + 1 + second
	if _, ok := acceptedPrefixes[s[:prefixEnd]]; !ok {
		return false
	}
	tokens := strings.Split(s[prefixEnd+1:], ".")
	if len(tokens) == 0 || len(tokens) > maxReasonSegments {
		return false
	}
	for _, t := range tokens {
		if !validCodeToken(t) {
			return false
		}
	}
	return true
}

// validCodeToken reports whether t is a non-empty bounded UPPER_SNAKE token
// ([A-Z0-9_]+, not starting/ending with '_').
func validCodeToken(t string) bool {
	if t == "" || len(t) > maxSegmentBytes || t[0] == '_' || t[len(t)-1] == '_' {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '_' {
			return false
		}
	}
	return true
}

// String returns the raw code string.
func (r ReasonCode) String() string { return string(r) }
