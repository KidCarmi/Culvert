package policy

// Remediation is a stable remediation identifier from a CLOSED vocabulary — never
// arbitrary user-provided prose in the runtime decision. Human-readable rendering
// belongs to Management/UI in a later slice.
type Remediation string

const (
	// RemediationNone — no remediation applies (e.g. a plain ALLOW).
	RemediationNone Remediation = "none"
	// RemediationRequestAccess — the caller should request access to the operation.
	RemediationRequestAccess Remediation = "request_access"
	// RemediationReviewToolDrift — a tool-drift/quarantine remediation.
	RemediationReviewToolDrift Remediation = "review_tool_drift"
	// RemediationRequestApproval — an approval-workflow remediation.
	RemediationRequestApproval Remediation = "request_approval"
	// RemediationRequestConfirmation — a confirmation-step remediation.
	RemediationRequestConfirmation Remediation = "request_confirmation"
	// RemediationUseCorrectResource — the request named a wrong/foreign resource.
	RemediationUseCorrectResource Remediation = "use_correct_resource"
	// RemediationIncreaseAssurance — the principal's assurance is below the floor.
	RemediationIncreaseAssurance Remediation = "increase_assurance"
	// RemediationContactPolicyOwner — escalate to the policy owner.
	RemediationContactPolicyOwner Remediation = "contact_policy_owner"
	// RemediationWaitForPolicyPublication — no snapshot yet; wait for publication.
	RemediationWaitForPolicyPublication Remediation = "wait_for_policy_publication"
	// RemediationVerifyServerIdentity — the server identity changed / is disabled.
	RemediationVerifyServerIdentity Remediation = "verify_server_identity"
	// RemediationNotPermitted — the operation is structurally not permitted (V1
	// Management boundary, cross-capability, invalid input).
	RemediationNotPermitted Remediation = "not_permitted"
)

// remediations is the closed set the parser validates rule remediation codes against.
var remediations = map[Remediation]struct{}{
	RemediationNone: {}, RemediationRequestAccess: {}, RemediationReviewToolDrift: {},
	RemediationRequestApproval: {}, RemediationRequestConfirmation: {},
	RemediationUseCorrectResource: {}, RemediationIncreaseAssurance: {},
	RemediationContactPolicyOwner: {}, RemediationWaitForPolicyPublication: {},
	RemediationVerifyServerIdentity: {}, RemediationNotPermitted: {},
}

// Valid reports whether the remediation is in the closed vocabulary.
func (r Remediation) Valid() bool { _, ok := remediations[r]; return ok }

// String returns the raw remediation identifier.
func (r Remediation) String() string { return string(r) }
