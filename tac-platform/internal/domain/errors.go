package domain

import "fmt"

// Code is the stable error taxonomy. Every failure maps to exactly one code so
// callers (tacctl, REST, future MCP) branch deterministically, never on strings.
type Code string

const (
	CodeNotFound          Code = "not_found"
	CodeConflict          Code = "conflict"            // idempotency-key reuse -> existing op
	CodeIllegalTransition Code = "illegal_transition"  // FSM legality
	CodePolicyRejected    Code = "policy_rejected"
	CodeApprovalInvalid   Code = "approval_invalid"    // stale/mismatch/author/consumed/expired
	CodeLeaseHeld         Code = "lease_held"          // another op holds the worker
	CodeCrossTenant       Code = "cross_tenant"        // scope violation
	CodeValidationFailed  Code = "validation_failed"
	CodeProviderError     Code = "provider_error"
	CodeUnknownOutcome    Code = "unknown_outcome"     // provider result in-doubt -> reconcile
	CodeManualRequired    Code = "manual_intervention_required"
	CodeInvalidInput      Code = "invalid_input"
	CodeInternal          Code = "internal"
)

type Error struct {
	Code    Code
	Message string
	Detail  string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func Err(code Code, msg string) *Error            { return &Error{Code: code, Message: msg} }
func Errf(code Code, f string, a ...any) *Error   { return &Error{Code: code, Message: fmt.Sprintf(f, a...)} }
func ErrD(code Code, msg, detail string) *Error   { return &Error{Code: code, Message: msg, Detail: detail} }

// CodeOf extracts the taxonomy code from any error (default internal).
func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return CodeInternal
}
