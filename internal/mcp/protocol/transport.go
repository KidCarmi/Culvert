package protocol

// TransportCondition is a transport-layer situation whose terminal HTTP status
// the kernel decides. These are the security-motivated rejection cases from the
// D-1 baseline / MCP-PROTO-017. This is a PURE DECISION FUNCTION: it maps a
// condition to a terminal status and asserts the no-stream invariant. It binds
// no socket, opens no SSE stream, and knows nothing about HTTP transport beyond
// the status code — a future PR-5 listener consults it.
type TransportCondition int

const (
	// CondSessionlessMissingVersion: a sessionless / first request with no
	// MCP-Protocol-Version header. D-1 CLOSED: reject with 400 (never silently
	// assume 2025-03-26).
	CondSessionlessMissingVersion TransportCondition = iota
	// CondInvalidVersionHeader: an invalid or unsupported MCP-Protocol-Version
	// header on a subsequent request → 400.
	CondInvalidVersionHeader
	// CondMissingSessionID: a required session identifier is missing → 400.
	CondMissingSessionID
	// CondUnknownOrTerminatedSession: an unknown or terminated session → 404.
	CondUnknownOrTerminatedSession
	// CondDeleteUnsupported: an unsupported DELETE → 405.
	CondDeleteUnsupported
	// CondGetWithoutNegotiatedContext: a GET without a valid negotiated context →
	// terminal 405, and NO text/event-stream is opened (no legacy SSE, no
	// pre-negotiation held stream).
	CondGetWithoutNegotiatedContext
	// CondInitializeVersionUnsupported: an initialize whose requested version is
	// unsupported. Preferred handling is a 200 InitializeResult counter-offer of a
	// supported version — NOT a 4xx — so a spec-conformant or catch-any SDK client
	// is never recruited into the legacy 2024-11-05 probe.
	CondInitializeVersionUnsupported
)

// TransportDecision is the terminal outcome for a transport condition.
type TransportDecision struct {
	// Status is the HTTP status the listener must return.
	Status int
	// RetainStream is ALWAYS false: no condition here ever allocates or holds a
	// stream. It is a field (not an implicit) so the invariant is visible and
	// testable — "N rejected clients ⇒ zero retained streams" begins here.
	RetainStream bool
	// CounterOffer is true only for the initialize counter-offer (a 200 carrying a
	// supported-version InitializeResult), false for every terminal 4xx.
	CounterOffer bool
	// Reason is a stable machine reason string.
	Reason string
}

// DecideTransport maps a transport condition to its terminal decision. Every
// decision retains zero streams; only the initialize-unsupported case is a
// non-4xx (a 200 counter-offer). There is deliberately no case that returns a
// legacy SSE stream, an endpoint event, or an automatic fallback.
func DecideTransport(cond TransportCondition) TransportDecision {
	switch cond {
	case CondSessionlessMissingVersion:
		return TransportDecision{Status: 400, Reason: "sessionless_missing_version_header"}
	case CondInvalidVersionHeader:
		return TransportDecision{Status: 400, Reason: "invalid_or_unsupported_version_header"}
	case CondMissingSessionID:
		return TransportDecision{Status: 400, Reason: "missing_session_id"}
	case CondUnknownOrTerminatedSession:
		return TransportDecision{Status: 404, Reason: "unknown_or_terminated_session"}
	case CondDeleteUnsupported:
		return TransportDecision{Status: 405, Reason: "delete_unsupported"}
	case CondGetWithoutNegotiatedContext:
		return TransportDecision{Status: 405, Reason: "get_without_negotiated_context"}
	case CondInitializeVersionUnsupported:
		return TransportDecision{Status: 200, CounterOffer: true, Reason: "initialize_counter_offer"}
	default:
		// Fail closed: an unrecognized condition is a terminal 400 with no stream.
		return TransportDecision{Status: 400, Reason: "unrecognized_transport_condition"}
	}
}
