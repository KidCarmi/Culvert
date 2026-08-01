package runtime

import (
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// MessageClass is the coarse JSON-RPC class of an observed message (safe metadata).
type MessageClass uint8

const (
	// ClassUnknown — not yet classified / not a decodable message.
	ClassUnknown MessageClass = iota
	// ClassRequest — a JSON-RPC request.
	ClassRequest
	// ClassNotification — a JSON-RPC notification (no response).
	ClassNotification
	// ClassResponse — a JSON-RPC response.
	ClassResponse
)

// String returns the class label.
func (c MessageClass) String() string {
	switch c {
	case ClassRequest:
		return "request"
	case ClassNotification:
		return "notification"
	case ClassResponse:
		return "response"
	default:
		return "unknown"
	}
}

// Disposition is the terminal disposition of an observed request.
type Disposition uint8

const (
	// DispRejected — the request was rejected before or at admission.
	DispRejected Disposition = iota
	// DispKernelTerminal — a protocol-correct kernel-terminal method completed
	// (initialize, notifications/initialized, ping, notifications/cancelled).
	DispKernelTerminal
	// DispObserveOnly — a decision-point method (tools/list, tools/call) reached the
	// observe boundary and was deterministically rejected (no policy/credential/
	// upstream). PR-5 default when no policy provider is wired.
	DispObserveOnly
	// DispPolicyAllowed — a decision-point method received an ALLOW-class policy
	// decision (PR-6). The policy result is recorded truthfully, but execution is NOT
	// implemented in this slice: no upstream call, no credential, no tool result.
	DispPolicyAllowed
)

// String returns the disposition label.
func (d Disposition) String() string {
	switch d {
	case DispKernelTerminal:
		return "kernel_terminal"
	case DispObserveOnly:
		return "observe_only"
	case DispPolicyAllowed:
		return "policy_allowed"
	default:
		return "rejected"
	}
}

// ObserveRecord is an IMMUTABLE, sanitized observation. It contains ONLY safe
// metadata — never a bearer token, DPoP proof, credential material, provider secret
// path, raw request body, full tool arguments, private certificate material, or
// unbounded user-controlled text. All potentially attacker-controlled or sensitive
// values are opaque IDs or one-way digests.
type ObserveRecord struct {
	ObservationID string              // listener-generated, monotonic
	Capability    protocol.Capability // Gateway / Management
	ListenerID    string              // stable listener identity
	ProtocolVer   string              // negotiated protocol version, if any
	Class         MessageClass        // request / notification / response
	Method        string              // admitted method name (from the closed allow-list only)
	PrincipalHash string              // one-way digest of the resolved principal, if authenticated
	ClientID      string              // OAuth client id (safe), if present
	AgentID       string              // agent id (safe), if present
	ServerID      string              // Gateway server id from the route, if present
	ToolRefHash   string              // one-way hash of the tool ref (never the raw name)
	CatalogState  string              // catalog eligibility label (carried, never promoted)
	AuthResult    string              // "ok" / stable failure reason code
	Disposition   Disposition         // terminal disposition
	Reason        mcperr.Reason       // stable rejection/observe reason (ReasonNone on success)
	HostReason    string              // hostcheck reason (stable string), if host/origin failed
	SessionDigest string              // digest of the session id (never raw attacker input)
	Start         time.Time           // request start
	DurationMS    int64               // bounded duration in ms
	RequestBytes  int                 // bounded body-byte count
	RuntimeRev    uint64              // runtime configuration revision

	// PR-6 policy-decision fields (set only for a decision-point method evaluated
	// against a policy snapshot). They carry safe metadata only — the policy action,
	// stable reason code, matched rule id, policy revision and the execution state.
	PolicyAction   string // policy action (e.g. "ALLOW", "DENY", "QUARANTINE"), if evaluated
	PolicyReason   string // stable policy reason code (e.g. "MCP.POLICY.NO_MATCH_DEFAULT_DENY")
	MatchedRule    string // matched rule id, if any
	PolicyRevision uint64 // policy snapshot revision that produced the decision
	ExecutionState string // "not_implemented" for an ALLOW-class decision in PR-6
}

// Sink receives sanitized observe records. Implementations MUST be bounded and MUST
// NOT block indefinitely; PR-5 does not implement the durable PR-8 spool. A sink
// error is advisory only — it never turns a rejection into a success, never permits
// a decision-point operation, and never blocks shutdown.
type Sink interface {
	Observe(rec ObserveRecord) error
}

// boundedChanSink is an in-memory, bounded, non-blocking sink for tests: records are
// dropped (counted) when full so a slow/failed sink can never block the request path
// or shutdown.
type boundedChanSink struct {
	ch      chan ObserveRecord
	dropped atomic.Int64
}

// NewBoundedSink returns a bounded in-memory sink holding up to size records. It is
// non-blocking: at capacity it drops (and counts) rather than blocking the caller.
func NewBoundedSink(size int) *boundedChanSink {
	if size <= 0 {
		size = 1
	}
	return &boundedChanSink{ch: make(chan ObserveRecord, size)}
}

// Observe enqueues without blocking; a full buffer drops the record.
func (s *boundedChanSink) Observe(rec ObserveRecord) error {
	select {
	case s.ch <- rec:
		return nil
	default:
		s.dropped.Add(1)
		return nil
	}
}

// Records drains and returns the buffered records (test helper).
func (s *boundedChanSink) Records() []ObserveRecord {
	out := make([]ObserveRecord, 0, len(s.ch))
	for {
		select {
		case r := <-s.ch:
			out = append(out, r)
		default:
			return out
		}
	}
}

// Dropped returns how many records were dropped at capacity.
func (s *boundedChanSink) Dropped() int64 { return s.dropped.Load() }
