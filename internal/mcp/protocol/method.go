package protocol

import (
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Handling is how the kernel treats an admitted method.
type Handling int

const (
	// HandlingRejected: the method is not admitted; there is no dispatch path.
	HandlingRejected Handling = iota
	// HandlingKernelTerminal: the kernel handles and answers the method itself and
	// never dispatches it downstream.
	HandlingKernelTerminal
	// HandlingDecisionPoint: the method is admitted and dispatched to exactly one
	// named downstream decision point (implemented in a later slice, not PR-1).
	HandlingDecisionPoint
)

func (h Handling) String() string {
	switch h {
	case HandlingKernelTerminal:
		return "kernel-terminal"
	case HandlingDecisionPoint:
		return "decision-point"
	default:
		return "rejected"
	}
}

// methodSpec is one row of the Culvert-reviewed admitted-method registry. Exactly
// one of {kernelTerminal, a non-empty decision point} holds for every admitted
// method — the forward-parity invariant (MCP-PROTO-016), asserted by
// ValidateRegistry and by tests.
type methodSpec struct {
	method         string
	kernelTerminal bool
	// decision points per capability (empty when kernelTerminal). They differ by
	// surface even for the same wire method (ADR-0024 §D-13).
	gatewayPoint    string
	managementPoint string
	// bidirectional methods are admissible from either requestor direction (ping,
	// notifications/cancelled). All others are client-originated only —
	// server-originated (reverse-channel) instances are rejected.
	bidirectional bool
	// notification is true for notification-only methods (they carry NO id); false
	// for request methods (they carry a correlatable id). A message whose wire
	// class disagrees with this is rejected — that is the "notifications with ids"
	// and "requests without ids" guard.
	notification bool
}

// registry is the exact V1 admitted set: initialize, notifications/initialized,
// ping, notifications/cancelled, tools/list, tools/call — and nothing else.
// Every other method (resources/*, prompts/*, completion/*, sampling/*,
// elicitation/*, roots/*, tasks/*, logging/*, *_list_changed) is admitted by NO
// row and is therefore rejected (reverse parity). There is no allow_unknown_methods
// escape: admission is membership in this compiled table.
var registry = []methodSpec{
	{method: "initialize", kernelTerminal: true},
	{method: "notifications/initialized", kernelTerminal: true, notification: true},
	{method: "ping", kernelTerminal: true, bidirectional: true},
	{method: "notifications/cancelled", kernelTerminal: true, bidirectional: true, notification: true},
	{method: "tools/list", gatewayPoint: "tool_catalog_discovery", managementPoint: "management_authorization"},
	{method: "tools/call", gatewayPoint: "policy_engine", managementPoint: "management_authorization"},
}

// registryIndex is the compiled lookup, built once at init.
var registryIndex = func() map[string]methodSpec {
	m := make(map[string]methodSpec, len(registry))
	for _, s := range registry {
		m[s.method] = s
	}
	return m
}()

// AdmittedMethods returns the admitted method names (registry order). Fresh copy.
func AdmittedMethods() []string {
	out := make([]string, len(registry))
	for i, s := range registry {
		out[i] = s.method
	}
	return out
}

// Admission is the result of admitting a method on a leg/direction/capability.
type Admission struct {
	Handling Handling
	// DecisionPoint is the named downstream owner for HandlingDecisionPoint.
	DecisionPoint string
	// Reason is set for HandlingRejected (always ReasonUnsupportedMethod).
	Reason mcperr.Reason
	// Detail is a fixed, non-hostile description for a rejection.
	Detail string
}

// Admit resolves how a method is handled for the given capability, requestor
// direction and wire class. It is the sole admission gate:
//
//   - a method absent from the registry is rejected (MCP-PROTO-016);
//   - a message whose wire class disagrees with the method's role is rejected —
//     a notification-only method carrying an id, or a request method sent without
//     one (the "notifications with ids" / "requests without ids" guard);
//   - a non-bidirectional method originated by the server (reverse channel) is
//     rejected, so server-originated sampling/elicitation/roots and any other
//     reverse request never dispatch (MCP-PROTO-015 / §5).
//
// Admission is intentionally version-agnostic: the registry is Culvert's
// reviewed set, NOT "whatever the negotiated version contains". A method valid in
// the negotiated spec version but absent here is rejected all the same.
func Admit(cap Capability, dir Direction, class jsonrpc.Class, method string) Admission {
	spec, ok := registryIndex[method]
	if !ok {
		return Admission{Handling: HandlingRejected, Reason: mcperr.ReasonUnsupportedMethod, Detail: "method not in reviewed registry"}
	}
	isNotification := class == jsonrpc.ClassNotification
	if isNotification != spec.notification {
		detail := "request method sent without an id (or as a notification)"
		if spec.notification {
			detail = "notification method carrying an id"
		}
		return Admission{Handling: HandlingRejected, Reason: mcperr.ReasonInvalidJSONRPC, Detail: detail}
	}
	if !spec.bidirectional && dir == ServerOriginated {
		// A server-originated instance of a client-direction method is a
		// reverse-channel request Culvert does not proxy in V1.
		return Admission{Handling: HandlingRejected, Reason: mcperr.ReasonUnsupportedMethod, Detail: "server-originated request not proxied in V1"}
	}
	if spec.kernelTerminal {
		return Admission{Handling: HandlingKernelTerminal}
	}
	point := spec.gatewayPoint
	if cap == Management {
		point = spec.managementPoint
	}
	return Admission{Handling: HandlingDecisionPoint, DecisionPoint: point}
}

// ValidateRegistry asserts the forward/reverse parity invariants of the admitted
// registry at runtime: every admitted method resolves to exactly one of
// {kernel-terminal, a per-capability decision point} — never both, never neither
// — and no method name is duplicated. It returns an error describing the first
// violation, or nil. A test calls this so a future registry edit that breaks
// parity fails the build.
func ValidateRegistry() error {
	seen := make(map[string]struct{}, len(registry))
	for _, s := range registry {
		if _, dup := seen[s.method]; dup {
			return mcperr.New(mcperr.ReasonInvalidLifecycle, "registry.validate", "duplicate method row: "+mcperr.Sanitize(s.method, 64))
		}
		seen[s.method] = struct{}{}
		hasPoint := s.gatewayPoint != "" || s.managementPoint != ""
		if s.kernelTerminal && hasPoint {
			return mcperr.New(mcperr.ReasonInvalidLifecycle, "registry.validate", "method is both kernel-terminal and a decision point: "+mcperr.Sanitize(s.method, 64))
		}
		if !s.kernelTerminal && !hasPoint {
			return mcperr.New(mcperr.ReasonInvalidLifecycle, "registry.validate", "method is neither kernel-terminal nor a decision point: "+mcperr.Sanitize(s.method, 64))
		}
		// A decision-point method must name a point for BOTH surfaces (each surface
		// dispatches it, per ADR-0024 §D-13).
		if !s.kernelTerminal && (s.gatewayPoint == "" || s.managementPoint == "") {
			return mcperr.New(mcperr.ReasonInvalidLifecycle, "registry.validate", "decision-point method missing a per-capability owner: "+mcperr.Sanitize(s.method, 64))
		}
	}
	return nil
}
