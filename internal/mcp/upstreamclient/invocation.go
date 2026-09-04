package upstreamclient

// invocation.go — method classification for Canary physical-effect accounting
// (First Controlled Canary review §4).
//
// The budget bounds AUTHORIZED TOOL EXECUTIONS, not HTTP POSTs. Those are not the
// same thing, and conflating them breaks the experiment in both directions:
//
//   - Counting every POST as an effect makes a CORRECT run look like a breach. A
//     future MCP lifecycle implementation legitimately sends `initialize`,
//     `notifications/initialized` and `tools/list`; none of them invokes a tool, so
//     a retry-free run of exactly three authorized invocations would report six or
//     more POSTs and trip witness reconciliation.
//   - Counting no POST as an effect is worse: an unrecognized method would consume
//     no budget while still reaching the peer.
//
// Classification is therefore explicit and FAIL-CLOSED: only the methods known to
// be free of tool side effects are exempt, and anything unrecognized is treated as
// side-effect-bearing so it can never obtain a free invocation.

// MethodClass partitions the admitted upstream methods by whether invoking them
// can cause a tool side effect at the peer.
type MethodClass uint8

const (
	// ClassUnknown is an unrecognized method. It is deliberately NOT exempt: see
	// SideEffectBearing.
	ClassUnknown MethodClass = iota
	// ClassLifecycle is MCP session/protocol traffic — it establishes or tears down
	// a session and invokes no tool.
	ClassLifecycle
	// ClassDiscovery enumerates the peer's tools. It reads a catalog; it invokes no
	// tool.
	ClassDiscovery
	// ClassToolInvocation is the ONLY class that can cause a tool side effect, and
	// therefore the only class that consumes a Canary execution reservation.
	ClassToolInvocation
)

// String returns the stable machine string used in evidence and witness records.
func (c MethodClass) String() string {
	switch c {
	case ClassLifecycle:
		return "lifecycle"
	case ClassDiscovery:
		return "discovery"
	case ClassToolInvocation:
		return "tool_invocation"
	default:
		return "unknown"
	}
}

// SideEffectBearing reports whether an invocation of this class must be counted
// against the Canary execution budget and carry an attempt identity.
//
// ClassUnknown answers TRUE. That is the fail-closed direction and it is the whole
// point of the predicate: a method nobody classified must never be cheaper than one
// that was. Exemption is granted only to classes positively known to invoke no
// tool.
func (c MethodClass) SideEffectBearing() bool {
	return c != ClassLifecycle && c != ClassDiscovery
}

// ClassifyMethod maps an upstream method to its class. The mapping is a closed
// allowlist over the admitted V1 method set; every other string is ClassUnknown.
func ClassifyMethod(method string) MethodClass {
	switch method {
	case "initialize", "notifications/initialized", "ping", "notifications/cancelled":
		return ClassLifecycle
	case "tools/list":
		return ClassDiscovery
	case "tools/call":
		return ClassToolInvocation
	default:
		return ClassUnknown
	}
}

// AttemptHeader carries the Culvert-minted attempt identity to the upstream so an
// independent recording witness can attribute each received invocation to exactly
// one authorized attempt. It is non-secret by construction: it names an attempt, it
// does not authorize one.
const AttemptHeader = "Mcp-Culvert-Attempt-Id"
