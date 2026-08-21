// Package protocol layers MCP admission on top of the version-agnostic
// jsonrpc decoder: supported-version negotiation and adapters (MCP-PROTO-010/011),
// peer-role- and direction-aware method admission against the Culvert-reviewed
// registry (MCP-PROTO-002/016), session lifecycle validation (MCP-PROTO-012),
// and the listener-independent terminal-status transport primitive
// (MCP-PROTO-017).
//
// Nothing here binds a socket, speaks HTTP, or holds a stream. The transport
// primitive is a pure decision function a future PR-5 listener will consult; PR-1
// ships the decision, not the listener.
package protocol

// Capability is one of the two MCP surfaces. They share the strict parser but
// carry independent admission decision points, limits and namespaces
// (ADR-0024 §D-13): a method admitted on both surfaces still resolves to a
// different downstream owner per surface.
type Capability int

const (
	// Gateway is the business MCP Security Gateway surface (Capability B).
	Gateway Capability = iota
	// Management is the read-only + draft/validate/simulate surface (Capability A).
	Management
)

// String returns the capability label.
func (c Capability) String() string {
	if c == Management {
		return "management"
	}
	return "gateway"
}

// PeerRole identifies which untrusted leg a message arrived on. The SAME strict
// parser serves both (MCP-PROTO-015); only admission may differ.
type PeerRole int

const (
	// ClientFacing — the agent → Culvert leg (TB-1 / TB-7).
	ClientFacing PeerRole = iota
	// UpstreamFacing — the Culvert ↔ upstream-MCP-server leg (TB-2).
	UpstreamFacing
)

// String returns the peer-role label.
func (r PeerRole) String() string {
	if r == UpstreamFacing {
		return "upstream-facing"
	}
	return "client-facing"
}

// Direction is the requestor direction of a message — who originated the
// request. It is a first-class dimension of correlation state
// (session, direction, id): the same JSON-RPC id may be outstanding in BOTH
// directions at once, and one direction must never touch the other's state
// (MCP-PROTO-015). It is also an admission input: reverse-channel
// (server-originated) requests are not proxied in V1.
type Direction int

const (
	// ClientOriginated — the natural client→server request flow (the client, or
	// Culvert acting as a client toward an upstream server, is the requestor).
	ClientOriginated Direction = iota
	// ServerOriginated — the reverse channel (the server is the requestor). In V1
	// server-originated requests are rejected at admission.
	ServerOriginated
)

// String returns the direction label.
func (d Direction) String() string {
	if d == ServerOriginated {
		return "server-originated"
	}
	return "client-originated"
}
