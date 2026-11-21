// Package hostpin decides whether an inner request on a TLS-inspected CONNECT
// tunnel names the destination the tunnel was authorized for (ADR-0052). It is
// one predicate, Pinned, over two strings. It holds no state, performs no I/O
// and does no logging.
//
// Ownership: package main (inspect_host_pin.go, runInspectExchange) owns the
// exchange, the decision to refuse, the refusal counter, the log line and the
// block response. This package owns only the comparison and its refusal rules.
//
// # Why the comparison is its own owner
//
// The pin's value rests on one invariant: whenever it answers "pinned", the
// authority the UPSTREAM receives is the destination policy authorized. Every
// defect found in it so far was a violation of that invariant reached through
// the comparison rather than around it: a value repaired by a shared helper
// while net/http serialized the unrepaired one. The rules are therefore
// written against the wire's own definition (httpguts.PunycodeHostPort and
// httpguts.ValidHostHeader, the helpers net/http and the HTTP/2 encoder
// apply) and are tested here against the real stdlib serialization, without
// the proxy.
//
// # Scope: a NAMED tunnel destination only
//
// The anchor is the CONNECT authority, because that is the value policy
// evaluated; it is not the client's SNI. When the tunnel host is an IP literal
// the pin does not fire: a client that resolved the name itself legitimately
// CONNECTs to an address and names the origin in SNI and Host, and the proxy
// holds no name to compare against. An empty or unserializable inner authority
// is still refused in that case. The full statement of what this leaves open,
// and why a mismatch is refused with a 403, is in inspect_host_pin.go, which
// owns the gate.
//
// # Fail closed
//
// A host that cannot be canonicalized on either side is refused, an empty host
// on either side is refused, and brackets that do not enclose an IP literal
// are refused. This is deliberately NOT internal/hostutil's StripHostPort
// behavior: that helper repairs bracketed and port-suffixed spellings for the
// matchers that read through it, and tightening it would change every one of
// those callers.
package hostpin
