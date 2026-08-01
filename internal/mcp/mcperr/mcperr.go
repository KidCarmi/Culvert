// Package mcperr defines the stable, sanitized error model shared by every
// package of the MCP protocol kernel (PR-1). It is a leaf package with no
// intra-kernel dependencies so that jsonrpc, protocol, session and limits can
// all return the same typed error without an import cycle.
//
// Two properties are load-bearing and are asserted by tests:
//
//   - Stable reason codes. Every kernel rejection carries a Reason whose numeric
//     value and machine string ("malformed_json", "unsupported_method", …) are
//     part of the package contract. Callers branch on Reason, never on free-form
//     message text.
//   - No hostile input in errors (MCP-PROTO-013). An Error never embeds raw,
//     attacker-controlled payload bytes. Detail is a fixed, developer-authored
//     string; any variable token that must appear is passed through Sanitize,
//     which strips control bytes and hard-bounds the length. This keeps a
//     malformed-input rejection from becoming a log-injection or memory vector.
package mcperr

import (
	"strconv"
	"strings"
)

// Reason is the stable category of a kernel rejection. The zero value,
// ReasonNone, means "not a kernel error".
type Reason int

const (
	// ReasonNone is the zero value: no kernel error.
	ReasonNone Reason = iota
	// ReasonMalformedJSON — the bytes are not well-formed strict JSON, or violate
	// a strict-decode rule (duplicate object key, invalid UTF-8, trailing bytes /
	// multiple top-level values, excessive nesting depth).
	ReasonMalformedJSON
	// ReasonInvalidJSONRPC — structurally valid JSON that is not a valid JSON-RPC
	// 2.0 envelope (bad "jsonrpc", invalid id shape, request without id,
	// notification with id, response with both result and error or neither,
	// ambiguous request/response shape).
	ReasonInvalidJSONRPC
	// ReasonUnsupportedBatch — a top-level JSON-RPC batch array. Rejected whole in
	// V1 — never split or partially processed.
	ReasonUnsupportedBatch
	// ReasonUnsupportedVersion — a protocol version outside the supported set, or a
	// sessionless first request missing the MCP-Protocol-Version identification.
	ReasonUnsupportedVersion
	// ReasonUnsupportedMethod — a method absent from the reviewed admitted registry
	// (every non-admitted method, including a method valid in the negotiated spec
	// version but not in Culvert's V1 set).
	ReasonUnsupportedMethod
	// ReasonResourceLimit — a structural or resource bound was exceeded (frame
	// bytes, depth, member/element counts, string/method/id/error-data bytes,
	// session or outstanding-request caps).
	ReasonResourceLimit
	// ReasonInvalidLifecycle — an operation illegal in the current lifecycle state.
	ReasonInvalidLifecycle
	// ReasonUncorrelatedResponse — a response whose (session, direction, id) matches
	// no outstanding request owned by this side.
	ReasonUncorrelatedResponse
	// ReasonDuplicateCompletion — a second completion for an already-resolved
	// request (distinct from a tolerated late cancellation).
	ReasonDuplicateCompletion
	// ReasonInvalidCancellation — a cancellation violating ownership, direction or
	// target rules (wrong owner, opposite direction, or naming initialize).
	ReasonInvalidCancellation
	// ReasonLateCancellation — a cancellation that arrives after its target already
	// completed. Tolerated per the spec — NOT a fault and NOT a duplicate
	// completion; surfaced as a distinct reason so callers can no-op it.
	ReasonLateCancellation

	// --- PR-2 (registry & catalog) reasons ---------------------------------
	// These extend the shared model for the server-registry and tool-catalog
	// packages. They are appended (never reordered) so every PR-1 numeric value is
	// unchanged. Byte/depth/element structural bounds keep using ReasonResourceLimit
	// (shared with the decoder); ReasonCapacityExceeded is reserved for entity-count
	// capacity (registered servers, tools, catalog entries).

	// ReasonInvalidRegistration — a server registration that fails validation:
	// empty/malformed id, malformed or non-canonical endpoint, missing pinned
	// identity, a Gateway record placed in the wrong capability namespace, a
	// duplicate id, or an already-registered canonical endpoint. Distinct from a
	// live-identity MISMATCH (ReasonServerIdentityMismatch) and from ingestion of an
	// UNREGISTERED server (ReasonUnregisteredServer).
	ReasonInvalidRegistration
	// ReasonUnregisteredServer — discovery/ingestion was attempted for a server id
	// that is not present (and enabled) in the registry snapshot. An unregistered
	// server is never eligible for tool ingestion.
	ReasonUnregisteredServer
	// ReasonServerIdentityMismatch — the caller-supplied verified identity does not
	// exactly match the server's pinned identity. A server-level fault that disables
	// the server; it can never be downgraded to tool-schema drift.
	ReasonServerIdentityMismatch
	// ReasonMalformedDiscovery — a tools/list discovery result that is structurally
	// invalid against the supported V1 contract (bad top-level shape, missing/typed
	// tool name, missing input schema, unknown envelope member) — distinct from raw
	// JSON malformation (ReasonMalformedJSON).
	ReasonMalformedDiscovery
	// ReasonDuplicateTool — two tools with the same name in one server's discovery
	// result. Never silently collapsed (no map/last-write-wins).
	ReasonDuplicateTool
	// ReasonCanonicalizationFailed — a value could not be canonicalized for hashing
	// (invalid UTF-8, duplicate key, trailing data, over-bound) when the failure is
	// not already a plain ReasonMalformedJSON at the byte layer.
	ReasonCanonicalizationFailed
	// ReasonCapacityExceeded — an entity-count capacity was exceeded (registered
	// servers, tools-per-server, or total catalog entries). Distinct from the
	// byte/structural ReasonResourceLimit.
	ReasonCapacityExceeded
	// ReasonUnknownTool — an observation for a (server,tool) with no prior catalog
	// record. Classified as quarantine-required; PR-2 never converts it to allowed.
	ReasonUnknownTool
	// ReasonPrivilegeExpansion — an observation that broadens a tool's capability
	// (proven, or conservatively-classified ambiguous security-relevant broadening).
	// Classified as quarantine-required.
	ReasonPrivilegeExpansion
	// ReasonSemanticDrift — a behavioral/description change that is neither proven
	// safe narrowing nor proven privilege expansion. Classified as review-required.
	ReasonSemanticDrift
	// ReasonStaleSnapshot — an optimistic publish whose base revision no longer
	// matches the current snapshot (a concurrent publish won). The caller re-reads
	// and retries; the current snapshot is left unchanged.
	ReasonStaleSnapshot
)

// reasonCode maps each Reason to its stable machine string. The strings are part
// of the package contract and MUST NOT change without a coordinated update.
var reasonCode = map[Reason]string{
	ReasonNone:                 "none",
	ReasonMalformedJSON:        "malformed_json",
	ReasonInvalidJSONRPC:       "invalid_jsonrpc",
	ReasonUnsupportedBatch:     "unsupported_batch",
	ReasonUnsupportedVersion:   "unsupported_version",
	ReasonUnsupportedMethod:    "unsupported_method",
	ReasonResourceLimit:        "resource_limit",
	ReasonInvalidLifecycle:     "invalid_lifecycle",
	ReasonUncorrelatedResponse: "uncorrelated_response",
	ReasonDuplicateCompletion:  "duplicate_completion",
	ReasonInvalidCancellation:  "invalid_cancellation",
	ReasonLateCancellation:     "late_cancellation",

	ReasonInvalidRegistration:    "invalid_registration",
	ReasonUnregisteredServer:     "unregistered_server",
	ReasonServerIdentityMismatch: "server_identity_mismatch",
	ReasonMalformedDiscovery:     "malformed_discovery",
	ReasonDuplicateTool:          "duplicate_tool",
	ReasonCanonicalizationFailed: "canonicalization_failed",
	ReasonCapacityExceeded:       "capacity_exceeded",
	ReasonUnknownTool:            "unknown_tool",
	ReasonPrivilegeExpansion:     "privilege_expansion",
	ReasonSemanticDrift:          "semantic_drift",
	ReasonStaleSnapshot:          "stale_snapshot",
}

// Code returns the stable machine string for the reason (e.g. "malformed_json").
// An unknown reason returns "unknown(<n>)" rather than panicking.
func (r Reason) Code() string {
	if s, ok := reasonCode[r]; ok {
		return s
	}
	return "unknown(" + strconv.Itoa(int(r)) + ")"
}

// String implements fmt.Stringer with the stable machine code.
func (r Reason) String() string { return r.Code() }

// Error is the single typed error returned by the MCP kernel. It carries a
// stable Reason, a fixed developer-authored Op/Detail (never raw hostile input),
// and an optional wrapped cause.
type Error struct {
	Reason  Reason
	Op      string // kernel operation, e.g. "decode", "classify", "admit"
	Detail  string // fixed, developer-authored description (no hostile bytes)
	wrapped error
}

// New builds a kernel Error. op and detail MUST be fixed, developer-authored
// strings. To include a variable token (e.g. an offending method name), the
// caller must pass it through Sanitize first.
func New(r Reason, op, detail string) *Error {
	return &Error{Reason: r, Op: op, Detail: detail}
}

// Wrap builds a kernel Error that wraps a lower-level cause. The cause is used
// only for errors.Is/As and Error() text; callers must ensure it too carries no
// raw hostile bytes (stdlib json errors are safe — they do not echo the input).
func Wrap(r Reason, op, detail string, cause error) *Error {
	return &Error{Reason: r, Op: op, Detail: detail, wrapped: cause}
}

// Error implements the error interface with a stable, sanitized message shape:
// "mcp: <op>: <code>: <detail>". It never prints raw payload bytes.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("mcp: ")
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(": ")
	}
	b.WriteString(e.Reason.Code())
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	return b.String()
}

// Unwrap exposes the wrapped cause for errors.Is/As.
func (e *Error) Unwrap() error { return e.wrapped }

// Is matches by Reason so callers can write errors.Is(err, mcperr.ErrX-style)
// checks via a sentinel, and also matches another *Error with the same Reason.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Reason == e.Reason && (t.Op == "" || t.Op == e.Op)
}

// ReasonOf extracts the kernel Reason from an error chain, or ReasonNone if the
// error is not (and does not wrap) a kernel Error.
func ReasonOf(err error) Reason {
	for err != nil {
		if e, ok := err.(*Error); ok {
			return e.Reason
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return ReasonNone
		}
		err = u.Unwrap()
	}
	return ReasonNone
}

// Sanitize renders an untrusted token safe to embed in an error/log message: it
// replaces every byte that is not a printable ASCII graphic (0x20–0x7E, excl.
// backslash and quote to keep CWE-117 scanners happy) with '.', and truncates to
// max bytes with a trailing "…" marker. It never returns the raw input. A
// non-positive maxLen defaults to 64.
func Sanitize(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 64
	}
	truncated := false
	if len(s) > maxLen {
		s = s[:maxLen]
		truncated = true
	}
	var b strings.Builder
	b.Grow(len(s) + 1)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '\\' || c == '"' {
			b.WriteByte('.')
			continue
		}
		b.WriteByte(c)
	}
	if truncated {
		b.WriteString("~")
	}
	return b.String()
}
