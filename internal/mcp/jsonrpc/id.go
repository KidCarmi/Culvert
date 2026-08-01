// Package jsonrpc is the MCP kernel's single strict JSON / JSON-RPC 2.0 decoder
// and envelope classifier. It has no second, lenient path: every inbound message
// is validated once by this package, and the classification it returns is the
// only one the rest of the kernel acts on (MCP-PROTO-001, no parser differential).
//
// The decoder is peer-role- and direction-agnostic on purpose: the SAME strict
// parser serves both the client-facing and the upstream-server-facing legs
// (MCP-PROTO-015); admission (which methods/versions are allowed) is layered on
// top by the protocol package, never by forking the parser.
package jsonrpc

import (
	"strconv"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// IDKind is the shape of a JSON-RPC id member.
type IDKind int

const (
	// IDAbsent: the message carried no "id" member (a notification).
	IDAbsent IDKind = iota
	// IDNull: an explicit JSON null id. Not correlatable; only ever legitimate on
	// an outbound "unparseable input" error, never accepted as a request id.
	IDNull
	// IDInt: an integer id preserved exactly as int64 (no float precision loss).
	IDInt
	// IDString: a string id.
	IDString
)

// ID is a decoded JSON-RPC id. Integer ids are kept as int64 — never routed
// through float64 — so a large integer id cannot be silently rounded into a
// different value and mis-correlate (MCP-PROTO-003).
type ID struct {
	Kind IDKind
	Int  int64
	Str  string
}

// Absent reports whether no id member was present (notification shape).
func (id ID) Absent() bool { return id.Kind == IDAbsent }

// Correlatable reports whether the id can key an outstanding-request entry —
// true only for a concrete integer or string id, never absent or null.
func (id ID) Correlatable() bool { return id.Kind == IDInt || id.Kind == IDString }

// Key returns a stable, collision-free correlation key for a correlatable id.
// Integer and string ids live in disjoint key spaces ("i:" vs "s:") so the
// integer id 7 and the string id "7" never collide. Panics on a non-correlatable
// id — callers must gate on Correlatable first.
func (id ID) Key() string {
	switch id.Kind {
	case IDInt:
		return "i:" + strconv.FormatInt(id.Int, 10)
	case IDString:
		return "s:" + id.Str
	default:
		panic("jsonrpc: Key called on non-correlatable id")
	}
}

// String renders the id for debugging. It never echoes raw hostile bytes beyond
// a bounded, sanitized form of a string id.
func (id ID) String() string {
	switch id.Kind {
	case IDAbsent:
		return "<absent>"
	case IDNull:
		return "null"
	case IDInt:
		return strconv.FormatInt(id.Int, 10)
	case IDString:
		return "\"" + mcperr.Sanitize(id.Str, 64) + "\""
	default:
		return "<invalid>"
	}
}

// parseID decodes the raw id member. raw is nil when the member is absent. The
// caller has already length-bounded raw (MaxIDBytes). Number ids MUST be exact
// integers: a fractional, exponent-bearing, or out-of-int64-range number is an
// invalid id shape, not a rounded acceptance.
func parseID(raw []byte) (ID, error) {
	if raw == nil {
		return ID{Kind: IDAbsent}, nil
	}
	// raw comes from a validated document, but trim defensively.
	s := trimSpace(raw)
	if len(s) == 0 {
		return ID{}, mcperr.New(mcperr.ReasonInvalidJSONRPC, "decode", "empty id")
	}
	if string(s) == "null" {
		return ID{Kind: IDNull}, nil
	}
	if s[0] == '"' {
		var str string
		if err := strictUnmarshalString(s, &str); err != nil {
			return ID{}, mcperr.New(mcperr.ReasonInvalidJSONRPC, "decode", "malformed string id")
		}
		return ID{Kind: IDString, Str: str}, nil
	}
	// Anything else must be an exact integer. ParseInt rejects fractions,
	// exponents, leading '+', and any value outside int64 — exactly the
	// "no float precision loss" contract.
	n, err := strconv.ParseInt(string(s), 10, 64)
	if err != nil {
		return ID{}, mcperr.New(mcperr.ReasonInvalidJSONRPC, "decode", "invalid id shape (not an exact integer or string)")
	}
	return ID{Kind: IDInt, Int: n}, nil
}
