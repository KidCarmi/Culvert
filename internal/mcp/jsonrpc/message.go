package jsonrpc

import (
	"bytes"
	"encoding/json"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Class is the JSON-RPC message class the strict decoder assigns. Every valid
// message is exactly one class; an ambiguous or malformed envelope is
// ClassInvalid and is never forwarded (MCP-PROTO-002).
type Class int

const (
	// ClassInvalid is the zero value: not a valid, classifiable message.
	ClassInvalid Class = iota
	// ClassRequest: has a method and a correlatable id.
	ClassRequest
	// ClassNotification: has a method and NO id (one-way).
	ClassNotification
	// ClassResponse: no method, a correlatable id, and exactly one of result/error.
	ClassResponse
)

func (c Class) String() string {
	switch c {
	case ClassRequest:
		return "request"
	case ClassNotification:
		return "notification"
	case ClassResponse:
		return "response"
	default:
		return "invalid"
	}
}

// ErrorObject is a validated JSON-RPC error member of a response. Data is kept as
// raw bytes (a view into the original frame) and is length-bounded; the kernel
// never re-parses business content.
type ErrorObject struct {
	Code    int64
	Message string
	Data    json.RawMessage
}

// Message is the result of decoding one frame. It carries the classification and
// the envelope fields; Params/Result are raw views into the ORIGINAL frame bytes
// so the message forwarded downstream is byte-identical to the one validated
// here (MCP-PROTO-001, no parser differential). Raw is the whole original frame.
type Message struct {
	Class  Class
	Method string          // request/notification only
	ID     ID              // request/response only
	Params json.RawMessage // request/notification only (may be nil)
	Result json.RawMessage // response only (present iff Error==nil)
	Error  *ErrorObject    // response only (present iff Result==nil)
	Raw    []byte          // the exact validated frame; forward THIS, never a re-encoding
}

// IsRequest / IsNotification / IsResponse are convenience predicates.
func (m Message) IsRequest() bool      { return m.Class == ClassRequest }
func (m Message) IsNotification() bool { return m.Class == ClassNotification }
func (m Message) IsResponse() bool     { return m.Class == ClassResponse }

// trimSpace trims JSON insignificant whitespace from both ends of a byte slice.
func trimSpace(b []byte) []byte {
	return bytes.TrimFunc(b, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// strictUnmarshalString decodes a JSON string literal into dst. It is used only
// after strict structural validation, so it cannot smuggle a second semantic
// path — it decodes exactly the bytes the validator already accepted.
func strictUnmarshalString(raw []byte, dst *string) error {
	return json.Unmarshal(raw, dst)
}

// invalidJSONRPC is a small helper for the many "not a valid JSON-RPC envelope"
// rejections, keeping every message fixed and free of hostile input.
func invalidJSONRPC(detail string) error {
	return mcperr.New(mcperr.ReasonInvalidJSONRPC, "decode", detail)
}
