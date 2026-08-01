package jsonrpc

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func malformed(detail string) error {
	return mcperr.New(mcperr.ReasonMalformedJSON, "decode", detail)
}

func resourceLimit(detail string) error {
	return mcperr.New(mcperr.ReasonResourceLimit, "decode", detail)
}

// envelopeKeys is the exact set of JSON-RPC 2.0 top-level members. An unknown
// top-level member makes the envelope ambiguous and is rejected — the kernel
// validates the envelope, not an open-world object.
var envelopeKeys = map[string]struct{}{
	"jsonrpc": {}, "method": {}, "id": {}, "params": {}, "result": {}, "error": {},
}

func envelopeKey(k string) bool { _, ok := envelopeKeys[k]; return ok }

// envelope is the six known JSON-RPC 2.0 top-level members, captured as raw views
// into the original frame (no business content is re-parsed).
type envelope struct {
	JSONRPC json.RawMessage `json:"jsonrpc"`
	Method  json.RawMessage `json:"method"`
	ID      json.RawMessage `json:"id"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// Decode strictly validates and classifies a single JSON-RPC frame under the
// given limits. It returns a Message whose Raw is the exact validated frame
// (forward Raw downstream — never a re-encoding — to preserve MCP-PROTO-001's
// no-differential guarantee) or a typed *mcperr.Error. It never panics on
// arbitrary input (MCP-PROTO-009) and never echoes raw hostile bytes.
func Decode(raw []byte, lim limits.Limits) (Message, error) {
	if err := validateStrict(raw, lim); err != nil {
		return Message{}, err
	}
	// Safe — validateStrict already proved this frame is strict JSON with only
	// known top-level members. RawMessage fields view the original bytes.
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Message{}, malformed("envelope extraction failed")
	}
	if string(trimSpace(env.JSONRPC)) != `"2.0"` {
		return Message{}, invalidJSONRPC(`jsonrpc member must be exactly "2.0"`)
	}
	if env.ID != nil && len(env.ID) > lim.MaxIDBytes() {
		return Message{}, resourceLimit("id length")
	}
	id, err := parseID(env.ID)
	if err != nil {
		return Message{}, err
	}
	if env.Method != nil {
		return classifyMethodful(raw, env, id, lim)
	}
	return classifyResponse(raw, env, id, lim)
}

// classifyMethodful classifies a message that carries a method (a request or a
// notification).
func classifyMethodful(raw []byte, env envelope, id ID, lim limits.Limits) (Message, error) {
	if env.Result != nil || env.Error != nil {
		return Message{}, invalidJSONRPC("message carries both method and result/error")
	}
	method, err := decodeMethod(env.Method, lim)
	if err != nil {
		return Message{}, err
	}
	switch id.Kind {
	case IDAbsent:
		return Message{Class: ClassNotification, Method: method, Params: env.Params, Raw: raw}, nil
	case IDInt, IDString:
		return Message{Class: ClassRequest, Method: method, ID: id, Params: env.Params, Raw: raw}, nil
	default: // IDNull — a notification must omit id; a request needs a correlatable one.
		return Message{}, invalidJSONRPC("method message with null id (neither a valid request nor notification)")
	}
}

// classifyResponse classifies a message that carries no method (a response).
func classifyResponse(raw []byte, env envelope, id ID, lim limits.Limits) (Message, error) {
	if env.Params != nil {
		return Message{}, invalidJSONRPC("response carries params")
	}
	hasResult, hasError := env.Result != nil, env.Error != nil
	if hasResult && hasError {
		return Message{}, invalidJSONRPC("response carries both result and error")
	}
	if !hasResult && !hasError {
		return Message{}, invalidJSONRPC("response carries neither result nor error")
	}
	if !id.Correlatable() {
		return Message{}, invalidJSONRPC("response without a correlatable id")
	}
	msg := Message{Class: ClassResponse, ID: id, Raw: raw}
	if hasResult {
		msg.Result = env.Result
		return msg, nil
	}
	eo, err := decodeErrorObject(env.Error, lim)
	if err != nil {
		return Message{}, err
	}
	msg.Error = eo
	return msg, nil
}

// decodeMethod extracts and validates a method token: a non-empty ASCII string
// within MaxMethodBytes, drawn from a conservative method-token charset. Non-ASCII
// method names are rejected (MCP-PROTO-014.3); the exact supported-set match is
// the protocol package's admission step, not this decoder's.
func decodeMethod(raw json.RawMessage, lim limits.Limits) (string, error) {
	var m string
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", invalidJSONRPC("method is not a JSON string")
	}
	if m == "" {
		return "", invalidJSONRPC("empty method")
	}
	if len(m) > lim.MaxMethodBytes() {
		return "", resourceLimit("method length")
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if c >= 0x80 {
			return "", invalidJSONRPC("non-ascii method token")
		}
		if !isMethodByte(c) {
			return "", invalidJSONRPC("invalid character in method token")
		}
	}
	return m, nil
}

func isMethodByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '/' || c == '_' || c == '-' || c == '.':
		return true
	default:
		return false
	}
}

// decodeErrorObject validates a response error member: an object with an integer
// code (no float precision loss), a string message, and optional bounded data.
func decodeErrorObject(raw json.RawMessage, lim limits.Limits) (*ErrorObject, error) {
	var e struct {
		Code    json.RawMessage `json:"code"`
		Message json.RawMessage `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, invalidJSONRPC("error member is not an object")
	}
	if e.Code == nil || e.Message == nil {
		return nil, invalidJSONRPC("error object missing code or message")
	}
	codeID, err := parseID(e.Code) // reuse exact-integer parsing
	if err != nil || codeID.Kind != IDInt {
		return nil, invalidJSONRPC("error code is not an exact integer")
	}
	var msg string
	if err := json.Unmarshal(e.Message, &msg); err != nil {
		return nil, invalidJSONRPC("error message is not a string")
	}
	if len(e.Data) > lim.MaxErrorDataBytes() {
		return nil, resourceLimit("error data length")
	}
	return &ErrorObject{Code: codeID.Int, Message: msg, Data: e.Data}, nil
}

// validateStrict enforces every structural rule before any semantic extraction:
// non-empty, within frame bytes, valid UTF-8, a single top-level JSON object
// (never a top-level batch array or scalar), bounded depth / object-member /
// array-element counts, bounded string and number token lengths, no duplicate
// object keys, only known top-level members, and no trailing bytes / second
// top-level value.
func validateStrict(raw []byte, lim limits.Limits) error {
	if len(raw) == 0 {
		return malformed("empty frame")
	}
	if len(raw) > lim.MaxFrameBytes() {
		return resourceLimit("frame bytes")
	}
	if !utf8.Valid(raw) {
		return malformed("invalid UTF-8")
	}
	// utf8.Valid only checks the ENCODED bytes; a JSON \uXXXX escape naming an
	// unpaired surrogate is ASCII-valid but encoding/json silently decodes it to
	// U+FFFD. Two distinct string ids ("\ud800" and "\udc00") would then collapse
	// to the same correlation key. Reject unpaired surrogate escapes up front.
	if err := rejectUnpairedSurrogateEscapes(raw); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // never route numbers through float64 during validation

	t, err := dec.Token()
	if err != nil {
		return malformed("not well-formed JSON")
	}
	d, ok := t.(json.Delim)
	if !ok {
		return invalidJSONRPC("top-level value is not a JSON object")
	}
	switch d {
	case '[':
		return mcperr.New(mcperr.ReasonUnsupportedBatch, "decode",
			"top-level JSON-RPC batch array is not supported in V1 (rejected whole)")
	case '{':
		// ok — fall through to body walk
	default:
		return invalidJSONRPC("top-level value is not a JSON object")
	}

	w := &walker{dec: dec, lim: lim}
	if err := w.objectBody(1, true); err != nil {
		return err
	}
	// Nothing may follow the single top-level value (trailing whitespace is fine —
	// the decoder skips it — but a second value is not).
	if _, err := dec.Token(); err != io.EOF {
		return invalidJSONRPC("trailing bytes or multiple top-level values")
	}
	return nil
}

// hex4 reads exactly four hex digits at raw[pos:pos+4], returning the value and
// ok=false if out of range or non-hex.
func hex4(raw []byte, pos int) (int, bool) {
	if pos+4 > len(raw) {
		return 0, false
	}
	v := 0
	for i := 0; i < 4; i++ {
		c := raw[pos+i]
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | int(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | int(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// rejectUnpairedSurrogateEscapes scans for JSON \uXXXX escapes and rejects any
// high surrogate (D800-DBFF) not immediately followed by a \u low surrogate
// (DC00-DFFF), and any lone low surrogate. A `\\` escapes the backslash, so a
// literal "\\uD800" is data, not an escape, and is skipped. Backslashes appear
// only inside JSON strings, and the structural walk independently rejects any
// backslash that is not part of a valid string.
func rejectUnpairedSurrogateEscapes(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			break // a trailing backslash is a JSON error the structural walk catches
		}
		if raw[i+1] != 'u' {
			i++ // an escaped char (\\, \", \n, …); skip it so \\u is not read as \u
			continue
		}
		consumed, err := checkUnicodeEscape(raw, i)
		if err != nil {
			return err
		}
		i += consumed
	}
	return nil
}

// checkUnicodeEscape validates the \uXXXX escape at raw[i] (raw[i]=='\\',
// raw[i+1]=='u'), rejecting an unpaired high or lone low surrogate. It returns
// the number of EXTRA bytes to advance past the escape(s) — the caller's loop
// adds the final +1 — so a single escape yields 5 and a valid surrogate pair 11.
func checkUnicodeEscape(raw []byte, i int) (int, error) {
	hi, ok := hex4(raw, i+2)
	if !ok {
		return 0, malformed("malformed \\u escape")
	}
	if hi >= 0xDC00 && hi <= 0xDFFF {
		return 0, malformed("lone low surrogate escape")
	}
	if hi < 0xD800 || hi > 0xDBFF {
		return 5, nil // a non-surrogate \uXXXX
	}
	// A high surrogate must be immediately followed by a low-surrogate \u escape.
	if i+6 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
		return 0, malformed("unpaired high surrogate escape")
	}
	lo, ok := hex4(raw, i+8)
	if !ok || lo < 0xDC00 || lo > 0xDFFF {
		return 0, malformed("unpaired high surrogate escape")
	}
	return 11, nil // consumed both \uXXXX escapes
}

// walker carries the decoder and limits through the recursive structural walk.
type walker struct {
	dec *json.Decoder
	lim limits.Limits
}

// objectBody validates an object whose opening '{' has already been consumed. It
// enforces member count, per-key uniqueness, string-key length, and — for the
// top-level envelope object (top) — the known-member allowlist.
func (w *walker) objectBody(depth int, top bool) error {
	members := 0
	var seen map[string]struct{}
	for w.dec.More() {
		kt, err := w.dec.Token()
		if err != nil {
			return malformed("bad object key")
		}
		key, ok := kt.(string)
		if !ok {
			return malformed("non-string object key")
		}
		if len(key) > w.lim.MaxStringBytes() {
			return resourceLimit("object key length")
		}
		members++
		if members > w.lim.MaxObjectMembers() {
			return resourceLimit("object member count")
		}
		if seen == nil {
			seen = make(map[string]struct{}, 8)
		}
		if _, dup := seen[key]; dup {
			return malformed("duplicate object key")
		}
		seen[key] = struct{}{}
		if top && !envelopeKey(key) {
			return invalidJSONRPC("unknown top-level member")
		}
		if err := w.value(depth + 1); err != nil {
			return err
		}
	}
	if _, err := w.dec.Token(); err != nil { // consume '}'
		return malformed("unterminated object")
	}
	return nil
}

// arrayBody validates an array whose opening '[' has already been consumed.
func (w *walker) arrayBody(depth int) error {
	elems := 0
	for w.dec.More() {
		elems++
		if elems > w.lim.MaxArrayElements() {
			return resourceLimit("array element count")
		}
		if err := w.value(depth + 1); err != nil {
			return err
		}
	}
	if _, err := w.dec.Token(); err != nil { // consume ']'
		return malformed("unterminated array")
	}
	return nil
}

// value validates the next single JSON value at the given depth.
func (w *walker) value(depth int) error {
	if depth > w.lim.MaxDepth() {
		return resourceLimit("nesting depth")
	}
	t, err := w.dec.Token()
	if err != nil {
		return malformed("bad value")
	}
	switch tok := t.(type) {
	case json.Delim:
		switch tok {
		case '{':
			return w.objectBody(depth, false)
		case '[':
			return w.arrayBody(depth)
		default:
			return malformed("unbalanced delimiter")
		}
	case string:
		if len(tok) > w.lim.MaxStringBytes() {
			return resourceLimit("string length")
		}
		return nil
	case json.Number:
		// Kept as a token string (UseNumber); bound its length so a pathological
		// numeric literal cannot force unbounded work (MCP-PROTO-007).
		if len(tok) > w.lim.MaxStringBytes() {
			return resourceLimit("number token length")
		}
		return nil
	case bool, nil:
		return nil
	default:
		return malformed("unexpected token")
	}
}
