package jsonrpc

import (
	"bytes"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func gw(t *testing.T) limits.Limits {
	t.Helper()
	return limits.DefaultGateway()
}

// tiny returns a deliberately small limit set for bound tests.
func tiny(t *testing.T) limits.Limits {
	t.Helper()
	l, err := limits.New(limits.Config{
		MaxFrameBytes: 256, MaxDepth: 4, MaxObjectMembers: 6, MaxArrayElements: 4,
		MaxStringBytes: 16, MaxMethodBytes: 12, MaxIDBytes: 8, MaxErrorDataBytes: 16,
		MaxSessions: 4, MaxOutstandingPerSession: 4, MaxTotalOutstanding: 8,
		SessionTTL: 60_000_000_000,
	})
	if err != nil {
		t.Fatalf("tiny limits: %v", err)
	}
	return l
}

func TestDecodeValidClasses(t *testing.T) {
	lim := gw(t)
	tests := []struct {
		name   string
		in     string
		class  Class
		method string
	}{
		{"request-int-id", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, ClassRequest, "ping"},
		{"request-string-id", `{"jsonrpc":"2.0","id":"a1","method":"tools/list"}`, ClassRequest, "tools/list"},
		{"request-with-params", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}}`, ClassRequest, "tools/call"},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, ClassNotification, "notifications/initialized"},
		{"notification-params", `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`, ClassNotification, "notifications/cancelled"},
		{"response-result", `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`, ClassResponse, ""},
		{"response-result-null", `{"jsonrpc":"2.0","id":1,"result":null}`, ClassResponse, ""},
		{"response-error", `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}`, ClassResponse, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := Decode([]byte(tc.in), lim)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if msg.Class != tc.class {
				t.Fatalf("class = %v, want %v", msg.Class, tc.class)
			}
			if msg.Method != tc.method {
				t.Fatalf("method = %q, want %q", msg.Method, tc.method)
			}
			// no parser differential: Raw is byte-identical to the input.
			if !bytes.Equal(msg.Raw, []byte(tc.in)) {
				t.Fatalf("Raw != input")
			}
		})
	}
}

func TestDecodeIDIntegerPrecision(t *testing.T) {
	// 2^53+1 is not representable in float64; a decoder that routed the id through
	// float64 would round it to 2^53. We must preserve the exact int64.
	const big = int64(9007199254740993)
	msg, err := Decode([]byte(`{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}`), gw(t))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.ID.Kind != IDInt || msg.ID.Int != big {
		t.Fatalf("id = %v (kind %v), want exact %d", msg.ID.Int, msg.ID.Kind, big)
	}
}

func TestDecodeRejections(t *testing.T) {
	lim := gw(t)
	tests := []struct {
		name string
		in   string
		want mcperr.Reason
	}{
		{"empty", ``, mcperr.ReasonMalformedJSON},
		{"not-json", `{`, mcperr.ReasonMalformedJSON},
		{"top-level-array-batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, mcperr.ReasonUnsupportedBatch},
		{"empty-batch", `[]`, mcperr.ReasonUnsupportedBatch},
		{"top-level-scalar", `"hi"`, mcperr.ReasonInvalidJSONRPC},
		{"top-level-number", `5`, mcperr.ReasonInvalidJSONRPC},
		{"duplicate-key", `{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`, mcperr.ReasonMalformedJSON},
		{"trailing-data", `{"jsonrpc":"2.0","id":1,"method":"ping"}{}`, mcperr.ReasonInvalidJSONRPC},
		{"two-values", `{"jsonrpc":"2.0","id":1,"method":"ping"} 7`, mcperr.ReasonInvalidJSONRPC},
		{"wrong-jsonrpc", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, mcperr.ReasonInvalidJSONRPC},
		{"missing-jsonrpc", `{"id":1,"method":"ping"}`, mcperr.ReasonInvalidJSONRPC},
		{"unknown-top-member", `{"jsonrpc":"2.0","id":1,"method":"ping","extra":1}`, mcperr.ReasonInvalidJSONRPC},
		{"method-and-result", `{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}`, mcperr.ReasonInvalidJSONRPC},
		{"request-null-id", `{"jsonrpc":"2.0","id":null,"method":"ping"}`, mcperr.ReasonInvalidJSONRPC},
		{"response-both", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}`, mcperr.ReasonInvalidJSONRPC},
		{"response-neither", `{"jsonrpc":"2.0","id":1}`, mcperr.ReasonInvalidJSONRPC},
		{"response-with-params", `{"jsonrpc":"2.0","id":1,"result":{},"params":{}}`, mcperr.ReasonInvalidJSONRPC},
		{"response-null-id", `{"jsonrpc":"2.0","id":null,"result":{}}`, mcperr.ReasonInvalidJSONRPC},
		{"id-float", `{"jsonrpc":"2.0","id":1.5,"method":"ping"}`, mcperr.ReasonInvalidJSONRPC},
		{"id-exponent", `{"jsonrpc":"2.0","id":1e3,"method":"ping"}`, mcperr.ReasonInvalidJSONRPC},
		{"id-object", `{"jsonrpc":"2.0","id":{},"method":"ping"}`, mcperr.ReasonInvalidJSONRPC},
		{"id-array", `{"jsonrpc":"2.0","id":[1],"method":"ping"}`, mcperr.ReasonInvalidJSONRPC},
		{"id-bool", `{"jsonrpc":"2.0","id":true,"method":"ping"}`, mcperr.ReasonInvalidJSONRPC},
		{"empty-method", `{"jsonrpc":"2.0","id":1,"method":""}`, mcperr.ReasonInvalidJSONRPC},
		{"method-not-string", `{"jsonrpc":"2.0","id":1,"method":5}`, mcperr.ReasonInvalidJSONRPC},
		{"non-ascii-method", `{"jsonrpc":"2.0","id":1,"method":"pïng"}`, mcperr.ReasonInvalidJSONRPC},
		{"method-space", `{"jsonrpc":"2.0","id":1,"method":"pi ng"}`, mcperr.ReasonInvalidJSONRPC},
		{"error-missing-code", `{"jsonrpc":"2.0","id":1,"error":{"message":"x"}}`, mcperr.ReasonInvalidJSONRPC},
		{"error-float-code", `{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"x"}}`, mcperr.ReasonInvalidJSONRPC},
		{"error-not-object", `{"jsonrpc":"2.0","id":1,"error":"boom"}`, mcperr.ReasonInvalidJSONRPC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.in), lim)
			if got := mcperr.ReasonOf(err); got != tc.want {
				t.Fatalf("reason = %v, want %v (err=%v)", got, tc.want, err)
			}
		})
	}
}

func TestDecodeInvalidUTF8(t *testing.T) {
	// A lone 0xFF byte inside the frame is invalid UTF-8 and must be rejected.
	raw := append([]byte(`{"jsonrpc":"2.0","id":1,"method":"pi`), 0xFF)
	raw = append(raw, []byte(`ng"}`)...)
	if got := mcperr.ReasonOf(mustErr(Decode(raw, gw(t)))); got != mcperr.ReasonMalformedJSON {
		t.Fatalf("invalid utf8 reason = %v, want malformed_json", got)
	}
}

func TestDecodeResourceBounds(t *testing.T) {
	lim := tiny(t)
	tests := []struct {
		name string
		in   string
	}{
		{"frame-bytes", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + repeat("a", 512) + `"}}`},
		{"depth", `{"jsonrpc":"2.0","id":1,"method":"ping","params":` + nest(10) + `}`},
		{"members", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7}}`},
		{"array-elems", `{"jsonrpc":"2.0","id":1,"method":"ping","params":[1,2,3,4,5]}`},
		{"string-len", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + repeat("a", 32) + `"}}`},
		{"method-len", `{"jsonrpc":"2.0","id":1,"method":"averylongmethodname"}`},
		{"id-len", `{"jsonrpc":"2.0","id":"aaaaaaaaaaaaaaaa","method":"ping"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.in), lim)
			if got := mcperr.ReasonOf(err); got != mcperr.ReasonResourceLimit {
				t.Fatalf("reason = %v, want resource_limit (err=%v)", got, err)
			}
		})
	}
}

// --- anti-weakening guard: duplicate keys ---------------------------------
//
// This pins the MCP-PROTO-001 duplicate-key control. A decoder weakened to fall
// back to encoding/json's last-wins semantics would classify this as a valid
// request and this test would fail — which is the point.
func TestDuplicateKeyIsRejectedNotLastWins(t *testing.T) {
	_, err := Decode([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}`), gw(t))
	if mcperr.ReasonOf(err) != mcperr.ReasonMalformedJSON {
		t.Fatalf("duplicate method key must be rejected, got %v", err)
	}
}

// --- anti-weakening guard: batch ------------------------------------------
func TestBatchIsRejectedWhole(t *testing.T) {
	// Even a batch of otherwise-valid messages is rejected as a whole, never split.
	_, err := Decode([]byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`), gw(t))
	if mcperr.ReasonOf(err) != mcperr.ReasonUnsupportedBatch {
		t.Fatalf("batch must be rejected whole, got %v", err)
	}
}

func TestDecodeNeverPanics(t *testing.T) {
	lim := gw(t)
	corpus := [][]byte{
		nil, {}, {'{'}, {'}'}, {'['}, {0x00}, {0xff, 0xfe}, []byte(`{"jsonrpc":`),
		[]byte(`{"jsonrpc":"2.0","id":`), []byte(`{"a":{"a":{"a":{"a":`),
		[]byte("\"\x00\""), []byte(`{"jsonrpc":"2.0","method":`),
	}
	for _, c := range corpus {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", c, r)
				}
			}()
			_, _ = Decode(c, lim)
		}()
	}
}

// helpers

func mustErr(_ Message, err error) error { return err }

func repeat(s string, n int) string {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		b.WriteString(s)
	}
	return b.String()
}

func nest(n int) string {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		b.WriteString(`{"x":`)
	}
	b.WriteString("1")
	for i := 0; i < n; i++ {
		b.WriteString("}")
	}
	return b.String()
}
