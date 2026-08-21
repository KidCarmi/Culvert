package jsonrpc

import (
	"bytes"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// FuzzDecode exercises MCP-PROTO-009: no hostile input may panic, cause unbounded
// work, or produce a non-deterministic result. It also pins MCP-PROTO-001: a
// successfully-decoded message's Raw is byte-identical to the input (no parser
// differential), and a successful decode is never ClassInvalid.
func FuzzDecode(f *testing.F) {
	lim := limits.DefaultGateway()
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"x","result":{}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		`{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`,
		`{"jsonrpc":"1.0"}`,
		`{`,
		`"scalar"`,
		"{\"jsonrpc\":\"2.0\",\"method\":\"\xff\"}",
		`{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}`,
		`{"a":{"a":{"a":{"a":{"a":1}}}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Decode(data, lim)
		// Determinism: a second decode of the same bytes yields the same outcome.
		msg2, err2 := Decode(data, lim)
		if mcperr.ReasonOf(err) != mcperr.ReasonOf(err2) {
			t.Fatalf("non-deterministic reason: %v vs %v", err, err2)
		}
		if (err == nil) != (err2 == nil) || msg.Class != msg2.Class {
			t.Fatalf("non-deterministic classification")
		}
		if err == nil {
			if msg.Class == ClassInvalid {
				t.Fatalf("nil error but ClassInvalid")
			}
			if !bytes.Equal(msg.Raw, data) {
				t.Fatalf("parser differential: Raw != input")
			}
			// A correlatable id must round-trip through Key without panic.
			if msg.ID.Correlatable() {
				_ = msg.ID.Key()
			}
		}
	})
}
