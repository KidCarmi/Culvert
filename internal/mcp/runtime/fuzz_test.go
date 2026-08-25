package runtime

import (
	"context"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// FuzzPipelineProcess feeds arbitrary bodies through the full pipeline (with a valid
// token + host) and asserts the load-bearing invariants hold for ALL inputs: the
// pipeline never panics, never retains a stream, and never turns a decision-point
// method into a fabricated success.
func FuzzPipelineProcess(f *testing.F) {
	k := newESKey(f, "k1")
	tok := gwToken(k)
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled"}`))
	f.Add([]byte(`garbage`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, body []byte) {
		p := newGatewayPipeline(t, testDeps(t, k, nil))
		out := p.Process(context.Background(), gwRequest(tok, body), fixedClock())
		if out.RetainStream {
			t.Fatal("pipeline retained a stream")
		}
		if out.Disposition == DispObserveOnly && out.Reason != mcperr.ReasonObserveOnly {
			t.Fatalf("observe-only without the stable reason: %v", out.Reason)
		}
		// A response body that decoded to a JSON-RPC success on a decision point is a
		// contract breach; observe-only bodies always carry an error member.
		if out.Disposition == DispObserveOnly && strings.Contains(string(out.ResponseBody), `"result"`) {
			t.Fatalf("observe-only produced a result: %q", out.ResponseBody)
		}
	})
}

// FuzzParseCredential asserts credential extraction never panics and never yields a
// credential from a forbidden/malformed source.
func FuzzParseCredential(f *testing.F) {
	f.Add("Bearer abc.def.ghi", false)
	f.Add("DPoP xyz", true)
	f.Add("", false)
	f.Add("Basic Zm9v", false)
	f.Fuzz(func(t *testing.T, header string, inQuery bool) {
		req := Request{BearerInQuery: inQuery}
		if header != "" {
			req.AuthorizationHeaders = []string{header}
		}
		cred, err := parseCredential(req)
		if err == nil && inQuery {
			t.Fatal("accepted a credential while a query credential was present")
		}
		if err == nil && cred.Token == "" {
			t.Fatal("accepted an empty-token credential")
		}
	})
}

// FuzzTransportMethod asserts every method string produces a deterministic decision
// that never retains a stream.
func FuzzTransportMethod(f *testing.F) {
	f.Add("POST")
	f.Add("GET")
	f.Add("DELETE")
	f.Add("\x00\x01")
	f.Fuzz(func(t *testing.T, method string) {
		tr := decideTransportMethod(method)
		if tr.retainStream {
			t.Fatal("transport decision retained a stream")
		}
		if tr.phase == phaseTerminal && (tr.status < 100 || tr.status > 599) {
			t.Fatalf("terminal status out of range: %d", tr.status)
		}
	})
}
