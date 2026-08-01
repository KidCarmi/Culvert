package protocol

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// FuzzNegotiateAndAdmit exercises the version-negotiation, adapter and
// method-admission surface: no input may panic, and the core invariants hold for
// every input — negotiation always selects a supported version, admission is
// deterministic, an admitted method resolves to exactly one handling, and an
// unsupported version never yields an adapter.
func FuzzNegotiateAndAdmit(f *testing.F) {
	seeds := []struct {
		v      string
		method string
		cap    int
		dir    int
	}{
		{"2025-11-25", "tools/call", 0, 0},
		{"2025-06-18", "ping", 1, 1},
		{"2025-03-26", "resources/read", 0, 1},
		{"garbage", "initialize", 1, 0},
		{"", "", 0, 0},
	}
	for _, s := range seeds {
		f.Add(s.v, s.method, s.cap, s.dir)
	}
	f.Fuzz(func(t *testing.T, vs, method string, capN, dirN int) {
		cap := Gateway
		if capN%2 != 0 {
			cap = Management
		}
		dir := ClientOriginated
		if dirN%2 != 0 {
			dir = ServerOriginated
		}
		v := Version(vs)

		// Negotiation always yields a SUPPORTED selected version.
		n := Negotiate(v)
		if !IsSupported(n.Selected) {
			t.Fatalf("negotiate selected an unsupported version %q", n.Selected)
		}
		if n.Accepted == n.CounterOffered {
			t.Fatalf("negotiate must be exactly one of accepted/counter-offered: %+v", n)
		}

		// An adapter exists iff the version is supported.
		_, hasAdapter := AdapterFor(v)
		if hasAdapter != IsSupported(v) {
			t.Fatalf("adapter presence != supported for %q", v)
		}

		// Admission is deterministic and resolves to exactly one handling.
		class := jsonrpc.ClassRequest
		if (capN>>1)&1 == 1 {
			class = jsonrpc.ClassNotification
		}
		a1 := Admit(cap, dir, class, method)
		a2 := Admit(cap, dir, class, method)
		if a1 != a2 {
			t.Fatalf("admission non-deterministic for %q", method)
		}
		switch a1.Handling {
		case HandlingRejected:
			// A rejection is either an unsupported method or a wire-class mismatch;
			// it must always carry a concrete reason.
			if a1.Reason != mcperr.ReasonUnsupportedMethod && a1.Reason != mcperr.ReasonInvalidJSONRPC {
				t.Fatalf("rejected method %q without a concrete reason (%v)", method, a1.Reason)
			}
		case HandlingKernelTerminal:
			if a1.DecisionPoint != "" {
				t.Fatalf("kernel-terminal method %q named a decision point", method)
			}
		case HandlingDecisionPoint:
			if a1.DecisionPoint == "" {
				t.Fatalf("decision-point method %q named no decision point", method)
			}
		default:
			t.Fatalf("unknown handling %v", a1.Handling)
		}
	})
}
