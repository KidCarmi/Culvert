package runtime

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// TestAntiWeakening_ObserveOnlyNeverSucceeds proves a decision-point method can
// NEVER produce a JSON-RPC success or a 2xx-with-result: the observe boundary always
// yields a typed rejection. A regression that "helpfully" executes tools/call would
// trip this.
func TestAntiWeakening_ObserveOnlyNeverSucceeds(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	tok := gwToken(k)
	sid := doInit(t, p, tok)
	p.Process(context.Background(), withSession(gwRequest(tok, initializedNotification()), sid), fixedClock())

	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(3)), sid), fixedClock())
	if out.Disposition != DispObserveOnly || out.Reason != mcperr.ReasonObserveOnly {
		t.Fatalf("tools/call was not observe-only: disp=%v reason=%v", out.Disposition, out.Reason)
	}
	if strings.Contains(string(out.ResponseBody), `"result"`) {
		t.Fatalf("tools/call fabricated a result: %q", out.ResponseBody)
	}
}

// TestAntiWeakening_NoRawTokenInRecord proves the sanitized observe record never
// carries the raw bearer token (or any obvious secret substring).
func TestAntiWeakening_NoRawTokenInRecord(t *testing.T) {
	k := newESKey(t, "k1")
	sink := NewBoundedSink(16)
	p := newGatewayPipeline(t, testDeps(t, k, sink))
	tok := gwToken(k)
	doInit(t, p, tok)
	for _, r := range sink.Records() {
		// Flatten the record's string fields and assert the token bytes never appear.
		blob := r.PrincipalHash + r.ClientID + r.ServerID + r.ToolRefHash + r.SessionDigest +
			r.AuthResult + r.Method + r.ProtocolVer + r.HostReason + r.ObservationID
		if strings.Contains(blob, tok) {
			t.Fatal("observe record leaked the raw bearer token")
		}
		// The token's middle (payload) segment must not appear either.
		payload := strings.Split(tok, ".")[1]
		if strings.Contains(blob, payload) {
			t.Fatal("observe record leaked the token payload")
		}
	}
}

// TestAntiWeakening_RetainStreamAlwaysFalse sweeps every disposition and proves the
// no-stream invariant is unconditional.
func TestAntiWeakening_RetainStreamAlwaysFalse(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	tok := gwToken(k)
	sid := doInit(t, p, tok)
	cases := []Request{
		gwRequest(tok, initializeBody(1)),
		withSession(gwRequest(tok, pingBody(2)), sid),
		withSession(gwRequest(tok, toolsListBody(3)), sid),
		func() Request { r := gwRequest(tok, nil); r.HTTPMethod = "GET"; return r }(),
		func() Request { r := gwRequest(tok, nil); r.HTTPMethod = "DELETE"; return r }(),
		func() Request { r := gwRequest(tok, []byte("garbage")); return r }(),
		func() Request { r := gwRequest(tok, initializeBody(1)); r.Host = "evil"; return r }(),
	}
	for i, req := range cases {
		if out := p.Process(context.Background(), req, fixedClock()); out.RetainStream {
			t.Fatalf("case %d retained a stream", i)
		}
	}
}

// TestAntiWeakening_DisabledRuntimeInert proves a disabled runtime binds nothing and
// its Process path is never reachable (no listener), i.e. no SWG effect.
func TestAntiWeakening_DisabledRuntimeInert(t *testing.T) {
	rt, err := NewRuntime(Config{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if rt.Addr(false) != "" || rt.Addr(true) != "" {
		t.Fatal("disabled runtime bound a socket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = rt.Shutdown(ctx)
}

// --- benchmarks ------------------------------------------------------------

// BenchmarkPipelineKernelTerminal measures the steady-state ping path.
func BenchmarkPipelineKernelTerminal(b *testing.B) {
	k := newESKey(b, "k1")
	p := newGatewayPipelineB(b, testDeps(b, k, nil))
	tok := gwToken(k)
	out := p.Process(context.Background(), gwRequest(tok, initializeBody(1)), fixedClock())
	sid := out.SessionID
	p.Process(context.Background(), withSession(gwRequest(tok, initializedNotification()), sid), fixedClock())
	req := withSession(gwRequest(tok, pingBody(2)), sid)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(context.Background(), req, fixedClock())
	}
}

// BenchmarkPipelineObserveOnly measures the decision-point observe path.
func BenchmarkPipelineObserveOnly(b *testing.B) {
	k := newESKey(b, "k1")
	p := newGatewayPipelineB(b, testDeps(b, k, nil))
	tok := gwToken(k)
	sid := p.Process(context.Background(), gwRequest(tok, initializeBody(1)), fixedClock()).SessionID
	p.Process(context.Background(), withSession(gwRequest(tok, initializedNotification()), sid), fixedClock())
	req := withSession(gwRequest(tok, toolsListBody(3)), sid)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(context.Background(), req, fixedClock())
	}
}

// BenchmarkRuntimeDisabledStartStop is the MCP-OFF overhead benchmark (MCP-OPS-001):
// a disabled runtime's whole lifecycle must be near-free — proving that when MCP is
// off the SWG path pays nothing for its presence.
func BenchmarkRuntimeDisabledStartStop(b *testing.B) {
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt, err := NewRuntime(Config{})
		if err != nil {
			b.Fatal(err)
		}
		_ = rt.Start()
		_ = rt.Shutdown(ctx)
	}
}

func newGatewayPipelineB(b *testing.B, deps Deps) *pipeline {
	b.Helper()
	ctr := &counters{}
	p, err := newPipeline(gwListenerConfig(b), deps, "bench-gw", ctr, 1)
	if err != nil {
		b.Fatalf("newPipeline: %v", err)
	}
	return p
}
