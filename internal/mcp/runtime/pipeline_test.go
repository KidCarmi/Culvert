package runtime

import (
	"encoding/json"
	"io"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// doInit runs an initialize on p and returns the created session id.
func doInit(t *testing.T, p *pipeline, token string) string {
	t.Helper()
	out := p.Process(gwRequest(token, initializeBody(1)), fixedClock())
	if out.Status != 200 || out.Disposition != DispKernelTerminal {
		t.Fatalf("initialize: status=%d disp=%v reason=%v", out.Status, out.Disposition, out.Reason)
	}
	if out.SessionID == "" || !out.NewSession {
		t.Fatalf("initialize did not create a session: %+v", out)
	}
	if out.RetainStream {
		t.Fatal("initialize retained a stream")
	}
	return out.SessionID
}

// withSession clones a Gateway request adding the session header fields.
func withSession(req Request, sid string) Request {
	req.SessionID = sid
	req.HasSession = true
	req.ProtocolVersion = "2025-11-25"
	req.HasVersionHeader = true
	return req
}

func TestPipeline_InitializeThenPing(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	tok := gwToken(k)
	sid := doInit(t, p, tok)

	// notifications/initialized completes the handshake (202, no body).
	ni := withSession(gwRequest(tok, initializedNotification()), sid)
	out := p.Process(ni, fixedClock())
	if out.Status != 202 || out.Disposition != DispKernelTerminal {
		t.Fatalf("initialized: status=%d disp=%v reason=%v", out.Status, out.Disposition, out.Reason)
	}
	if len(out.ResponseBody) != 0 {
		t.Fatalf("notification produced a response body: %q", out.ResponseBody)
	}
	// ping in steady state → 200 with an empty result.
	out = p.Process(withSession(gwRequest(tok, pingBody(2)), sid), fixedClock())
	if out.Status != 200 || out.Disposition != DispKernelTerminal {
		t.Fatalf("ping: status=%d disp=%v", out.Status, out.Disposition)
	}
}

func TestPipeline_DecisionPointObserveOnly(t *testing.T) {
	k := newESKey(t, "k1")
	sink := NewBoundedSink(16)
	p := newGatewayPipeline(t, testDeps(t, k, sink))
	tok := gwToken(k)
	sid := doInit(t, p, tok)
	p.Process(withSession(gwRequest(tok, initializedNotification()), sid), fixedClock())

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"tools/list", toolsListBody(3)},
		{"tools/call", toolsCallBody(4)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := p.Process(withSession(gwRequest(tok, tc.body), sid), fixedClock())
			if out.Disposition != DispObserveOnly {
				t.Fatalf("disposition = %v, want observe-only", out.Disposition)
			}
			if out.Reason != mcperr.ReasonObserveOnly {
				t.Fatalf("reason = %v, want observe_only", out.Reason)
			}
			if out.Status != 200 {
				t.Fatalf("status = %d, want 200 (JSON-RPC error rides 200)", out.Status)
			}
			// A deterministic typed error — never a fabricated success.
			var env struct {
				Error *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
				Result json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal(out.ResponseBody, &env); err != nil {
				t.Fatalf("response not JSON: %v (%q)", err, out.ResponseBody)
			}
			if env.Error == nil {
				t.Fatalf("no error member in observe-only response: %q", out.ResponseBody)
			}
			if env.Result != nil {
				t.Fatalf("observe-only response fabricated a result: %q", out.ResponseBody)
			}
			if env.Error.Message != "observe_only" {
				t.Fatalf("error message = %q, want observe_only", env.Error.Message)
			}
			if out.RetainStream {
				t.Fatal("observe-only retained a stream")
			}
		})
	}
}

func TestPipeline_HostRejected(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	req := gwRequest(gwToken(k), initializeBody(1))
	req.Host = "evil.example.com" // not on the allowlist
	out := p.Process(req, fixedClock())
	if out.Status != 403 || out.Reason != mcperr.ReasonHostRejected {
		t.Fatalf("host reject: status=%d reason=%v", out.Status, out.Reason)
	}
	if out.Disposition != DispRejected || out.RetainStream {
		t.Fatalf("host reject disposition=%v retain=%v", out.Disposition, out.RetainStream)
	}
}

func TestPipeline_TransportMethods(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	for _, m := range []string{"GET", "DELETE", "PUT", "PATCH", "HEAD"} {
		req := gwRequest(gwToken(k), nil)
		req.HTTPMethod = m
		out := p.Process(req, fixedClock())
		if out.Status != 405 {
			t.Fatalf("%s: status=%d, want 405", m, out.Status)
		}
		if out.RetainStream {
			t.Fatalf("%s retained a stream", m)
		}
		if len(out.ResponseBody) != 0 {
			t.Fatalf("%s produced a body (possible stream): %q", m, out.ResponseBody)
		}
	}
}

func TestPipeline_DecodeFailure(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	out := p.Process(gwRequest(gwToken(k), []byte(`{not json`)), fixedClock())
	if out.Status != 400 || out.Disposition != DispRejected {
		t.Fatalf("decode failure: status=%d disp=%v", out.Status, out.Disposition)
	}
}

func TestPipeline_UnknownServerRejected(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	req := gwRequest(gwToken(k), initializeBody(1))
	req.ServerID = "does-not-exist"
	out := p.Process(req, fixedClock())
	if out.Status != 404 || out.Reason != mcperr.ReasonRegistryServerUnavailable {
		t.Fatalf("unknown server: status=%d reason=%v", out.Status, out.Reason)
	}
}

func TestPipeline_InitializeAuthFailClosesSession(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	// An initialize with NO credential must not leave a session pinning the cap.
	req := gwRequest(gwToken(k), initializeBody(1))
	req.AuthorizationHeaders = nil
	out := p.Process(req, fixedClock())
	if out.Status != 401 {
		t.Fatalf("status = %d, want 401", out.Status)
	}
	if n := p.sessions.SessionCount(); n != 0 {
		t.Fatalf("session count = %d after rejected initialize, want 0 (leak)", n)
	}
	if p.bindings.Len() != 0 {
		t.Fatalf("binding count = %d, want 0", p.bindings.Len())
	}
}

func TestPipeline_ReconcileUnbindsSweptSessions(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	sid := doInit(t, p, gwToken(k))
	if p.bindings.Len() != 1 {
		t.Fatalf("binding count = %d, want 1", p.bindings.Len())
	}
	// Simulate the kernel sweeper reclaiming the session out from under the pipeline.
	p.sessions.Close(sid)
	p.reconcileBindings()
	if p.bindings.Len() != 0 {
		t.Fatalf("binding not reconciled after session close: Len=%d", p.bindings.Len())
	}
}

func TestPipeline_BodyReadOnlyAfterHostOrigin(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	// A bad-Host request supplying a body via BodyReader must be rejected WITHOUT
	// the body ever being read (host/origin precedes the body-read step).
	tr := &trackReader{}
	req := gwRequest(gwToken(k), nil)
	req.Body = nil
	req.BodyReader = tr
	req.Host = "evil.example.com"
	out := p.Process(req, fixedClock())
	if out.Status != 403 {
		t.Fatalf("status = %d, want 403", out.Status)
	}
	if tr.reads != 0 {
		t.Fatalf("body was read %d times for a host-rejected request", tr.reads)
	}
}

// trackReader counts Read calls to prove the body is not read on a rejected path.
type trackReader struct{ reads int }

func (t *trackReader) Read(p []byte) (int, error) {
	t.reads++
	return 0, io.EOF
}

func TestPipeline_ObserveRecordEmitted(t *testing.T) {
	k := newESKey(t, "k1")
	sink := NewBoundedSink(16)
	p := newGatewayPipeline(t, testDeps(t, k, sink))
	sid := doInit(t, p, gwToken(k))
	recs := sink.Records()
	if len(recs) == 0 {
		t.Fatal("no observe record emitted")
	}
	r := recs[len(recs)-1]
	if r.Method != "initialize" || r.Disposition != DispKernelTerminal {
		t.Fatalf("record: method=%q disp=%v", r.Method, r.Disposition)
	}
	if r.ServerID != testServerID {
		t.Fatalf("record server id = %q", r.ServerID)
	}
	if r.PrincipalHash == "" || r.SessionDigest == "" {
		t.Fatal("record missing principal/session digest")
	}
	_ = sid
}
