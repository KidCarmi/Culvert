package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestRunInspectExchange_TransportOutcomes proves the protocol-neutral seam routes
// the four transport outcomes correctly via in-memory hooks — no conn, no protocol.
// This is the contract the HTTP/2 per-stream handler reuses (invariant C5); the
// block paths are covered by the MITM e2e suite and TestC5_*.
func TestRunInspectExchange_TransportOutcomes(t *testing.T) {
	mkReq := func() *http.Request {
		rq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://h.test/x", http.NoBody)
		return rq
	}
	mkResp := func(status int) *http.Response {
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
		}
	}
	base := func() *inspectExchange {
		return &inspectExchange{
			outer:     mkReq(),
			req:       mkReq(),
			host:      "h.test",
			clientIP:  "1.2.3.4",
			responder: &spyResponder{},
		}
	}

	t.Run("delivered", func(t *testing.T) {
		var delivered *http.Response
		ex := base()
		ex.roundTrip = func(*http.Request) (*http.Response, error) { return mkResp(http.StatusOK), nil }
		ex.deliver = func(rp *http.Response) error { delivered = rp; return nil }
		out := runInspectExchange(ex)
		if out.kind != exDelivered {
			t.Fatalf("kind = %v, want exDelivered", out.kind)
		}
		if delivered == nil {
			t.Fatal("deliver hook was not invoked on the clean path")
		}
	})

	t.Run("roundTripError", func(t *testing.T) {
		delivered := false
		ex := base()
		ex.roundTrip = func(*http.Request) (*http.Response, error) { return nil, errors.New("dial fail") }
		ex.deliver = func(*http.Response) error { delivered = true; return nil }
		out := runInspectExchange(ex)
		if out.kind != exRoundTripError {
			t.Fatalf("kind = %v, want exRoundTripError", out.kind)
		}
		if delivered {
			t.Fatal("deliver must not run after a round-trip error")
		}
	})

	t.Run("deliverError", func(t *testing.T) {
		ex := base()
		ex.roundTrip = func(*http.Request) (*http.Response, error) { return mkResp(http.StatusOK), nil }
		ex.deliver = func(*http.Response) error { return errors.New("client gone") }
		out := runInspectExchange(ex)
		if out.kind != exDeliverError {
			t.Fatalf("kind = %v, want exDeliverError", out.kind)
		}
	})

	t.Run("upgrade101Surfaced", func(t *testing.T) {
		delivered := false
		ex := base()
		ex.roundTrip = func(*http.Request) (*http.Response, error) { return mkResp(http.StatusSwitchingProtocols), nil }
		ex.deliver = func(*http.Response) error { delivered = true; return nil }
		out := runInspectExchange(ex)
		if out.kind != exUpgrade {
			t.Fatalf("kind = %v, want exUpgrade", out.kind)
		}
		if out.resp == nil || out.resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal("exUpgrade must surface the 101 response for the transport driver to raw-relay")
		}
		if delivered {
			t.Fatal("deliver must not run for a 101 upgrade (transport driver owns the raw relay)")
		}
	})

	t.Run("scrubAndHopStripApplied", func(t *testing.T) {
		ex := base()
		ex.req.Header.Set("X-User-Identity", "spoofed")
		ex.req.Header.Set("Connection", "keep-alive")
		var seen http.Header
		ex.roundTrip = func(rq *http.Request) (*http.Response, error) {
			seen = rq.Header.Clone()
			return mkResp(http.StatusOK), nil
		}
		ex.deliver = func(*http.Response) error { return nil }
		if out := runInspectExchange(ex); out.kind != exDelivered {
			t.Fatalf("kind = %v, want exDelivered", out.kind)
		}
		if seen.Get("X-User-Identity") != "" {
			t.Error("scrubForwardedHeaders must strip X-User-Identity before the upstream round-trip")
		}
		if seen.Get("Connection") != "" {
			t.Error("removeHopHeaders must strip Connection before the upstream round-trip")
		}
	})
}
