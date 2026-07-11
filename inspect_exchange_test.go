package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// countingRC is a resp.Body that records Close() calls for leak/double-close
// verification across exchange outcomes.
type countingRC struct {
	r      *strings.Reader
	closes int
}

func newCountingRC(s string) *countingRC { return &countingRC{r: strings.NewReader(s)} }

func (c *countingRC) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *countingRC) Close() error               { c.closes++; return nil }

func mkExchangeReq() *http.Request {
	rq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://h.test/x", http.NoBody)
	return rq
}

func mkExchangeResp(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
	}
}

func baseExchange() *inspectExchange {
	return &inspectExchange{
		outer:     mkExchangeReq(),
		req:       mkExchangeReq(),
		host:      "h.test",
		clientIP:  "1.2.3.4",
		responder: &spyResponder{},
	}
}

// TestRunInspectExchange_TransportOutcomes proves the protocol-neutral seam routes
// the transport outcomes correctly via in-memory hooks — no conn, no protocol.
// This is the contract the HTTP/2 per-stream handler reuses (invariant C5).
func TestRunInspectExchange_TransportOutcomes(t *testing.T) {
	mkResp := mkExchangeResp
	base := baseExchange

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

// TestRunInspectExchange_BlockAndLifecycle covers block short-circuit, body-close
// counting per outcome, closeAfter propagation, and gRPC trailer survival.
func TestRunInspectExchange_BlockAndLifecycle(t *testing.T) {
	base := baseExchange

	t.Run("blockedShortCircuitsDeliver", func(t *testing.T) {
		// A file-profile block must fire inside the exchange: kind=exBlocked,
		// deliver NOT called, responder invoked — the orchestrator honors the
		// block by not delivering (the highest-value gap all three reviewers named).
		delivered := false
		resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: newCountingRC("payload")}
		blk := &spyResponder{}
		ex := base()
		ex.req.URL.Path = "/malware/setup.exe"
		yes := true
		ex.match = &PolicyMatch{Rule: &PolicyRule{FileFiltering: true, FileProfile: FileProfileExecutables, Enabled: &yes}}
		ex.responder = blk
		ex.roundTrip = func(*http.Request) (*http.Response, error) { return resp, nil }
		ex.deliver = func(*http.Response) error { delivered = true; return nil }
		out := runInspectExchange(ex)
		if out.kind != exBlocked {
			t.Fatalf("kind = %v, want exBlocked", out.kind)
		}
		if delivered {
			t.Fatal("deliver must NOT run once a block fires (payload must not reach the client)")
		}
		if blk.calls != 1 {
			t.Fatalf("responder invoked %d times, want 1", blk.calls)
		}
	})

	t.Run("closeAfterPropagation", func(t *testing.T) {
		for _, tc := range []struct {
			name              string
			reqClose, rspClse bool
			want              bool
		}{
			{"neither", false, false, false},
			{"reqClose", true, false, true},
			{"respClose", false, true, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ex := base()
				ex.req.Close = tc.reqClose
				ex.roundTrip = func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Close: tc.rspClse}, nil
				}
				ex.deliver = func(*http.Response) error { return nil }
				out := runInspectExchange(ex)
				if out.kind != exDelivered {
					t.Fatalf("kind=%v", out.kind)
				}
				if out.closeAfter != tc.want {
					t.Fatalf("closeAfter = %v, want %v", out.closeAfter, tc.want)
				}
			})
		}
	})

	t.Run("trailerSurvivesToDeliver", func(t *testing.T) {
		// The gRPC-forwarding load-bearing property: deliver receives the whole
		// *http.Response, so resp.Trailer (e.g. grpc-status) survives the pipeline.
		var got *http.Response
		ex := base()
		ex.roundTrip = func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/grpc"}},
				Trailer:    http.Header{"Grpc-Status": {"0"}},
				Body:       io.NopCloser(strings.NewReader("frame")),
			}, nil
		}
		ex.deliver = func(rp *http.Response) error { got = rp; return nil }
		if out := runInspectExchange(ex); out.kind != exDelivered {
			t.Fatalf("kind=%v", out.kind)
		}
		if got == nil || got.Trailer.Get("Grpc-Status") != "0" {
			t.Fatal("resp.Trailer (grpc-status) must survive the pipeline to deliver")
		}
	})
}

// errAfterReadCloser yields some bytes and then fails with a non-EOF error,
// simulating an origin that resets / truncates the response mid-body while the
// scan buffer is reading it. It records Close() calls to prove no double-close.
type errAfterReadCloser struct {
	data   []byte
	off    int
	closes int
}

func (e *errAfterReadCloser) Read(p []byte) (int, error) {
	if e.off < len(e.data) {
		n := copy(p, e.data[e.off:])
		e.off += n
		return n, nil
	}
	return 0, io.ErrUnexpectedEOF // origin reset / truncation, NOT io.EOF
}

func (e *errAfterReadCloser) Close() error { e.closes++; return nil }

// TestRunInspectExchange_ScanReadErrorFailsClosed is the regression guard for the
// H2 silent-empty-200 defect: when the scan buffer cannot read the full response
// body (origin RST/GOAWAY/truncation mid-buffer), runInspectExchange must return
// exDeliverError — NOT exBlocked — so both transports fail closed (H1 tears the
// tunnel down; H2 resets the stream). Conflating the read failure with a policy
// block let the H2 handler write nothing and http2.Server emit a clean, empty,
// cacheable 200 for what was actually a failed fetch. The scan responder must not
// be invoked (no block page was written) and deliver must not run (no truncated
// body reaches the client).
func TestRunInspectExchange_ScanReadErrorFailsClosed(t *testing.T) {
	// Enable the DPI scanner with a never-matching pattern and use a text
	// content-type so bodyNeedsBuffering() is true and the scan buffer engages.
	origScanner := dpiScanner
	dpiScanner = &ContentScanner{}
	if err := dpiScanner.Add("NEVERMATCHZZZ"); err != nil {
		t.Fatalf("enable dpi: %v", err)
	}
	t.Cleanup(func() { dpiScanner = origScanner })

	body := &errAfterReadCloser{data: []byte("partial-body-then-reset")}
	blk := &spyResponder{}
	delivered := false

	ex := baseExchange()
	ex.responder = blk
	ex.roundTrip = func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/plain"}}, // → bodyNeedsBuffering true (DPI on)
			Body:       body,
		}, nil
	}
	ex.deliver = func(*http.Response) error { delivered = true; return nil }

	out := runInspectExchange(ex)

	if out.kind != exDeliverError {
		t.Fatalf("scan read error: kind = %v, want exDeliverError (must fail closed, never exBlocked/exDelivered)", out.kind)
	}
	if delivered {
		t.Fatal("deliver must NOT run on a scan read error (a truncated body must not reach the client)")
	}
	if blk.calls != 0 {
		t.Fatalf("block responder invoked %d times on a read error, want 0 (no block page was written — this is a failure, not a block)", blk.calls)
	}
	if body.closes == 0 {
		t.Fatal("the origin body must be closed on a scan read error (no fd leak)")
	}
}

// TestRunInspectExchange_BodyClose verifies resp.Body is closed exactly once on
// the delivered and deliverError paths and NOT closed by the seam on the upgrade
// path (the transport driver owns the 101 teardown).
func TestRunInspectExchange_BodyClose(t *testing.T) {
	base := baseExchange
	t.Run("bodyCloseCountsPerOutcome", func(t *testing.T) {
		// delivered: seam closes resp.Body exactly once.
		rc := newCountingRC("ok")
		ex := base()
		ex.roundTrip = func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: rc}, nil
		}
		ex.deliver = func(*http.Response) error { return nil }
		if out := runInspectExchange(ex); out.kind != exDelivered {
			t.Fatalf("delivered: kind=%v", out.kind)
		}
		if rc.closes != 1 {
			t.Fatalf("delivered: resp.Body closed %d times, want 1", rc.closes)
		}

		// deliverError: seam still closes resp.Body exactly once.
		rc2 := newCountingRC("ok")
		ex2 := base()
		ex2.roundTrip = func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: rc2}, nil
		}
		ex2.deliver = func(*http.Response) error { return errors.New("client gone") }
		if out := runInspectExchange(ex2); out.kind != exDeliverError {
			t.Fatalf("deliverError: kind=%v", out.kind)
		}
		if rc2.closes != 1 {
			t.Fatalf("deliverError: resp.Body closed %d times, want 1", rc2.closes)
		}

		// upgrade: seam must NOT close resp.Body (the transport driver owns it).
		rc3 := newCountingRC("")
		ex3 := base()
		ex3.roundTrip = func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: make(http.Header), Body: rc3}, nil
		}
		ex3.deliver = func(*http.Response) error { return nil }
		if out := runInspectExchange(ex3); out.kind != exUpgrade {
			t.Fatalf("upgrade: kind=%v", out.kind)
		}
		if rc3.closes != 0 {
			t.Fatalf("upgrade: seam closed resp.Body %d times, want 0 (driver owns 101 teardown)", rc3.closes)
		}
	})
}
