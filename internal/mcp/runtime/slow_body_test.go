package runtime

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// A stalled request BODY must be bounded by RequestDeadline, not ReadTimeout.
//
// ctx bounds every stage that observes it, but pipeline.readBody blocks in
// io.ReadAll on the socket and the budget is only re-checked after that read
// returns. A client that sends a syntactically valid Authorization header and
// then stops sending its POST body therefore held a worker slot AND a
// per-connection budget slot until ReadTimeout -- and LimitConfig.Validate
// deliberately does not tie ReadTimeout to RequestDeadline, so an operator may
// legitimately configure it far higher. Enough concurrent slow uploads then
// exhaust MaxConcurrent despite the end-to-end deadline, which is the exact
// amplification OVN-07's per-connection budget exists to prevent.
//
// This drives a REAL listener over a REAL socket, because the mechanism under
// test is a kernel read deadline: httptest.ResponseRecorder has no socket, so a
// handler-level test could not distinguish the fix from its absence.
func slowBodyLimits(t *testing.T, requestDeadline, readTimeout time.Duration) Limits {
	t.Helper()
	c := DefaultLimits().c
	c.RequestDeadline = requestDeadline
	c.ReadTimeout = readTimeout
	l, err := NewLimits(c)
	if err != nil {
		t.Fatalf("NewLimits: %v", err)
	}
	return l
}

func TestSlowBody_BoundedByRequestDeadlineNotReadTimeout(t *testing.T) {
	// ReadTimeout is 40x RequestDeadline and Validate accepts it -- that gap is
	// the whole finding.
	const reqDeadline = 300 * time.Millisecond
	const readTimeout = 12 * time.Second

	srv := httptest.NewUnstartedServer(nil)
	addr := srv.Listener.Addr().String()

	k := newESKey(t, "k1")
	cfg := gwListenerConfig(t)
	cfg.AllowedHosts = []string{addr}
	cfg.Limits = slowBodyLimits(t, reqDeadline, readTimeout)

	l, err := newListener(cfg, testDeps(t, k, NewBoundedSink(8)), "slow-gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	srv.Config.Handler = l
	srv.Config.ReadTimeout = readTimeout
	srv.Start()
	defer srv.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A complete, well-formed request head promising 4096 body bytes -- then one
	// byte, and silence. The header passes Host/Origin, method, path/capability
	// and the credential precheck, so the request reaches the body read holding
	// both slots.
	head := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n"+
			"Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n",
		gwResource, addr, gwToken(k))
	if _, err := conn.Write([]byte(head + "{")); err != nil {
		t.Fatalf("write head: %v", err)
	}

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout - 2*time.Second))
	resp, rerr := http.ReadResponse(bufio.NewReader(conn), nil)
	elapsed := time.Since(start)

	// Either outcome is acceptable evidence that the gateway stopped waiting: a
	// status written back, or the connection torn down. What must NOT happen is
	// the request still being held when RequestDeadline has long passed.
	if rerr != nil && elapsed >= readTimeout-2*time.Second {
		t.Fatalf("no response and no teardown after %v: the stalled body is still "+
			"holding its worker and connection-budget slots, bounded by ReadTimeout "+
			"(%v) rather than RequestDeadline (%v)", elapsed, readTimeout, reqDeadline)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the stalled body was released only after %v; RequestDeadline is %v, "+
			"so the request deadline is not bounding the body read", elapsed, reqDeadline)
	}
	if resp != nil {
		defer resp.Body.Close()
		// 503 is the overload answer the budget check and the verification-slot
		// bound already use. 413 would be a lie: nothing was over-cap.
		if resp.StatusCode == http.StatusRequestEntityTooLarge {
			t.Fatalf("a body that stopped arriving was reported as 413 (over-cap). " +
				"It is a timeout, and filing it as a client size error sends the " +
				"operator looking for a large upload during a slow-upload flood")
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Logf("status %d (accepted: the connection may also simply be torn down)", resp.StatusCode)
		}
	}
}

// The classification half, driven directly: an aborted read under an expired
// context is a deadline overrun, not a resource limit.
func TestSlowBody_AbortedReadIsClassifiedAsTimeout(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, NewBoundedSink(8)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already expired when the read fails

	req := gwRequest(gwToken(k), nil)
	req.Body = nil
	req.BodyReader = &erroringReader{}

	_, reason, ok := p.readBody(ctx, req)
	if ok {
		t.Fatal("readBody reported success on a failed read")
	}
	if reason != mcperr.ReasonRequestDeadlineExceeded {
		t.Fatalf("reason = %v, want %v — a body that stopped arriving under an "+
			"expired deadline is an overload episode, not an over-cap body",
			reason, mcperr.ReasonRequestDeadlineExceeded)
	}
}

// An genuinely over-cap body must STILL be a resource limit: the timeout branch
// must not swallow the size check it sits next to.
func TestSlowBody_OverCapBodyIsStillAResourceLimit(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, NewBoundedSink(8)))

	req := gwRequest(gwToken(k), nil)
	req.Body = nil
	req.BodyReader = strings.NewReader(strings.Repeat("a", p.lim.MaxBodyBytes()+64))

	_, reason, ok := p.readBody(context.Background(), req)
	if ok {
		t.Fatal("an over-cap body was accepted")
	}
	if reason != mcperr.ReasonResourceLimit {
		t.Fatalf("reason = %v, want %v", reason, mcperr.ReasonResourceLimit)
	}
}

type erroringReader struct{}

func (*erroringReader) Read([]byte) (int, error) { return 0, context.DeadlineExceeded }
