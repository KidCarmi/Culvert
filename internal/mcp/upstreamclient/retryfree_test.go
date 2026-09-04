package upstreamclient

// retryfree_test.go — gates for the First-Controlled-Canary retry-free execution
// mode (review blocker #6: "the Canary budget does not bound physical
// side-effect-bearing upstream invocations").
//
// The invariant these gates protect:
//
//	one accepted execution reservation  =>  at most one physical tool invocation
//
// The budget reserves ONCE per logical execution, but Client.Call owns its own
// transport retry loop. The dangerous shape is not a contrived one: a peer that
// reads the FULL request body and then drops the connection without responding
// produces exactly the (idempotent, preResponse) classification that authorizes a
// re-send — so the side effect may already have happened at the peer while
// Culvert re-sends it, with no emergency-kill re-read in between.
//
// TestRetryFree_* pins the fix; TestRetryDefault_* is the CONTROL that proves the
// gate is measuring something real (the same server shape DOES cause multiple
// physical sends under the historical default) and that existing non-Canary
// behavior is unchanged.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// newClientWithLimits builds a client with caller-chosen limits so a test can
// contrast retry-free against the historical default on one server shape.
func newClientWithLimits(t *testing.T, resolver destination.Resolver, lim Limits) *Client {
	t.Helper()
	c, err := New(Config{
		Limits:           lim,
		Resolver:         resolver,
		Policy:           testPolicy(t),
		InspectionLimits: limits.DefaultGatewayInspection(),
		Clock:            time.Now,
	}, limits.DefaultGateway())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ambiguousPeer starts a TLS server that READS THE WHOLE REQUEST — i.e. the tool
// invocation has reached it and may have taken effect — and then drops the
// connection without a response. It returns the server, its SPKI pin and a
// counter of received requests (physical side-effect-bearing sends).
func ambiguousPeer(t *testing.T) (*httptest.Server, string, *atomic.Int64) {
	t.Helper()
	var received atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain the body first: the peer has now fully received the invocation.
		_, _ = io.Copy(io.Discard, r.Body)
		received.Add(1)
		// Drop without responding — a pre-response failure for the client.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("server does not support hijack")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	}))
	cert := srv.TLS.Certificates[0]
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		cert.Leaf = leaf
	}
	sum := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	return srv, base64.StdEncoding.EncodeToString(sum[:]), &received
}

// callAmbiguous drives one idempotent Call against the ambiguous peer and returns
// how many physical requests the peer actually received.
func callAmbiguous(t *testing.T, lim Limits) int64 {
	t.Helper()
	restore := ssrf.AllowLoopbackForTest()
	defer restore()

	srv, pin, received := ambiguousPeer(t)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	ipStr, portStr, _ := net.SplitHostPort(host)
	addr, _ := netip.ParseAddr(ipStr)
	c := newClientWithLimits(t, fixedResolver{addrs: []netip.Addr{addr}}, lim)

	// Idempotent:true is the retry-authorizing classification — a read/discovery
	// operation, which is exactly what the First Canary is scoped to.
	_, err := c.Call(context.Background(),
		Target{ServerID: "s1", Endpoint: "https://" + ipStr + ":" + portStr, PinnedIdentity: pin},
		"tools/call", nil, CallOptions{Idempotent: true, WireID: "call-1"})
	if err == nil {
		t.Fatal("expected the dropped connection to surface as an error")
	}
	return received.Load()
}

// TestRetryFree_ExactlyOnePhysicalSendOnAmbiguousDrop is the primary gate for
// blocker #6: under retry-free limits, a peer that receives the invocation and
// then drops MUST NOT be sent a second one.
func TestRetryFree_ExactlyOnePhysicalSendOnAmbiguousDrop(t *testing.T) {
	lim, err := RetryFreeLimits(LimitConfig{})
	if err != nil {
		t.Fatalf("RetryFreeLimits: %v", err)
	}
	if !lim.RetriesDisabled() {
		t.Fatal("RetryFreeLimits must report RetriesDisabled")
	}
	if got := callAmbiguous(t, lim); got != 1 {
		t.Fatalf("retry-free mode must produce EXACTLY ONE physical side-effect-bearing send, got %d", got)
	}
}

// TestRetryDefault_ControlMultipleSendsOnAmbiguousDrop is the CONTROL. It proves
// the gate above measures a real behavior change: the identical server shape
// causes MORE than one physical send under the historical default limits. If this
// ever reports 1, the gate above has stopped proving anything.
func TestRetryDefault_ControlMultipleSendsOnAmbiguousDrop(t *testing.T) {
	if got := callAmbiguous(t, DefaultLimits()); got <= 1 {
		t.Fatalf("control: default limits should re-send an idempotent read after a pre-response drop, got %d", got)
	}
}

// TestRetryFreeLimits_RejectsContradictoryBudget pins the fail-closed config
// contract: retry-disabled plus a retry budget is a contradiction, not a
// preference to be silently resolved.
func TestRetryFreeLimits_RejectsContradictoryBudget(t *testing.T) {
	if _, err := NewLimits(LimitConfig{RetryMode: RetryDisabled, MaxReadRetries: 2}); err == nil {
		t.Fatal("retry-disabled with a non-zero retry budget must fail closed")
	}
}

// TestNewLimits_RejectsUnknownRetryMode pins that an unrecognized mode fails
// closed rather than degrading to the retrying default.
func TestNewLimits_RejectsUnknownRetryMode(t *testing.T) {
	if _, err := NewLimits(LimitConfig{RetryMode: RetryMode(200)}); err == nil {
		t.Fatal("unknown retry mode must fail closed")
	}
}

// TestRetryDefault_PreservesHistoricalZeroSemantics pins that this change does not
// alter any existing caller: zero MaxReadRetries under the default mode still
// fills with the safe default, and retries stay enabled.
func TestRetryDefault_PreservesHistoricalZeroSemantics(t *testing.T) {
	lim, err := NewLimits(LimitConfig{})
	if err != nil {
		t.Fatalf("NewLimits: %v", err)
	}
	if lim.RetriesDisabled() {
		t.Fatal("default mode must not disable retries")
	}
	if got := lim.MaxReadRetries(); got != defMaxReadRetries {
		t.Fatalf("zero MaxReadRetries under RetryDefault must fill to %d, got %d", defMaxReadRetries, got)
	}
}
