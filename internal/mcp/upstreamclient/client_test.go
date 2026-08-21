package upstreamclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

type fixedResolver struct{ addrs []netip.Addr }

func (r fixedResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	return r.addrs, nil
}

func testPolicy(t *testing.T) destination.Policy {
	t.Helper()
	p, err := destination.NewPolicy(destination.PolicyConfig{Schemes: []string{"https"}, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestClient(t *testing.T, resolver destination.Resolver) *Client {
	t.Helper()
	c, err := New(Config{
		Limits:           DefaultLimits(),
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

func TestAdmittedMethods(t *testing.T) {
	for _, m := range []string{"initialize", "notifications/initialized", "ping", "notifications/cancelled", "tools/list", "tools/call"} {
		if !Admitted(m) {
			t.Fatalf("%q should be admitted", m)
		}
	}
	for _, m := range []string{"tools/get", "sampling/createMessage", "resources/list", "roots/list", "completion/complete", ""} {
		if Admitted(m) {
			t.Fatalf("%q must NOT be admitted", m)
		}
	}
}

func TestCallRejectsUnadmittedMethod(t *testing.T) {
	c := newTestClient(t, fixedResolver{})
	_, err := c.Call(context.Background(), Target{ServerID: "s1", Endpoint: "https://e/"}, "resources/list", nil, CallOptions{})
	if mcperr.ReasonOf(err) != mcperr.ReasonUpstreamTransportRejected {
		t.Fatalf("expected transport-rejected, got %v", err)
	}
}

func TestCallRequiresRegisteredEndpoint(t *testing.T) {
	c := newTestClient(t, fixedResolver{})
	_, err := c.Call(context.Background(), Target{ServerID: "s1", Endpoint: ""}, "tools/list", nil, CallOptions{})
	if mcperr.ReasonOf(err) != mcperr.ReasonUpstreamEndpointInvalid {
		t.Fatalf("expected endpoint-invalid, got %v", err)
	}
}

func TestRetryRules(t *testing.T) {
	// Write (non-idempotent): never retried.
	if retryable(false, 0, 5, true) {
		t.Fatal("write must never be retried")
	}
	// Read after a response was received: never retried.
	if retryable(true, 0, 5, false) {
		t.Fatal("must not retry after a response was received")
	}
	// Read, pre-response, within budget: retryable.
	if !retryable(true, 1, 5, true) {
		t.Fatal("idempotent pre-response within budget should retry")
	}
	// Budget exhausted: no retry.
	if retryable(true, 5, 5, true) {
		t.Fatal("must not retry past budget")
	}
}

func TestNegotiateVersion(t *testing.T) {
	if v, err := NegotiateVersion(""); err != nil || v != protocol.VersionPrimary {
		t.Fatalf("empty selection should offer primary: %v %v", v, err)
	}
	if v, err := NegotiateVersion(protocol.VersionFloor); err != nil || v != protocol.VersionFloor {
		t.Fatalf("floor should be accepted: %v %v", v, err)
	}
	if _, err := NegotiateVersion(protocol.Version("2024-11-05")); mcperr.ReasonOf(err) != mcperr.ReasonUpstreamVersionUnsupported {
		t.Fatalf("legacy version must be rejected, got %v", err)
	}
}

func TestSPKIVerifier(t *testing.T) {
	v := spkiVerifier{}
	if err := v.VerifyIdentity(tls.ConnectionState{}, ""); err != nil {
		t.Fatal("empty pinned identity ⇒ standard verification (nil)")
	}
	if err := v.VerifyIdentity(tls.ConnectionState{}, "somehash"); mcperr.ReasonOf(err) != mcperr.ReasonUpstreamTLSIdentity {
		t.Fatalf("no peer cert should fail identity, got %v", err)
	}
}

func TestPoolExhaustion(t *testing.T) {
	lim, _ := NewLimits(LimitConfig{MaxInFlight: 1, MaxQueuePerServer: 1})
	p := newServerPool(lim)
	// Hold the single in-flight slot.
	rel1, err := p.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Second acquire consumes the single queue slot then blocks on the sem; a third
	// must be rejected as pool-exhausted (queue full).
	done := make(chan error, 1)
	go func() {
		rel2, e := p.acquire(context.Background())
		if rel2 != nil {
			rel2()
		}
		done <- e
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := p.acquire(context.Background()); mcperr.ReasonOf(err) != mcperr.ReasonUpstreamPoolExhausted {
		t.Fatalf("third acquire should be pool-exhausted, got %v", err)
	}
	rel1()
	if e := <-done; e != nil {
		t.Fatalf("queued acquire should succeed after release: %v", e)
	}
}

func TestReadBoundedRejectsOversize(t *testing.T) {
	_, err := readBounded(strings.NewReader("0123456789"), 4)
	if mcperr.ReasonOf(err) != mcperr.ReasonUpstreamResponseTooLarge {
		t.Fatalf("oversize response must be rejected, got %v", err)
	}
	out, err := readBounded(strings.NewReader("abc"), 8)
	if err != nil || string(out) != "abc" {
		t.Fatalf("within-bound read failed: %v", err)
	}
}

func TestBuildRequestShapes(t *testing.T) {
	// A notification carries no id.
	b, _ := buildRequest("notifications/initialized", "x", nil)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, hasID := m["id"]; hasID {
		t.Fatal("a notification must not carry an id")
	}
	// A request carries the independent wire id.
	b2, _ := buildRequest("tools/list", "wire-7", nil)
	_ = json.Unmarshal(b2, &m)
	if m["id"] != "wire-7" {
		t.Fatal("request must carry the wire id")
	}
}

// ── End-to-end over real TLS with a pinned loopback server ──────────────────

func spkiPin(cert *tls.Certificate) string {
	sum := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestCallEndToEndPinned(t *testing.T) {
	restore := ssrf.AllowLoopbackForTest()
	defer restore()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("no Authorization header may be forwarded upstream")
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%q,"result":{"tools":[]}}`, req["id"])
	}))
	defer srv.Close()

	// The server's leaf cert must be parsed for its SPKI.
	cert := srv.TLS.Certificates[0]
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		cert.Leaf = leaf
	}
	pin := spkiPin(&cert)

	host := strings.TrimPrefix(srv.URL, "https://")
	ipStr, portStr, _ := net.SplitHostPort(host)
	addr, _ := netip.ParseAddr(ipStr)
	c := newTestClient(t, fixedResolver{addrs: []netip.Addr{addr}})

	resp, err := c.Call(context.Background(), Target{ServerID: "s1", Endpoint: "https://" + ipStr + ":" + portStr, PinnedIdentity: pin}, "tools/list", nil, CallOptions{Idempotent: true, WireID: "call-1"})
	if err != nil {
		t.Fatalf("pinned call failed: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error object: %+v", resp.Error)
	}
	if !strings.Contains(string(resp.Result), "tools") {
		t.Fatalf("unexpected result: %s", resp.Result)
	}
}

func TestCallEndToEndIdentityMismatch(t *testing.T) {
	restore := ssrf.AllowLoopbackForTest()
	defer restore()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"x","result":{}}`)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	ipStr, portStr, _ := net.SplitHostPort(host)
	addr, _ := netip.ParseAddr(ipStr)
	c := newTestClient(t, fixedResolver{addrs: []netip.Addr{addr}})
	_, err := c.Call(context.Background(), Target{ServerID: "s1", Endpoint: "https://" + ipStr + ":" + portStr, PinnedIdentity: "wrong-pin"}, "tools/list", nil, CallOptions{})
	if mcperr.ReasonOf(err) != mcperr.ReasonUpstreamTLSIdentity {
		t.Fatalf("wrong pinned identity must fail with tls-identity, got %v", err)
	}
}

func TestCallRejectsMetadataDestination(t *testing.T) {
	c := newTestClient(t, fixedResolver{addrs: []netip.Addr{netip.MustParseAddr("169.254.169.254")}})
	// AllowPrivate lets the pin form, but VerifyPeer's authoritative ssrf.Control
	// refuses the metadata peer at connect time.
	_, err := c.Call(context.Background(), Target{ServerID: "s1", Endpoint: "https://metadata.internal:443"}, "tools/list", nil, CallOptions{})
	if err == nil {
		t.Fatal("a metadata destination must be refused")
	}
}
