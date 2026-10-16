package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// installDistributedAdmissionOwners binds fresh admission owners, installs r
// as the production limiter, and swaps the cluster store, the fleet aggregator
// and the connection limiter for test-local instances, restoring everything on
// cleanup. The snapshot apply mutates ipf/rl in place (RISK-030).
func installDistributedAdmissionOwners(t *testing.T) *RateLimiter {
	t.Helper()
	bindFreshAdmissionOwners(t)
	r := newRateLimiter()
	useProductionRateLimiter(t, r)
	oldURL, oldTrust := cfg.ProxyBaseURL(), trustForwardedHeaders
	oldCS, oldAgg := globalClusterStore, globalRLAggregator
	oldConns := connLimiter
	connLimiter = newConnLimiter()
	t.Cleanup(func() {
		SetProxyBaseURL(oldURL)
		trustForwardedHeaders = oldTrust
		globalClusterStore, globalRLAggregator = oldCS, oldAgg
		connLimiter = oldConns
	})
	globalClusterStore = &ClusterStore{st: ClusterState{Nodes: map[string]*EnrolledNode{}}}
	globalRLAggregator = &rateLimitAggregator{perNode: map[string]map[string]int{}, expireAt: map[string]time.Time{}}
	return r
}

// gossipStub is the one stubbed layer of the production wiring: the transport.
// Every SyncRateLimits call reaches the real CP handler with a real peer
// certificate until fail is set, after which each call reports a controlled
// outage and signals calls once.
type gossipStub struct {
	fail  atomic.Bool
	calls chan struct{}
}

func (g *gossipStub) client(t *testing.T, cp *controlPlaneServer, cert *x509.Certificate, ip string) *DataPlaneClient {
	t.Helper()
	return &DataPlaneClient{nodeID: "local", callForTest: func(_ context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
		if method != methodSyncRateLimits {
			return nil, errors.New("unexpected method")
		}
		if g.fail.Load() {
			select {
			case g.calls <- struct{}{}:
			default:
			}
			return nil, errors.New("controlled CP outage")
		}
		response, err := cp.SyncRateLimits(ctxWithPeerCert(cert), raw)
		if err == nil {
			var broadcast RateLimitBroadcast
			if e := json.Unmarshal(response, &broadcast); e != nil || broadcast.RemoteCounts[ip] != 2 {
				t.Errorf("CP must exclude this node's six requests: response=%s err=%v", response, e)
			}
		}
		return response, err
	}}
}

// assertClusterRateLimitDiagnosticsLive checks that metrics and the cluster
// rate-limit API read the application owner's live broadcast.
func assertClusterRateLimitDiagnosticsLive(t *testing.T) {
	t.Helper()
	if body := renderMetrics(t); !strings.Contains(body, "culvert_cluster_ratelimit_remote_stale 0") {
		t.Fatalf("metrics missed live broadcast: %s", extractClusterRLMetrics(body))
	}
	out := httptest.NewRecorder()
	apiClusterRateLimits(out, withRole(httptest.NewRequest(http.MethodGet, "/api/cluster/rate-limits", http.NoBody), RoleViewer))
	var status map[string]any
	if err := json.Unmarshal(out.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if out.Code != http.StatusOK || status["enabled"] != true || status["remote_ips"] != float64(1) || status["rate_limit_rpm"] != float64(8) || status["remote_counts_applied"] != true || status["remote_counts_stale"] != false {
		t.Fatalf("diagnostics missed admission owner: %s", out.Body.String())
	}
}

// awaitSignal waits for one signal or fails with msg.
func awaitSignal(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(msg)
	}
}

// The transport is the only stub: real authenticated CP aggregation feeds the
// real DP loop, then the same owner drives HTTP admission, metrics and the API.
func TestDistributedAdmission_ProductionWiring(t *testing.T) {
	r := installDistributedAdmissionOwners(t)
	const ip = "198.51.100.71"
	r.Configure(10, time.Minute)
	for i := 0; i < 6; i++ {
		if !r.Allow(ip) {
			t.Fatal("priming local count")
		}
	}
	// Use the production traffic slice shared by full and delta snapshot apply.
	applySnapshotTrafficExceptBlocklist(ConfigSnapshot{RateLimitRPM: 8, RateLimitExempt: []string{}})
	if rl != r || r.Limit() != 8 {
		t.Fatal("snapshot changed the admission owner or missed it")
	}
	cert := makeTestLeafCert(t, big.NewInt(71))
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "local", CertSerial: cert.SerialNumber.Text(16)})
	globalRLAggregator.Update("remote", []RateLimitDelta{{IP: ip, Count: 2}})
	stub := &gossipStub{calls: make(chan struct{}, 1)}
	c := stub.client(t, &controlPlaneServer{}, cert, ip)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.rateLimitGossipLoop(ctx, time.Millisecond, r) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("gossip did not stop")
		}
	})
	awaitAdmissionBroadcast(t, r)
	if got := globalRLAggregator.ClusterTotalsExcluding("remote")[ip]; got != 6 {
		t.Fatalf("gossip exported %d local requests, want 6", got)
	}
	if r.AllowAuto(ip) {
		t.Fatal("6 local + 2 remote did not deny at snapshot limit 8")
	}
	assertDistributedIngressDenied(t, ip)
	assertClusterRateLimitDiagnosticsLive(t)

	stub.fail.Store(true)
	awaitSignal(t, stub.calls, "did not exercise failed RPC")
	if r.AllowAuto(ip) || r.RemoteIPCount() != 1 {
		t.Fatal("failed RPC cleared a still-fresh broadcast")
	}
	other := withClusterRateLimiter(t, 8, time.Minute)
	other.ApplyRemoteCounts(map[string]int{ip: 8})
	cancel()
	awaitSignal(t, done, "gossip did not stop")
	if r.ClusterEnabled() || r.ClusterFreshness().Armed || !r.AllowAuto(ip) {
		t.Fatal("stop did not restore this owner's local-only admission")
	}
	if !other.ClusterEnabled() || other.AllowAuto(ip) {
		t.Fatal("stop changed another owner")
	}
}

func awaitAdmissionBroadcast(t *testing.T, r *RateLimiter) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !r.ClusterFreshness().Applied {
		select {
		case <-deadline.C:
			t.Fatal("CP broadcast never reached limiter")
		case <-tick.C:
		}
	}
}

// Exercise both real ingress consumers without an upstream network dependency.
func assertDistributedIngressDenied(t *testing.T, ip string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", http.NoBody)
	req.RemoteAddr = ip + ":1234"
	out := httptest.NewRecorder()
	handleRequest(out, req)
	if out.Code != http.StatusTooManyRequests {
		t.Fatalf("HTTP uses a different owner: status %d", out.Code)
	}
	// SOCKS5 performs the same check before reading its greeting. A remote-cap
	// denial must close immediately, even though the local bucket has room.
	client, server := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	socksDone := make(chan struct{})
	go func() { defer close(socksDone); handleSOCKS5(admissionPeerConn{Conn: server, ip: ip}) }()
	var greeting [1]byte
	if _, err := client.Read(greeting[:]); !errors.Is(err, io.EOF) {
		t.Errorf("SOCKS5 did not deny remote cap: %v", err)
	}
	client.Close()
	select {
	case <-socksDone:
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS5 did not finish")
	}
}

// Give the in-memory connection the real client IP used by both ingress paths.
type admissionPeerConn struct {
	net.Conn
	ip string
}

func (c admissionPeerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(c.ip), Port: 1234}
}
