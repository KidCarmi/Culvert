package main

import (
	"context"
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

// The transport is the only stub: real authenticated CP aggregation feeds the
// real DP loop, then the same owner drives HTTP admission, metrics and the API.
func TestDistributedAdmission_ProductionWiring(t *testing.T) {
	r := newRateLimiter()
	useProductionRateLimiter(t, r)
	oldIPF, oldURL, oldTrust := ipf, cfg.ProxyBaseURL(), trustForwardedHeaders
	oldCS, oldAgg := globalClusterStore, globalRLAggregator
	oldConns := connLimiter
	connLimiter = newConnLimiter()
	t.Cleanup(func() {
		ipf = oldIPF
		SetProxyBaseURL(oldURL)
		trustForwardedHeaders = oldTrust
		globalClusterStore, globalRLAggregator = oldCS, oldAgg
		connLimiter = oldConns
	})
	globalClusterStore = &ClusterStore{st: ClusterState{Nodes: map[string]*EnrolledNode{}}}
	globalRLAggregator = &rateLimitAggregator{perNode: map[string]map[string]int{}, expireAt: map[string]time.Time{}}
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
	cp := &controlPlaneServer{}
	var fail atomic.Bool
	calls := make(chan struct{}, 1)
	c := &DataPlaneClient{nodeID: "local", callForTest: func(_ context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
		if method != methodSyncRateLimits {
			return nil, errors.New("unexpected method")
		}
		if fail.Load() {
			select {
			case calls <- struct{}{}:
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
	fail.Store(true)
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("did not exercise failed RPC")
	}
	if r.AllowAuto(ip) || r.RemoteIPCount() != 1 {
		t.Fatal("failed RPC cleared a still-fresh broadcast")
	}
	other := withClusterRateLimiter(t, 8, time.Minute)
	other.ApplyRemoteCounts(map[string]int{ip: 8})
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gossip did not stop")
	}
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
