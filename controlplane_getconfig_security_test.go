package main

// controlplane_getconfig_security_test.go — C1 fix coverage: GetConfig
// must redact SessionHMAC from the response for callers that are not
// enrolled, non-revoked nodes.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// makeTestLeafCert mints a self-signed leaf cert with a specified serial.
// Returned cert has SerialNumber set and is in the TLS ConnectionState
// format expected by credentials.TLSInfo.
func makeTestLeafCert(t *testing.T, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// ctxWithPeerCert returns a context carrying a gRPC peer with the given
// leaf cert — simulates an authenticated gRPC call.
func ctxWithPeerCert(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	})
}

// resetCPSecurityTestGlobals snapshots/restores globalClusterStore and
// globalConfigStore for isolation under -shuffle.
func resetCPSecurityTestGlobals(t *testing.T) {
	t.Helper()
	origSnap := globalConfigStore.Get()
	origVer := globalConfigStore.version
	// globalClusterStore is swapped out for a fresh instance so tests
	// don't leak nodes into each other; restored on cleanup.
	origCS := globalClusterStore
	globalClusterStore = &ClusterStore{st: ClusterState{Nodes: map[string]*EnrolledNode{}}}
	t.Cleanup(func() {
		globalClusterStore = origCS
		globalConfigStore.mu.Lock()
		globalConfigStore.snap = origSnap
		globalConfigStore.version = origVer
		globalConfigStore.mu.Unlock()
	})
}

// TestGetConfig_RedactsSessionHMAC_ForUnauthenticatedCaller verifies
// the core C1 fix: a caller with no TLS peer info receives a snapshot
// with SessionHMAC scrubbed.
func TestGetConfig_RedactsSessionHMAC_ForUnauthenticatedCaller(t *testing.T) {
	resetCPSecurityTestGlobals(t)
	globalConfigStore.Update(ConfigSnapshot{SessionHMAC: "deadbeef"})

	s := &controlPlaneServer{}
	raw, err := s.GetConfig(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SessionHMAC != "" {
		t.Errorf("SessionHMAC leaked to unauthenticated caller: %q", got.SessionHMAC)
	}
}

// TestGetConfig_RedactsSessionHMAC_ForUnenrolledPeer covers the more
// subtle case: the caller presented a TLS cert, but the cert serial
// is not registered with the cluster store.
func TestGetConfig_RedactsSessionHMAC_ForUnenrolledPeer(t *testing.T) {
	resetCPSecurityTestGlobals(t)
	globalConfigStore.Update(ConfigSnapshot{SessionHMAC: "deadbeef"})

	strangerCert := makeTestLeafCert(t, big.NewInt(9999))
	ctx := ctxWithPeerCert(strangerCert)

	s := &controlPlaneServer{}
	raw, err := s.GetConfig(ctx, nil)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SessionHMAC != "" {
		t.Errorf("SessionHMAC leaked to unenrolled peer: %q", got.SessionHMAC)
	}
}

// TestGetConfig_IncludesSessionHMAC_ForEnrolledPeer verifies we don't
// over-redact: an enrolled, non-revoked node must still receive
// SessionHMAC so cluster session continuity continues to work.
func TestGetConfig_IncludesSessionHMAC_ForEnrolledPeer(t *testing.T) {
	resetCPSecurityTestGlobals(t)
	globalConfigStore.Update(ConfigSnapshot{SessionHMAC: "deadbeef"})

	serial := big.NewInt(42)
	cert := makeTestLeafCert(t, serial)
	globalClusterStore.RegisterNode(&EnrolledNode{
		NodeID:     "dp-1",
		CertSerial: serial.Text(16),
	})
	ctx := ctxWithPeerCert(cert)

	s := &controlPlaneServer{}
	raw, err := s.GetConfig(ctx, nil)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SessionHMAC != "deadbeef" {
		t.Errorf("enrolled peer should receive SessionHMAC; got %q", got.SessionHMAC)
	}
}

// TestGetConfig_RedactsSessionHMAC_ForRevokedNode covers the revoked
// branch: an otherwise-enrolled cert whose serial appears on the
// revocation list must be treated as unauthenticated.
func TestGetConfig_RedactsSessionHMAC_ForRevokedNode(t *testing.T) {
	resetCPSecurityTestGlobals(t)
	globalConfigStore.Update(ConfigSnapshot{SessionHMAC: "deadbeef"})

	serial := big.NewInt(7)
	cert := makeTestLeafCert(t, serial)
	globalClusterStore.RegisterNode(&EnrolledNode{
		NodeID:     "dp-revoked",
		CertSerial: serial.Text(16),
	})
	if err := globalClusterStore.RevokeNode("dp-revoked", "test", "security-test"); err != nil {
		t.Fatalf("RevokeNode: %v", err)
	}
	ctx := ctxWithPeerCert(cert)

	s := &controlPlaneServer{}
	raw, err := s.GetConfig(ctx, nil)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SessionHMAC != "" {
		t.Errorf("revoked cert should NOT receive SessionHMAC; got %q", got.SessionHMAC)
	}
}

// TestGetConfig_PublicFieldsStillReturned guards against an over-broad
// scrub: non-secret fields (PolicyRules counts, BlockedHosts, etc.)
// must still flow through to unauthenticated callers so the bootstrap
// path continues to function.
func TestGetConfig_PublicFieldsStillReturned(t *testing.T) {
	resetCPSecurityTestGlobals(t)
	globalConfigStore.Update(ConfigSnapshot{
		SessionHMAC:   "deadbeef",
		BlockedHosts:  []string{"evil.example"},
		DefaultAction: "deny",
	})

	s := &controlPlaneServer{}
	raw, err := s.GetConfig(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SessionHMAC != "" {
		t.Errorf("SessionHMAC leaked: %q", got.SessionHMAC)
	}
	if len(got.BlockedHosts) != 1 || got.BlockedHosts[0] != "evil.example" {
		t.Errorf("BlockedHosts lost during redaction: %v", got.BlockedHosts)
	}
	if got.DefaultAction != "deny" {
		t.Errorf("DefaultAction lost during redaction: %q", got.DefaultAction)
	}
}
