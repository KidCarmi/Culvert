package main

// controlplane_verifynodecert_security_test.go — H3 fix coverage.
//
// Before H3: verifyNodeCert returned nil whenever no TLS peer info was
// present, silently authenticating any caller as any claimed node ID.
// After H3: fails closed by default; --cluster-insecure is required for
// the dev-mode bypass.

import (
	"context"
	"crypto/tls"
	"math/big"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ctxWithEmptyPeerCerts simulates a peer that carries TLS AuthInfo but
// with an empty PeerCertificates slice — the second fail-closed branch
// in verifyNodeCert.
func ctxWithEmptyPeerCerts() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}},
	})
}

// withClusterInsecure runs fn with clusterInsecure set to v, restoring
// the previous value on return. Scoped to this file so other tests are
// unaffected.
func withClusterInsecure(t *testing.T, v bool, fn func()) {
	t.Helper()
	orig := clusterInsecure
	clusterInsecure = v
	defer func() { clusterInsecure = orig }()
	fn()
}

// withClusterStore swaps globalClusterStore for a fresh fixture,
// restoring the original on return.
func withClusterStore(t *testing.T, fn func()) {
	t.Helper()
	orig := globalClusterStore
	globalClusterStore = &ClusterStore{st: ClusterState{Nodes: map[string]*EnrolledNode{}}}
	defer func() { globalClusterStore = orig }()
	fn()
}

// TestVerifyNodeCert_FailsClosedOnMissingPeerInfo is the core H3 guard:
// a caller with no gRPC peer info must NOT be accepted when
// --cluster-insecure is off (default).
func TestVerifyNodeCert_FailsClosedOnMissingPeerInfo(t *testing.T) {
	withClusterInsecure(t, false, func() {
		withClusterStore(t, func() {
			globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", CertSerial: "s1"})

			err := verifyNodeCert(context.Background(), "dp-1")
			if err == nil {
				t.Fatal("expected error; got nil (silent bypass)")
			}
			if got := status.Code(err); got != codes.Unauthenticated {
				t.Errorf("expected Unauthenticated; got %v (%v)", got, err)
			}
		})
	})
}

// TestVerifyNodeCert_FailsClosedOnMissingTLSCert covers the second
// branch: peer info is present but carries no TLS cert (e.g. non-TLS
// AuthInfo or an empty PeerCertificates slice).
func TestVerifyNodeCert_FailsClosedOnMissingTLSCert(t *testing.T) {
	withClusterInsecure(t, false, func() {
		withClusterStore(t, func() {
			globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", CertSerial: "s1"})

			// Simulate an authenticated peer with no TLS info by presenting
			// a cert-less peer context: ctxWithPeerCert with a cert whose
			// PeerCertificates slice is empty.
			ctx := ctxWithEmptyPeerCerts()
			err := verifyNodeCert(ctx, "dp-1")
			if err == nil {
				t.Fatal("expected error; got nil")
			}
			if got := status.Code(err); got != codes.Unauthenticated {
				t.Errorf("expected Unauthenticated; got %v (%v)", got, err)
			}
		})
	})
}

// TestVerifyNodeCert_InsecureOptInAllowsMissingPeer verifies that the
// dev-mode bypass is still available when the operator has explicitly
// opted in via --cluster-insecure.
func TestVerifyNodeCert_InsecureOptInAllowsMissingPeer(t *testing.T) {
	withClusterInsecure(t, true, func() {
		withClusterStore(t, func() {
			globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", CertSerial: "s1"})

			err := verifyNodeCert(context.Background(), "dp-1")
			if err != nil {
				t.Errorf("insecure opt-in should accept missing peer; got %v", err)
			}
		})
	})
}

// TestVerifyNodeCert_MatchingSerialPasses confirms the happy path
// (present peer, matching cert serial) still returns nil.
func TestVerifyNodeCert_MatchingSerialPasses(t *testing.T) {
	withClusterInsecure(t, false, func() {
		withClusterStore(t, func() {
			serial := big.NewInt(123)
			cert := makeTestLeafCert(t, serial)
			globalClusterStore.RegisterNode(&EnrolledNode{
				NodeID:     "dp-1",
				CertSerial: serial.Text(16),
			})
			ctx := ctxWithPeerCert(cert)

			if err := verifyNodeCert(ctx, "dp-1"); err != nil {
				t.Errorf("matching cert should pass; got %v", err)
			}
		})
	})
}

// TestVerifyNodeCert_SerialMismatchStillRejects confirms the existing
// PermissionDenied branch is unchanged by the H3 fix.
func TestVerifyNodeCert_SerialMismatchStillRejects(t *testing.T) {
	withClusterInsecure(t, false, func() {
		withClusterStore(t, func() {
			attackerCert := makeTestLeafCert(t, big.NewInt(999))
			globalClusterStore.RegisterNode(&EnrolledNode{
				NodeID:     "dp-1",
				CertSerial: big.NewInt(1).Text(16), // enrolled as "1"
			})
			ctx := ctxWithPeerCert(attackerCert)

			err := verifyNodeCert(ctx, "dp-1")
			if err == nil {
				t.Fatal("expected serial mismatch error; got nil")
			}
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Errorf("expected PermissionDenied; got %v", got)
			}
		})
	})
}
