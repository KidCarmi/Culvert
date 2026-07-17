package main

// CHAOS-12 remainder — expired-node re-enrollment recovery path.
//
// A registered DP node whose cert expired (e.g. the CP was unreachable for
// the whole 30-day renewal window) cannot present the cert (TLS rejects it)
// and cannot renew (RenewCert requires the mTLS handshake). Before this fix
// admitEnrollment's blanket duplicate-node denial made the brick permanent:
// the only recovery was revoking the node and re-enrolling. These tests pin
// the recovery gate and, just as importantly, that the gate opens ONLY for
// a provably-dead cert:
//   - expired cert + valid admin-issued token → re-enrollment succeeds,
//     labels carry forward, superseded serial lands on the CRL, and the
//     swap is audited + alerted (never invisible);
//   - live cert → denial byte-identical to before, token NOT consumed;
//   - zero CertExpiry (unknown) → still denied (fail closed on missing data);
//   - expired cert + bad token → denied, registration untouched.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// enrollCSRForNode builds a CSR whose CN matches nodeID (what the DP does).
func enrollCSRForNode(t *testing.T, nodeID string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: nodeID}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// swapEnrollFixture installs a fresh cluster store + ready CA and restores
// the originals on cleanup (the established Enroll-test harness).
func swapEnrollFixture(t *testing.T) {
	t.Helper()
	origStore := globalClusterStore
	origCA := globalClusterCA
	t.Cleanup(func() {
		globalClusterStore = origStore
		globalClusterCA = origCA
	})
	globalClusterStore = newTestClusterStore(t)
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(t.TempDir()); err != nil {
		t.Fatalf("CA init: %v", err)
	}
}

func enrollRequestJSON(t *testing.T, token, nodeID string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(EnrollRequest{Token: token, NodeID: nodeID, CSR: enrollCSRForNode(t, nodeID)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// enrollAlertCapture swaps the enrollAlertFire seam for synchronous capture.
func enrollAlertCapture(t *testing.T) *[]AlertPayload {
	t.Helper()
	var got []AlertPayload
	orig := enrollAlertFire
	enrollAlertFire = func(event string, p AlertPayload) {
		p.Event = event
		got = append(got, p)
	}
	t.Cleanup(func() { enrollAlertFire = orig })
	return &got
}

func TestEnroll_ExpiredNodeReenrollsWithToken(t *testing.T) {
	swapEnrollFixture(t)
	alerts := enrollAlertCapture(t)

	// A registered node whose cert expired 3 days ago, carrying an
	// admin-assigned label (node-group membership must survive recovery).
	globalClusterStore.RegisterNode(&EnrolledNode{
		NodeID:     "dp-expired",
		CertSerial: "old-serial-1",
		CertExpiry: time.Now().Add(-72 * time.Hour),
		Status:     "disconnected",
		Labels:     map[string]string{"region": "us-east"},
	})

	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	baseline := time.Now().UnixMilli()
	srv := &controlPlaneServer{}
	resp, err := srv.Enroll(context.Background(), enrollRequestJSON(t, token, "dp-expired"))
	if err != nil {
		t.Fatalf("expired-node re-enrollment must succeed with a valid token, got: %v", err)
	}
	var er EnrollResponse
	if err := json.Unmarshal(resp, &er); err != nil || er.CertPEM == "" {
		t.Fatalf("re-enrollment response missing cert: err=%v resp=%s", err, resp)
	}

	node, ok := globalClusterStore.GetNode("dp-expired")
	if !ok {
		t.Fatal("node must remain registered after re-enrollment")
	}
	if node.CertSerial == "old-serial-1" || node.CertSerial == "" {
		t.Fatalf("node must carry a NEW serial, got %q", node.CertSerial)
	}
	if node.Status != "connected" {
		t.Fatalf("status = %q, want connected", node.Status)
	}
	if !node.CertExpiry.After(time.Now()) {
		t.Fatalf("new cert expiry %v must be in the future", node.CertExpiry)
	}
	if node.Labels["region"] != "us-east" {
		t.Fatalf("admin-assigned labels must carry forward, got %v", node.Labels)
	}

	// Superseded serial on the CRL; the new one not.
	if !globalClusterStore.IsRevoked("old-serial-1") {
		t.Fatal("superseded serial must be added to the CRL")
	}
	if globalClusterStore.IsRevoked(node.CertSerial) {
		t.Fatal("replacement serial must NOT be revoked")
	}

	// Audit entry (content-asserted, never len — audit-ring-saturation pitfall).
	found := false
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "cluster.node.reenroll-expired" && e.Object == "dp-expired" &&
			strings.Contains(e.Detail, "old-serial-1") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no cluster.node.reenroll-expired audit entry")
	}

	// Alert through the seam.
	if len(*alerts) != 1 || (*alerts)[0].Event != "cluster_node_reenrolled" ||
		(*alerts)[0].Host != "dp-expired" || (*alerts)[0].Source != "cluster" {
		t.Fatalf("want one cluster_node_reenrolled alert for dp-expired, got %+v", *alerts)
	}
}

func TestEnroll_ExpiredDrainingNodePreservesDrainingOnReenroll(t *testing.T) {
	swapEnrollFixture(t)
	_ = enrollAlertCapture(t)

	// An operator put the node into maintenance (draining) via SetNodeDraining
	// BEFORE its cert expired. A recovery-token re-enrollment must not silently
	// return it to active service — the draining status carries forward so an
	// explicit undrain is still required.
	globalClusterStore.RegisterNode(&EnrolledNode{
		NodeID:     "dp-drained",
		CertSerial: "old-serial-drain",
		CertExpiry: time.Now().Add(-72 * time.Hour),
		Status:     "draining",
		Labels:     map[string]string{"region": "us-west"},
	})

	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	srv := &controlPlaneServer{}
	if _, err := srv.Enroll(context.Background(), enrollRequestJSON(t, token, "dp-drained")); err != nil {
		t.Fatalf("expired draining node must re-enroll with a valid token, got: %v", err)
	}

	node, ok := globalClusterStore.GetNode("dp-drained")
	if !ok {
		t.Fatal("node must remain registered after re-enrollment")
	}
	if node.Status != "draining" {
		t.Fatalf("operator-set draining state must survive re-enrollment, status = %q, want draining", node.Status)
	}
	// Sanity: this is a genuine recovery (new serial), not a no-op denial.
	if node.CertSerial == "old-serial-drain" || node.CertSerial == "" {
		t.Fatalf("node must carry a NEW serial, got %q", node.CertSerial)
	}
	if node.Labels["region"] != "us-west" {
		t.Fatalf("admin-assigned labels must carry forward, got %v", node.Labels)
	}
}

func TestEnroll_ValidCertNodeStillDenied_TokenUnconsumed(t *testing.T) {
	swapEnrollFixture(t)
	alerts := enrollAlertCapture(t)

	// Cert still valid for a year — the pre-fix denial must stay byte-identical.
	globalClusterStore.RegisterNode(&EnrolledNode{
		NodeID:     "dp-live",
		CertSerial: "live-serial",
		CertExpiry: time.Now().Add(365 * 24 * time.Hour),
		Status:     "connected",
	})
	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	srv := &controlPlaneServer{}
	_, err = srv.Enroll(context.Background(), enrollRequestJSON(t, token, "dp-live"))
	if err == nil {
		t.Fatal("live-cert node must still be denied")
	}
	if strings.Contains(err.Error(), "dp-live") || strings.Contains(err.Error(), "already") {
		t.Errorf("error leaks node existence: %v", err)
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("error should say 'denied', got: %v", err)
	}
	if node, _ := globalClusterStore.GetNode("dp-live"); node.CertSerial != "live-serial" {
		t.Fatalf("denied enrollment must not touch the registration, serial = %q", node.CertSerial)
	}
	if globalClusterStore.IsRevoked("live-serial") {
		t.Fatal("denied enrollment must not revoke anything")
	}
	if len(*alerts) != 0 {
		t.Fatalf("denied enrollment must not alert, got %+v", *alerts)
	}

	// The denial happens BEFORE token consumption — the same token must
	// still enroll a brand-new node.
	if _, err := srv.Enroll(context.Background(), enrollRequestJSON(t, token, "dp-fresh")); err != nil {
		t.Fatalf("token must remain unconsumed after a duplicate-node denial, got: %v", err)
	}
}

func TestEnroll_ZeroExpiryNodeStillDenied(t *testing.T) {
	swapEnrollFixture(t)

	// Zero CertExpiry = unknown; the gate must fail closed and keep denying.
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-unknown", Status: "connected"})
	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	srv := &controlPlaneServer{}
	_, err = srv.Enroll(context.Background(), enrollRequestJSON(t, token, "dp-unknown"))
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("zero-expiry node must stay denied (fail closed), got: %v", err)
	}
}

func TestEnroll_ExpiredNodeBadTokenDenied_RegistrationUntouched(t *testing.T) {
	swapEnrollFixture(t)
	alerts := enrollAlertCapture(t)

	globalClusterStore.RegisterNode(&EnrolledNode{
		NodeID:     "dp-expired",
		CertSerial: "old-serial-2",
		CertExpiry: time.Now().Add(-time.Hour),
		Status:     "disconnected",
	})

	srv := &controlPlaneServer{}
	_, err := srv.Enroll(context.Background(), enrollRequestJSON(t, "cul-bogus-token", "dp-expired"))
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expired node with an invalid token must be denied, got: %v", err)
	}
	node, _ := globalClusterStore.GetNode("dp-expired")
	if node.CertSerial != "old-serial-2" || node.Status != "disconnected" {
		t.Fatalf("failed re-enrollment must not touch the registration: %+v", node)
	}
	if globalClusterStore.IsRevoked("old-serial-2") {
		t.Fatal("failed re-enrollment must not revoke the existing serial")
	}
	if len(*alerts) != 0 {
		t.Fatalf("failed re-enrollment must not alert, got %+v", *alerts)
	}
}
