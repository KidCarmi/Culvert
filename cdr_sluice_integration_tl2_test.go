package main

// cdr_sluice_integration_tl2_test.go — ROUND 2 real-Sluice proofs for the
// issued-response-lost paths (R11): the PINNED daemon issues a renewed
// credential whose response the appliance never records (the exact "lost
// response" shape), and DELETE / revoke-by-name must resolve that operation
// AUTHORITATIVELY through EnrollStatus before mutating — with CDR disabled,
// with no pool, and after a daemon restart. Written RED-first against
// d567f4d5 (fails there: the unresolved generation is silently omitted).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

func TestSluiceIntegration_LostRenewal_DeleteAndRevokeResolveAuthoritatively(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	if err := cdrInstances.Load(filepath.Join(t.TempDir(), "cdr_instances.json")); err != nil {
		t.Fatal(err)
	}
	if err := cdrEnrollReceipts.Load(filepath.Join(t.TempDir(), "receipts.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cdrCertsRoot, 0o700); err != nil {
		t.Skipf("cannot write %s (test env restricted): %v", cdrCertsRoot, err)
	}
	d := startSluiceDaemon(t)
	enroll := func(name, token string) CDREnrolledInstance {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"name": name, "endpoint": d.addr, "serverFingerprint": d.serverFP, "token": token})
		w := httptest.NewRecorder()
		apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", body))
		if w.Code != http.StatusOK {
			t.Fatalf("enroll %s: %d %s", name, w.Code, w.Body.String())
		}
		inst, _ := cdrInstances.GetCopy(name)
		t.Cleanup(func() { shredCDRCerts(&inst) })
		return inst
	}
	const nameA, nameB = "it2-lost-a", "it2-lost-b"
	instA := enroll(nameA, d.token)
	d.restart()
	instB := enroll(nameB, d.token)
	if err := initCDRClient(CDRConfig{Enabled: true, TimeoutSec: 10}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Lost renewal on A: the intent is durable, Sluice issues + binds, and
	// the response is dropped on the floor.
	const opA = "it2-lost-renewal-a-0123456789ab"
	if _, err := cdrInstances.StageRenewal(nameA, opA); err != nil {
		t.Fatal(err)
	}
	rr, err := cdrPool.Get(nameA).Client.RenewCert(ctx, &pb.RenewCertRequest{OperationId: opA})
	if err != nil {
		t.Fatal(err)
	}
	issuedA := rr.ClientCertFingerprint
	_ = rr // the bundle is never stored — exactly the lost-response shape

	// revoke-by-name from B must cover the issued-but-unrecorded credential.
	w := tlRevokeByName(t, nameA, "it2")
	if w.Code != http.StatusOK {
		t.Fatalf("revoke A: %d %s", w.Code, w.Body.String())
	}
	var rv struct {
		Outcomes map[string]string `json:"outcomes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &rv)
	if rv.Outcomes[issuedA] != "revoked" || rv.Outcomes[instA.ClientCertFingerprint] != "revoked" {
		t.Fatalf("revoke-by-name did not cover the lost renewal: %s", w.Body.String())
	}
	pcB := cdrPool.Get(nameB)
	if pcB == nil {
		t.Fatal("B not pooled after reinit")
	}
	if st, err := pcB.Client.EnrollStatus(ctx, opA); err != nil || st.Outcome != pb.EnrollOutcome_ENROLL_ISSUED || !st.Revoked || st.ClientCertFingerprint != issuedA {
		t.Fatalf("daemon truth for the lost renewal: (%+v, %v)", st, err)
	}

	// Lost renewal on B, then DELETE with CDR DISABLED and NO pool: the
	// bootstrap EnrollStatus channel resolves it and the response names
	// the issued fingerprint as still trusted.
	const opB = "it2-lost-renewal-b-0123456789ab"
	if _, err := cdrInstances.StageRenewal(nameB, opB); err != nil {
		t.Fatal(err)
	}
	rrB, err := pcB.Client.RenewCert(ctx, &pb.RenewCertRequest{OperationId: opB})
	if err != nil {
		t.Fatal(err)
	}
	issuedB := rrB.ClientCertFingerprint
	shutdownCDRClient()
	withTempPool(t)
	w = httptest.NewRecorder()
	apiCDRInstances(w, newAdminRequest(http.MethodDelete, "/api/cdr/instances?name="+nameB, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete B: %d %s", w.Code, w.Body.String())
	}
	var del struct {
		Fingerprints []string `json:"clientCertFingerprints"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &del)
	if !tl2Contains(del.Fingerprints, issuedB) || !tl2Contains(del.Fingerprints, instB.ClientCertFingerprint) {
		t.Fatalf("DELETE forgot the credential Sluice issued for the lost renewal: %v (issued %s)", del.Fingerprints, issuedB)
	}
	// No instance can issue the orphan revocation from here: the exact
	// Sluice-host command is returned, and nothing is invented.
	body, _ := json.Marshal(map[string]string{"fingerprint": issuedB})
	w = httptest.NewRecorder()
	apiCDRRevokeRPC(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/revoke", body))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("orphan revoke with no caller: %d %s", w.Code, w.Body.String())
	}

	// Restart: the binding for the lost renewal is durable at the daemon.
	d.restart()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel2()
	if st, err := EnrollStatus(ctx2, d.addr, d.serverFP, opB); err != nil || st.Outcome != pb.EnrollOutcome_ENROLL_ISSUED || st.ClientCertFingerprint != issuedB || st.Revoked {
		t.Fatalf("after restart: (%+v, %v)", st, err)
	}
	if st, err := EnrollStatus(ctx2, d.addr, d.serverFP, opA); err != nil || !st.Revoked {
		t.Fatalf("after restart the revoked lost renewal is not denied: (%+v, %v)", st, err)
	}
}
