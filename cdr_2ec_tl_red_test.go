package main

// cdr_2ec_tl_red_test.go — 2E-C TRUST-LIFECYCLE correction matrix. Written
// RED-FIRST against the rejected candidate 978f95b5aa8238a7dbff6079549301726bf6ff1e:
// every test compiles with the Sluice v0.2.0 contract that candidate pins
// and FAILS there for the reason the external review named.
//
//	R6  Revocation must prove an effective durable deny. The handler
//	    discarded RevokeClientResponse.Revoked: a response that proves
//	    NOTHING (revoked=false, the fake's default) still produced 200, a
//	    pruned registry, shredded PEMs and a success audit — "unknown
//	    fingerprint" presented as "safely revoked".
//	R7  Renewal must preserve the complete credential lineage. RenewCert
//	    does not retire the presented cert at Sluice, yet the appliance
//	    overwrote the PEMs and the ONE recorded fingerprint, so the still-
//	    valid predecessor became unidentifiable; a renewal racing a delete
//	    resurrected PEMs after the removal; a registry persistence failure
//	    after the PEM swap left new PEMs + an old durable fingerprint.
//	R8  Enrollment needs identifiable unknown-outcome recovery: a local
//	    persistence failure after Sluice issued the credential destroyed
//	    the bundle and recorded no durable non-secret identity for it.
//	R9  PUT /api/cdr/config decoded `{}` as enabled=false (a silent
//	    disable) instead of refusing a body that carries no decision.
//	R10 Policy identity held only in Add: Load accepted duplicate names
//	    from a legacy file and DELETE then silently chose a victim.

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Sluice/pkg/sluiceauth"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// tlFakeSluice is a scripted server for the lifecycle RPCs, built ONLY from
// v0.2.0 wire types so this file compiles at the rejected candidate.
type tlFakeSluice struct {
	fakeSluice
	// renewResp is returned by RenewCert; renewGate, when non-nil, blocks
	// the RPC until closed (deterministic interleaving without sleeps).
	renewResp *pb.RenewCertResponse
	renewGate chan struct{}
	// revokeResp is returned by RevokeClient (default: an EMPTY response —
	// exactly what the shipped fake returns).
	revokeResp *pb.RevokeClientResponse
}

func (f *tlFakeSluice) RenewCert(_ context.Context, _ *pb.RenewCertRequest) (*pb.RenewCertResponse, error) {
	if f.renewGate != nil {
		<-f.renewGate
	}
	if f.renewResp == nil {
		return nil, context.DeadlineExceeded
	}
	return f.renewResp, nil
}

func (f *tlFakeSluice) RevokeClient(_ context.Context, _ *pb.RevokeClientRequest) (*pb.RevokeClientResponse, error) {
	if f.revokeResp != nil {
		return f.revokeResp, nil
	}
	return &pb.RevokeClientResponse{}, nil
}

// tlPooled dials a scripted server over bufconn and wraps it as a pool member.
func tlPooled(t *testing.T, name string, srv pb.SluiceServiceServer) (*cdrPooledClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	pb.RegisterSluiceServiceServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := newCDRClientFromConn(conn, CDRClientConfig{Endpoint: "bufnet", Timeout: 5 * time.Second, ChunkSize: 1024})
	pc := &cdrPooledClient{Name: name, Client: c, Breaker: newCDRCircuitBreaker(cdrBreakerConfig{})}
	return pc, func() { _ = c.Close(); s.Stop(); _ = lis.Close() }
}

// tlSeedInstance writes a real client cert under the sanitised certs root and
// registers the instance in a DURABLE registry (tmp path). Returns the
// instance copy, its cert fingerprint, and the registry path.
func tlSeedInstance(t *testing.T, name string) (CDREnrolledInstance, string, string) {
	t.Helper()
	dir, err := cdrInstanceCertsDir(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skipf("cannot write %s (test env restricted): %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	caPath := filepath.Join(dir, "ca.pem")
	pemBytes := mustGenerateTestCertPEM(t)
	for _, p := range []string{certPath, keyPath, caPath} {
		if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fp, err := sluiceauth.Fingerprint(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	regPath := filepath.Join(t.TempDir(), "cdr_instances.json")
	if err := cdrInstances.Load(regPath); err != nil {
		t.Fatal(err)
	}
	inst, err := cdrInstances.Add(CDREnrolledInstance{
		Name: name, Endpoint: "sluice-tl:8443",
		CACertPath: caPath, ClientCertPath: certPath, ClientKeyPath: keyPath,
		ClientCertFingerprint: fp,
	})
	if err != nil {
		t.Fatal(err)
	}
	return inst, fp, regPath
}

func tlAuditHas(action, discriminator string) bool {
	for _, e := range auditGet() {
		if e.Action == action && strings.Contains(e.Detail, discriminator) {
			return true
		}
	}
	return false
}

// ─── R6: revocation must prove a durable deny ───────────────────────────────

// TestCDR2ECTL_Revoke_UnprovenOutcomeIsNotSuccess: the caller's Sluice
// answers RevokeClient with a response that proves nothing (revoked=false,
// no outcome — the shipped fake's default). The appliance must NOT prune,
// shred, success-audit or return success.
func TestCDR2ECTL_Revoke_UnprovenOutcomeIsNotSuccess(t *testing.T) {
	resetCDRState(t)
	const target = "cdr-tl-revoke-target"
	inst, fp, _ := tlSeedInstance(t, target)
	caller, stop := tlPooled(t, "cdr-tl-caller", &tlFakeSluice{revokeResp: &pb.RevokeClientResponse{Revoked: false}})
	defer stop()
	withTempPool(t, caller)

	discriminator := "tl-unproven-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000"), ".", "-")
	body, _ := json.Marshal(map[string]string{"name": target, "reason": discriminator})
	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodPost, "/api/cdr/instances/revoke", body)
	r.RemoteAddr = "198.51.100.91:0"
	apiCDRRevokeRPC(w, r)

	if w.Code == http.StatusOK {
		t.Errorf("revoke returned 200 on an UNPROVEN outcome (revoked=false, no durable-deny proof); body=%s", w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "already") {
		t.Errorf("an unproven outcome must never be presented as 'already revoked': %s", w.Body.String())
	}
	if cdrInstances.Get(target) == nil {
		t.Error("registry entry was pruned without a durable-deny proof")
	}
	if _, err := os.Stat(inst.ClientCertPath); err != nil {
		t.Errorf("client cert was shredded without a durable-deny proof: %v", err)
	}
	if tlAuditHas("cdr.instance.revoke_rpc", discriminator) {
		t.Errorf("a success audit was recorded for fingerprint %s without proof", fp)
	}
}

// ─── R7: renewal must preserve the credential lineage ───────────────────────

func tlRenewedCert(t *testing.T) ([]byte, string) {
	t.Helper()
	pemBytes := mustGenerateTestCertPEM(t)
	fp, err := sluiceauth.Fingerprint(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return pemBytes, fp
}

// TestCDR2ECTL_Renewal_PredecessorFingerprintStaysIdentifiable: after a
// successful renewal the DURABLE registry must still identify the
// predecessor credential (unrevoked and unexpired at Sluice) — on disk and
// after a reload — not only the newest fingerprint.
func TestCDR2ECTL_Renewal_PredecessorFingerprintStaysIdentifiable(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tl-renew-lineage"
	inst, oldFP, regPath := tlSeedInstance(t, name)
	newPEM, newFP := tlRenewedCert(t)
	pc, stop := tlPooled(t, name, &tlFakeSluice{renewResp: &pb.RenewCertResponse{ClientCert: newPEM, ClientKey: newPEM, DaysUntilExpiry: 400}})
	defer stop()
	withTempPool(t, pc)

	runRenewFor(pc, inst)

	onDisk, err := loadCertFingerprint(inst.ClientCertPath)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk != newFP {
		t.Fatalf("precondition: renewal did not install the new cert (disk=%s)", onDisk)
	}
	raw, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), newFP) {
		t.Errorf("durable registry does not identify the successor %s", newFP)
	}
	if !strings.Contains(string(raw), oldFP) {
		t.Errorf("durable registry FORGOT the still-valid predecessor %s (Sluice keeps trusting it; it can no longer be revoked from here)", oldFP)
	}
	// Restart truth: a fresh load must still identify both.
	fresh := &CDRInstanceRegistry{}
	if err := fresh.Load(regPath); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := json.Marshal(fresh.SnapshotView())
	if !strings.Contains(string(reloaded), oldFP) || !strings.Contains(string(reloaded), newFP) {
		t.Errorf("after reload the lineage is incomplete: %s", reloaded)
	}
}

// The renewal-vs-removal window. maybeRenewExpiringClients DECIDES to renew
// from a registry snapshot and then runs the RPC on its own goroutine; the
// removal can commit anywhere in between, and the handlers' pool teardown
// only masks the race when the RPC has not yet completed (a response
// already received is processed regardless). The tests model the decided-
// then-removed interleaving deterministically: the renewal's RPC completes
// against a client that survived the teardown (pcB), AFTER the removal
// committed. A correct implementation re-validates the instance under the
// per-instance lifecycle lock before touching disk or registry.

// TestCDR2ECTL_RenewalVsDelete_NoResurrection: a renewal decided before the
// instance is deleted must not write PEMs, resurrect registry state, or
// introduce a new fingerprint after the removal commits.
func TestCDR2ECTL_RenewalVsDelete_NoResurrection(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tl-renew-vs-delete"
	inst, _, _ := tlSeedInstance(t, name)
	newPEM, newFP := tlRenewedCert(t)
	pcA, stopA := tlPooled(t, name, &tlFakeSluice{})
	defer stopA()
	withTempPool(t, pcA)
	// The renewal decision was taken from THIS snapshot of the registry.
	decided, ok := cdrInstances.GetCopy(name)
	if !ok || decided.ClientCertPath != inst.ClientCertPath {
		t.Fatal("precondition: instance present")
	}

	// The removal commits (registry pruned, PEMs shredded, pool torn down).
	w := httptest.NewRecorder()
	apiCDRInstances(w, newAdminRequest(http.MethodDelete, "/api/cdr/instances?name="+name, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}

	// The already-decided renewal now completes its RPC.
	pcB, stopB := tlPooled(t, name, &tlFakeSluice{renewResp: &pb.RenewCertResponse{ClientCert: newPEM, ClientKey: newPEM, DaysUntilExpiry: 400}})
	defer stopB()
	runRenewFor(pcB, decided)

	for _, p := range []string{inst.ClientCertPath, inst.ClientKeyPath, inst.ClientCertPath + ".tmp", inst.ClientKeyPath + ".tmp"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("renewal resurrected %s after the delete committed", p)
		}
	}
	if cdrInstances.Get(name) != nil {
		t.Error("renewal resurrected the registry entry")
	}
	if raw, _ := json.Marshal(cdrInstances.SnapshotView()); strings.Contains(string(raw), newFP) {
		t.Error("renewal introduced a new trusted fingerprint after removal")
	}
}

// TestCDR2ECTL_RenewalVsRevoke_NoResurrection: same window against a
// (proven) revocation issued through a second instance.
func TestCDR2ECTL_RenewalVsRevoke_NoResurrection(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tl-renew-vs-revoke"
	inst, _, _ := tlSeedInstance(t, name)
	newPEM, newFP := tlRenewedCert(t)
	target, stopT := tlPooled(t, name, &tlFakeSluice{})
	defer stopT()
	caller, stopC := tlPooled(t, "cdr-tl-revoker", &tlFakeSluice{revokeResp: &pb.RevokeClientResponse{Revoked: true}})
	defer stopC()
	withTempPool(t, target, caller)
	decided, ok := cdrInstances.GetCopy(name)
	if !ok {
		t.Fatal("precondition: instance present")
	}

	body, _ := json.Marshal(map[string]string{"name": name, "reason": "tl-race"})
	w := httptest.NewRecorder()
	apiCDRRevokeRPC(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/revoke", body))
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}

	pcB, stopB := tlPooled(t, name, &tlFakeSluice{renewResp: &pb.RenewCertResponse{ClientCert: newPEM, ClientKey: newPEM, DaysUntilExpiry: 400}})
	defer stopB()
	runRenewFor(pcB, decided)

	for _, p := range []string{inst.ClientCertPath, inst.ClientKeyPath} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("renewal resurrected %s after the revocation committed", p)
		}
	}
	if cdrInstances.Get(name) != nil {
		t.Error("renewal resurrected the registry entry after revocation")
	}
	if raw, _ := json.Marshal(cdrInstances.SnapshotView()); strings.Contains(string(raw), newFP) {
		t.Error("renewal introduced a new trusted fingerprint after revocation")
	}
}

// TestCDR2ECTL_Renewal_PersistFailureAfterRPC_NeverNewPEMsWithOldFingerprint:
// when the registry cannot persist after RenewCert succeeded, the appliance
// must not end in "new PEMs on disk + old durable fingerprint" — the
// on-disk credential and the durable record must agree.
func TestCDR2ECTL_Renewal_PersistFailureAfterRPC_NeverNewPEMsWithOldFingerprint(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tl-renew-persist-fail"
	inst, oldFP, regPath := tlSeedInstance(t, name)
	newPEM, newFP := tlRenewedCert(t)
	pc, stop := tlPooled(t, name, &tlFakeSluice{renewResp: &pb.RenewCertResponse{ClientCert: newPEM, ClientKey: newPEM, DaysUntilExpiry: 400}})
	defer stop()
	withTempPool(t, pc)

	// Break durability: point the registry at a path whose directory
	// cannot exist (AtomicWrite needs the parent).
	cdrInstances.mu.Lock()
	cdrInstances.path = filepath.Join("/proc/culvert-nonexistent", "cdr_instances.json")
	cdrInstances.mu.Unlock()

	runRenewFor(pc, inst)

	onDisk, err := loadCertFingerprint(inst.ClientCertPath)
	if err != nil {
		t.Fatal(err)
	}
	durable, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	durableHasNew := strings.Contains(string(durable), newFP)
	if onDisk == newFP && !durableHasNew {
		t.Errorf("NEW PEMs installed (disk=%s) while the durable registry only knows %s — the live credential is unidentifiable after a restart", newFP, oldFP)
	}
}

// ─── R8: enrollment unknown-outcome recovery ────────────────────────────────

// TestCDR2ECTL_Enroll_LocalPersistFailureLeavesDurableIdentity: Sluice
// issued the credential; local persistence then failed. The appliance must
// leave a durable, non-secret record of the issued fingerprint (audit
// trail at minimum) instead of destroying the only handle for revoking it.
func TestCDR2ECTL_Enroll_LocalPersistFailureLeavesDurableIdentity(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	const name = "cdr-tl-enroll-persistfail"
	// Force persistCDREnrollment to fail AFTER the RPC: the per-instance
	// certs dir path is occupied by a regular FILE.
	dir, err := cdrInstanceCertsDir(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Skipf("cannot write %s (test env restricted): %v", dir, err)
	}
	_ = os.RemoveAll(dir)
	if err := os.WriteFile(dir, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	issuedPEM, issuedFP := tlRenewedCert(t)
	// The enroll RPC is a fresh dial to req.Endpoint, so route the fake
	// through the Enroll seam used by the coverage suite: a bufconn cannot
	// be dialed by address, so exercise persistCDREnrollment + the handler's
	// failure path directly with the issued bundle.
	resp := &pb.EnrollResponse{CaCert: issuedPEM, ClientCert: issuedPEM, ClientKey: issuedPEM}
	_, perr := persistCDREnrollment(cdrEnrollRequest{Name: name, Endpoint: "sluice:8443", ServerFingerprint: strings.Repeat("ab", 32), Token: "t"}, resp)
	if perr == nil {
		t.Fatal("precondition: local persistence must fail")
	}
	// What a lost bundle must leave behind: the issued fingerprint in the
	// durable audit trail under a recovery-specific action.
	if !tlAuditHas("cdr.instance.enroll.issued_not_stored", issuedFP) {
		t.Errorf("no durable record of the issued-but-not-stored credential %s — the only handle for revoking it was destroyed", issuedFP)
	}
}

// ─── R9: strict config action contract ──────────────────────────────────────

func TestCDR2ECTL_ConfigPut_RefusesBodiesWithoutADecision(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	// Arm CDR so a silent `enabled=false` decode would be an observable
	// (and dangerous) disable.
	if err := setCDREnabledRuntime(true); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty object":  `{}`,
		"null":          `null`,
		"missing field": `{"other":true}`,
		"wrong type":    `{"enabled":"true"}`,
		"unknown field": `{"enabled":true,"extra":1}`,
		"trailing JSON": `{"enabled":false}{"enabled":true}`,
		"array":         `[true]`,
		"empty body":    ``,
	}
	for label, body := range cases {
		if err := setCDREnabledRuntime(true); err != nil {
			t.Fatal(err)
		}
		baseline := time.Now().UnixMilli()
		w := httptest.NewRecorder()
		r := newAdminRequest(http.MethodPut, "/api/cdr/config", []byte(body))
		r.RemoteAddr = "198.51.100.92:0"
		apiCDRConfig(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body=%s)", label, w.Code, w.Body.String())
		}
		if !cdrActiveConfig().Enabled {
			t.Errorf("%s: runtime state was mutated by a refused body", label)
		}
		if !cdrRuntimeEnabled() {
			t.Errorf("%s: durable sentinel was mutated by a refused body", label)
		}
		for _, e := range auditGet() {
			if e.Action == "cdr.config.toggle" && e.Actor == "198.51.100.92" && e.TS >= baseline {
				t.Errorf("%s: an audit event was emitted for a refused body", label)
			}
		}
	}
	// Valid bodies stay idempotent absolute-state writes.
	for _, body := range []string{`{"enabled":false}`, `{"enabled":false}`, `{"enabled":true}`} {
		w := httptest.NewRecorder()
		apiCDRConfig(w, newAdminRequest(http.MethodPut, "/api/cdr/config", []byte(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("valid body %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if !cdrActiveConfig().Enabled {
		t.Error("final state must be enabled")
	}
}

// ─── R10: policy identity across restart ────────────────────────────────────

func TestCDR2ECTL_PolicyLoad_DuplicateNamesNeverSilentlyChosen(t *testing.T) {
	resetCDRState(t)
	path := filepath.Join(t.TempDir(), "cdr_policies.json")
	legacy := `[{"priority":10,"name":"dup","mode":"ENFORCE"},{"priority":5,"name":"dup","mode":"REPORT_ONLY"},{"priority":1,"name":" ","mode":"ENFORCE"}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = cdrPolicyStore.Load(path)

	// A DELETE by the ambiguous name must not silently pick a victim.
	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete, "/api/cdr/policies?name=dup", nil))
	if w.Code == http.StatusOK {
		t.Errorf("DELETE of an ambiguous name returned 200 — one of two rules was silently chosen (body=%s)", w.Body.String())
	}
	n := 0
	for _, r := range cdrPolicyStore.List() {
		if r.Name == "dup" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d 'dup' rules remain, want both (nothing may be deleted under an ambiguous identity)", n)
	}
	// The read surface must tell the operator the store is degraded.
	w = httptest.NewRecorder()
	apiCDRPolicies(w, newViewerRequest("/api/cdr/policies"))
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["integrity"] == nil {
		t.Errorf("GET /api/cdr/policies exposes no integrity/degraded truth for a duplicate-identity store: %s", w.Body.String())
	}
	// Replace must refuse duplicates too.
	dupRules := []*CDRPolicyRule{{Name: "x", Priority: 1}, {Name: "x", Priority: 2}}
	if err := cdrPolicyStore.Replace(dupRules); err == nil {
		t.Error("Replace accepted duplicate names")
	}
	if err := cdrPolicyStore.Replace([]*CDRPolicyRule{{Name: "  ", Priority: 1}}); err == nil {
		t.Error("Replace accepted an empty normalized name")
	}
}

// keep bytes imported for body builders in future additions to this matrix.
var _ = bytes.NewReader
