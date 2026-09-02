package main

// cdr_2ec_tl2_red_test.go — 2E-C TRUST-LIFECYCLE correction ROUND 2. Written
// RED-FIRST against the rejected candidate d567f4d5cdc3c29c969832ec23d29f8bdc62cd83
// (every test compiles there and FAILS for the reason the review named):
//
//	R11 A "renewing" generation carries a durable operation id but no
//	    fingerprint; LiveFingerprints() omitted it, so after Sluice issued a
//	    renewed credential whose response was lost, DELETE and revoke-by-name
//	    processed only the known fingerprints and then removed the registry
//	    entry — destroying the only identity of a credential Sluice trusts.
//	R12 The enrollment operation binding was mutable: the receipt store
//	    REPLACED a receipt with the same operation id, a "dispatched" id
//	    could be re-dispatched, serialization was by instance name, recovery
//	    could override the bound endpoint/pin, a corrupt receipt file loaded
//	    silently, and DELETE destroyed unresolved receipts.
//	R13 Enrollment success reported "auto-enabled" while a sentinel write
//	    failure had left CDR disabled.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const tl2Op = "tl2-op-0123456789abcdef01234567"

// tl2Stage records a renewal INTENT (durable operation id, no fingerprint)
// exactly as a lost RenewCert response leaves it.
func tl2Stage(t *testing.T, name string) int {
	t.Helper()
	seq, err := cdrInstances.StageRenewal(name, tl2Op)
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

func tl2Delete(t *testing.T, name string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodDelete, "/api/cdr/instances?name="+name, nil)
	r.RemoteAddr = "198.51.100.111:0"
	apiCDRInstances(w, r)
	return w
}

func tl2Fingerprints(t *testing.T, w *httptest.ResponseRecorder) []string {
	t.Helper()
	var got struct {
		Fingerprints []string `json:"clientCertFingerprints"`
		Revoked      []string `json:"fingerprints"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	return append(got.Fingerprints, got.Revoked...)
}

// ─── R11 ────────────────────────────────────────────────────────────────────

func TestCDR2ECTL2_Delete_ResolvesLostRenewal_NamesIssuedFingerprint(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tl2-del-lost"
	_, seedFP, _ := tlSeedInstance(t, name)
	tl2Stage(t, name)
	_, issued := tlRenewedCert(t)
	tlStubStatus(t, func(_ context.Context, _, _, op string) (*pb.EnrollStatusResponse, error) {
		if op != tl2Op {
			return &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_NOT_ISSUED}, nil
		}
		return &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_ISSUED, ClientCertFingerprint: issued}, nil
	})
	w := tl2Delete(t, name)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	fps := tl2Fingerprints(t, w)
	if !tl2Contains(fps, issued) || !tl2Contains(fps, seedFP) {
		t.Errorf("DELETE forgot the credential Sluice issued for the lost renewal: response fingerprints %v, want both %s and %s", fps, seedFP, issued)
	}
	if !tlAuditHas("cdr.instance.remove", issued) {
		t.Errorf("the audit trail does not name the still-trusted issued fingerprint %s", issued)
	}
}

func TestCDR2ECTL2_RevokeByName_ResolvesLostRenewal_RevokesIssuedFingerprint(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tl2-rev-lost"
	_, seedFP, _ := tlSeedInstance(t, name)
	tl2Stage(t, name)
	_, issued := tlRenewedCert(t)
	tlStubStatus(t, func(context.Context, string, string, string) (*pb.EnrollStatusResponse, error) {
		return &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_ISSUED, ClientCertFingerprint: issued}, nil
	})
	srv := &tlRecordingSluice{}
	caller, stop := tlPooled(t, "cdr-tl2-caller", srv)
	defer stop()
	withTempPool(t, caller)
	w := tlRevokeByName(t, name, "tl2")
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	srv.mu.Lock()
	revoked := append([]string(nil), srv.revoked...)
	srv.mu.Unlock()
	if !tl2Contains(revoked, issued) || !tl2Contains(revoked, seedFP) {
		t.Errorf("revoke-by-name did not cover the credential issued for the lost renewal: RevokeClient targets %v, want %s and %s", revoked, seedFP, issued)
	}
	if fps := tl2Fingerprints(t, w); !tl2Contains(fps, issued) {
		t.Errorf("response does not report the issued fingerprint as revoked: %s", w.Body.String())
	}
}

func TestCDR2ECTL2_DestructiveOps_EnrollStatusUnavailable_ZeroMutation(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tl2-unavail"
	inst, _, _ := tlSeedInstance(t, name)
	tl2Stage(t, name)
	tlStubStatus(t, func(context.Context, string, string, string) (*pb.EnrollStatusResponse, error) {
		return nil, status.Error(codes.Unavailable, "engine down")
	})
	srv := &tlRecordingSluice{}
	caller, stop := tlPooled(t, "cdr-tl2-caller-u", srv)
	defer stop()
	withTempPool(t, caller)

	check := func(label string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code == http.StatusOK {
			t.Errorf("%s returned 200 while a renewal outcome is unresolved and the engine cannot be asked: %s", label, w.Body.String())
		}
		cur, ok := cdrInstances.GetCopy(name)
		if !ok {
			t.Fatalf("%s: registry entry was removed with an unresolved renewal", label)
		}
		pending := false
		for _, g := range cur.Credentials {
			if g.State == cdrCredRenewing && g.OperationID == tl2Op {
				pending = true
			}
		}
		if !pending {
			t.Errorf("%s: the renewal operation id was lost", label)
		}
		if _, err := os.Stat(inst.ClientCertPath); err != nil {
			t.Errorf("%s: PEM shredded: %v", label, err)
		}
		if tlAuditHas("cdr.instance.remove", name) || tlAuditHas("cdr.instance.revoke_rpc", "tl2-unavail") {
			t.Errorf("%s: a success audit was recorded", label)
		}
	}
	check("DELETE", tl2Delete(t, name))
	check("revoke-by-name", tlRevokeByName(t, name, "tl2-unavail"))
	srv.mu.Lock()
	n := len(srv.revoked)
	srv.mu.Unlock()
	if n != 0 {
		t.Errorf("RevokeClient was issued %d time(s) while the lineage was unresolved", n)
	}
}

func TestCDR2ECTL2_DestructiveOps_NotIssued_DropsIntentThenProceeds(t *testing.T) {
	for _, op := range []string{"delete", "revoke"} {
		t.Run(op, func(t *testing.T) {
			resetCDRState(t)
			name := "cdr-tl2-notissued-" + op
			_, seedFP, _ := tlSeedInstance(t, name)
			tl2Stage(t, name)
			calls := 0
			tlStubStatus(t, func(context.Context, string, string, string) (*pb.EnrollStatusResponse, error) {
				calls++
				return &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_NOT_ISSUED}, nil
			})
			srv := &tlRecordingSluice{}
			caller, stop := tlPooled(t, "cdr-tl2-caller-n", srv)
			defer stop()
			withTempPool(t, caller)
			var w *httptest.ResponseRecorder
			if op == "delete" {
				w = tl2Delete(t, name)
			} else {
				w = tlRevokeByName(t, name, "tl2-ni")
			}
			if w.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", op, w.Code, w.Body.String())
			}
			if calls == 0 {
				t.Errorf("%s did not resolve the pending renewal against the engine before mutating", op)
			}
			fps := tl2Fingerprints(t, w)
			if len(fps) != 1 || fps[0] != seedFP {
				t.Errorf("%s: fingerprints %v, want exactly [%s]", op, fps, seedFP)
			}
		})
	}
}

func TestCDR2ECTL2_Delete_AfterRestartWhileDisabled_ResolvesLostRenewal(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tl2-restart"
	_, seedFP, regPath := tlSeedInstance(t, name)
	tl2Stage(t, name)
	_, issued := tlRenewedCert(t)
	// Restart: fresh registry from the durable file; CDR disabled; no pool,
	// no poller.
	cdrInstances = &CDRInstanceRegistry{}
	if err := cdrInstances.Load(regPath); err != nil {
		t.Fatal(err)
	}
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{Enabled: false}
	cdrClientMu.Unlock()
	withTempPool(t)
	tlStubStatus(t, func(context.Context, string, string, string) (*pb.EnrollStatusResponse, error) {
		return &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_ISSUED, ClientCertFingerprint: issued}, nil
	})
	w := tl2Delete(t, name)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if fps := tl2Fingerprints(t, w); !tl2Contains(fps, issued) || !tl2Contains(fps, seedFP) {
		t.Errorf("after restart with CDR disabled, DELETE forgot the issued credential: %v", fps)
	}
}

// ─── R12 ────────────────────────────────────────────────────────────────────

func tl2EnrollBody(name, endpoint, op string) []byte {
	b, _ := json.Marshal(map[string]string{"name": name, "endpoint": endpoint, "serverFingerprint": strings.Repeat("ab", 32), "token": "tok-secret", "operationId": op})
	return b
}

// tl2GatedEnroll counts dispatches; the FIRST dispatch signals `entered` and
// blocks until `release` is closed (deterministic interleaving, no sleeps).
func tl2GatedEnroll(t *testing.T) (dispatched *int32, entered, release chan struct{}) {
	t.Helper()
	var n int32
	entered = make(chan struct{})
	release = make(chan struct{})
	var once sync.Once
	pemBytes, _ := tlRenewedCert(t)
	tlStubEnroll(t, func(context.Context, string, string, string, string) (*pb.EnrollResponse, error) {
		k := atomic.AddInt32(&n, 1)
		if k == 1 {
			once.Do(func() { close(entered) })
			<-release
		}
		return &pb.EnrollResponse{CaCert: pemBytes, ClientCert: pemBytes, ClientKey: pemBytes}, nil
	})
	return &n, entered, release
}

func tl2ConcurrentSameOperation(t *testing.T, nameA, epA, nameB, epB string) {
	t.Helper()
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	tlReceiptsOnDisk(t)
	for _, n := range []string{nameA, nameB} {
		dir, _ := cdrInstanceCertsDir(n)
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			t.Skipf("cannot write %s: %v", dir, err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	dispatched, entered, release := tl2GatedEnroll(t)
	codes := make([]int, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w := httptest.NewRecorder()
		apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tl2EnrollBody(nameA, epA, tl2Op)))
		codes[0] = w.Code
	}()
	<-entered // A's receipt exists and its RPC is in flight
	// B runs to COMPLETION while A is still inside the RPC (deterministic:
	// the gate is released only after B returned), so B decides against a
	// receipt that is still "dispatched" — never against A's final state.
	var wgB sync.WaitGroup
	wgB.Add(1)
	go func() {
		defer wg.Done()
		defer wgB.Done()
		w := httptest.NewRecorder()
		apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tl2EnrollBody(nameB, epB, tl2Op)))
		codes[1] = w.Code
	}()
	wgB.Wait()
	close(release)
	wg.Wait()
	if n := atomic.LoadInt32(dispatched); n != 1 {
		t.Errorf("operation %s was dispatched %d times, want exactly 1", tl2Op, n)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusConflict {
		t.Errorf("codes = %v, want [200 409]", codes)
	}
	if rc, ok := cdrEnrollReceipts.Get(tl2Op); !ok || rc.Name != nameA || rc.Endpoint != epA {
		t.Errorf("the binding was rewritten: %+v", rc)
	}
}

func TestCDR2ECTL2_ConcurrentEnroll_SameOperation_DifferentNames(t *testing.T) {
	tl2ConcurrentSameOperation(t, "cdr-tl2-conc-a", "sluice-x:8443", "cdr-tl2-conc-b", "sluice-x:8443")
}

func TestCDR2ECTL2_ConcurrentEnroll_SameOperation_DifferentEndpoints(t *testing.T) {
	tl2ConcurrentSameOperation(t, "cdr-tl2-conc-c", "sluice-one:8443", "cdr-tl2-conc-d", "sluice-two:8443")
}

func TestCDR2ECTL2_SerialReuse_OfDispatchedOperation_NoRedispatch(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	tlReceiptsOnDisk(t)
	var n int32
	tlStubEnroll(t, func(context.Context, string, string, string, string) (*pb.EnrollResponse, error) {
		atomic.AddInt32(&n, 1)
		return nil, status.Error(codes.DeadlineExceeded, "lost")
	})
	body := tl2EnrollBody("cdr-tl2-serial", "sluice:8443", tl2Op)
	w := httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", body))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("first: %d", w.Code)
	}
	w = httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", body))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), cdrEnrollRecoverPath) {
		t.Errorf("exact retry of a dispatched operation: %d %s, want 409 naming the recovery path", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&n) != 1 {
		t.Errorf("the single-use token was re-dispatched: %d dispatches", n)
	}
}

func TestCDR2ECTL2_Recover_CannotOverrideBoundEndpointOrPin(t *testing.T) {
	resetCDRState(t)
	tlReceiptsOnDisk(t)
	if err := cdrEnrollReceipts.Put(CDREnrollReceipt{OperationID: tl2Op, Name: "cdr-tl2-bound", Endpoint: "sluice-bound:8443", ServerFingerprint: strings.Repeat("ab", 32), State: cdrReceiptDispatched, Actor: "admin@198.51.100.1"}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	tlStubStatus(t, func(_ context.Context, ep, fp, _ string) (*pb.EnrollStatusResponse, error) {
		calls++
		return &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_NOT_ISSUED}, nil
	})
	for _, body := range []map[string]string{
		{"operationId": tl2Op, "endpoint": "attacker:8443"},
		{"operationId": tl2Op, "serverFingerprint": strings.Repeat("cd", 32)},
	} {
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		apiCDREnrollRecover(w, newAdminRequest(http.MethodPost, cdrEnrollRecoverPath, b))
		if w.Code != http.StatusConflict {
			t.Errorf("override %v: %d %s, want 409 before any network activity", body, w.Code, w.Body.String())
		}
	}
	if calls != 0 {
		t.Errorf("EnrollStatus was called %d time(s) with caller-supplied values", calls)
	}
}

func TestCDR2ECTL2_ReceiptFile_CorruptAtStartup_IsDegradedAndFailClosed(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	path := filepath.Join(t.TempDir(), "receipts.json")
	var recs []map[string]any
	valid := func(op, name string) map[string]any {
		return map[string]any{"operationId": op, "name": name, "endpoint": "e:1", "serverFingerprint": strings.Repeat("ab", 32), "state": "stored", "actor": "a", "startedAt": "2026-09-01T00:00:00Z", "updatedAt": "2026-09-01T00:00:00Z"}
	}
	recs = append(recs, valid(tl2Op, "dup-a"), valid(tl2Op, "dup-b")) // duplicate id
	recs = append(recs, valid("bad id!", "grammar"))                  // invalid grammar
	r := valid("tl2-badstate-0123456789abcdef", "state")
	r["state"] = "teleported"
	recs = append(recs, r) // invalid state
	r = valid("tl2-missing-0123456789abcdef0", "missing")
	delete(r, "endpoint")
	recs = append(recs, r) // missing identity
	for i := 0; i < 70; i++ {
		recs = append(recs, valid(fmt.Sprintf("tl2-cap-%026d", i), fmt.Sprintf("cap-%d", i)))
	}
	data, _ := json.Marshal(recs)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = cdrEnrollReceipts.Load(path)
	w := httptest.NewRecorder()
	apiCDREnrollReceipts(w, newViewerRequest(cdrEnrollReceiptsAPI))
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	integ, _ := got["integrity"].(map[string]any)
	if integ == nil || integ["ok"] != false {
		t.Errorf("a corrupt receipt file loaded without a DEGRADED integrity truth: %s", w.Body.String())
	}
	dispatched := 0
	tlStubEnroll(t, func(context.Context, string, string, string, string) (*pb.EnrollResponse, error) {
		dispatched++
		return nil, errors.New("must not dispatch")
	})
	w = httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tl2EnrollBody("cdr-tl2-degraded", "sluice:8443", "")))
	if w.Code != http.StatusServiceUnavailable || dispatched != 0 {
		t.Errorf("enrollment on a degraded receipt store: %d (dispatched %d), want 503 and no dispatch", w.Code, dispatched)
	}
}

func TestCDR2ECTL2_ReceiptDelete_RefusesUnresolved_AllowsTerminal(t *testing.T) {
	resetCDRState(t)
	tlReceiptsOnDisk(t)
	cases := map[string]int{
		cdrReceiptDispatched:      http.StatusConflict,
		cdrReceiptIssuedNotStored: http.StatusConflict,
		cdrReceiptStored:          http.StatusOK,
		cdrReceiptNotIssued:       http.StatusOK,
		cdrReceiptRevoked:         http.StatusOK,
	}
	i := 0
	for state, want := range cases {
		op := fmt.Sprintf("tl2-del-%s-%020d", strings.ReplaceAll(state, "_", "-"), i)
		i++
		if err := cdrEnrollReceipts.Put(CDREnrollReceipt{OperationID: op, Name: "n", Endpoint: "e:1", ServerFingerprint: strings.Repeat("ab", 32), State: state, Actor: "a"}); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		apiCDREnrollReceipts(w, newAdminRequest(http.MethodDelete, cdrEnrollReceiptsAPI+"?operationId="+op, nil))
		if w.Code != want {
			t.Errorf("DELETE of a %s receipt: %d, want %d", state, w.Code, want)
		}
		_, still := cdrEnrollReceipts.Get(op)
		if want == http.StatusConflict && !still {
			t.Errorf("an unresolved %s receipt was destroyed", state)
		}
	}
}

// ─── R13 ────────────────────────────────────────────────────────────────────

func TestCDR2ECTL2_Enroll_AutoEnableSentinelFailure_IsReportedTruthfully(t *testing.T) {
	resetCDRState(t)
	tlReceiptsOnDisk(t)
	// The sentinel's parent "directory" is a regular file: the durable
	// auto-enable cannot succeed.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := cdrRuntimeEnabledPath
	cdrRuntimeEnabledPath = filepath.Join(blocker, "cdr_enabled")
	t.Cleanup(func() { cdrRuntimeEnabledPath = orig })
	const name = "cdr-tl2-autoenable"
	dir, _ := cdrInstanceCertsDir(name)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Skipf("cannot write %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pemBytes, _ := tlRenewedCert(t)
	tlStubEnroll(t, func(context.Context, string, string, string, string) (*pb.EnrollResponse, error) {
		return &pb.EnrollResponse{CaCert: pemBytes, ClientCert: pemBytes, ClientKey: pemBytes}, nil
	})
	w := httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tl2EnrollBody(name, "sluice:8443", tl2Op)))
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	auto, _ := got["autoEnable"].(map[string]any)
	if got["stored"] != true || got["cdrEnabled"] != false || auto == nil || auto["succeeded"] != false {
		t.Errorf("the response does not report the truthful post-operation state (stored, CDR still disabled, auto-enable failed): %s", w.Body.String())
	}
	if cdrActiveConfig().Enabled {
		t.Error("precondition: the sentinel failure must leave CDR disabled")
	}
}

func tl2Contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
