package main

// cdr_2ec_tl_green_test.go — the post-fix proofs for the 2E-C trust-
// lifecycle correction (companion to the RED matrix in
// cdr_2ec_tl_red_test.go, which pins the failure shapes at 978f95b5).
//
//	R6  proof semantics for every RevokeClient outcome + RPC failure
//	R7  lineage: every live generation is revoked; crash/restart at each
//	    renewal commit boundary; lost-response reconciliation; cap
//	R8  enrollment receipts: lost response, reload, auth boundary,
//	    storage failure, duplicate operation, handler-level persist
//	    failure, recovery classification, orphan revocation
//	R10 degraded store: add refused, positional repair, restart truth

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
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tlRecordingSluice records every RevokeClient fingerprint and answers
// with a scripted outcome per fingerprint (default REVOKED).
type tlRecordingSluice struct {
	tlFakeSluice
	mu        sync.Mutex
	revoked   []string
	outcomes  map[string]*pb.RevokeClientResponse
	revokeErr error
	status    *pb.EnrollStatusResponse
}

func (f *tlRecordingSluice) RevokeClient(_ context.Context, req *pb.RevokeClientRequest) (*pb.RevokeClientResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	f.revoked = append(f.revoked, req.Fingerprint)
	if r, ok := f.outcomes[req.Fingerprint]; ok {
		return r, nil
	}
	return &pb.RevokeClientResponse{Revoked: true, Outcome: pb.RevokeOutcome_REVOKE_OUTCOME_REVOKED}, nil
}

func (f *tlRecordingSluice) EnrollStatus(_ context.Context, _ *pb.EnrollStatusRequest) (*pb.EnrollStatusResponse, error) {
	if f.status == nil {
		return nil, status.Error(codes.Unavailable, "no status scripted")
	}
	return f.status, nil
}

func tlRevokeByName(t *testing.T, name, reason string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name, "reason": reason})
	w := httptest.NewRecorder()
	apiCDRRevokeRPC(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/revoke", body))
	return w
}

// ─── R6 ─────────────────────────────────────────────────────────────────────

func TestCDR2ECTLG_Revoke_ProvenOutcomesSucceed_ErrorsPruneNothing(t *testing.T) {
	for _, tc := range []struct {
		label   string
		resp    *pb.RevokeClientResponse
		err     error
		wantOK  bool
		outcome string
	}{
		{"v0.3 REVOKED", &pb.RevokeClientResponse{Outcome: pb.RevokeOutcome_REVOKE_OUTCOME_REVOKED, Revoked: true}, nil, true, "revoked"},
		{"v0.3 ALREADY_REVOKED", &pb.RevokeClientResponse{Outcome: pb.RevokeOutcome_REVOKE_OUTCOME_ALREADY_REVOKED}, nil, true, "already_revoked"},
		{"v0.3 TOMBSTONED (unknown fp → durable deny)", &pb.RevokeClientResponse{Outcome: pb.RevokeOutcome_REVOKE_OUTCOME_TOMBSTONED}, nil, true, "tombstoned"},
		{"v0.2 revoked=true", &pb.RevokeClientResponse{Revoked: true}, nil, true, "revoked"},
		{"v0.2 revoked=false (unknown fp no-op)", &pb.RevokeClientResponse{}, nil, false, ""},
		{"RPC error", nil, status.Error(codes.Unavailable, "down"), false, ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			resetCDRState(t)
			const target = "cdr-tlg-revoke"
			inst, fp, _ := tlSeedInstance(t, target)
			srv := &tlRecordingSluice{outcomes: map[string]*pb.RevokeClientResponse{fp: tc.resp}, revokeErr: tc.err}
			caller, stop := tlPooled(t, "cdr-tlg-caller", srv)
			defer stop()
			withTempPool(t, caller)
			w := tlRevokeByName(t, target, "tlg-"+tc.label)
			if tc.wantOK {
				if w.Code != http.StatusOK {
					t.Fatalf("status %d body %s", w.Code, w.Body.String())
				}
				var got struct {
					Outcomes map[string]string `json:"outcomes"`
					Pruned   bool              `json:"localPruned"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &got)
				if got.Outcomes[fp] != tc.outcome || !got.Pruned {
					t.Fatalf("outcomes=%v pruned=%v", got.Outcomes, got.Pruned)
				}
				if cdrInstances.Get(target) != nil {
					t.Error("entry not pruned after proof")
				}
				return
			}
			if w.Code == http.StatusOK {
				t.Fatalf("expected non-200, got 200: %s", w.Body.String())
			}
			if cdrInstances.Get(target) == nil {
				t.Error("entry pruned without proof")
			}
			if _, err := os.Stat(inst.ClientCertPath); err != nil {
				t.Error("PEM shredded without proof")
			}
		})
	}
}

// ─── R7 ─────────────────────────────────────────────────────────────────────

// Every live generation is revoked, per-generation progress is durable,
// and a failure midway leaves the entry (retry finishes the rest).
func TestCDR2ECTLG_Revoke_CoversWholeLineage_ProgressIsDurable(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tlg-lineage-revoke"
	_, oldFP, regPath := tlSeedInstance(t, name)
	newPEM, newFP := tlRenewedCert(t)
	pc, stop := tlPooled(t, name, &tlFakeSluice{renewResp: &pb.RenewCertResponse{ClientCert: newPEM, ClientKey: newPEM, DaysUntilExpiry: 400}})
	defer stop()
	inst, _ := cdrInstances.GetCopy(name)
	withTempPool(t, pc)
	runRenewFor(pc, inst)
	cur, _ := cdrInstances.GetCopy(name)
	if live := cur.LiveFingerprints(time.Now()); len(live) != 2 || live[0] != newFP || live[1] != oldFP {
		t.Fatalf("lineage after renewal = %v, want [new old]", live)
	}

	// First attempt: the predecessor's revoke fails after the successor's
	// was proven — progress must be durable and the entry must remain.
	srv := &tlRecordingSluice{outcomes: map[string]*pb.RevokeClientResponse{oldFP: {}}}
	caller, stopC := tlPooled(t, "cdr-tlg-caller", srv)
	defer stopC()
	withTempPool(t, caller)
	if w := tlRevokeByName(t, name, "first"); w.Code == http.StatusOK {
		t.Fatalf("partial revocation reported success: %s", w.Body.String())
	}
	if cdrInstances.Get(name) == nil {
		t.Fatal("entry pruned after a partial revocation")
	}
	fresh := &CDRInstanceRegistry{}
	if err := fresh.Load(regPath); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := fresh.GetCopy(name)
	states := map[string]string{}
	for _, g := range reloaded.Credentials {
		states[g.Fingerprint] = g.State
	}
	if states[newFP] != cdrCredRevoked || states[oldFP] == cdrCredRevoked {
		t.Fatalf("durable per-generation progress wrong: %v", states)
	}

	// Retry: only the remaining generation is targeted; then pruned.
	srv.mu.Lock()
	srv.outcomes = nil
	srv.revoked = nil
	srv.mu.Unlock()
	if w := tlRevokeByName(t, name, "retry"); w.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", w.Code, w.Body.String())
	}
	srv.mu.Lock()
	got := append([]string(nil), srv.revoked...)
	srv.mu.Unlock()
	if len(got) != 1 || got[0] != oldFP {
		t.Fatalf("retry targeted %v, want only the unrevoked predecessor %s", got, oldFP)
	}
	if cdrInstances.Get(name) != nil {
		t.Error("entry not pruned after the full lineage was proven revoked")
	}
}

// Crash/restart at each renewal commit boundary: the durable lineage +
// on-disk state let reconcileCredentialLineage finish or abandon safely.
func TestCDR2ECTLG_Renewal_CrashBoundariesReconcileAtRestart(t *testing.T) {
	type boundary struct {
		label     string
		arrange   func(inst CDREnrolledInstance, newPEM []byte)
		wantState string
		wantDisk  string // "new" | "old"
	}
	for _, b := range []boundary{
		{"staged, both tmp files written, no rename", func(inst CDREnrolledInstance, newPEM []byte) {
			_ = os.WriteFile(inst.ClientCertPath+".tmp", newPEM, 0o600)
			_ = os.WriteFile(inst.ClientKeyPath+".tmp", newPEM, 0o600)
		}, cdrCredActive, "new"},
		{"staged, cert renamed, key tmp pending", func(inst CDREnrolledInstance, newPEM []byte) {
			_ = os.WriteFile(inst.ClientCertPath, newPEM, 0o600)
			_ = os.WriteFile(inst.ClientKeyPath+".tmp", newPEM, 0o600)
		}, cdrCredActive, "new"},
		{"staged, both renamed, activation lost", func(inst CDREnrolledInstance, newPEM []byte) {
			_ = os.WriteFile(inst.ClientCertPath, newPEM, 0o600)
			_ = os.WriteFile(inst.ClientKeyPath, newPEM, 0o600)
		}, cdrCredActive, "new"},
		{"staged, material never written (crash before tmp)", func(CDREnrolledInstance, []byte) {}, cdrCredOrphaned, "old"},
	} {
		t.Run(b.label, func(t *testing.T) {
			resetCDRState(t)
			const name = "cdr-tlg-crash"
			inst, oldFP, regPath := tlSeedInstance(t, name)
			newPEM, newFP := tlRenewedCert(t)
			seq, err := cdrInstances.StageRenewal(name, mintCDROperationID())
			if err != nil {
				t.Fatal(err)
			}
			if err := cdrInstances.RecordIssuedCredential(name, seq, newFP, time.Now().Add(time.Hour).Unix(), cdrCredStaged); err != nil {
				t.Fatal(err)
			}
			b.arrange(inst, newPEM)

			// "Restart": a fresh registry loads the durable file, then the
			// boot-path reconcile runs.
			cdrInstances = &CDRInstanceRegistry{}
			if err := cdrInstances.Load(regPath); err != nil {
				t.Fatal(err)
			}
			reconcileCredentialLineage()

			cur, ok := cdrInstances.GetCopy(name)
			if !ok {
				t.Fatal("instance lost")
			}
			var gen CDRCredentialGeneration
			for _, g := range cur.Credentials {
				if g.Seq == seq {
					gen = g
				}
			}
			if gen.State != b.wantState {
				t.Fatalf("generation state %q, want %q (%+v)", gen.State, b.wantState, cur.Credentials)
			}
			disk, _ := loadCertFingerprint(inst.ClientCertPath)
			wantDisk := oldFP
			if b.wantDisk == "new" {
				wantDisk = newFP
			}
			if disk != wantDisk {
				t.Fatalf("disk cert %s, want %s", disk, wantDisk)
			}
			if b.wantState == cdrCredActive {
				if cur.ClientCertFingerprint != newFP {
					t.Fatalf("dial fingerprint %s, want %s", cur.ClientCertFingerprint, newFP)
				}
				for _, p := range []string{inst.ClientCertPath + ".tmp", inst.ClientKeyPath + ".tmp"} {
					if _, err := os.Stat(p); err == nil {
						t.Errorf("tmp file %s left behind", p)
					}
				}
			}
			// The predecessor is still identifiable in every case.
			if raw, _ := os.ReadFile(regPath); !strings.Contains(string(raw), oldFP) {
				t.Error("predecessor fingerprint lost")
			}
		})
	}
}

// A renewal whose RPC response was lost is resolved by the poller through
// EnrollStatus: ISSUED ⇒ orphaned (fingerprint recorded, audited),
// NOT_ISSUED ⇒ dropped. Until resolved, no second renewal is staged.
func TestCDR2ECTLG_Renewal_LostResponseIsReconciledByPoller(t *testing.T) {
	for _, tc := range []struct {
		label   string
		status  *pb.EnrollStatusResponse
		wantGen bool
		state   string
	}{
		{"issued → orphaned", &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_ISSUED, ClientCertFingerprint: "sha256:" + strings.Repeat("ee", 32)}, true, cdrCredOrphaned},
		{"not issued → dropped", &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_NOT_ISSUED}, false, ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			resetCDRState(t)
			const name = "cdr-tlg-lost-renewal"
			_, _, _ = tlSeedInstance(t, name)
			srv := &tlRecordingSluice{status: tc.status}
			pc, stop := tlPooled(t, name, srv)
			defer stop()
			withTempPool(t, pc)
			// The RPC never answered: the generation stays "renewing".
			inst, _ := cdrInstances.GetCopy(name)
			runRenewFor(pc, inst) // tlFakeSluice.renewResp nil ⇒ RPC error
			cur, _ := cdrInstances.GetCopy(name)
			var pending CDRCredentialGeneration
			for _, g := range cur.Credentials {
				if g.State == cdrCredRenewing {
					pending = g
				}
			}
			if pending.OperationID == "" {
				t.Fatalf("no durable renewing generation: %+v", cur.Credentials)
			}
			if _, err := cdrInstances.StageRenewal(name, mintCDROperationID()); !errors.Is(err, errCDRRenewalInProgress) {
				t.Fatalf("second renewal staged while one is unresolved: %v", err)
			}
			reconcilePendingRenewals([]*cdrPooledClient{pc})
			cur, _ = cdrInstances.GetCopy(name)
			var found *CDRCredentialGeneration
			for i := range cur.Credentials {
				if cur.Credentials[i].Seq == pending.Seq {
					found = &cur.Credentials[i]
				}
			}
			if tc.wantGen {
				if found == nil || found.State != tc.state || found.Fingerprint != tc.status.ClientCertFingerprint {
					t.Fatalf("generation after reconcile = %+v", found)
				}
				if !tlAuditHas("cdr.instance.credential.orphaned", tc.status.ClientCertFingerprint) {
					t.Error("orphaned credential not audited")
				}
			} else if found != nil {
				t.Fatalf("unissued generation kept: %+v", found)
			}
			if _, err := cdrInstances.StageRenewal(name, mintCDROperationID()); err != nil {
				t.Fatalf("renewal still blocked after reconciliation: %v", err)
			}
		})
	}
}

func TestCDR2ECTLG_Lineage_CapRefusesRenewalNeverForgetsLive(t *testing.T) {
	resetCDRState(t)
	const name = "cdr-tlg-cap"
	_, _, _ = tlSeedInstance(t, name)
	future := time.Now().Add(24 * time.Hour).Unix()
	for i := 0; i < cdrMaxCredentialGenerations-1; i++ {
		seq, err := cdrInstances.StageRenewal(name, mintCDROperationID())
		if err != nil {
			t.Fatalf("stage %d: %v", i, err)
		}
		fp := "sha256:" + strings.Repeat("a", 60) + fmt.Sprintf("%04x", i)
		if err := cdrInstances.RecordIssuedCredential(name, seq, fp, future, cdrCredStaged); err != nil {
			t.Fatal(err)
		}
		if err := cdrInstances.ActivateCredential(name, seq); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cdrInstances.StageRenewal(name, mintCDROperationID()); !errors.Is(err, errCDRLineageFull) {
		t.Fatalf("expected the lineage cap to refuse renewal, got %v", err)
	}
	cur, _ := cdrInstances.GetCopy(name)
	if n := len(cur.LiveFingerprints(time.Now())); n != cdrMaxCredentialGenerations {
		t.Fatalf("%d live generations, want %d (none may be forgotten)", n, cdrMaxCredentialGenerations)
	}
	// Revoking one frees the slot: revoked generations are prunable.
	if err := cdrInstances.MarkCredentialRevoked(name, cur.Credentials[0].Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := cdrInstances.StageRenewal(name, mintCDROperationID()); err != nil {
		t.Fatalf("renewal still refused after a revocation freed a slot: %v", err)
	}
}

// ─── R8 ─────────────────────────────────────────────────────────────────────

func tlEnrollBody(name, opID string) []byte {
	m := map[string]string{"name": name, "endpoint": "sluice-tlg:8443", "serverFingerprint": strings.Repeat("ab", 32), "token": "tok-secret"}
	if opID != "" {
		m["operationId"] = opID
	}
	b, _ := json.Marshal(m)
	return b
}

func tlStubEnroll(t *testing.T, fn func(ctx context.Context, endpoint, fp, token, opID string) (*pb.EnrollResponse, error)) {
	t.Helper()
	prev := cdrEnrollRPC
	cdrEnrollRPC = fn
	t.Cleanup(func() { cdrEnrollRPC = prev })
}

func tlStubStatus(t *testing.T, fn func(ctx context.Context, endpoint, fp, opID string) (*pb.EnrollStatusResponse, error)) {
	t.Helper()
	prev := cdrEnrollStatusRPC
	cdrEnrollStatusRPC = fn
	t.Cleanup(func() { cdrEnrollStatusRPC = prev })
}

func tlReceiptsOnDisk(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cdr_enroll_receipts.json")
	if err := cdrEnrollReceipts.Load(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCDR2ECTLG_Enroll_LostResponse_ReceiptDispatchedBeforeRPC(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	path := tlReceiptsOnDisk(t)
	const op = "tlg-lost-0123456789abcdef"
	var receiptAtDispatch string
	tlStubEnroll(t, func(_ context.Context, _, _, token, opID string) (*pb.EnrollResponse, error) {
		raw, _ := os.ReadFile(path)
		receiptAtDispatch = string(raw)
		if strings.Contains(receiptAtDispatch, token) {
			t.Error("the durable receipt carries the token")
		}
		return nil, status.Error(codes.DeadlineExceeded, "lost")
	})
	w := httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tlEnrollBody("cdr-tlg-lost", op)))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), op) || !strings.Contains(w.Body.String(), cdrEnrollRecoverPath) {
		t.Fatalf("lost response: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(receiptAtDispatch, op) || !strings.Contains(receiptAtDispatch, cdrReceiptDispatched) {
		t.Fatalf("receipt was not durable BEFORE the dispatch: %q", receiptAtDispatch)
	}
	rc, ok := cdrEnrollReceipts.Get(op)
	if !ok || rc.State != cdrReceiptDispatched {
		t.Fatalf("receipt after lost response = %+v", rc)
	}
	if cdrInstances.Get("cdr-tlg-lost") != nil {
		t.Error("registry entry created without a credential")
	}
	// Reload truth: a fresh store sees the receipt.
	fresh := &cdrEnrollReceiptStore{}
	if err := fresh.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Get(op); !ok {
		t.Error("receipt not durable across reload")
	}
}

func TestCDR2ECTLG_Enroll_ReceiptStorageFailure_SendsNothing(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	if err := cdrEnrollReceipts.Load(filepath.Join("/proc/culvert-nonexistent", "receipts.json")); err != nil {
		t.Fatal(err)
	}
	dispatched := 0
	tlStubEnroll(t, func(context.Context, string, string, string, string) (*pb.EnrollResponse, error) {
		dispatched++
		return nil, errors.New("must not be called")
	})
	w := httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tlEnrollBody("cdr-tlg-nostore", "")))
	if w.Code != http.StatusServiceUnavailable || dispatched != 0 {
		t.Fatalf("status %d dispatched %d body %s", w.Code, dispatched, w.Body.String())
	}
}

func TestCDR2ECTLG_Enroll_DuplicateOperation_RecordedIssuedNotStored(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	tlReceiptsOnDisk(t)
	const op = "tlg-dup-0123456789abcdef"
	issuedFP := "sha256:" + strings.Repeat("cd", 32)
	tlStubEnroll(t, func(context.Context, string, string, string, string) (*pb.EnrollResponse, error) {
		return nil, status.Errorf(codes.AlreadyExists, "operation already issued credential %s", issuedFP)
	})
	tlStubStatus(t, func(context.Context, string, string, string) (*pb.EnrollStatusResponse, error) {
		return &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_ISSUED, ClientCertFingerprint: issuedFP}, nil
	})
	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tlEnrollBody("cdr-tlg-dup", op))
	r.RemoteAddr = "198.51.100.93:0"
	apiCDREnroll(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), issuedFP) {
		t.Fatalf("duplicate operation: %d %s", w.Code, w.Body.String())
	}
	rc, _ := cdrEnrollReceipts.Get(op)
	if rc.State != cdrReceiptIssuedNotStored || rc.Fingerprint != issuedFP {
		t.Fatalf("receipt = %+v", rc)
	}
	if !tlAuditHas("cdr.instance.enroll.issued_not_stored", issuedFP) {
		t.Error("issued-but-not-stored credential not audited")
	}
	// A resolved operation cannot be re-dispatched.
	w = httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tlEnrollBody("cdr-tlg-dup", op)))
	if w.Code != http.StatusConflict {
		t.Fatalf("re-dispatch of a resolved operation: %d", w.Code)
	}
}

func TestCDR2ECTLG_Enroll_HandlerLocalPersistFailure_NamesTheIssuedFingerprint(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	tlReceiptsOnDisk(t)
	const name = "cdr-tlg-handler-persistfail"
	dir, err := cdrInstanceCertsDir(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Skipf("cannot write %s: %v", dir, err)
	}
	_ = os.RemoveAll(dir)
	if err := os.WriteFile(dir, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	issuedPEM, issuedFP := tlRenewedCert(t)
	const op = "tlg-persist-0123456789abcdef"
	tlStubEnroll(t, func(context.Context, string, string, string, string) (*pb.EnrollResponse, error) {
		return &pb.EnrollResponse{CaCert: issuedPEM, ClientCert: issuedPEM, ClientKey: issuedPEM, ClientCertFingerprint: issuedFP, OperationId: op}, nil
	})
	w := httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tlEnrollBody(name, op)))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), issuedFP) {
		t.Fatalf("persist failure: %d %s", w.Code, w.Body.String())
	}
	rc, _ := cdrEnrollReceipts.Get(op)
	if rc.State != cdrReceiptIssuedNotStored || rc.Fingerprint != issuedFP {
		t.Fatalf("receipt = %+v", rc)
	}
}

func TestCDR2ECTLG_Recover_ClassifiesEveryOutcome(t *testing.T) {
	const op = "tlg-recover-0123456789abcdef"
	issuedFP := "sha256:" + strings.Repeat("ef", 32)
	for _, tc := range []struct {
		label  string
		status *pb.EnrollStatusResponse
		err    error
		seed   func(t *testing.T)
		want   string
	}{
		{"ambiguous", nil, status.Error(codes.Unavailable, "down"), nil, cdrRecoverAmbiguous},
		{"not issued", &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_NOT_ISSUED}, nil, nil, cdrRecoverNotIssued},
		{"issued, not stored", &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_ISSUED, ClientCertFingerprint: issuedFP}, nil, nil, cdrRecoverNotStored},
		{"landed and stored", &pb.EnrollStatusResponse{Outcome: pb.EnrollOutcome_ENROLL_ISSUED, ClientCertFingerprint: issuedFP}, nil, func(t *testing.T) {
			if _, err := cdrInstances.Add(CDREnrolledInstance{Name: "cdr-tlg-landed", Endpoint: "e:1", ClientCertFingerprint: issuedFP}); err != nil {
				t.Fatal(err)
			}
		}, cdrRecoverLanded},
	} {
		t.Run(tc.label, func(t *testing.T) {
			resetCDRState(t)
			tlReceiptsOnDisk(t)
			if err := cdrEnrollReceipts.Put(CDREnrollReceipt{OperationID: op, Name: "cdr-tlg-rec", Endpoint: "sluice:8443", ServerFingerprint: strings.Repeat("ab", 32), State: cdrReceiptDispatched}); err != nil {
				t.Fatal(err)
			}
			if tc.seed != nil {
				tc.seed(t)
			}
			tlStubStatus(t, func(context.Context, string, string, string) (*pb.EnrollStatusResponse, error) {
				return tc.status, tc.err
			})
			body, _ := json.Marshal(map[string]string{"operationId": op})
			w := httptest.NewRecorder()
			apiCDREnrollRecover(w, newAdminRequest(http.MethodPost, cdrEnrollRecoverPath, body))
			if w.Code != http.StatusOK {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			var got map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &got)
			if got["classification"] != tc.want {
				t.Fatalf("classification %v, want %s (%s)", got["classification"], tc.want, w.Body.String())
			}
			switch tc.want {
			case cdrRecoverNotStored:
				rev, _ := got["revocation"].(map[string]any)
				if rev == nil || rev["fingerprint"] != issuedFP || rev["cli"] == nil {
					t.Fatalf("no exact revocation path: %s", w.Body.String())
				}
				if rc, _ := cdrEnrollReceipts.Get(op); rc.State != cdrReceiptIssuedNotStored || rc.Fingerprint != issuedFP {
					t.Fatalf("receipt = %+v", rc)
				}
			case cdrRecoverAmbiguous:
				if got["retryable"] != true {
					t.Error("ambiguous must be retryable")
				}
				if rc, _ := cdrEnrollReceipts.Get(op); rc.State != cdrReceiptDispatched {
					t.Errorf("ambiguous mutated the receipt: %+v", rc)
				}
			case cdrRecoverNotIssued:
				if rc, _ := cdrEnrollReceipts.Get(op); rc.State != cdrReceiptNotIssued {
					t.Errorf("receipt = %+v", rc)
				}
			case cdrRecoverLanded:
				if got["name"] != "cdr-tlg-landed" {
					t.Errorf("landed name = %v", got["name"])
				}
			}
		})
	}
}

func TestCDR2ECTLG_Recover_AuthBoundary(t *testing.T) {
	resetCDRState(t)
	body, _ := json.Marshal(map[string]string{"operationId": "tlg-auth-0123456789abcdef"})
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.WithValue(context.Background(), uiRoleKey{}, RoleViewer), http.MethodPost, cdrEnrollRecoverPath, strings.NewReader(string(body)))
	apiCDREnrollRecover(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer recover: %d", w.Code)
	}
	w = httptest.NewRecorder()
	apiCDREnrollReceipts(w, newViewerRequest(cdrEnrollReceiptsAPI))
	if w.Code != http.StatusOK {
		t.Fatalf("viewer list receipts: %d", w.Code)
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequestWithContext(context.WithValue(context.Background(), uiRoleKey{}, RoleViewer), http.MethodDelete, cdrEnrollReceiptsAPI+"?operationId=tlg-auth-0123456789abcdef", nil)
	apiCDREnrollReceipts(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer delete receipt: %d", w.Code)
	}
}

func TestCDR2ECTLG_RevokeOrphanByFingerprint_ClosesTheReceipt(t *testing.T) {
	resetCDRState(t)
	tlReceiptsOnDisk(t)
	orphan := "sha256:" + strings.Repeat("0a", 32)
	const op = "tlg-orphan-0123456789abcdef"
	if err := cdrEnrollReceipts.Put(CDREnrollReceipt{OperationID: op, Name: "x", Endpoint: "e", ServerFingerprint: "f", State: cdrReceiptIssuedNotStored, Fingerprint: orphan}); err != nil {
		t.Fatal(err)
	}
	// No pooled client: the exact CLI instruction is returned.
	withTempPool(t)
	body, _ := json.Marshal(map[string]string{"fingerprint": orphan})
	w := httptest.NewRecorder()
	apiCDRRevokeRPC(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/revoke", body))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "sluice node revoke "+orphan) {
		t.Fatalf("no caller: %d %s", w.Code, w.Body.String())
	}
	// With a caller: proof required, receipt closed.
	srv := &tlRecordingSluice{outcomes: map[string]*pb.RevokeClientResponse{orphan: {Outcome: pb.RevokeOutcome_REVOKE_OUTCOME_TOMBSTONED}}}
	caller, stop := tlPooled(t, "cdr-tlg-orphan-caller", srv)
	defer stop()
	withTempPool(t, caller)
	w = httptest.NewRecorder()
	apiCDRRevokeRPC(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/revoke", body))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "tombstoned") {
		t.Fatalf("orphan revoke: %d %s", w.Code, w.Body.String())
	}
	if rc, _ := cdrEnrollReceipts.Get(op); rc.State != cdrReceiptRevoked {
		t.Fatalf("receipt = %+v", rc)
	}
	// Name + fingerprint together is refused.
	both, _ := json.Marshal(map[string]string{"fingerprint": orphan, "name": "x"})
	w = httptest.NewRecorder()
	apiCDRRevokeRPC(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/revoke", both))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("name+fingerprint: %d", w.Code)
	}
}

// ─── R10 ────────────────────────────────────────────────────────────────────

func TestCDR2ECTLG_PolicyStore_DegradedRepairAndRestartTruth(t *testing.T) {
	resetCDRState(t)
	path := filepath.Join(t.TempDir(), "cdr_policies.json")
	legacy := `[{"priority":10,"name":"dup","mode":"ENFORCE"},{"priority":5,"name":"dup ","mode":"REPORT_ONLY"},{"priority":1,"name":" ","mode":"ENFORCE"},{"priority":0,"name":"ok","mode":"ENFORCE"}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cdrPolicyStore.Load(path); err != nil {
		t.Fatal(err)
	}
	integ := cdrPolicyStore.Integrity()
	if integ.OK || len(integ.Issues) != 2 {
		t.Fatalf("integrity = %+v", integ)
	}
	// Add is refused while degraded.
	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", []byte(`{"name":"new","priority":3,"mode":"ENFORCE"}`)))
	if w.Code != http.StatusConflict {
		t.Fatalf("add while degraded: %d %s", w.Code, w.Body.String())
	}
	// Positional repair is fenced on the verbatim name.
	w = httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete, "/api/cdr/policies?name=dup&position=1", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("mis-fenced positional delete accepted: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete, "/api/cdr/policies?name=dup+&position=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("positional delete: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete, "/api/cdr/policies?name=+&position=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("positional delete of the empty name: %d %s", w.Code, w.Body.String())
	}
	if integ := cdrPolicyStore.Integrity(); !integ.OK {
		t.Fatalf("still degraded after repair: %+v", integ)
	}
	// Positional delete is unavailable once healthy; Add works again.
	w = httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete, "/api/cdr/policies?name=ok&position=1", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("positional delete on a healthy store: %d", w.Code)
	}
	w = httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", []byte(`{"name":"new","priority":3,"mode":"ENFORCE"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("add after repair: %d %s", w.Code, w.Body.String())
	}
	// Restart truth.
	fresh := &CDRPolicyStore{}
	if err := fresh.Load(path); err != nil {
		t.Fatal(err)
	}
	if !fresh.Integrity().OK || len(fresh.List()) != 3 {
		t.Fatalf("after restart: integrity=%+v rules=%d", fresh.Integrity(), len(fresh.List()))
	}
}
