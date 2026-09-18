package main

// fe6b0d_green_test.go — FE-6B.0 correction round 3: GREEN proofs of the
// corrected behaviour the RED matrix (fe6b0d_red_test.go) does not reach —
// the settlement-time durability resolution, the recovery loop's load
// branch, an invalid bundle beside a repairing writer, and the read-model
// evidence classes. No sleeps; fault seams at the persistence boundaries.

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// G01 — a settlement whose directory re-sync fails records the recoverable
// durability_unproven verdict, BLOCKS a writer of the object, and commits
// (once, with its audit) as soon as the directory can be synchronised.
func TestFE6B0D_G01_SettlementResyncFailureIsRecoverableAndBlocksWriters(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	_, rev := fe6b0Fingerprint(), fe6b0Revision(t)
	// The handler's write lands unproven (post-rename), leaving the intent
	// pending with the candidate installed.
	reached := fe6b0dSyncHook(t, "atomic-dir", caRuntime.path)
	opX := fe6b0OpID()
	ch, _ := fe6b0Challenge(t, mux, opX, rev)
	code, m, _ := fe6b0Rotate(mux, opX, rev, ch)
	if !*reached {
		t.Fatal("seam not reached")
	}
	fe6b0dAssertDurabilityUnproven(t, code, m, opX)
	// Now every DIRECTORY sync of the data root fails: the settlement cannot
	// prove the durability and must not credit.
	restore := fileutil.SetSyncHookForTest(func(k, p string) error {
		if k == "dir" && p == dir {
			return errors.New("injected directory sync fault")
		}
		return nil
	})
	state, l := fe6b0cLookupState(t, mux, opX)
	if state != certOpOutcomeUnknown || l["code"] != "lookup_"+certCodeDurabilityUnproven {
		t.Fatalf("lookup under a failing resync = %s %v, want outcome_unknown lookup_durability_unproven", state, l)
	}
	if n, _, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 0 {
		t.Fatal("audited before durability was proven")
	}
	// A writer of the CA is held while the intent's durability is unproven.
	certA, keyA, _ := fe6b0CAPair(t, "A", true)
	if code, m, _ := fe6b0Upload(t, mux, "?target=mitm&operationId="+fe6b0OpID()+"&caRevision="+fe6b0Revision(t),
		map[string]string{"target": "mitm", "cert": string(certA), "key": string(keyA)}); code != http.StatusServiceUnavailable || m["code"] != refusalOperationUnsettled {
		t.Fatalf("a writer was admitted while durability is unproven: %d %v", code, m)
	}
	restore()
	if state, l := fe6b0cLookupState(t, mux, opX); state != certOpCommitted || l["code"] != "lookup_committed" {
		t.Fatalf("after the fault cleared = %s %v", state, l)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
	_ = dir
}

// G02 — the CA recovery loop's LOAD branch reads the bundle an
// unavailable-evidence intent waits on, and settles the intent from the
// recovered evidence right after the load; its settle-first rule stays on
// the writing branches.
func TestFE6B0D_G02_RecoveryLoadBranchSettlesUnavailableEvidence(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	fe6b0dSeal(t, "sealed-under-this")
	since := fe6aSince()
	fe6b0cCommitWithFinishFailure(dir)
	opX := fe6b0OpID()
	fe6b0RotateOK(t, mux, opX)
	digest := certMgr.LiveCertificateHex()
	fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
	// Boot under the wrong passphrase: the load fails, the failure is
	// recorded, X is settled as unavailable evidence.
	caRuntime.passphrase = "wrong"
	swapInspectionCA(t)
	if err := certMgr.LoadCA(caRuntime.path, caRuntime.passphrase); err == nil {
		t.Fatal("precondition: undecodable")
	}
	noteSSLInspectionUnavailable(caRuntime.path, errors.New("boot: undecodable"))
	t.Cleanup(func() { noteSSLInspectionRecovered("test cleanup") })
	reopenCertificateOperationsForTest()
	reconcileCertificateOperations()
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.Code != "reconciled_"+certCodeEvidenceUnavailable {
		t.Fatalf("boot settlement = %+v", rec)
	}
	// The operator restores the passphrase; the recovery loop's next attempt
	// (a LOAD — the node holds no CA) must run despite the blocking intent
	// and settle it from the loaded bundle.
	caRuntime.passphrase = "sealed-under-this"
	attempted, err := tryInspectionCARecovery(rootCAStartupConfig{Path: caRuntime.path, Passphrase: caRuntime.passphrase}, 1)
	if !attempted || err != nil {
		t.Fatalf("recovery attempt = %v %v", attempted, err)
	}
	rec := fe6b0cRecord(t, opX)
	if rec == nil || rec.State != certOpCommitted || rec.CommittedRevision != caRevisionPrefix+digest {
		t.Fatalf("the recovered load did not settle X: %+v", rec)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
	if sslInspectionLoadFailure() != "" {
		t.Fatal("the load failure was not cleared")
	}
}

// G03 — a bundle that reads but is not a CA bundle is INVALID evidence:
// recorded as recoverable evidence_invalid (never absence, never a commit),
// and it does not block a repairing import.
func TestFE6B0D_G03_InvalidBundleIsRecoverableAndDoesNotBlockRepair(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	_, _, fpA := fe6b0CAPair(t, "A", true)
	opX := fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionImport, Actor: "10.99.0.1",
		Target: "root_ca", CandidateDigest: fpA, Fence: fe6b0Revision(t)})
	// Live CA ≠ candidate; the bundle's bytes are not a bundle at all.
	if err := os.WriteFile(caRuntime.path, []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, l := fe6b0cLookupState(t, mux, opX)
	if state != certOpOutcomeUnknown || l["code"] != "lookup_"+certCodeEvidenceInvalid {
		t.Fatalf("invalid bundle = %s %v, want outcome_unknown lookup_evidence_invalid", state, l)
	}
	certB, keyB, fpB := fe6b0CAPair(t, "B", true)
	code, m, _ := fe6b0Upload(t, mux, "?target=mitm&operationId="+fe6b0OpID()+"&caRevision="+fe6b0Revision(t),
		map[string]string{"target": "mitm", "cert": string(certB), "key": string(keyB)})
	if code != http.StatusOK || m["imported"] != true {
		t.Fatalf("a repairing import was refused beside an invalid bundle: %d %v", code, m)
	}
	if certMgr.LiveCertificateHex() != fpB {
		t.Fatal("the import did not install B")
	}
	// The writer settled X BEFORE it wrote: the bundle was still invalid at
	// that instant, so X stayed recoverable (writer_evidence_invalid) — the
	// writer's own write is never evidence for an earlier intent. The next
	// settlement reads the bundle B wrote: readable, not A ⇒ aborted, never
	// credited with B.
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != certOpOutcomeUnknown || rec.Code != "writer_"+certCodeEvidenceInvalid {
		t.Fatalf("X right after the repairing writer = %+v", rec)
	}
	if state, l := fe6b0cLookupState(t, mux, opX); state != certOpAborted || l["code"] != "lookup_absent" {
		t.Fatalf("X decided against B's bundle = %s %v", state, l)
	}
}

// G04 — the read model names the pair's evidence class and the token never
// collapses unavailable or incomplete into none.
func TestFE6B0D_G04_UIPairReadModelStatesTheEvidenceClass(t *testing.T) {
	_, _ = fe6b0cNode(t)
	mux := fe6b0Mux()
	leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leaf, key); code != http.StatusOK {
		t.Fatalf("seed = %d %v", code, m)
	}
	if ev := uiPairEvidenceNow(); ev.class != uiPairComplete || !ev.valid || ev.certDigest != hexDigest(leaf) {
		t.Fatalf("complete pair = %+v", ev)
	}
	if err := os.Remove(customUITLSKeyPath()); err != nil {
		t.Fatal(err)
	}
	if tok := uiCertRevisionToken(); tok != uiCertRevisionIncomplete {
		t.Fatalf("one remnant file = %s, want %s", tok, uiCertRevisionIncomplete)
	}
	restore := fe6b0cMakeDir(t, customUITLSCertPath())
	if tok := uiCertRevisionToken(); tok != uiCertRevisionUnavailable {
		t.Fatalf("directory at the path = %s, want %s", tok, uiCertRevisionUnavailable)
	}
	// A mutation against unavailable evidence is refused with nothing
	// written and no intent recorded.
	opX := fe6b0OpID()
	code, m := fe6b0cUIReplace(t, mux, opX, uiCertRevisionUnavailable, leaf, key)
	if code != http.StatusServiceUnavailable || m["code"] != refusalEvidenceUnavail {
		t.Fatalf("replace against unavailable evidence = %d %v", code, m)
	}
	if rec := fe6b0cRecord(t, opX); rec != nil {
		t.Fatalf("an intent was recorded for a refused replace: %+v", rec)
	}
	restore()
	if err := os.Remove(customUITLSCertPath()); err != nil {
		t.Fatal(err)
	}
	if tok := uiCertRevisionToken(); tok != uiCertRevisionNone {
		t.Fatalf("positively absent = %s", tok)
	}
}
