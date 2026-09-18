package main

// fe6b0d_red_test.go — FE-6B.0 CORRECTION ROUND 2: deterministic RED matrix on
// the exact rejected candidate f2e59ed9 (three source-level durability and
// recovery blockers).
//
//	B1  D01 CA bundle: a POST-rename synchronisation failure is not an abort
//	    D02 UI certificate write: post-rename failure completes the pair, never aborts
//	    D03 UI key write: post-rename failure is not "unchanged" — the pair on disk IS the new pair
//	B2  D04 an interrupted replace (crash between the two writes) never credits an incomplete pair
//	    D05 an interrupted FIRST installation leaves no cert-without-key remnant at the live path
//	    D06 an interrupted deletion distinguishes incomplete cleanup from complete deletion
//	B3  D07 unavailable (undecodable / unreadable) CA evidence is not absence; writers are held; recovery settles
//	    D08 unavailable UI evidence is not absence
//	    D09 a recovered CA result names the evidence that decided it, not a different live CA
//	    D10 controls: a PRE-replacement failure is still a terminal abort; positive absence still aborts;
//	        a complete deletion is credited as complete
//
// Fault seams sit at the actual persistence boundaries: the key-write seam
// `uiTLSAtomicWrite` (baseline), `fileutil.SetSyncHookForTest` on the
// `atomic-file`/`atomic-dir` steps of AtomicWrite (the correction wires it),
// crash simulation by a panic raised INSIDE the write seam (the handler's
// deferred unlocks run, nothing after the write does), evidence made
// unavailable without changing its bytes (a directory at the path; a
// passphrase the bundle was not sealed under), and restart by re-opening the
// ledger and re-loading the object from disk. No sleeps.

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// fe6b0dRestart re-opens the ledger from its file and re-loads the inspection
// CA from the configured bundle into a FRESH manager, then runs boot
// reconciliation — a process restart as far as the certificate lifecycle is
// concerned. The load error is returned (an unreadable bundle is a valid
// boot).
func fe6b0dRestart(t *testing.T) error {
	t.Helper()
	swapInspectionCA(t)
	err := certMgr.LoadCA(caRuntime.path, caRuntime.passphrase)
	reopenCertificateOperationsForTest()
	reconcileCertificateOperations()
	return err
}

// fe6b0dRestartUI re-runs the boot-time UI pair resolution against the files
// on disk (what startUI would load) and re-opens the ledger.
func fe6b0dRestartUI(t *testing.T) {
	t.Helper()
	uiCustomTLSActive, uiCustomTLSCorrupt = false, false
	resolveUITLSCertKey("", "")
	reopenCertificateOperationsForTest()
	reconcileCertificateOperations()
}

// fe6b0dSeal re-seals the node's bundle under a passphrase so the CA
// evidence can later be made UNDECODABLE (a passphrase it was not sealed
// under) without touching its bytes.
func fe6b0dSeal(t *testing.T, passphrase string) {
	t.Helper()
	if err := certMgr.SaveCA(caRuntime.path, passphrase); err != nil {
		t.Fatal(err)
	}
	caRuntime.passphrase = passphrase
}

// fe6b0dKeyWrite swaps the UI key-write seam for the test's duration.
func fe6b0dKeyWrite(t *testing.T, fn func(path string, data []byte, perm os.FileMode) error) {
	t.Helper()
	prev := uiTLSAtomicWrite
	uiTLSAtomicWrite = fn
	t.Cleanup(func() { uiTLSAtomicWrite = prev })
}

// fe6b0dCrash runs fn and reports whether it crashed (a panic raised inside a
// persistence seam stands in for a process death at that instant).
func fe6b0dCrash(fn func()) (crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			crashed = true
		}
	}()
	fn()
	return false
}

type fe6b0dCrashSignal struct{}

// fe6b0dSyncHook installs a fileutil synchronisation hook that fails the
// given step for the given target path exactly once and reports whether it
// was reached at all (the baseline's AtomicWrite consults no hook).
func fe6b0dSyncHook(t *testing.T, kind, target string) (reached *bool) {
	t.Helper()
	var hit bool
	reached = &hit
	restore := fileutil.SetSyncHookForTest(func(k, p string) error {
		if k == kind && p == target && !hit {
			hit = true
			return errors.New("injected synchronisation failure")
		}
		return nil
	})
	t.Cleanup(restore)
	return reached
}

func fe6b0dAssertDurabilityUnproven(t *testing.T, code int, m map[string]any, opID string) {
	t.Helper()
	if code != http.StatusInternalServerError || m["code"] != refusalOutcomeUnknown {
		t.Fatalf("a post-rename synchronisation failure must be the NON-terminal 500 outcome_unknown (the replacement is on disk), got %d %v", code, m)
	}
	cur, _ := m["current"].(map[string]any)
	if cur["detail"] != "durability_unproven" || cur["state"] != certOpPending || cur["operationId"] != opID {
		t.Fatalf("outcome_unknown must carry current.detail=durability_unproven, current.state=pending and the operationId: %v", m)
	}
}

func fe6b0dLiveRemnant(t *testing.T) (certOnly, keyOnly bool) {
	t.Helper()
	_, cerr := os.Stat(customUITLSCertPath())
	_, kerr := os.Stat(customUITLSKeyPath())
	return cerr == nil && kerr != nil, kerr == nil && cerr != nil
}

// ── B1 ──────────────────────────────────────────────────────────────────────

func TestFE6B0D_D01_CABundlePostRenameSyncFailureIsNotAnAbort(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	fpBefore, rev := fe6b0Fingerprint(), fe6b0Revision(t)
	reached := fe6b0dSyncHook(t, "atomic-dir", caRuntime.path)
	opX := fe6b0OpID()
	ch, _ := fe6b0Challenge(t, mux, opX, rev)
	code, m, _ := fe6b0Rotate(mux, opX, rev, ch)
	if !*reached {
		t.Fatal("AtomicWrite reached no synchronisation seam for the bundle's parent directory (correction absent: the post-rename failure cannot be exercised)")
	}
	fe6b0dAssertDurabilityUnproven(t, code, m, opX)
	rec := fe6b0cRecord(t, opX)
	if rec == nil || rec.State != certOpPending {
		t.Fatalf("the intent must stay PENDING (no terminal non-commit verdict without evidence), got %+v", rec)
	}
	// The replacement IS on disk (the rename landed): the bundle carries the
	// candidate, and the process serves it (a split live/disk state is never
	// published).
	probe := ca.New()
	if err := probe.LoadCA(caRuntime.path, caRuntime.passphrase); err != nil {
		t.Fatal(err)
	}
	if probe.LiveCertificateHex() != rec.CandidateDigest {
		t.Fatalf("the bundle on disk does not carry the candidate although the rename landed")
	}
	if certMgr.LiveCertificateHex() != rec.CandidateDigest {
		t.Fatalf("live CA %s ≠ the replacement on disk %s (split state)", certMgr.LiveCertificateHex(), rec.CandidateDigest)
	}
	if n, _, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 0 {
		t.Fatal("durable success was audited before durability was proven")
	}
	// Durability is resolved by the lookup (the directory is re-synchronised
	// with the fault gone) and only then is the success reported and audited.
	if state, l := fe6b0cLookupState(t, mux, opX); state != "committed" {
		t.Fatalf("lookup after the fault cleared = %s %v", state, l)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
	// And across a restart the same evidence decides the same way.
	if err := fe6b0dRestart(t); err != nil {
		t.Fatal(err)
	}
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != "committed" {
		t.Fatalf("after restart = %+v", rec)
	}
	if fe6b0Fingerprint() == fpBefore {
		t.Fatal("the restart did not load the replacement")
	}
	_ = dir
}

func TestFE6B0D_D02_UICertWritePostRenameSyncFailureCompletesThePair(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
	// Fail the parent-directory synchronisation of the CERTIFICATE write — the
	// correction stages the pair, so the write may land at the live path or at
	// a staging path; the hook matches either.
	var reached bool
	restore := fileutil.SetSyncHookForTest(func(k, p string) error {
		if k == "atomic-dir" && strings.HasPrefix(filepath.Base(p), customUITLSCertFile) && !reached {
			reached = true
			return errors.New("injected synchronisation failure")
		}
		return nil
	})
	t.Cleanup(restore)
	opX := fe6b0OpID()
	code, m := fe6b0cUIReplace(t, mux, opX, uiCertRevisionNone, leaf, key)
	if !reached {
		t.Fatal("AtomicWrite reached no synchronisation seam for the certificate write (correction absent)")
	}
	fe6b0dAssertDurabilityUnproven(t, code, m, opX)
	// The pair on disk is COMPLETE and valid — the key write was not skipped
	// because the certificate's durability was in doubt.
	if !customUITLSFilesPresent() || !customUITLSPairValid() {
		t.Fatal("the pair on disk is incomplete or invalid after a post-rename certificate failure")
	}
	if n, _, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 0 {
		t.Fatal("success audited before durability was proven")
	}
	if state, l := fe6b0cLookupState(t, mux, opX); state != "committed" {
		t.Fatalf("lookup = %s %v", state, l)
	}
	fe6b0dRestartUI(t)
	if !uiCustomTLSActive || uiCustomTLSCorrupt {
		t.Fatalf("restart did not activate the completed pair (active=%v corrupt=%v)", uiCustomTLSActive, uiCustomTLSCorrupt)
	}
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != "committed" {
		t.Fatalf("after restart = %+v", rec)
	}
	_ = dir
}

func TestFE6B0D_D03_UIKeyWritePostRenameSyncFailureIsNotAnAbort(t *testing.T) {
	_, _ = fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
	// The key write LANDS (the real atomic write runs) and then reports the
	// post-rename failure fileutil documents.
	fe6b0dKeyWrite(t, func(path string, data []byte, perm os.FileMode) error {
		if err := fileutil.AtomicWrite(path, data, perm); err != nil {
			return err
		}
		return errors.New("parent dir fsync: injected: " + fileutil.ErrReplacedNotSynced.Error())
	})
	// errors.Is must hold for the seam's error: wrap the sentinel properly.
	fe6b0dKeyWrite(t, func(path string, data []byte, perm os.FileMode) error {
		if err := fileutil.AtomicWrite(path, data, perm); err != nil {
			return err
		}
		return errors.Join(errors.New("parent dir fsync: injected"), fileutil.ErrReplacedNotSynced)
	})
	opX := fe6b0OpID()
	code, m := fe6b0cUIReplace(t, mux, opX, uiCertRevisionNone, leaf, key)
	if code == http.StatusInternalServerError && m["code"] == refusalPersistFailed {
		t.Fatalf("the response claims the UI certificate is unchanged (terminal persist_failed) while the NEW pair is on disk: %v", m)
	}
	fe6b0dAssertDurabilityUnproven(t, code, m, opX)
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State == certOpAborted {
		t.Fatalf("a durable ABORT was recorded for a replacement that is on disk: %+v", rec)
	}
	if !customUITLSPairValid() {
		t.Fatal("the pair on disk is not the valid new pair")
	}
	if n, _, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 0 {
		t.Fatal("success audited before durability was proven")
	}
	// Restart activates the replacement; the ledger must agree exactly once.
	fe6b0dRestartUI(t)
	if !uiCustomTLSActive {
		t.Fatal("the restart did not activate the replacement that was on disk")
	}
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != "committed" {
		t.Fatalf("the operation whose replacement the restart activated reads %+v", rec)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
}

// ── B2 ──────────────────────────────────────────────────────────────────────

func TestFE6B0D_D04_InterruptedReplaceNeverCreditsAnIncompletePair(t *testing.T) {
	_, _ = fe6b0cNode(t)
	mux := fe6b0Mux()
	leafC, keyC, _ := fe6b0CAPair(t, "ui-c", false)
	leafD, keyD, _ := fe6b0CAPair(t, "ui-d", false)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leafC, keyC); code != http.StatusOK {
		t.Fatalf("seed = %d %v", code, m)
	}
	since := fe6aSince()
	revC := fe6b0cUIRevision(t, mux)
	// The process dies AFTER the certificate write and BEFORE the key write.
	fe6b0dKeyWrite(t, func(string, []byte, os.FileMode) error { panic(fe6b0dCrashSignal{}) })
	opX := fe6b0OpID()
	if !fe6b0dCrash(func() { fe6b0cUIReplace(t, mux, opX, revC, leafD, keyD) }) {
		t.Fatal("the crash seam did not fire")
	}
	fe6b0dKeyWrite(t, fileutil.AtomicWrite)
	// Restart from the files on disk and the durable pending intent.
	fe6b0dRestartUI(t)
	if uiCustomTLSCorrupt {
		t.Fatal("the restart found a MISMATCHED pair (new certificate, old key): the interrupted transition destroyed the working pair")
	}
	state, l := fe6b0cLookupState(t, mux, opX)
	if state == "committed" {
		t.Fatalf("an incomplete pair (certificate written, key not written) was credited as committed: %v", l)
	}
	if n, _, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 0 {
		t.Fatal("a success audit was emitted for an incomplete pair")
	}
	// The working pair C is still what the node serves (or would serve).
	if !customUITLSFilesPresent() || !customUITLSPairValid() || fe6b0cUIRevision(t, mux) != revC {
		t.Fatalf("the previous valid pair was not preserved (present=%v valid=%v rev=%s)", customUITLSFilesPresent(), customUITLSPairValid(), fe6b0cUIRevision(t, mux))
	}
}

func TestFE6B0D_D05_InterruptedFirstInstallLeavesNoLiveRemnant(t *testing.T) {
	_, _ = fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
	fe6b0dKeyWrite(t, func(string, []byte, os.FileMode) error { panic(fe6b0dCrashSignal{}) })
	opX := fe6b0OpID()
	if !fe6b0dCrash(func() { fe6b0cUIReplace(t, mux, opX, uiCertRevisionNone, leaf, key) }) {
		t.Fatal("the crash seam did not fire")
	}
	fe6b0dKeyWrite(t, fileutil.AtomicWrite)
	fe6b0dRestartUI(t)
	if certOnly, keyOnly := fe6b0dLiveRemnant(t); certOnly || keyOnly {
		t.Fatalf("an interrupted first installation left a remnant at the live path (certOnly=%v keyOnly=%v): the live pair must be written only as a complete pair", certOnly, keyOnly)
	}
	if state, l := fe6b0cLookupState(t, mux, opX); state == "committed" {
		t.Fatalf("an incomplete first installation was credited: %v", l)
	}
	if n, _, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 0 {
		t.Fatal("success audited for an incomplete installation")
	}
	if uiCustomTLSActive || uiCustomTLSCorrupt {
		t.Fatalf("boot resolved a pair that was never completed (active=%v corrupt=%v)", uiCustomTLSActive, uiCustomTLSCorrupt)
	}
}

func TestFE6B0D_D06_InterruptedDeleteDistinguishesIncompleteCleanup(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leaf, key); code != http.StatusOK {
		t.Fatalf("seed = %d %v", code, m)
	}
	since := fe6aSince()
	rev := fe6b0cUIRevision(t, mux)
	// The delete's intent is durable; the process died after the key was
	// removed and before the certificate was.
	opX := fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionUIDelete, Actor: "10.99.0.1", Target: "ui_cert", Fence: rev})
	if err := os.Remove(customUITLSKeyPath()); err != nil {
		t.Fatal(err)
	}
	fe6b0dRestartUI(t)
	state, l := fe6b0cLookupState(t, mux, opX)
	if state != "committed" {
		t.Fatalf("the deletion's cleanup must be COMPLETED at settlement and recorded, got %s %v", state, l)
	}
	res, _ := l["result"].(map[string]any)
	if res["cleanup"] != "completed_at_settlement" {
		t.Fatalf("an incomplete cleanup (certificate file left behind) was recorded as a complete deletion: %v", l)
	}
	if _, err := os.Stat(customUITLSCertPath()); err == nil {
		t.Fatal("the certificate remnant is still on disk after the deletion was credited")
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.delete"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
}

// ── B3 ──────────────────────────────────────────────────────────────────────

// D06b — the SUCCESS answer of a deletion states that the cleanup was
// complete, so an operator (and the recovery path in D06) can tell a
// completed pair removal from a cleanup finished later at settlement.
func TestFE6B0D_D06b_CompleteDeletionIsCreditedAsComplete(t *testing.T) {
	_, _ = fe6b0cNode(t)
	mux := fe6b0Mux()
	leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leaf, key); code != http.StatusOK {
		t.Fatalf("seed = %d %v", code, m)
	}
	opX := fe6b0OpID()
	code, m := fe6b0cUIDelete(mux, opX, fe6b0cUIRevision(t, mux))
	if code != http.StatusOK || m["deleted"] != true {
		t.Fatalf("delete = %d %v", code, m)
	}
	if m["cleanup"] != "complete" {
		t.Fatalf("a complete deletion must say so: %v", m)
	}
	if customUITLSFilesPresent() {
		t.Fatal("pair still present")
	}
}

func TestFE6B0D_D07a_UndecodableCAEvidenceIsNotAbsence(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	fe6b0dSeal(t, "sealed-under-this")
	since := fe6aSince()
	fe6b0cCommitWithFinishFailure(dir)
	opX := fe6b0OpID()
	fe6b0RotateOK(t, mux, opX)
	digest := certMgr.LiveCertificateHex()
	fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
	// Restart: the bundle is intact but cannot be decoded (the passphrase
	// the node booted with is not the one it was sealed under).
	caRuntime.passphrase = "not-the-sealing-passphrase"
	if err := fe6b0dRestart(t); err == nil {
		t.Fatal("precondition: the bundle must be undecodable under the wrong passphrase")
	}
	rec := fe6b0cRecord(t, opX)
	if rec == nil || rec.State == certOpAborted || rec.State == "committed" {
		t.Fatalf("undecodable evidence was converted into a terminal verdict: %+v", rec)
	}
	// A later writer must not destroy the unresolved evidence.
	certA, keyA, _ := fe6b0CAPair(t, "A", true)
	if code, m, _ := fe6b0Upload(t, mux, "?target=mitm&operationId="+fe6b0OpID()+"&caRevision="+fe6b0Revision(t),
		map[string]string{"target": "mitm", "cert": string(certA), "key": string(keyA)}); code != http.StatusServiceUnavailable || m["code"] != refusalOperationUnsettled {
		t.Fatalf("a writer of the CA was admitted while X's evidence is unavailable: %d %v", code, m)
	}
	if n, _, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 0 {
		t.Fatal("audited without evidence")
	}
	// Access restored WITHOUT changing the bytes: the CA loads, the ledger
	// reconciles X from the evidence — committed, naming the candidate.
	caRuntime.passphrase = "sealed-under-this"
	if err := fe6b0dRestart(t); err != nil {
		t.Fatal(err)
	}
	rec = fe6b0cRecord(t, opX)
	if rec == nil || rec.State != "committed" {
		t.Fatalf("restored evidence did not reconcile X: %+v", rec)
	}
	if _, l := fe6b0cLookupState(t, mux, opX); l["committedRevision"] != caRevisionPrefix+digest {
		t.Fatalf("committed revision %v ≠ the candidate %s", l["committedRevision"], digest)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
}

func TestFE6B0D_D07b_UnreadableCAEvidenceIsNotAbsence(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	fe6b0cCommitWithFinishFailure(dir)
	opX := fe6b0OpID()
	fe6b0RotateOK(t, mux, opX)
	digest := certMgr.LiveCertificateHex()
	fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
	// The bundle's bytes are untouched; the path is temporarily not readable.
	restoreBundle := fe6b0cMakeDir(t, caRuntime.path)
	if err := fe6b0dRestart(t); err == nil {
		t.Fatal("precondition: the bundle must be unreadable")
	}
	rec := fe6b0cRecord(t, opX)
	if rec == nil || rec.State == certOpAborted || rec.State == "committed" {
		t.Fatalf("unreadable evidence was converted into a terminal verdict: %+v", rec)
	}
	if state, _ := fe6b0cLookupState(t, mux, opX); state == certOpAborted || state == "committed" {
		t.Fatalf("the lookup converted unreadable evidence into %s", state)
	}
	restoreBundle()
	if err := fe6b0dRestart(t); err != nil {
		t.Fatal(err)
	}
	rec = fe6b0cRecord(t, opX)
	if rec == nil || rec.State != "committed" || rec.CommittedRevision != caRevisionPrefix+digest {
		t.Fatalf("restored evidence did not reconcile X to the candidate: %+v", rec)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
}

func TestFE6B0D_D08_UnavailableUIEvidenceIsNotAbsence(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leaf, key); code != http.StatusOK {
		t.Fatalf("seed = %d %v", code, m)
	}
	rev := fe6b0cUIRevision(t, mux)
	opDel := fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opDel, Action: certActionUIDelete, Actor: "10.99.0.1", Target: "ui_cert", Fence: rev})
	opRep := fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opRep, Action: certActionUIReplace, Actor: "10.99.0.1", Target: "ui_cert", CandidateDigest: hexDigest(leaf), Fence: uiCertRevisionNone})
	// The certificate's bytes are untouched; the path is temporarily not readable.
	restoreCert := fe6b0cMakeDir(t, customUITLSCertPath())
	for _, op := range []string{opDel, opRep} {
		if state, l := fe6b0cLookupState(t, mux, op); state == "committed" || state == certOpAborted {
			t.Fatalf("unavailable UI evidence was converted into a terminal verdict for %s: %s %v", op, state, l)
		}
	}
	if n, _, _ := fe6b0cAuditEntries(since, "cert.ui.delete"); n != 0 {
		t.Fatal("a delete was credited from unavailable evidence")
	}
	restoreCert()
	// Restored: the pair is present and valid, so the delete never happened
	// and the replace of the SAME content is decided from the real evidence.
	if state, _ := fe6b0cLookupState(t, mux, opDel); state != certOpAborted {
		t.Fatalf("delete after restore = %s, want aborted (the pair is still there)", state)
	}
}

func TestFE6B0D_D09_RecoveredCAResultNamesTheEvidenceNotTheLiveManager(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	// The bundle on disk is candidate A (X persisted it and died before its
	// record); the live manager holds a DIFFERENT CA B.
	fpA := certMgr.LiveCertificateHex()
	infoA := certMgr.CACertInfo()
	opX := fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionImport, Actor: "10.99.0.1",
		Target: "root_ca", CandidateDigest: fpA, Fence: caRevisionNone, Previous: map[string]any{"fingerprint": "none", "revision": caRevisionNone}})
	swapInspectionCA(t)
	if err := certMgr.InitCA(); err != nil {
		t.Fatal(err)
	}
	fpB := certMgr.LiveCertificateHex()
	if fpB == fpA {
		t.Fatal("precondition")
	}
	state, l := fe6b0cLookupState(t, mux, opX)
	if state != "committed" {
		t.Fatalf("lookup = %s %v", state, l)
	}
	res, _ := l["result"].(map[string]any)
	caM, _ := res["ca"].(map[string]any)
	if caM["fingerprint"] != infoA["fingerprint"] || caM["revision"] != caRevisionPrefix+fpA {
		t.Fatalf("the recovered result names a CA other than the evidence that decided the commit: result %v, evidence A=%s, live B=%s", caM, fpA, fpB)
	}
	if l["committedRevision"] != caRevisionPrefix+fpA {
		t.Fatalf("committedRevision %v ≠ evidence", l["committedRevision"])
	}
}

// ── D10 controls ────────────────────────────────────────────────────────────

func TestFE6B0D_D10_Controls(t *testing.T) {
	t.Run("pre_replacement_failure_is_still_a_terminal_abort", func(t *testing.T) {
		_, _ = fe6b0cNode(t)
		mux := fe6b0Mux()
		leafC, keyC, _ := fe6b0CAPair(t, "ui-c", false)
		leafD, keyD, _ := fe6b0CAPair(t, "ui-d", false)
		if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leafC, keyC); code != http.StatusOK {
			t.Fatalf("seed = %d %v", code, m)
		}
		since := fe6aSince()
		revC := fe6b0cUIRevision(t, mux)
		onDisk, _ := os.ReadFile(customUITLSCertPath())
		// The KEY write fails BEFORE anything is replaced (nothing lands); the
		// compensating certificate rollback goes through the real write so the
		// control exercises the terminal pre-replacement refusal, not the
		// rollback-failed branch.
		fe6b0dKeyWrite(t, func(path string, data []byte, perm os.FileMode) error {
			if strings.HasPrefix(filepath.Base(path), customUITLSKeyFile) {
				return errors.New("injected: no space")
			}
			return fileutil.AtomicWrite(path, data, perm)
		})
		opX := fe6b0OpID()
		code, m := fe6b0cUIReplace(t, mux, opX, revC, leafD, keyD)
		if code != http.StatusInternalServerError || m["code"] != refusalPersistFailed {
			t.Fatalf("pre-replacement failure = %d %v, want terminal persist_failed", code, m)
		}
		if now, _ := os.ReadFile(customUITLSCertPath()); !bytes.Equal(now, onDisk) || !customUITLSPairValid() {
			t.Fatal("the previous pair was not preserved intact")
		}
		if state, _ := fe6b0cLookupState(t, mux, opX); state != certOpAborted {
			t.Fatalf("lookup = %s", state)
		}
		if n, _, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 0 {
			t.Fatal("audited a refused replace")
		}
	})

	t.Run("positively_absent_bundle_still_aborts", func(t *testing.T) {
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		_, _, fpA := fe6b0CAPair(t, "A", true)
		opX := fe6b0OpID()
		fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionImport, Actor: "10.99.0.1",
			Target: "root_ca", CandidateDigest: fpA, Fence: fe6b0Revision(t)})
		if err := os.Remove(caRuntime.path); err != nil {
			t.Fatal(err)
		}
		if state, _ := fe6b0cLookupState(t, mux, opX); state != certOpAborted {
			t.Fatalf("absent bundle + live ≠ candidate = %s, want aborted", state)
		}
	})
}
