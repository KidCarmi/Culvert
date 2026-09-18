package main

// fe6b0e_red_test.go — FE-6B.0 CORRECTION ROUND 4: deterministic RED matrix on
// the exact rejected candidate d00ffa6a (code head bc2da436) — three
// source-level attribution / persistence-ordering / evidence blockers.
//
//	B1  E01 a SAME-candidate repair beside invalid evidence never credits the unresolved intent
//	    E02 a DIFFERENT-candidate repair never aborts the intent from the repairer's content
//	    E03 the superseding decision is durable BEFORE the repair writes (else the repair is refused)
//	B2  E04 a replace keeps its marker until the completed pair is durably synchronised
//	    E05 a delete keeps its marker until the removal is durably synchronised
//	    E06 a barrier-1 fault on a replace keeps the marker; recovery completes idempotently
//	    E07 a barrier-2 fault on a replace, and a marker that reappears, are idempotent
//	    E08 a barrier-1 fault on a delete keeps the marker; recovery completes
//	B3  E09 an unreadable private key is UNAVAILABLE evidence (recoverable, blocking), never an invalid pair
//	    E10 controls: readable malformed / mismatched keys are invalid pairs (not blocking); recovery from
//	        every filesystem state permitted before each barrier; accepted round-3 rows untouched
//
// Every row fails on the product VERDICT or the PERSISTENCE ORDERING, never
// on the absence of a seam: ordering is observed through the existing
// fileutil "dir" synchronisation hook (which samples the on-disk state at the
// instant the directory is about to be synchronised), an unreadable key is a
// unix socket standing at the key path with the key's bytes moved aside
// (a read failure on a present, non-directory object — deterministic under
// any uid, unlike a mode bit for root), restarts re-open the ledger and
// re-run the boot resolution. No sleeps.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// fe6b0eUnreadable makes the file at path unreadable WITHOUT changing its
// bytes: the file is moved aside and a unix socket takes its place (stat
// succeeds, it is not a directory, a read fails). restore puts the bytes
// back exactly.
func fe6b0eUnreadable(t *testing.T, path string) (restore func()) {
	t.Helper()
	aside := path + ".bytes"
	if err := os.Rename(path, aside); err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	restored := false
	restore = func() {
		if restored {
			return
		}
		restored = true
		_ = ln.Close()
		_ = os.Remove(path)
		if err := os.Rename(aside, path); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)
	return restore
}

type fe6b0eDirSample struct {
	marker  bool // the transition marker exists
	pairNew bool // both live files carry the NEW pair
	absent  bool // neither live file exists
}

// fe6b0eObserveDirSyncs samples the on-disk state at every directory
// synchronisation of the data root (the fileutil "dir" hook runs BEFORE the
// fsync), failing the failNth one (0 = never). It returns the samples.
func fe6b0eObserveDirSyncs(t *testing.T, dir string, newCert, newKey []byte, failNth int) *[]fe6b0eDirSample {
	t.Helper()
	samples := &[]fe6b0eDirSample{}
	n := 0
	restore := fileutil.SetSyncHookForTest(func(kind, path string) error {
		if kind != "dir" || path != dir {
			return nil
		}
		n++
		_, merr := os.Stat(customUITLSTransitionPath())
		c, cerr := os.ReadFile(customUITLSCertPath())
		k, kerr := os.ReadFile(customUITLSKeyPath())
		*samples = append(*samples, fe6b0eDirSample{
			marker:  merr == nil,
			pairNew: cerr == nil && kerr == nil && bytes.Equal(c, newCert) && bytes.Equal(k, newKey),
			absent:  errors.Is(cerr, os.ErrNotExist) && errors.Is(kerr, os.ErrNotExist),
		})
		if n == failNth {
			return errors.New("injected directory synchronisation fault")
		}
		return nil
	})
	t.Cleanup(restore)
	return samples
}

func fe6b0eMarkerPresent() bool {
	_, err := os.Stat(customUITLSTransitionPath())
	return err == nil
}

func fe6b0eLive(t *testing.T) (cert, key []byte) {
	t.Helper()
	cert, _ = os.ReadFile(customUITLSCertPath())
	key, _ = os.ReadFile(customUITLSKeyPath())
	return cert, key
}

func fe6b0eSeedPair(t *testing.T, mux *http.ServeMux, name string) (cert, key []byte, rev string) {
	t.Helper()
	cert, key, _ = fe6b0CAPair(t, name, false)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), fe6b0cUIRevision(t, mux), cert, key); code != http.StatusOK {
		t.Fatalf("seed %s = %d %v", name, code, m)
	}
	return cert, key, fe6b0cUIRevision(t, mux)
}

func fe6b0eImport(t *testing.T, mux *http.ServeMux, opID string, cert, key []byte) (code int, m map[string]any) {
	t.Helper()
	code, m, _ = fe6b0Upload(t, mux, "?target=mitm&operationId="+opID+"&caRevision="+fe6b0Revision(t),
		map[string]string{"target": "mitm", "cert": string(cert), "key": string(key)})
	return code, m
}

// fe6b0eInvalidBundleWithPendingImport injects a pending import of A while the
// bundle on disk is not a bundle, and settles it once (evidence_invalid).
func fe6b0eInvalidBundleWithPendingImport(t *testing.T, dir string, mux *http.ServeMux) (opX, fpA string, certA, keyA []byte) {
	t.Helper()
	certA, keyA, fpA = fe6b0CAPair(t, "A", true)
	opX = fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionImport, Actor: "10.99.0.1",
		Target: "root_ca", CandidateDigest: fpA, Fence: fe6b0Revision(t), Previous: map[string]any{"fingerprint": "none", "revision": caRevisionNone}})
	if err := os.WriteFile(caRuntime.path, []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state, l := fe6b0cLookupState(t, mux, opX); state != certOpOutcomeUnknown || l["code"] != "lookup_"+certCodeEvidenceInvalid {
		t.Fatalf("precondition: invalid bundle = %s %v", state, l)
	}
	return opX, fpA, certA, keyA
}

func fe6b0eAssertSuperseded(t *testing.T, mux *http.ServeMux, opX, by, what string) {
	t.Helper()
	state, l := fe6b0cLookupState(t, mux, opX)
	if state == certOpCommitted {
		t.Fatalf("%s: the unresolved intent was CREDITED with the repairing writer's content: %v", what, l)
	}
	if state == certOpAborted {
		t.Fatalf("%s: the unresolved intent was ABORTED from the repairing writer's content: %v", what, l)
	}
	if state != certOpOutcomeUnknown || l["code"] != "writer_evidence_superseded" || l["supersededBy"] != by {
		t.Fatalf("%s: want outcome_unknown writer_evidence_superseded by %s, got %s %v", what, by, state, l)
	}
}

// ── B1 ──────────────────────────────────────────────────────────────────────

func TestFE6B0E_E01_SameCandidateRepairNeverCreditsTheUnresolvedIntent(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	opX, fpA, certA, keyA := fe6b0eInvalidBundleWithPendingImport(t, dir, mux)
	// The repairing import Y installs the SAME candidate A.
	opY := fe6b0OpID()
	if code, m := fe6b0eImport(t, mux, opY, certA, keyA); code != http.StatusOK {
		t.Fatalf("repair = %d %v", code, m)
	}
	if certMgr.LiveCertificateHex() != fpA {
		t.Fatal("precondition: Y installed A")
	}
	fe6b0eAssertSuperseded(t, mux, opX, opY, "lookup after the repair")
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.import"); n != 1 || ids[0] != opY {
		t.Fatalf("import audits = %d %v, want exactly Y", n, ids)
	}
	// Repeated settlement and a restart change nothing.
	fe6b0eAssertSuperseded(t, mux, opX, opY, "second lookup")
	if err := fe6b0dRestart(t); err != nil {
		t.Fatal(err)
	}
	fe6b0eAssertSuperseded(t, mux, opX, opY, "lookup after restart")
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.import"); n != 1 || ids[0] != opY {
		t.Fatalf("import audits after restart = %d %v", n, ids)
	}
}

func TestFE6B0E_E02_DifferentCandidateRepairNeverAbortsFromTheRepairersContent(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	opX, _, _, _ := fe6b0eInvalidBundleWithPendingImport(t, dir, mux)
	certB, keyB, fpB := fe6b0CAPair(t, "B", true)
	opY := fe6b0OpID()
	if code, m := fe6b0eImport(t, mux, opY, certB, keyB); code != http.StatusOK {
		t.Fatalf("repair = %d %v", code, m)
	}
	if certMgr.LiveCertificateHex() != fpB {
		t.Fatal("precondition: Y installed B")
	}
	fe6b0eAssertSuperseded(t, mux, opX, opY, "lookup after a different-candidate repair")
	if err := fe6b0dRestart(t); err != nil {
		t.Fatal(err)
	}
	fe6b0eAssertSuperseded(t, mux, opX, opY, "lookup after restart")
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.import"); n != 1 || ids[0] != opY {
		t.Fatalf("import audits = %d %v", n, ids)
	}
}

func TestFE6B0E_E03_SupersedingDecisionIsDurableBeforeTheRepairWrites(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	opX, _, certA, keyA := fe6b0eInvalidBundleWithPendingImport(t, dir, mux)
	invalid, _ := os.ReadFile(caRuntime.path)
	// The ledger becomes unwritable: the decision that X's evidence is about
	// to be replaced cannot be made durable, so the repair must be refused
	// with nothing written.
	ledger := filepath.Join(dir, fe6b0LedgerFile)
	fe6b0cBreakLedger(ledger)
	opY := fe6b0OpID()
	code, m := fe6b0eImport(t, mux, opY, certA, keyA)
	if code != http.StatusServiceUnavailable || m["code"] != refusalOperationUnsettled {
		t.Fatalf("a repair whose superseding decision cannot be recorded must be refused operation_unsettled, got %d %v", code, m)
	}
	if now, _ := os.ReadFile(caRuntime.path); !bytes.Equal(now, invalid) {
		t.Fatal("the repair wrote although X's decision was not durable")
	}
	fe6b0cRestoreLedger(t, ledger)
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State == certOpCommitted || rec.State == certOpAborted {
		t.Fatalf("X after the refused repair = %+v", rec)
	}
	// Ledger writable again: the repair is admitted and X is superseded by it.
	opY2 := fe6b0OpID()
	if code, m := fe6b0eImport(t, mux, opY2, certA, keyA); code != http.StatusOK {
		t.Fatalf("repair after recovery = %d %v", code, m)
	}
	fe6b0eAssertSuperseded(t, mux, opX, opY2, "lookup after the admitted repair")
}

// ── B2 ──────────────────────────────────────────────────────────────────────

func TestFE6B0E_E04_ReplaceRetainsTheMarkerUntilThePairIsDurable(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	_, _, rev := fe6b0eSeedPair(t, mux, "ui-p")
	newCert, newKey, _ := fe6b0CAPair(t, "ui-q", false)
	samples := fe6b0eObserveDirSyncs(t, dir, newCert, newKey, 0)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), rev, newCert, newKey); code != http.StatusOK {
		t.Fatalf("replace = %d %v", code, m)
	}
	s := *samples
	if len(s) < 2 {
		t.Fatalf("the completed pair and the marker removal must be synchronised SEPARATELY (two directory syncs), observed %d: %+v", len(s), s)
	}
	if !s[0].pairNew || !s[0].marker {
		t.Fatalf("the first directory synchronisation after the pair became live must find the marker STILL PRESENT beside the complete new pair (no durability barrier between completing the pair and deleting its recovery evidence), observed %+v", s[0])
	}
	if last := s[len(s)-1]; last.marker || !last.pairNew {
		t.Fatalf("the last synchronisation must cover the marker's removal with the pair intact, observed %+v", last)
	}
	if fe6b0eMarkerPresent() {
		t.Fatal("marker left behind")
	}
}

func TestFE6B0E_E05_DeleteRetainsTheMarkerUntilTheRemovalIsDurable(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	_, _, rev := fe6b0eSeedPair(t, mux, "ui-p")
	samples := fe6b0eObserveDirSyncs(t, dir, nil, nil, 0)
	if code, m := fe6b0cUIDelete(mux, fe6b0OpID(), rev); code != http.StatusOK {
		t.Fatalf("delete = %d %v", code, m)
	}
	s := *samples
	if len(s) < 2 {
		t.Fatalf("the removal and the marker removal must be synchronised separately, observed %d: %+v", len(s), s)
	}
	if !s[0].absent || !s[0].marker {
		t.Fatalf("the first synchronisation after the removal must find the marker STILL PRESENT with both files gone, observed %+v", s[0])
	}
	if last := s[len(s)-1]; last.marker || !last.absent {
		t.Fatalf("the last synchronisation must cover the marker's removal, observed %+v", last)
	}
}

func TestFE6B0E_E06_ReplaceBarrierOneFaultKeepsTheMarkerAndRecovers(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	_, _, rev := fe6b0eSeedPair(t, mux, "ui-p")
	newCert, newKey, _ := fe6b0CAPair(t, "ui-q", false)
	fe6b0eObserveDirSyncs(t, dir, newCert, newKey, 1) // the pair's own durability barrier fails once
	opX := fe6b0OpID()
	code, m := fe6b0cUIReplace(t, mux, opX, rev, newCert, newKey)
	fe6b0dAssertDurabilityUnproven(t, code, m, opX)
	c, k := fe6b0eLive(t)
	if !bytes.Equal(c, newCert) || !bytes.Equal(k, newKey) || !customUITLSPairValid() {
		t.Fatal("the new pair must be live and valid after a barrier-1 fault")
	}
	if !fe6b0eMarkerPresent() {
		t.Fatal("the marker was removed although the completed pair's synchronisation FAILED: a crash now could lose the pair while the marker's removal survives, and recovery would then abandon the transition")
	}
	if n, _, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 1 { // the seed only
		t.Fatalf("audits = %d", n)
	}
	// The next settlement completes the transition from the retained marker
	// (fault gone): durable, credited once, marker consumed.
	if state, l := fe6b0cLookupState(t, mux, opX); state != certOpCommitted {
		t.Fatalf("lookup = %s %v", state, l)
	}
	if fe6b0eMarkerPresent() {
		t.Fatal("marker not consumed after the settlement synchronised the pair")
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 2 || ids[1] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
	c, k = fe6b0eLive(t)
	if !bytes.Equal(c, newCert) || !bytes.Equal(k, newKey) {
		t.Fatal("the settlement changed the pair")
	}
}

func TestFE6B0E_E07_ReplaceBarrierTwoFaultAndReappearingMarkerAreIdempotent(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	_, _, rev := fe6b0eSeedPair(t, mux, "ui-p")
	newCert, newKey, _ := fe6b0CAPair(t, "ui-q", false)
	fe6b0eObserveDirSyncs(t, dir, newCert, newKey, 2) // the marker removal's barrier fails
	opX := fe6b0OpID()
	code, m := fe6b0cUIReplace(t, mux, opX, rev, newCert, newKey)
	fe6b0dAssertDurabilityUnproven(t, code, m, opX)
	c, k := fe6b0eLive(t)
	if !bytes.Equal(c, newCert) || !bytes.Equal(k, newKey) || !customUITLSPairValid() {
		t.Fatal("the new pair must be live and valid after a barrier-2 fault")
	}
	// A crash before the marker removal reached the disk: the marker
	// REAPPEARS beside the already-complete pair. Recovery must be idempotent.
	if err := writeUITLSTransition(uiTLSTransition{Kind: uiTLSTransitionReplace, OperationID: opX, CertDigest: hexDigest(newCert)}); err != nil {
		t.Fatal(err)
	}
	rec := recoverUITLSTransition()
	if rec.Err != nil || !rec.Completed || rec.Kind != uiTLSTransitionReplace {
		t.Fatalf("recovery with a reappeared marker = %+v", rec)
	}
	if fe6b0eMarkerPresent() {
		t.Fatal("marker not consumed")
	}
	c, k = fe6b0eLive(t)
	if !bytes.Equal(c, newCert) || !bytes.Equal(k, newKey) {
		t.Fatal("recovery changed the completed pair")
	}
	if state, l := fe6b0cLookupState(t, mux, opX); state != certOpCommitted {
		t.Fatalf("lookup = %s %v", state, l)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 2 || ids[1] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
}

func TestFE6B0E_E08_DeleteBarrierOneFaultKeepsTheMarkerAndRecovers(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	_, _, rev := fe6b0eSeedPair(t, mux, "ui-p")
	fe6b0eObserveDirSyncs(t, dir, nil, nil, 1)
	opX := fe6b0OpID()
	code, m := fe6b0cUIDelete(mux, opX, rev)
	fe6b0dAssertDurabilityUnproven(t, code, m, opX)
	if customUITLSFilesPresent() {
		t.Fatal("the pair must be removed")
	}
	if !fe6b0eMarkerPresent() {
		t.Fatal("the marker was removed although the removal's synchronisation FAILED")
	}
	state, l := fe6b0cLookupState(t, mux, opX)
	res, _ := l["result"].(map[string]any)
	if state != certOpCommitted || res["deleted"] != true || res["cleanup"] != certCleanupComplete {
		t.Fatalf("lookup = %s %v (the delete itself removed both files; the settlement only proved it)", state, l)
	}
	if fe6b0eMarkerPresent() {
		t.Fatal("marker not consumed")
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.delete"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
}

// ── B3 ──────────────────────────────────────────────────────────────────────

func TestFE6B0E_E09_UnreadableKeyIsUnavailableEvidenceNotAnInvalidPair(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	_, _, rev := fe6b0eSeedPair(t, mux, "ui-p")
	since := fe6aSince()
	newCert, newKey, _ := fe6b0CAPair(t, "ui-q", false)
	// The replacement COMPLETES but its terminal record is never persisted.
	fe6b0cCommitWithFinishFailure(dir)
	opX := fe6b0OpID()
	if code, m := fe6b0cUIReplace(t, mux, opX, rev, newCert, newKey); code != http.StatusOK || m["recordState"] != "pending_reconciliation" {
		t.Fatalf("replace = %d %v", code, m)
	}
	fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != certOpPending {
		t.Fatalf("precondition: X pending, got %+v", rec)
	}
	// Only the KEY becomes unreadable; its bytes are untouched.
	restoreKey := fe6b0eUnreadable(t, customUITLSKeyPath())
	if ev := uiPairEvidenceNow(); ev.class != uiPairUnavailable {
		t.Fatalf("a present but unreadable key was classified %q (valid=%v) — a read failure collapsed into an invalid pair", ev.class, ev.valid)
	}
	state, l := fe6b0cLookupState(t, mux, opX)
	if state != certOpOutcomeUnknown || l["code"] != "lookup_"+certCodeEvidenceUnavailable {
		t.Fatalf("lookup with an unreadable key = %s %v, want the recoverable outcome_unknown lookup_evidence_unavailable", state, l)
	}
	// A writer must be held while the evidence cannot be read.
	other, otherKey, _ := fe6b0CAPair(t, "ui-r", false)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), fe6b0cUIRevision(t, mux), other, otherKey); code == http.StatusOK {
		t.Fatalf("a writer replaced the pair while X's key evidence was unreadable: %d %v", code, m)
	}
	// Restart with the key still unreadable: nothing is decided, nothing loaded.
	fe6b0dRestartUI(t)
	if uiCustomTLSActive || uiCustomTLSCorrupt {
		t.Fatalf("boot resolved an unreadable pair (active=%v corrupt=%v)", uiCustomTLSActive, uiCustomTLSCorrupt)
	}
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State == certOpCommitted || rec.State == certOpAborted {
		t.Fatalf("restart converted unreadable evidence into a terminal verdict: %+v", rec)
	}
	if n, _, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 0 {
		t.Fatal("audited without readable evidence")
	}
	// Access restored, bytes unchanged: the commit is established exactly once.
	restoreKey()
	if state, l := fe6b0cLookupState(t, mux, opX); state != certOpCommitted || l["committedRevision"] != "uic1:"+hexDigest(newCert) {
		t.Fatalf("lookup after access restored = %s %v", state, l)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 1 || ids[0] != opX {
		t.Fatalf("audits = %d %v", n, ids)
	}
	fe6b0dRestartUI(t)
	if !uiCustomTLSActive {
		t.Fatal("the restart did not activate the pair")
	}
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != certOpCommitted {
		t.Fatalf("after restart = %+v", rec)
	}
}

// ── E10 controls ────────────────────────────────────────────────────────────

// E10a — control.
func TestFE6B0E_E10a_ReadableMalformedKeyIsAnInvalidPairNotUnavailable(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	cert, _, _ := fe6b0eSeedPair(t, mux, "ui-p")
	if err := os.WriteFile(customUITLSKeyPath(), []byte("-----BEGIN EC PRIVATE KEY-----\nnot a key\n-----END EC PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ev := uiPairEvidenceNow()
	if ev.class != uiPairComplete || ev.valid || ev.certDigest != hexDigest(cert) {
		t.Fatalf("malformed readable key = %+v, want complete/invalid", ev)
	}
	// A pending replace whose fence is not the current token is unproven —
	// decidable by no evidence — and does NOT hold a writer.
	opX := fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionUIReplace, Actor: "10.99.0.1",
		Target: "ui_cert", CandidateDigest: hexDigest([]byte("other")), Fence: uiCertRevisionNone, Candidate: map[string]any{"fingerprint": "n/a"}})
	if state, l := fe6b0cLookupState(t, mux, opX); state != certOpOutcomeUnknown || l["code"] != "lookup_"+certCodeUnproven {
		t.Fatalf("lookup = %s %v", state, l)
	}
	other, otherKey, _ := fe6b0CAPair(t, "ui-r", false)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), fe6b0cUIRevision(t, mux), other, otherKey); code != http.StatusOK {
		t.Fatalf("a writer must be admitted beside a readable invalid pair: %d %v", code, m)
	}
}

// E10b — control.
func TestFE6B0E_E10b_ReadableMismatchedKeyIsAnInvalidPairNotUnavailable(t *testing.T) {
	_, _ = fe6b0cNode(t)
	mux := fe6b0Mux()
	cert, _, _ := fe6b0eSeedPair(t, mux, "ui-p")
	_, otherKey, _ := fe6b0CAPair(t, "ui-r", false)
	if err := os.WriteFile(customUITLSKeyPath(), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	ev := uiPairEvidenceNow()
	if ev.class != uiPairComplete || ev.valid || ev.certDigest != hexDigest(cert) {
		t.Fatalf("mismatched readable key = %+v, want complete/invalid", ev)
	}
	if tok := uiCertRevisionToken(); tok != "uic1:"+hexDigest(cert) {
		t.Fatalf("token = %s", tok)
	}
}

// E10c — control.
func TestFE6B0E_E10c_RecoveryFromEveryStateBeforeEachBarrier(t *testing.T) {
	_, _ = fe6b0cNode(t)
	mux := fe6b0Mux()
	cert1, key1, _ := fe6b0eSeedPair(t, mux, "ui-p")
	cert2, key2, _ := fe6b0CAPair(t, "ui-q", false)
	marker := uiTLSTransition{Kind: uiTLSTransitionReplace, OperationID: fe6b0OpID(), CertDigest: hexDigest(cert2)}
	// (a) key renamed, certificate still staged, marker present.
	if err := os.WriteFile(customUITLSCertStagePath(), cert2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customUITLSKeyPath(), key2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeUITLSTransition(marker); err != nil {
		t.Fatal(err)
	}
	if rec := recoverUITLSTransition(); rec.Err != nil || !rec.Completed {
		t.Fatalf("(a) = %+v", rec)
	}
	if c, k := fe6b0eLive(t); !bytes.Equal(c, cert2) || !bytes.Equal(k, key2) || !customUITLSPairValid() || fe6b0eMarkerPresent() {
		t.Fatal("(a) not completed")
	}
	// (b) both renames done, marker present (a crash after barrier 1).
	if err := writeUITLSTransition(marker); err != nil {
		t.Fatal(err)
	}
	if rec := recoverUITLSTransition(); rec.Err != nil || !rec.Completed {
		t.Fatalf("(b) = %+v", rec)
	}
	if c, k := fe6b0eLive(t); !bytes.Equal(c, cert2) || !bytes.Equal(k, key2) || fe6b0eMarkerPresent() {
		t.Fatal("(b) not idempotent")
	}
	// (c) delete: key removed, certificate present, marker present.
	if err := writeUITLSTransition(uiTLSTransition{Kind: uiTLSTransitionDelete, OperationID: fe6b0OpID()}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(customUITLSKeyPath()); err != nil {
		t.Fatal(err)
	}
	if rec := recoverUITLSTransition(); rec.Err != nil || !rec.Completed || rec.Kind != uiTLSTransitionDelete {
		t.Fatalf("(c) = %+v", rec)
	}
	if ev := uiPairEvidenceNow(); ev.class != uiPairAbsent || fe6b0eMarkerPresent() {
		t.Fatalf("(c) = %+v marker=%v", ev, fe6b0eMarkerPresent())
	}
	// (d) delete: both removed, marker present (a crash after barrier 1).
	if err := writeUITLSTransition(uiTLSTransition{Kind: uiTLSTransitionDelete, OperationID: fe6b0OpID()}); err != nil {
		t.Fatal(err)
	}
	if rec := recoverUITLSTransition(); rec.Err != nil || !rec.Completed || fe6b0eMarkerPresent() {
		t.Fatalf("(d) = %+v", rec)
	}
	_ = cert1
	_ = key1
}
