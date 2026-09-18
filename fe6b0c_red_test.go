package main

// fe6b0c_red_test.go — FE-6B.0 CORRECTION ROUND: deterministic RED matrix on
// the exact rejected candidate 3206ca47 (FRONTEND-MIGRATION-PLAN.md FE-6B.0,
// external freeze review REJECTED — four source-level lifecycle blockers).
//
// Every row is channel- or fault-controlled (a ledger path replaced by a
// directory, a bundle/settings/key path replaced by a directory, the
// durable-write success observer, the durable-commit/terminal-record seam,
// crash-simulated pending intents written straight into the ledger file);
// nothing sleeps.
//
//	Blocker 1  R01 CA commit + terminal-record failure + competitor ⇒ X stays committed exactly once
//	           R02 CA intent that never wrote + competitor installs the SAME candidate ⇒ X never credited
//	           R03 UI cert: replace/delete equivalents of R01/R02 (identical content, absence)
//	           R04 OCSP: commit + finalization failure + posture change; never-wrote + same target
//	Blocker 2  R05 automatic rotation parked against an unresolved CA operation
//	           R06 the startup rotation round waits for operation reconciliation (+ R06b source pin)
//	Blocker 3  R07 a refusal whose aborted record is not durable is NON-terminal (rotate/UI replace/UI delete/OCSP)
//	           R08 after ledger recovery the refusal becomes durable; a repeat replays it without redispatch
//	Blocker 4  R09 a reconciled commit replays the complete action-bound result + one bounded audit
//	Controls   R10 unrelated targets unblocked; completed operations never re-executed; valid auto-rotation works
//
// Rows 1–9 FAIL on 3206ca47; row 10 passes (a control that failed on the
// baseline would be measuring the defect, not the correction).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// ── seams ───────────────────────────────────────────────────────────────────
// caRotationBootGateObserver, certLifecycleBootGateArmForTest and
// certLifecycleBootGateReleaseForTest were declared here on the baseline
// (nil, never called) and now live in certificate_operations.go beside the
// boot gate they instrument.

// ── fixtures ────────────────────────────────────────────────────────────────

// fe6b0cLedgerBreaker arms a one-shot fault: the first SUCCESSFUL durable
// write to the ledger path (an intent record) turns the ledger path into a
// directory, so every LATER ledger write in the same operation fails.
type fe6b0cLedgerBreaker struct {
	ledger string
	armed  atomic.Bool
	fired  atomic.Bool
}

func fe6b0cNode(t *testing.T) (dir string, br *fe6b0cLedgerBreaker) {
	t.Helper()
	dir = fe6b0Node(t)
	br = &fe6b0cLedgerBreaker{ledger: filepath.Join(dir, fe6b0LedgerFile)}
	fileutil.SetWriteSuccessObserver(func(path string) {
		noteStorageWriteSuccess(path)
		if path == br.ledger && br.armed.CompareAndSwap(true, false) {
			fe6b0cBreakLedger(br.ledger)
			br.fired.Store(true)
		}
	})
	t.Cleanup(func() { fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess) })
	return dir, br
}

func fe6b0cBreakLedger(ledger string) {
	_ = os.Rename(ledger, ledger+".aside")
	_ = os.Mkdir(ledger, 0o700)
}

func fe6b0cRestoreLedger(t *testing.T, ledger string) {
	t.Helper()
	if err := os.Remove(ledger); err != nil && !os.IsNotExist(err) {
		t.Fatalf("restore ledger: %v", err)
	}
	if err := os.Rename(ledger+".aside", ledger); err != nil && !os.IsNotExist(err) {
		t.Fatalf("restore ledger: %v", err)
	}
}

// fe6b0cMakeDir replaces a regular file (or an absent path) with a NON-EMPTY
// directory so an atomic write (rename onto it) and a removal both fail.
func fe6b0cMakeDir(t *testing.T, path string) (restore func()) {
	t.Helper()
	aside := path + ".aside"
	had := false
	if err := os.Rename(path, aside); err == nil {
		had = true
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return func() {
		_ = os.RemoveAll(path)
		if had {
			if err := os.Rename(aside, path); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// fe6b0cInjectPending writes a crash-simulated PENDING intent straight into
// the durable ledger (the intent was durable before the write; the process
// died before it wrote) and re-opens the ledger from its file.
func fe6b0cInjectPending(t *testing.T, dir string, op certOperation) {
	t.Helper()
	ledger := filepath.Join(dir, fe6b0LedgerFile)
	var ops []*certOperation
	if data, err := os.ReadFile(ledger); err == nil {
		if err := json.Unmarshal(data, &ops); err != nil {
			t.Fatal(err)
		}
	}
	op.State = certOpPending
	if op.StartedAt == "" {
		op.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	ops = append(ops, &op)
	data, _ := json.MarshalIndent(ops, "", "  ")
	if err := os.WriteFile(ledger, data, 0o600); err != nil {
		t.Fatal(err)
	}
	reopenCertificateOperationsForTest()
}

// fe6b0cRecord reads the ledger record directly (no lookup settlement).
func fe6b0cRecord(t *testing.T, opID string) *certOperation {
	t.Helper()
	rec, err := certOpsStore().Get(opID)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	return rec
}

func fe6b0cAuditEntries(since int64, action string) (n int, opIDs, details []string) {
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.TS < since || e.Action != action {
			continue
		}
		n++
		opIDs = append(opIDs, e.OperationID)
		details = append(details, e.Detail)
	}
	return n, opIDs, details
}

func fe6b0cOCSPRevision(mux *http.ServeMux) string {
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, viewerCtx(getReq("/api/ocsp")))
	rev, _ := fe6b0Decode(w)["revision"].(string)
	return rev
}

func fe6b0cOCSPSet(mux *http.ServeMux, opID, rev string, enabled bool) (status int, m map[string]any) {
	status, m, _ = fe6b0Do(mux, http.MethodPost, "/api/ocsp?operationId="+opID+"&ocspRevision="+rev, map[string]any{"enabled": enabled})
	return status, m
}

func fe6b0cUIReplace(t *testing.T, mux *http.ServeMux, opID, rev string, certPEM, keyPEM []byte) (status int, m map[string]any) {
	t.Helper()
	status, m, _ = fe6b0Upload(t, mux, "?target=ui&operationId="+opID+"&uiCertRevision="+rev,
		map[string]string{"target": "ui", "cert": string(certPEM), "key": string(keyPEM)})
	return status, m
}

func fe6b0cUIDelete(mux *http.ServeMux, opID, rev string) (status int, m map[string]any) {
	status, m, _ = fe6b0Do(mux, http.MethodDelete, "/api/certs/ui?operationId="+opID+"&uiCertRevision="+rev, nil)
	return status, m
}

func fe6b0cUIRevision(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, viewerCtx(getReq("/api/certificates")))
	m := fe6b0Decode(w)
	uc, _ := m["uiCert"].(map[string]any)
	rev, _ := uc["revision"].(string)
	if rev == "" {
		t.Fatalf("no UI cert revision in %v", m)
	}
	return rev
}

// fe6b0cCommitWithFinishFailure makes the NEXT durable-commit's terminal
// record fail (the ledger path becomes a directory between the commit and
// its record) and returns the ledger path for the later restore.
func fe6b0cCommitWithFinishFailure(dir string) {
	ledger := filepath.Join(dir, fe6b0LedgerFile)
	caOpsBeforeFinishHook = func() {
		fe6b0cBreakLedger(ledger)
		caOpsBeforeFinishHook = nil
	}
}

// fe6b0cNearExpiry forces the live inspection CA into the auto-rotation
// window without changing its identity (the DER is untouched).
func fe6b0cNearExpiry() {
	certMgr.CACertForTest().NotAfter = time.Now().Add(24 * time.Hour)
}

// fe6b0cRotationRound starts the auto-rotation loop (one immediate round),
// waits for the round to complete and stops the loop. gateReleased says
// whether the boot gate must be released first (post-correction the first
// round waits for it).
func fe6b0cRotationRound(t *testing.T, gateReleased bool) {
	t.Helper()
	if gateReleased && certLifecycleBootGateReleaseForTest != nil {
		certLifecycleBootGateReleaseForTest()
	}
	wait := awaitFirstRotationRound(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := StartCAAutoRotation(ctx, caRuntime.path, caRuntime.passphrase)
	wait()
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the rotation loop did not exit")
	}
}

func fe6b0cLookupState(t *testing.T, mux *http.ServeMux, opID string) (state string, m map[string]any) {
	t.Helper()
	code, l := fe6b0Lookup(mux, opID)
	if code != http.StatusOK {
		t.Fatalf("lookup %s = %d %v", opID, code, l)
	}
	state, _ = l["state"].(string)
	return state, l
}

// ── R01 CA: a committed operation survives a competitor ─────────────────────

func TestFE6B0C_R01_CACommitSurvivesCompetitorAfterFinalizationFailure(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	// X rotates; the bundle lands and the CA is live; the terminal record fails.
	fe6b0cCommitWithFinishFailure(dir)
	opX := fe6b0OpID()
	revX, mX := fe6b0RotateOK(t, mux, opX)
	if mX["recordState"] != "pending_reconciliation" {
		t.Fatalf("X's terminal record must have failed: %v", mX)
	}
	fpA := fe6b0Fingerprint()
	// Storage recovers. Y installs CA B BEFORE anyone looks X up.
	fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
	certB, keyB, fpBHex := fe6b0CAPair(t, "B", true)
	opY := fe6b0OpID()
	code, mY, w := fe6b0Upload(t, mux, "?target=mitm&operationId="+opY+"&caRevision="+revX,
		map[string]string{"target": "mitm", "cert": string(certB), "key": string(keyB)})
	if code != http.StatusOK || mY["imported"] != true {
		t.Fatalf("Y import = %d %s", code, w.Body.String())
	}
	if got := certMgr.LiveCertificateHex(); got != fpBHex {
		t.Fatalf("Y is not authoritative: live %s ≠ B %s", got, fpBHex)
	}
	// X's historical commit is a fact the competitor cannot erase.
	state, l := fe6b0cLookupState(t, mux, opX)
	if state != "committed" {
		t.Fatalf("X committed CA A and was then superseded by Y; its record reads %q (%v) — current content is not historical provenance", state, l)
	}
	if got := certMgr.LiveCertificateHex(); got != fpBHex {
		t.Fatalf("settling X changed the live CA: %s", got)
	}
	_ = fpA
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 1 || ids[0] != opX {
		t.Fatalf("ca.rotate audits = %d %v, want exactly one keyed on X", n, ids)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.import"); n != 1 || ids[0] != opY {
		t.Fatalf("ca.import audits = %d %v, want exactly one keyed on Y", n, ids)
	}
	// Idempotent: a second lookup settles nothing twice.
	if s2, _ := fe6b0cLookupState(t, mux, opX); s2 != "committed" {
		t.Fatalf("second lookup = %s", s2)
	}
	if n, _, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 1 {
		t.Fatalf("a second lookup re-audited X: %d", n)
	}
}

// ── R02 CA: a never-written intent is not credited with a competitor's commit

func TestFE6B0C_R02_PendingCAIntentIsNeverCreditedWithACompetitorsCommit(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	rev0 := fe6b0Revision(t)
	certA, keyA, fpAHex := fe6b0CAPair(t, "A", true)
	// X recorded its intent to import A and died before writing anything.
	opX := fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionImport, Actor: "10.99.0.1",
		Target: "root_ca", CandidateDigest: fpAHex, Fence: rev0})
	// Y imports the SAME candidate.
	opY := fe6b0OpID()
	code, mY, w := fe6b0Upload(t, mux, "?target=mitm&operationId="+opY+"&caRevision="+rev0,
		map[string]string{"target": "mitm", "cert": string(certA), "key": string(keyA)})
	if code != http.StatusOK || mY["imported"] != true {
		t.Fatalf("Y import = %d %s", code, w.Body.String())
	}
	state, l := fe6b0cLookupState(t, mux, opX)
	if state == "committed" {
		t.Fatalf("X never wrote; Y installed the identical candidate; X is credited with Y's commit: %v", l)
	}
	if state != "aborted" {
		t.Fatalf("X must be a durable abort, got %q (%v)", state, l)
	}
	if n, ids, _ := fe6b0cAuditEntries(since, "ca.import"); n != 1 || ids[0] != opY {
		t.Fatalf("ca.import audits = %d %v, want exactly one keyed on Y (none on X)", n, ids)
	}
	if got := certMgr.LiveCertificateHex(); got != fpAHex {
		t.Fatalf("settling X changed the live CA: %s", got)
	}
}

// ── R03 UI certificate: replace and delete/absence equivalents ──────────────

// fe6b0cUIPairs mints the two UI leaf pairs the R03 rows share.
func fe6b0cUIPairs(t *testing.T) (leafC, keyC, leafD, keyD []byte, digestC string) {
	t.Helper()
	leafC, keyC, _ = fe6b0CAPair(t, "ui-c", false)
	leafD, keyD, _ = fe6b0CAPair(t, "ui-d", false)
	return leafC, keyC, leafD, keyD, hexDigest(leafC)
}

func TestFE6B0C_R03a_UIReplaceCommitSurvivesCompetitor(t *testing.T) {
	leafC, keyC, leafD, keyD, digestC := fe6b0cUIPairs(t)
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		since := fe6aSince()
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		if code, m := fe6b0cUIReplace(t, mux, opX, uiCertRevisionNone, leafC, keyC); code != http.StatusOK || m["recordState"] != "pending_reconciliation" {
			t.Fatalf("X replace = %d %v", code, m)
		}
		fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
		opY := fe6b0OpID()
		if code, m := fe6b0cUIReplace(t, mux, opY, "uic1:"+digestC, leafD, keyD); code != http.StatusOK || m["replaced"] != true {
			t.Fatalf("Y replace = %d %v", code, m)
		}
		if state, l := fe6b0cLookupState(t, mux, opX); state != "committed" {
			t.Fatalf("X replaced the UI pair with C and Y then replaced it with D; X reads %q (%v)", state, l)
		}
		if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 2 || ids[0] == ids[1] {
			t.Fatalf("cert.ui.replace audits = %d %v, want one for X and one for Y", n, ids)
		}
		if got := fe6b0cUIRevision(t, mux); got != "uic1:"+hexDigest(leafD) {
			t.Fatalf("Y is not authoritative: %s", got)
		}
	}
}

func TestFE6B0C_R03b_UIReplaceNeverWrittenSameCandidate(t *testing.T) {
	leafC, keyC, _, _, digestC := fe6b0cUIPairs(t)
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		since := fe6aSince()
		opX := fe6b0OpID()
		fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionUIReplace, Actor: "10.99.0.1",
			Target: "ui_cert", CandidateDigest: digestC, Fence: uiCertRevisionNone})
		opY := fe6b0OpID()
		if code, m := fe6b0cUIReplace(t, mux, opY, uiCertRevisionNone, leafC, keyC); code != http.StatusOK || m["replaced"] != true {
			t.Fatalf("Y replace = %d %v", code, m)
		}
		if state, l := fe6b0cLookupState(t, mux, opX); state != "aborted" {
			t.Fatalf("X never wrote; Y installed the identical pair; X reads %q (%v)", state, l)
		}
		if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 1 || ids[0] != opY {
			t.Fatalf("cert.ui.replace audits = %d %v, want exactly one keyed on Y", n, ids)
		}
	}
}

func TestFE6B0C_R03c_UIDeleteCommitSurvivesCompetitor(t *testing.T) {
	leafC, keyC, leafD, keyD, digestC := fe6b0cUIPairs(t)
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leafC, keyC); code != http.StatusOK {
			t.Fatalf("seed = %d %v", code, m)
		}
		since := fe6aSince()
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		if code, m := fe6b0cUIDelete(mux, opX, "uic1:"+digestC); code != http.StatusOK || m["recordState"] != "pending_reconciliation" {
			t.Fatalf("X delete = %d %v", code, m)
		}
		fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
		opY := fe6b0OpID()
		if code, m := fe6b0cUIReplace(t, mux, opY, uiCertRevisionNone, leafD, keyD); code != http.StatusOK || m["replaced"] != true {
			t.Fatalf("Y replace = %d %v", code, m)
		}
		if state, l := fe6b0cLookupState(t, mux, opX); state != "committed" {
			t.Fatalf("X deleted the pair and Y then installed D; X reads %q (%v)", state, l)
		}
		if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.delete"); n != 1 || ids[0] != opX {
			t.Fatalf("cert.ui.delete audits = %d %v, want exactly one keyed on X", n, ids)
		}
	}
}

func TestFE6B0C_R03d_UIDeleteNeverWrittenThenCompetitorDeletes(t *testing.T) {
	leafC, keyC, _, _, digestC := fe6b0cUIPairs(t)
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leafC, keyC); code != http.StatusOK {
			t.Fatalf("seed = %d %v", code, m)
		}
		since := fe6aSince()
		opX := fe6b0OpID()
		fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionUIDelete, Actor: "10.99.0.1",
			Target: "ui_cert", Fence: "uic1:" + digestC})
		opY := fe6b0OpID()
		if code, m := fe6b0cUIDelete(mux, opY, "uic1:"+digestC); code != http.StatusOK || m["deleted"] != true {
			t.Fatalf("Y delete = %d %v", code, m)
		}
		if state, l := fe6b0cLookupState(t, mux, opX); state != "aborted" {
			t.Fatalf("X never removed anything; Y removed the pair; absence credits X: %q (%v)", state, l)
		}
		if n, ids, _ := fe6b0cAuditEntries(since, "cert.ui.delete"); n != 1 || ids[0] != opY {
			t.Fatalf("cert.ui.delete audits = %d %v, want exactly one keyed on Y", n, ids)
		}
	}
}

// ── R04 OCSP attribution ────────────────────────────────────────────────────

func TestFE6B0C_R04_OCSPAttribution(t *testing.T) {
	t.Run("commit_survives_posture_change", func(t *testing.T) {
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		since := fe6aSince()
		globalOCSP.Disable()
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		code, mX := fe6b0cOCSPSet(mux, opX, fe6b0cOCSPRevision(mux), true)
		if code != http.StatusOK || mX["recordState"] != "pending_reconciliation" {
			t.Fatalf("X set = %d %v", code, mX)
		}
		adminSettingsSaveWG.Wait()
		fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
		opY := fe6b0OpID()
		if code, m := fe6b0cOCSPSet(mux, opY, fe6b0cOCSPRevision(mux), false); code != http.StatusOK || m["ok"] != true {
			t.Fatalf("Y set = %d %v", code, m)
		}
		adminSettingsSaveWG.Wait()
		if state, l := fe6b0cLookupState(t, mux, opX); state != "committed" {
			t.Fatalf("X durably enabled OCSP and Y then disabled it; X reads %q (%v)", state, l)
		}
		if globalOCSP.Enabled() {
			t.Fatal("settling X re-applied its posture over Y's")
		}
		if n, ids, _ := fe6b0cAuditEntries(since, "ocsp.set"); n != 2 || ids[0] == ids[1] {
			t.Fatalf("ocsp.set audits = %d %v, want one for X and one for Y", n, ids)
		}
	})

	t.Run("never_written_then_competitor_recreates_target", func(t *testing.T) {
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		since := fe6aSince()
		globalOCSP.Disable()
		rev0 := fe6b0cOCSPRevision(mux)
		opX := fe6b0OpID()
		fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionOCSPSet, Actor: "10.99.0.1",
			Target: "ocsp", CandidateDigest: "enabled", Fence: rev0, Expect: "gen=1"})
		opY := fe6b0OpID()
		if code, m := fe6b0cOCSPSet(mux, opY, rev0, true); code != http.StatusOK || m["ok"] != true {
			t.Fatalf("Y set = %d %v", code, m)
		}
		adminSettingsSaveWG.Wait()
		if state, l := fe6b0cLookupState(t, mux, opX); state != "aborted" {
			t.Fatalf("X never wrote; Y produced X's exact target state; X reads %q (%v)", state, l)
		}
		if n, ids, _ := fe6b0cAuditEntries(since, "ocsp.set"); n != 1 || ids[0] != opY {
			t.Fatalf("ocsp.set audits = %d %v, want exactly one keyed on Y", n, ids)
		}
	})
}

// ── R05 automatic rotation vs an unresolved CA operation ───────────────────

func TestFE6B0C_R05_AutoRotationParkedBehindUnresolvedCAOperation(t *testing.T) {
	t.Run("committed_but_unsettled_commit_is_not_overwritten", func(t *testing.T) {
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		since := fe6aSince()
		ledger := filepath.Join(dir, fe6b0LedgerFile)
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		fe6b0RotateOK(t, mux, opX)
		fpA := certMgr.LiveCertificateHex()
		bundleA := fe6b0Bundle(t)
		// The CA is now near expiry; the ledger is still unwritable, so X cannot
		// be settled durably.
		fe6b0cNearExpiry()
		fe6b0cRotationRound(t, true)
		if got := certMgr.LiveCertificateHex(); got != fpA {
			t.Fatalf("automatic rotation replaced the evidence of the unsettled operation X (live %s → %s) before X was settled durably", fpA, got)
		}
		if !bytes.Equal(fe6b0Bundle(t), bundleA) {
			t.Fatal("automatic rotation rewrote the bundle behind an unsettled operation")
		}
		// Storage recovers: the next round settles X FIRST, then rotates.
		fe6b0cRestoreLedger(t, ledger)
		fe6b0cRotationRound(t, true)
		rec := fe6b0cRecord(t, opX)
		if rec == nil || rec.State != "committed" {
			t.Fatalf("X after the round = %+v, want committed (settled by the writer before it wrote)", rec)
		}
		if got := certMgr.LiveCertificateHex(); got == fpA {
			t.Fatal("the rotation did not proceed once X was settled")
		}
		if n, ids, _ := fe6b0cAuditEntries(since, "ca.rotate"); n != 1 || ids[0] != opX {
			t.Fatalf("ca.rotate audits = %d %v, want exactly one keyed on X (auto-rotation is not an admin operation)", n, ids)
		}
		if state, _ := fe6b0cLookupState(t, mux, opX); state != "committed" {
			t.Fatalf("X after rotation = %s", state)
		}
	})

	t.Run("never_written_intent_is_settled_before_rotation", func(t *testing.T) {
		dir, _ := fe6b0cNode(t)
		rev0 := fe6b0Revision(t)
		_, _, fpAHex := fe6b0CAPair(t, "A", true)
		opX := fe6b0OpID()
		fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionImport, Actor: "10.99.0.1",
			Target: "root_ca", CandidateDigest: fpAHex, Fence: rev0})
		fe6b0cNearExpiry()
		fe6b0cRotationRound(t, true)
		rec := fe6b0cRecord(t, opX)
		if rec == nil || rec.State != "aborted" || !strings.HasPrefix(rec.Code, "writer_") {
			t.Fatalf("the rotation writer must settle X durably BEFORE it writes (state aborted, code writer_*); got %+v", rec)
		}
		if fe6b0Revision(t) == rev0 {
			t.Fatal("the rotation did not proceed once X was settled")
		}
	})
}

// ── R06 startup ordering ────────────────────────────────────────────────────

func TestFE6B0C_R06_StartupRotationRoundWaitsForOperationReconciliation(t *testing.T) {
	dir, _ := fe6b0cNode(t)
	rev0 := fe6b0Revision(t)
	_, _, fpAHex := fe6b0CAPair(t, "A", true)
	opX := fe6b0OpID()
	fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionImport, Actor: "10.99.0.1",
		Target: "root_ca", CandidateDigest: fpAHex, Fence: rev0})
	fe6b0cNearExpiry()
	if certLifecycleBootGateArmForTest == nil || certLifecycleBootGateReleaseForTest == nil {
		// Baseline: the loop's immediate round runs before anything reconciles the ledger.
		fe6b0cRotationRound(t, false)
		rec := fe6b0cRecord(t, opX)
		if fe6b0Revision(t) != rev0 && rec != nil && rec.State == certOpPending {
			t.Fatal("the startup rotation round rotated the CA while the operation ledger was still unreconciled (no boot gate exists)")
		}
		t.Fatal("no certificate-lifecycle boot gate (correction absent)")
	}
	certLifecycleBootGateArmForTest()
	t.Cleanup(certLifecycleBootGateReleaseForTest)
	waiting := make(chan struct{})
	var once sync.Once
	prevObs := caRotationBootGateObserver
	caRotationBootGateObserver = func() { once.Do(func() { close(waiting) }) }
	t.Cleanup(func() { caRotationBootGateObserver = prevObs })
	wait := awaitFirstRotationRound(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := StartCAAutoRotation(ctx, caRuntime.path, caRuntime.passphrase)
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("the rotation loop did not exit")
		}
	}()
	select {
	case <-waiting:
	case <-time.After(15 * time.Second):
		t.Fatal("the rotation loop never reported waiting for the boot gate")
	}
	if fe6b0Revision(t) != rev0 {
		t.Fatal("the CA rotated before the boot gate was released")
	}
	if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != certOpPending {
		t.Fatalf("X was touched before reconciliation: %+v", rec)
	}
	// Boot continues: the admin-settings slice reconciles the ledger and
	// releases the gate (the settings file is absent — every load path must).
	LoadAdminSettings(filepath.Join(dir, "admin_settings.json"))
	adminSettingsSaveWG.Wait()
	wait()
	rec := fe6b0cRecord(t, opX)
	if rec == nil || rec.State != "aborted" {
		t.Fatalf("X must be reconciled before the first rotation round, got %+v", rec)
	}
	if fe6b0Revision(t) == rev0 {
		t.Fatal("the released round did not rotate the near-expiry CA")
	}
}

// R06b pins the ordering in SOURCE: LoadAdminSettings reconciles the ledger
// and then releases the gate on every load path; the loop awaits the gate
// before its first round.
func TestFE6B0C_R06b_BootOrderIsPinnedInSource(t *testing.T) {
	admin, err := os.ReadFile(filepath.Join(pkgSourceDir(), "admin_settings.go"))
	if err != nil {
		t.Fatal(err)
	}
	loop, err := os.ReadFile(filepath.Join(pkgSourceDir(), "ca.go"))
	if err != nil {
		t.Fatal(err)
	}
	a := string(admin)
	start := strings.Index(a, "func LoadAdminSettings(")
	if start < 0 {
		t.Fatal("LoadAdminSettings not found")
	}
	body := a[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "defer finishCertificateLifecycleBoot()") {
		t.Fatal("LoadAdminSettings must reconcile the certificate ledger and release the boot gate on EVERY return path (defer finishCertificateLifecycleBoot())")
	}
	if strings.Contains(body, "reconcileCertificateOperations()") {
		t.Fatal("the direct reconcile call in LoadAdminSettings is reachable only on the readable path; the deferred finish owns it")
	}
	l := string(loop)
	i, j := strings.Index(l, "awaitCertLifecycleBootGate("), strings.Index(l, "checkRound()")
	if i < 0 || j < 0 || i > j {
		t.Fatal("StartCAAutoRotation must await the certificate-lifecycle boot gate BEFORE its immediate round")
	}
}

// ── R07 a non-durable refusal is non-terminal ───────────────────────────────

func fe6b0cAssertRefusalNotDurable(t *testing.T, code int, m map[string]any, opID string) {
	t.Helper()
	if code != http.StatusInternalServerError || m["code"] != refusalOutcomeUnknown {
		t.Fatalf("a refusal whose aborted record is NOT durable must be the NON-terminal 500 outcome_unknown, got %d %v", code, m)
	}
	cur, _ := m["current"].(map[string]any)
	if cur["detail"] != "refusal_not_durable" || cur["state"] != certOpPending || cur["operationId"] != opID {
		t.Fatalf("outcome_unknown must carry current.detail=refusal_not_durable, current.state=pending and the operationId: %v", m)
	}
}

func TestFE6B0C_R07_NonDurableRefusalIsNonTerminal(t *testing.T) {
	t.Run("ca_rotate_persist_failure", func(t *testing.T) {
		dir, br := fe6b0cNode(t)
		mux := fe6b0Mux()
		fp, rev, bundle, since := fe6b0Fingerprint(), fe6b0Revision(t), fe6b0Bundle(t), fe6aSince()
		restoreBundle := fe6b0cMakeDir(t, caRuntime.path)
		defer restoreBundle()
		opX := fe6b0OpID()
		ch, _ := fe6b0Challenge(t, mux, opX, rev)
		br.armed.Store(true)
		code, m, _ := fe6b0Rotate(mux, opX, rev, ch)
		if !br.fired.Load() {
			t.Fatal("the ledger breaker did not fire after the intent record")
		}
		fe6b0cAssertRefusalNotDurable(t, code, m, opX)
		if got := fe6b0Fingerprint(); got != fp {
			t.Fatalf("live CA changed: %s → %s", fp, got)
		}
		for _, a := range []string{"ca.rotate", "ca.import"} {
			if n, _, _ := fe6b0cAuditEntries(since, a); n != 0 {
				t.Fatalf("a refused operation emitted a %s audit", a)
			}
		}
		fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
		if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != certOpPending {
			t.Fatalf("the durable truth must still be the pending intent: %+v", rec)
		}
		_ = bundle
	})

	t.Run("ui_replace_persist_failure", func(t *testing.T) {
		_, br := fe6b0cNode(t)
		mux := fe6b0Mux()
		leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
		restoreCert := fe6b0cMakeDir(t, customUITLSCertPath())
		defer restoreCert()
		opX := fe6b0OpID()
		br.armed.Store(true)
		code, m := fe6b0cUIReplace(t, mux, opX, uiCertRevisionNone, leaf, key)
		if !br.fired.Load() {
			t.Fatal("the ledger breaker did not fire after the intent record")
		}
		fe6b0cAssertRefusalNotDurable(t, code, m, opX)
		if _, err := os.Stat(customUITLSKeyPath()); err == nil {
			t.Fatal("a refused replace wrote the key")
		}
	})

	t.Run("ui_delete_persist_failure", func(t *testing.T) {
		_, br := fe6b0cNode(t)
		mux := fe6b0Mux()
		leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
		if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leaf, key); code != http.StatusOK {
			t.Fatalf("seed = %d %v", code, m)
		}
		rev := fe6b0cUIRevision(t, mux)
		restoreKey := fe6b0cMakeDir(t, customUITLSKeyPath())
		defer restoreKey()
		opX := fe6b0OpID()
		br.armed.Store(true)
		code, m := fe6b0cUIDelete(mux, opX, rev)
		if !br.fired.Load() {
			t.Fatal("the ledger breaker did not fire after the intent record")
		}
		fe6b0cAssertRefusalNotDurable(t, code, m, opX)
		if _, err := os.Stat(customUITLSCertPath()); err != nil {
			t.Fatal("a refused delete removed the certificate")
		}
	})

	t.Run("ocsp_persist_failure", func(t *testing.T) {
		dir, br := fe6b0cNode(t)
		mux := fe6b0Mux()
		globalOCSP.Disable()
		if code, m := fe6b0cOCSPSet(mux, fe6b0OpID(), fe6b0cOCSPRevision(mux), true); code != http.StatusOK {
			t.Fatalf("seed = %d %v", code, m)
		}
		adminSettingsSaveWG.Wait()
		rev := fe6b0cOCSPRevision(mux)
		restoreSettings := fe6b0cMakeDir(t, filepath.Join(dir, "admin_settings.json"))
		defer restoreSettings()
		opX := fe6b0OpID()
		br.armed.Store(true)
		code, m := fe6b0cOCSPSet(mux, opX, rev, false)
		if !br.fired.Load() {
			t.Fatal("the ledger breaker did not fire after the intent record")
		}
		fe6b0cAssertRefusalNotDurable(t, code, m, opX)
		if !globalOCSP.Enabled() {
			t.Fatal("a refused set changed the runtime posture")
		}
	})
}

// ── R08 after ledger recovery the refusal is durable and replays terminal ──

func TestFE6B0C_R08_RefusalBecomesDurableAfterLedgerRecoveryAndReplaysTerminal(t *testing.T) {
	t.Run("same_process_lookup", func(t *testing.T) {
		dir, br := fe6b0cNode(t)
		mux := fe6b0Mux()
		fp, rev := fe6b0Fingerprint(), fe6b0Revision(t)
		restoreBundle := fe6b0cMakeDir(t, caRuntime.path)
		opX := fe6b0OpID()
		ch, _ := fe6b0Challenge(t, mux, opX, rev)
		br.armed.Store(true)
		code, m, _ := fe6b0Rotate(mux, opX, rev, ch)
		fe6b0cAssertRefusalNotDurable(t, code, m, opX)
		// Storage recovers (bundle path and ledger).
		restoreBundle()
		fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
		state, l := fe6b0cLookupState(t, mux, opX)
		if state != "aborted" {
			t.Fatalf("after recovery the refusal must be recorded durably as aborted, got %q (%v)", state, l)
		}
		if l["code"] != refusalPersistFailed {
			t.Fatalf("the recorded terminal refusal must carry the refusal it stood for (persist_failed), got %v", l["code"])
		}
		// A repeat of the same operationId replays the terminal refusal and dispatches nothing.
		ch2, _ := fe6b0Challenge(t, mux, fe6b0OpID(), fe6b0Revision(t))
		code, m, _ = fe6b0Rotate(mux, opX, fe6b0Revision(t), ch2)
		if code != http.StatusConflict || m["code"] != refusalOperationAborted {
			t.Fatalf("replay of a durably refused operation = %d %v, want 409 operation_aborted", code, m)
		}
		if got := fe6b0Fingerprint(); got != fp {
			t.Fatalf("the replay rotated: %s → %s", fp, got)
		}
	})

	t.Run("across_restart_reconciliation", func(t *testing.T) {
		dir, br := fe6b0cNode(t)
		mux := fe6b0Mux()
		leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
		if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leaf, key); code != http.StatusOK {
			t.Fatalf("seed = %d %v", code, m)
		}
		rev := fe6b0cUIRevision(t, mux)
		restoreKey := fe6b0cMakeDir(t, customUITLSKeyPath())
		opX := fe6b0OpID()
		br.armed.Store(true)
		code, m := fe6b0cUIDelete(mux, opX, rev)
		fe6b0cAssertRefusalNotDurable(t, code, m, opX)
		restoreKey()
		fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
		// Restart: boot reconciliation records the refusal durably.
		reopenCertificateOperationsForTest()
		reconcileCertificateOperations()
		rec := fe6b0cRecord(t, opX)
		if rec == nil || rec.State != "aborted" {
			t.Fatalf("boot reconciliation must record the refusal durably, got %+v", rec)
		}
		code, m = fe6b0cUIDelete(mux, opX, rev)
		if code != http.StatusConflict || m["code"] != refusalOperationAborted {
			t.Fatalf("replay after restart = %d %v, want 409 operation_aborted", code, m)
		}
		if !customUITLSFilesPresent() {
			t.Fatal("the replay removed the pair")
		}
	})
}

// ── R09 a reconciled commit replays the complete action-bound result ────────

func fe6b0cRecoverAndCheck(t *testing.T, mux *http.ServeMux, dir, opX, action string, check func(res map[string]any)) {
	t.Helper()
	fe6b0cRestoreLedger(t, filepath.Join(dir, fe6b0LedgerFile))
	state, l := fe6b0cLookupState(t, mux, opX)
	if state != "committed" {
		t.Fatalf("%s: lookup = %s %v", action, state, l)
	}
	res, _ := l["result"].(map[string]any)
	if res == nil {
		t.Fatalf("%s: the recovered record carries no action-bound result: %v", action, l)
	}
	if res["operationId"] != opX || res["action"] != action {
		t.Fatalf("%s: result is not bound to the operation: %v", action, res)
	}
	check(res)
	if rev, _ := l["committedRevision"].(string); rev == "" {
		t.Fatalf("%s: no committedRevision: %v", action, l)
	}
}

func TestFE6B0C_R09a_RecoveredRotateReplaysActionBoundResult(t *testing.T) {
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		// A clean rotation fixes the bounded audit detail this action emits.
		since0 := fe6aSince()
		fe6b0RotateOK(t, mux, fe6b0OpID())
		_, _, details := fe6b0cAuditEntries(since0, "ca.rotate")
		if len(details) != 1 || details[0] == "" {
			t.Fatalf("clean rotation audit = %v", details)
		}
		since := fe6aSince()
		fpBefore := fe6b0Fingerprint()
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		fe6b0RotateOK(t, mux, opX)
		fpAfter := fe6b0Fingerprint()
		fe6b0cRecoverAndCheck(t, mux, dir, opX, certActionRotate, func(res map[string]any) {
			caM, _ := res["ca"].(map[string]any)
			prev, _ := res["previous"].(map[string]any)
			if res["rotated"] != true || caM["fingerprint"] != fpAfter || caM["revision"] != fe6b0Revision(t) || prev["fingerprint"] != fpBefore {
				t.Fatalf("rotation result incomplete: %v", res)
			}
		})
		code, m, _ := fe6b0Rotate(mux, opX, fe6b0Revision(t), "")
		if code != http.StatusOK || m["replayed"] != true || m["rotated"] != true {
			t.Fatalf("replay = %d %v", code, m)
		}
		if caM, _ := m["ca"].(map[string]any); caM["fingerprint"] != fpAfter {
			t.Fatalf("replay ca = %v", m)
		}
		n, ids, det := fe6b0cAuditEntries(since, "ca.rotate")
		if n != 1 || ids[0] != opX || det[0] != details[0] {
			t.Fatalf("recovered audit = %d %v %v, want exactly one keyed on X with the action's bounded detail %q", n, ids, det, details[0])
		}
	}
}

func TestFE6B0C_R09b_RecoveredImportReplaysActionBoundResult(t *testing.T) {
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		since := fe6aSince()
		fpBefore := fe6b0Fingerprint()
		certA, keyA, fpAHex := fe6b0CAPair(t, "A", true)
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		code, m, w := fe6b0Upload(t, mux, "?target=mitm&operationId="+opX+"&caRevision="+fe6b0Revision(t),
			map[string]string{"target": "mitm", "cert": string(certA), "key": string(keyA)})
		if code != http.StatusOK || m["recordState"] != "pending_reconciliation" {
			t.Fatalf("import = %d %s", code, w.Body.String())
		}
		fe6b0cRecoverAndCheck(t, mux, dir, opX, certActionImport, func(res map[string]any) {
			caM, _ := res["ca"].(map[string]any)
			prev, _ := res["previous"].(map[string]any)
			if res["imported"] != true || res["target"] != "mitm" || caM["fingerprint"] != fe6b0Fingerprint() || prev["fingerprint"] != fpBefore {
				t.Fatalf("import result incomplete: %v", res)
			}
		})
		if certMgr.LiveCertificateHex() != fpAHex {
			t.Fatal("live CA is not the imported candidate")
		}
		code, m, _ = fe6b0Upload(t, mux, "?target=mitm&operationId="+opX+"&caRevision=x",
			map[string]string{"target": "mitm", "cert": string(certA), "key": string(keyA)})
		if code != http.StatusOK || m["replayed"] != true || m["imported"] != true || m["target"] != "mitm" {
			t.Fatalf("replay = %d %v", code, m)
		}
		if n, ids, det := fe6b0cAuditEntries(since, "ca.import"); n != 1 || ids[0] != opX || det[0] == "" {
			t.Fatalf("recovered audit = %d %v %v", n, ids, det)
		}
	}
}

func TestFE6B0C_R09c_RecoveredUIReplaceReplaysActionBoundResult(t *testing.T) {
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		since := fe6aSince()
		leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		if code, m := fe6b0cUIReplace(t, mux, opX, uiCertRevisionNone, leaf, key); code != http.StatusOK || m["recordState"] != "pending_reconciliation" {
			t.Fatalf("replace = %d %v", code, m)
		}
		fe6b0cRecoverAndCheck(t, mux, dir, opX, certActionUIReplace, func(res map[string]any) {
			uc, _ := res["uiCert"].(map[string]any)
			cand, _ := res["candidate"].(map[string]any)
			if res["replaced"] != true || res["activation"] != "restart_required" || uc["revision"] != "uic1:"+hexDigest(leaf) || cand["fingerprint"] == nil {
				t.Fatalf("UI replace result incomplete: %v", res)
			}
		})
		code, m := fe6b0cUIReplace(t, mux, opX, "x", leaf, key)
		if code != http.StatusOK || m["replayed"] != true || m["replaced"] != true || m["activation"] != "restart_required" {
			t.Fatalf("replay = %d %v", code, m)
		}
		if n, ids, det := fe6b0cAuditEntries(since, "cert.ui.replace"); n != 1 || ids[0] != opX || det[0] == "" {
			t.Fatalf("recovered audit = %d %v %v", n, ids, det)
		}
	}
}

func TestFE6B0C_R09d_RecoveredUIDeleteReplaysActionBoundResult(t *testing.T) {
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
		if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leaf, key); code != http.StatusOK {
			t.Fatalf("seed = %d %v", code, m)
		}
		uiCustomTLSActive = true // the running listener uses the pair (activation posture must survive recovery)
		since := fe6aSince()
		rev := fe6b0cUIRevision(t, mux)
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		if code, m := fe6b0cUIDelete(mux, opX, rev); code != http.StatusOK || m["recordState"] != "pending_reconciliation" {
			t.Fatalf("delete = %d %v", code, m)
		}
		fe6b0cRecoverAndCheck(t, mux, dir, opX, certActionUIDelete, func(res map[string]any) {
			uc, _ := res["uiCert"].(map[string]any)
			if res["deleted"] != true || res["activation"] != "restart_required" || uc["present"] != false {
				t.Fatalf("UI delete result incomplete: %v", res)
			}
		})
		code, m := fe6b0cUIDelete(mux, opX, "x")
		if code != http.StatusOK || m["replayed"] != true || m["deleted"] != true || m["activation"] != "restart_required" {
			t.Fatalf("replay = %d %v", code, m)
		}
		if n, ids, det := fe6b0cAuditEntries(since, "cert.ui.delete"); n != 1 || ids[0] != opX || det[0] == "" {
			t.Fatalf("recovered audit = %d %v %v", n, ids, det)
		}
	}
}

func TestFE6B0C_R09e_RecoveredOCSPSetReplaysActionBoundResult(t *testing.T) {
	{
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		since := fe6aSince()
		globalOCSP.Disable()
		fe6b0cCommitWithFinishFailure(dir)
		opX := fe6b0OpID()
		if code, m := fe6b0cOCSPSet(mux, opX, fe6b0cOCSPRevision(mux), true); code != http.StatusOK || m["recordState"] != "pending_reconciliation" {
			t.Fatalf("set = %d %v", code, m)
		}
		adminSettingsSaveWG.Wait()
		fe6b0cRecoverAndCheck(t, mux, dir, opX, certActionOCSPSet, func(res map[string]any) {
			des, _ := res["desired"].(map[string]any)
			rt, _ := res["runtime"].(map[string]any)
			if res["ok"] != true || res["enabled"] != true || res["durable"] != true || res["revision"] != fe6b0cOCSPRevision(mux) || des["enabled"] != true || rt["enabled"] != true {
				t.Fatalf("OCSP result incomplete: %v", res)
			}
		})
		code, m := fe6b0cOCSPSet(mux, opX, "x", true)
		if code != http.StatusOK || m["replayed"] != true || m["ok"] != true || m["durable"] != true {
			t.Fatalf("replay = %d %v", code, m)
		}
		if n, ids, det := fe6b0cAuditEntries(since, "ocsp.set"); n != 1 || ids[0] != opX || det[0] == "" {
			t.Fatalf("recovered audit = %d %v %v", n, ids, det)
		}
	}
}

// ── R10 controls ────────────────────────────────────────────────────────────

func TestFE6B0C_R10_Controls(t *testing.T) {
	t.Run("unrelated_targets_stay_unblocked_and_untouched", func(t *testing.T) {
		dir, _ := fe6b0cNode(t)
		mux := fe6b0Mux()
		rev0 := fe6b0Revision(t)
		_, _, fpAHex := fe6b0CAPair(t, "A", true)
		opX := fe6b0OpID()
		fe6b0cInjectPending(t, dir, certOperation{OperationID: opX, Action: certActionImport, Actor: "10.99.0.1",
			Target: "root_ca", CandidateDigest: fpAHex, Fence: rev0})
		leaf, key, _ := fe6b0CAPair(t, "ui-x", false)
		if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, leaf, key); code != http.StatusOK {
			t.Fatalf("a pending CA operation blocked a UI replace: %d %v", code, m)
		}
		globalOCSP.Disable()
		if code, m := fe6b0cOCSPSet(mux, fe6b0OpID(), fe6b0cOCSPRevision(mux), true); code != http.StatusOK {
			t.Fatalf("a pending CA operation blocked an OCSP set: %d %v", code, m)
		}
		adminSettingsSaveWG.Wait()
		if rec := fe6b0cRecord(t, opX); rec == nil || rec.State != certOpPending {
			t.Fatalf("writers of OTHER targets settled the CA operation: %+v", rec)
		}
		if state, _ := fe6b0cLookupState(t, mux, opX); state != "aborted" {
			t.Fatalf("X = %s", state)
		}
	})

	t.Run("completed_operations_are_never_re_executed", func(t *testing.T) {
		_, _ = fe6b0cNode(t)
		mux := fe6b0Mux()
		opX := fe6b0OpID()
		newRev, _ := fe6b0RotateOK(t, mux, opX)
		fp := fe6b0Fingerprint()
		for i := 0; i < 2; i++ {
			if state, _ := fe6b0cLookupState(t, mux, opX); state != "committed" {
				t.Fatalf("lookup %d = %s", i, state)
			}
		}
		reopenCertificateOperationsForTest()
		reconcileCertificateOperations()
		if code, m, _ := fe6b0Rotate(mux, opX, newRev, ""); code != http.StatusOK || m["replayed"] != true {
			t.Fatalf("replay = %d %v", code, m)
		}
		if got := fe6b0Fingerprint(); got != fp || fe6b0Revision(t) != newRev {
			t.Fatalf("a completed operation was re-executed: %s → %s", fp, got)
		}
	})

	t.Run("valid_automatic_rotation_still_works", func(t *testing.T) {
		_, _ = fe6b0cNode(t)
		fp, bundle := fe6b0Fingerprint(), fe6b0Bundle(t)
		before := statCARotations.Load()
		fe6b0cNearExpiry()
		fe6b0cRotationRound(t, true)
		if got := fe6b0Fingerprint(); got == fp {
			t.Fatal("a near-expiry CA with no pending operation did not rotate")
		}
		if bytes.Equal(fe6b0Bundle(t), bundle) {
			t.Fatal("the rotation was not persisted")
		}
		if statCARotations.Load() != before+1 {
			t.Fatal("the rotation counter did not move")
		}
		if !certMgr.SecondaryCAActive() {
			t.Fatal("dual-CA overlap not active after auto-rotation")
		}
	})
}
