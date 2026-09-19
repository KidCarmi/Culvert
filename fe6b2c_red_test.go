package main

// FE-6B.2 CORRECTION ROUND — RED matrix (record 6B2C), written against the
// rejected FE-6B.2 candidate fcdd626f BEFORE any product change.
//
// Review blocker B1: "a lookup 404 does not establish safe re-send". The
// candidate offered an explicit Re-send of the SAME operation after the
// authoritative lookup answered 404, on the argument that the contract makes
// it safe by construction (a known id replays, a moved fence is 409 stale,
// identical content is 409 candidate_duplicate). The argument holds only
// while the ledger still HOLDS the record: a DECIDED record is evictable
// (certOperationsMax = 256, evictDecidedLocked), and a content-derived
// fence (uic1:<sha256 of the certificate bytes>) is the SAME token whenever
// the SAME bytes are persisted again. So the re-send's three protections
// can all be absent at once:
//
//   1. UI pair A is persisted (fence uic1:A).
//   2. Operation X deletes A; its answer is lost to the browser.
//   3. Later operations evict X from the ledger (decided records go first).
//   4. Another operation reinstalls the IDENTICAL pair A (fence uic1:A again).
//   5. GET /api/ca/operations/X → 404, and the marker's ORIGINAL fence
//      matches the current object again.
//   6. Re-sending X with the original fence is accepted as a NEW intent and
//      EXECUTES A SECOND DELETE — of a pair X never deleted.
//
// This file is the permanent DEFECT PROOF at the API level: it passes on the
// candidate and MUST keep passing after the frontend correction, because the
// backend contract is deliberately unchanged (the review bounded the fix to
// the frontend: keep absent operations UNKNOWN and withhold re-send). The
// frontend rows that turn RED → GREEN live in
// frontend/src/test/fe6b2c-red-page.test.tsx; a page proof that the 404
// cannot authorise another mutation is there, the API hazard is here. If a
// future backend slice adds a durable identity/continuity contract that
// makes re-send provable, the row below is what it must invalidate.
//
//   B1a the hazard: retained-record replay protection is lost with the
//       record; an identical reinstall re-arms the original fence; the
//       re-sent operation executes again (deleted:true, no replay).
//   B1b CONTROL: while the record is RETAINED the same re-send replays
//       (replayed:true) and deletes nothing — the protection the candidate
//       relied on exists, and depends entirely on retention.

import (
	"net/http"
	"testing"
)

// fe6b2cEvictUntilAbsent performs decided OCSP sets until the lookup of opX
// answers 404 (X evicted), bounded so a retention change fails the test
// loudly instead of looping.
func fe6b2cEvictUntilAbsent(t *testing.T, mux *http.ServeMux, opX string) (sets int) {
	t.Helper()
	enabled := true
	for sets = 0; sets < certOperationsMax+8; sets++ {
		if code, _ := fe6b0Lookup(mux, opX); code == http.StatusNotFound {
			return sets
		}
		rev := fe6b0cOCSPRevision(mux)
		if code, m := fe6b0cOCSPSet(mux, fe6b0OpID(), rev, enabled); code != http.StatusOK {
			t.Fatalf("OCSP set %d = %d %v", sets, code, m)
		}
		enabled = !enabled
	}
	t.Fatalf("operation %s still retained after %d decided operations (certOperationsMax=%d)", opX, sets, certOperationsMax)
	return sets
}

func fe6b2cPairState(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	code, m, _ := fe6b0Do(mux, http.MethodGet, "/api/certificates", nil)
	if code != http.StatusOK {
		t.Fatalf("inventory = %d %v", code, m)
	}
	uc, _ := m["uiCert"].(map[string]any)
	state, _ := uc["pairState"].(string)
	return state
}

func TestFE6B2C_B1a_EvictedDeleteResentAfterIdenticalReinstallExecutesTwice(t *testing.T) {
	fe6b0cNode(t)
	mux := fe6b0Mux()
	certA, keyA, _ := fe6b0CAPair(t, "ui-a", false)
	fenceA := "uic1:" + hexDigest(certA)

	// 1. pair A persisted.
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, certA, keyA); code != http.StatusOK || m["replaced"] != true {
		t.Fatalf("seed replace = %d %v", code, m)
	}
	if rev := fe6b0cUIRevision(t, mux); rev != fenceA {
		t.Fatalf("persisted fence %q, want the content-derived %q", rev, fenceA)
	}
	// 2. X deletes A (the browser never sees this answer).
	opX := fe6b0OpID()
	if code, m := fe6b0cUIDelete(mux, opX, fenceA); code != http.StatusOK || m["deleted"] != true || m["replayed"] == true {
		t.Fatalf("X delete = %d %v", code, m)
	}
	if code, m := fe6b0Lookup(mux, opX); code != http.StatusOK || m["state"] != "committed" {
		t.Fatalf("X lookup while retained = %d %v", code, m)
	}
	// 3. X is evicted by later decided operations.
	sets := fe6b2cEvictUntilAbsent(t, mux, opX)
	if code, m := fe6b0Lookup(mux, opX); code != http.StatusNotFound || m["code"] != "not_found" {
		t.Fatalf("X lookup after %d decided operations = %d %v, want 404 not_found", sets, code, m)
	}
	// 4. the IDENTICAL pair A is reinstalled by an unrelated operation.
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, certA, keyA); code != http.StatusOK || m["replaced"] != true {
		t.Fatalf("reinstall A = %d %v", code, m)
	}
	// 5. the original fence matches the current object again, and X is 404.
	if rev := fe6b0cUIRevision(t, mux); rev != fenceA {
		t.Fatalf("reinstalled fence %q, want %q (identical bytes ⇒ identical token)", rev, fenceA)
	}
	if code, _ := fe6b0Lookup(mux, opX); code != http.StatusNotFound {
		t.Fatalf("X lookup after reinstall = %d, want 404", code)
	}
	if state := fe6b2cPairState(t, mux); state != "complete" {
		t.Fatalf("pair before the re-send: %q, want complete", state)
	}
	// 6. THE HAZARD: re-sending X under its original fence is a NEW intent
	//    and executes a second delete — no replay, no stale, no duplicate.
	code, m := fe6b0cUIDelete(mux, opX, fenceA)
	if code != http.StatusOK || m["deleted"] != true {
		t.Fatalf("re-sent X = %d %v; the defect proof expects the second execution to be ACCEPTED (a refusal here would mean the backend now carries a continuity contract this proof must be rewritten for)", code, m)
	}
	if m["replayed"] == true {
		t.Fatalf("re-sent X was answered as a replay; the record was supposed to be evicted: %v", m)
	}
	if state := fe6b2cPairState(t, mux); state != "absent" {
		t.Fatalf("pair after the re-send: %q — the second execution should have removed the reinstalled pair", state)
	}
	if code, m := fe6b0Lookup(mux, opX); code != http.StatusOK || m["state"] != "committed" {
		t.Fatalf("X after the re-send = %d %v, want a fresh committed record (the second execution)", code, m)
	}
}

func TestFE6B2C_B1b_Control_RetainedRecordReplaysWithoutExecuting(t *testing.T) {
	fe6b0cNode(t)
	mux := fe6b0Mux()
	certA, keyA, _ := fe6b0CAPair(t, "ui-a", false)
	fenceA := "uic1:" + hexDigest(certA)
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, certA, keyA); code != http.StatusOK {
		t.Fatalf("seed replace = %d %v", code, m)
	}
	opX := fe6b0OpID()
	if code, m := fe6b0cUIDelete(mux, opX, fenceA); code != http.StatusOK || m["deleted"] != true {
		t.Fatalf("X delete = %d %v", code, m)
	}
	// Identical reinstall WITHOUT eviction: the record is retained.
	if code, m := fe6b0cUIReplace(t, mux, fe6b0OpID(), uiCertRevisionNone, certA, keyA); code != http.StatusOK {
		t.Fatalf("reinstall A = %d %v", code, m)
	}
	code, m := fe6b0cUIDelete(mux, opX, fenceA)
	if code != http.StatusOK || m["replayed"] != true {
		t.Fatalf("re-sent X with a retained record = %d %v, want the recorded result replayed", code, m)
	}
	if state := fe6b2cPairState(t, mux); state != "complete" {
		t.Fatalf("pair after the replay: %q — a replay must execute nothing", state)
	}
}
