package server

// server_journal_test.go — RISK-022 wiring: a journaled op records PhaseAdmitted
// at admission and has its record retired at terminal; non-journaled kinds write
// nothing.

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

func newJournalTestServer(t *testing.T) (*Server, *journal.Journal) {
	t.Helper()
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	al, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	pol, err := auth.NewPolicy([]string{strconv.Itoa(os.Geteuid())})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	jnl, err := journal.New(tmp)
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	srv, err := New(Options{
		Cfg:       &config.Config{ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml", SocketPath: filepath.Join(tmp, "s.sock"), StateDir: tmp, PrivilegeMode: config.PrivilegeSudoers, OperationTimeout: 30 * time.Second},
		Auth:      pol,
		Audit:     al,
		Ops:       ops.NewManager(nil),
		Status:    &fakeStatus{},
		StateDir:  tmp,
		AuditPath: auditPath,
		Journal:   jnl,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, jnl
}

// TestJournal_AdmitWritesAndTerminalRemoves: a journaled op (upgrades.apply)
// records PhaseAdmitted while running, and the record is retired once terminal.
func TestJournal_AdmitWritesAndTerminalRemoves(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	peer := auth.PeerInfo{UID: 1000, Username: "cp"}
	release := make(chan struct{})

	op, _, e := srv.startAsyncOp(nil, peer, ops.KindUpgradeApply, "", nil, blockingStages(release))
	if e != nil {
		t.Fatalf("admit: %+v", e)
	}
	// While the op is blocked mid-flight, its journal record exists (PhaseAdmitted).
	rec, found, err := jnl.Read(op.ID)
	if err != nil || !found {
		t.Fatalf("expected a journal record for the in-flight op: found=%v err=%v", found, err)
	}
	if rec.Phase != journal.PhaseAdmitted || rec.Kind != ops.KindUpgradeApply || rec.Actor != peer.String() {
		t.Errorf("unexpected record: %+v", *rec)
	}
	// Let it finish → terminal → record retired.
	close(release)
	srv.opWG.Wait()
	if _, found, _ := jnl.Read(op.ID); found {
		t.Error("journal record must be removed once the op reaches a terminal state")
	}
}

// TestJournal_PersistsRollbackMode: a rollbacks.create record must carry the
// mode (image vs data) — the reconciler needs it (image is Docker-reconcilable;
// data must not be auto-reconciled), and it's the only durable signal of which
// rollback was interrupted.
func TestJournal_PersistsRollbackMode(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	peer := auth.PeerInfo{UID: 1000, Username: "cp"}
	release := make(chan struct{})

	params := map[string]interface{}{"mode": "data"}
	op, _, e := srv.startAsyncOp(nil, peer, ops.KindRollbackCreate, "", params, blockingStages(release))
	if e != nil {
		t.Fatalf("admit: %+v", e)
	}
	rec, found, err := jnl.Read(op.ID)
	if err != nil || !found {
		t.Fatalf("expected journal record: found=%v err=%v", found, err)
	}
	if rec.Mode != "data" {
		t.Errorf("record mode = %q, want data", rec.Mode)
	}
	close(release)
	srv.opWG.Wait()
}

// TestJournal_ImageRollbackPersistsTargetRef pins the Codex #787 P2 fix: a
// standalone image rollback's target is fixed and fully validated at admission,
// and NO later stage folds it into the journal (journal_phases is
// apply-specific) — so the admission write must persist TargetRef/TargetDigest
// itself. Without it the record carries no actionable ref and the E1c trust
// gate (validateReconcileRefs) can only mark it invalid, making an interrupted
// image rollback permanently un-reconcilable (always loud-stop).
func TestJournal_ImageRollbackPersistsTargetRef(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	peer := auth.PeerInfo{UID: 1000, Username: "cp"}
	release := make(chan struct{})

	const dig = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	ref := "ghcr.io/kidcarmi/culvert@sha256:" + dig
	params := map[string]interface{}{"mode": "image", "image_ref": ref}
	op, _, e := srv.startAsyncOp(nil, peer, ops.KindRollbackCreate, "", params, blockingStages(release))
	if e != nil {
		t.Fatalf("admit: %+v", e)
	}
	rec, found, err := jnl.Read(op.ID)
	if err != nil || !found {
		t.Fatalf("expected journal record: found=%v err=%v", found, err)
	}
	if rec.TargetRef != ref {
		t.Errorf("record target_ref = %q, want %q", rec.TargetRef, ref)
	}
	if rec.TargetDigest != dig {
		t.Errorf("record target_digest = %q, want %q", rec.TargetDigest, dig)
	}
	// And the E1c trust gate must now accept the record as actionable.
	if ok, why := validateReconcileRefs(rec, "ghcr.io/kidcarmi/culvert"); !ok {
		t.Errorf("admitted image-rollback record failed the reconcile trust gate: %s", why)
	}
	close(release)
	srv.opWG.Wait()
}

// TestJournal_NonJournaledKindWritesNothing: a non-journaled kind (read-only
// upgrades.check / backup.list) never touches the journal.
func TestJournal_NonJournaledKindWritesNothing(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	peer := auth.PeerInfo{UID: 1000, Username: "cp"}

	if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "", nil, quickStages); e != nil {
		t.Fatalf("admit: %+v", e)
	}
	srv.opWG.Wait()
	recs, err := jnl.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("non-journaled kind must not write a journal record, got %d", len(recs))
	}
}
