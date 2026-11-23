package server

// journal_retire_test.go — when a later operation retires the record of an
// earlier, interrupted one, and when it must not.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

const staleOpULID = "01HZZZZZZZZZZZZZZZZZZZZZZY"

func seedStaleRecord(t *testing.T, jnl *journal.Journal) {
	t.Helper()
	now := time.Now().UTC()
	if err := jnl.Write(journal.Record{
		OpID: staleOpULID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting,
		Actor: "uid=0", StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func runRetireCase(t *testing.T, kind string, stages func() ([]ops.FlowStage, *opError), opts ...startOpt) (*Server, *journal.Journal, *ops.Op) {
	t.Helper()
	srv, jnl := newJournalTestServer(t)
	srv.opts.Cfg.ProxyRepo = repo
	seedStaleRecord(t, jnl)
	op, _, e := srv.startAsyncOp(nil, auth.PeerInfo{UID: 1000, Username: "cp"}, kind, "", nil, stages, opts...)
	if e != nil {
		t.Fatalf("admit: %+v", e)
	}
	srv.opWG.Wait()
	return srv, jnl, srv.opts.Ops.Get(op.ID)
}

func failingStages() ([]ops.FlowStage, *opError) {
	return []ops.FlowStage{{
		Name: "boom", FailureReason: ops.ReasonCommandError,
		Run: func(context.Context) ([]byte, []byte, error) { return nil, nil, errors.New("boom") },
	}}, nil
}

func TestRetire_SuccessOfAnEstablishingOpRetiresStaleRecords(t *testing.T) {
	srv, jnl, op := runRetireCase(t, ops.KindUpgradeApply, quickStages, withRetiresInterrupted(func() bool { return true }))
	if op.State != ops.StateSucceeded {
		t.Fatalf("op = %s", op.State)
	}
	if _, found, _ := jnl.Read(staleOpULID); found {
		t.Error("stale record survived a later successful image change")
	}
	ids, _ := op.Result["superseded_interrupted_ops"].([]interface{}) //nolint:errcheck // absent → nil, asserted below
	if len(ids) != 1 || ids[0] != staleOpULID {
		t.Errorf("op result must name what it retired: %#v", op.Result)
	}
	// The retirement is audited against the retired op, naming the retirer.
	events, err := audit.Recent(srv.opts.AuditPath, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev.OpID == staleOpULID && strings.HasSuffix(ev.Kind, auditKindSuperseded) && ev.Params["superseded_by"] == op.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("no %s audit entry for the retired op", auditKindSuperseded)
	}
}

func TestRetire_NotOnFailure(t *testing.T) {
	_, jnl, op := runRetireCase(t, ops.KindUpgradeApply, failingStages, withRetiresInterrupted(func() bool { return true }))
	if op.State != ops.StateFailed {
		t.Fatalf("op = %s", op.State)
	}
	if _, found, _ := jnl.Read(staleOpULID); !found {
		t.Error("a FAILED op retired an interrupted record")
	}
}

func TestRetire_NotWhenTheOpEstablishedNothing(t *testing.T) {
	// An already-current apply: succeeded, but the tag was not re-pinned.
	_, jnl, op := runRetireCase(t, ops.KindUpgradeApply, quickStages, withRetiresInterrupted(func() bool { return false }))
	if op.State != ops.StateSucceeded {
		t.Fatalf("op = %s", op.State)
	}
	if _, found, _ := jnl.Read(staleOpULID); !found {
		t.Error("an op that established no image state retired an interrupted record")
	}
}

func TestRetire_NotByOtherKinds(t *testing.T) {
	// A data rollback (no option) and a backup must leave the journal alone.
	for _, kind := range []string{ops.KindRollbackCreate, ops.KindBackupCreate} {
		_, jnl, op := runRetireCase(t, kind, quickStages)
		if op.State != ops.StateSucceeded {
			t.Fatalf("%s = %s", kind, op.State)
		}
		if _, found, _ := jnl.Read(staleOpULID); !found {
			t.Errorf("%s retired an interrupted record", kind)
		}
	}
}

// TestRetire_UnreadableJournalRetiresNothing: with one corrupt file present the
// list fails closed, and a record that cannot be told apart is not removed.
func TestRetire_UnreadableJournalRetiresNothing(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	seedStaleRecord(t, jnl)
	if err := os.WriteFile(filepath.Join(jnl.Dir(), "01HZZZZZZZZZZZZZZZZZZZZZZX.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := srv.retireSupersededRecords(testOpULID, "uid=0"); len(got) != 0 {
		t.Errorf("retired %v from an unreadable journal", got)
	}
	if _, err := os.Stat(filepath.Join(jnl.Dir(), staleOpULID+".json")); err != nil {
		t.Errorf("stale record gone: %v", err)
	}
}

// SEC-AGT-DATAREC-KEEP-1. A later IMAGE change must not retire an interrupted
// DATA-rollback record.
//
// Retirement's whole justification is image-state reasoning: the record stops
// being true once a later operation re-pins the tag, recreates the proxy and
// passes the health gate, because the tag and the container are then both on a
// known image. An interrupted data rollback claims neither — it says /data may
// be half-restored, and it carries the only durable pointer to the recovery
// procedure (actionData). The loop filtered on op id and running-state only, so
// a successful upgrade cleared /v1/status and that instruction with it, while
// the data directory was exactly as the interrupted restore had left it. The
// agent does not repair a data directory, so nothing it can do makes the record
// untrue.
func TestRetire_DoesNotRetireADataRollbackRecord(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	srv.opts.Cfg.ProxyRepo = repo
	now := time.Now().UTC()
	if err := jnl.Write(journal.Record{
		OpID: staleOpULID, Kind: ops.KindRollbackCreate, Mode: "data",
		Phase: journal.PhaseAdmitted, Actor: "uid=0", StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Confirm the fixture really is the class under test before asserting on it.
	rec, found, err := jnl.Read(staleOpULID)
	if err != nil || !found {
		t.Fatalf("seeded record not readable: found=%v err=%v", found, err)
	}
	if got := DescribeInterrupted(rec, repo).DockerState; got != DockerStateDataIndeterminate {
		t.Fatalf("seeded record classifies as %q, want %q", got, DockerStateDataIndeterminate)
	}

	if retired := srv.retireSupersededRecords(testOpULID, "uid=0"); len(retired) != 0 {
		t.Errorf("a successful image change retired %v, taking the interrupted data rollback's recovery instruction with it", retired)
	}
	if _, found, _ := jnl.Read(staleOpULID); !found {
		t.Fatal("the interrupted data-rollback record was removed by an image change, which establishes nothing about /data")
	}
}

// The control: an interrupted IMAGE record in the same position is still
// retired, so the filter above cannot be satisfied by retiring nothing.
func TestRetire_StillRetiresAnImageRecord(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	srv.opts.Cfg.ProxyRepo = repo
	seedStaleRecord(t, jnl)
	if retired := srv.retireSupersededRecords(testOpULID, "uid=0"); len(retired) != 1 {
		t.Fatalf("retired %v, want the one interrupted image record", retired)
	}
	if _, found, _ := jnl.Read(staleOpULID); found {
		t.Error("the interrupted image record survived a later successful image change")
	}
}
