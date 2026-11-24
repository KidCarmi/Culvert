package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
)

// markNewer rewrites the record file of opID as a newer agent would have
// written it (schema above this build's), bypassing Write, which refuses it.
func markNewer(t *testing.T, jnl *journal.Journal, opID string) {
	t.Helper()
	path := filepath.Join(jnl.Dir(), opID+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["schema"] = journal.SchemaCurrent + 1
	m["checkpoint"] = map[string]any{"step": "gate:target", "result": "failed"} // a fact this build cannot read
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestStartupReconcile_NewerRecordIsReportedNeverActedOn (ADR-0062 slice 2):
// a record a newer agent wrote is recovery_required/record_from_newer_agent;
// converge neither changes Docker nor rewrites or retires the record, even
// where the same record from this build would be realigned.
func TestStartupReconcile_NewerRecordIsReportedNeverActedOn(t *testing.T) {
	r := newReconRig(t, true)
	r.world.pinned = cfgNew // tag ahead, container on prior: a schema-1 record realigns
	r.seed(t, journal.PhaseRestarting, nil)
	markNewer(t, r.jnl, testOpULID)
	before, err := os.ReadFile(filepath.Join(r.jnl.Dir(), testOpULID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "record_from_newer_agent" {
		t.Fatalf("result = %+v, want recovery_required/record_from_newer_agent", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("acted on a newer agent's record: %v", c)
	}
	after, err := os.ReadFile(filepath.Join(r.jnl.Dir(), testOpULID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the newer record was rewritten:\nbefore %s\nafter  %s", before, after)
	}
}

// TestRetire_NewerRecordIsNeverSuperseded: a later successful image change
// does not retire a record a newer agent wrote, and writes no
// interrupted_superseded entry for it (the audit would claim a retirement
// the journal refuses to carry out).
func TestRetire_NewerRecordIsNeverSuperseded(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	srv.opts.Cfg.ProxyRepo = repo
	seedStaleRecord(t, jnl)
	markNewer(t, jnl, staleOpULID)
	if got := srv.retireSupersededRecords(testOpULID, "uid=0"); len(got) != 0 {
		t.Fatalf("retired %v", got)
	}
	if _, found, err := jnl.Read(staleOpULID); err != nil || !found {
		t.Fatalf("newer record gone: found=%v err=%v", found, err)
	}
	events, err := audit.Recent(srv.opts.AuditPath, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := range events {
		if events[i].OpID == staleOpULID {
			t.Errorf("an audit entry names the newer record: %+v", events[i])
		}
	}
}
