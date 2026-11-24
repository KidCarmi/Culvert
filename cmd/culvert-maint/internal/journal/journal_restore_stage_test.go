package journal

// journal_restore_stage_test.go — the restore_stage key: its closed set, and
// what a build on either side of the key does with the other's records.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func restoreRecord(stage RestoreStage) Record {
	rec := sampleRecord()
	rec.Kind, rec.Phase = "restore.commit", PhaseAdmitted
	rec.TargetRef, rec.TargetDigest, rec.PriorRef, rec.PriorDigest = "", "", "", ""
	rec.RestoreStage = stage
	return rec
}

// TestRestoreStage_ClosedSetRoundTrips: every stage a running operation writes
// is accepted and read back unchanged.
func TestRestoreStage_ClosedSetRoundTrips(t *testing.T) {
	for _, stage := range []RestoreStage{
		RestoreStageAdmitted, RestoreStagePreflight, RestoreStageStopping, RestoreStageCommitting,
		RestoreStageCommitted, RestoreStageCommitFailed, RestoreStageStarting, RestoreStageStarted,
	} {
		j := newTestJournal(t)
		if err := j.Write(restoreRecord(stage)); err != nil {
			t.Fatalf("%s: Write: %v", stage, err)
		}
		back, found, err := j.Read(ulidA)
		if err != nil || !found || back.RestoreStage != stage {
			t.Errorf("%s: read back %+v found=%v err=%v", stage, back, found, err)
		}
		if back != nil && back.Phase != PhaseAdmitted {
			t.Errorf("%s: a restore record's phase must stay admitted, got %q", stage, back.Phase)
		}
	}
}

// TestRestoreStage_WriteRejectsUnknown: a typo cannot be persisted, and a
// refused write leaves no file behind.
func TestRestoreStage_WriteRejectsUnknown(t *testing.T) {
	j := newTestJournal(t)
	for _, stage := range []RestoreStage{"done", "COMMITTED", "restarting", " "} {
		if err := j.Write(restoreRecord(stage)); err == nil || !strings.Contains(err.Error(), "invalid restore stage") {
			t.Errorf("Write(%q) = %v, want an invalid-restore-stage error", stage, err)
		}
	}
	if recs, err := j.List(); err != nil || len(recs) != 0 {
		t.Errorf("a refused write left %d record(s), err=%v", len(recs), err)
	}
}

// TestRestoreStage_OmittedWhenUnset: an upgrade or image-rollback record is
// byte-compatible with the schema that predates the key.
func TestRestoreStage_OmittedWhenUnset(t *testing.T) {
	j := newTestJournal(t)
	if err := j.Write(sampleRecord()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(j.Dir(), ulidA+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "restore_stage") {
		t.Errorf("a record without a stage carries the key:\n%s", raw)
	}
}

// TestUpgrade_OlderRecordWithoutRestoreStageLoads: a record written before the
// key existed — here a data rollback, the one restore-class kind that was
// already journaled — reads normally, with no stage.
func TestUpgrade_OlderRecordWithoutRestoreStageLoads(t *testing.T) {
	j := newTestJournal(t)
	const id = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
	body := `{"op_id":"` + id + `","kind":"rollbacks.create","mode":"data","phase":"admitted",` +
		`"started_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:01Z","interrupted_seen":2,"interrupt_audited":true}`
	if err := os.WriteFile(filepath.Join(j.Dir(), id+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, found, err := j.Read(id)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if rec.RestoreStage != "" || rec.Mode != "data" || rec.InterruptedSeen != 2 || !rec.InterruptAudited {
		t.Errorf("older record misread: %+v", rec)
	}
	// And startup can write it back (it rewrites every record it finds).
	if werr := j.Write(*rec); werr != nil {
		t.Errorf("an older record cannot be written back: %v", werr)
	}
}

// TestDowngrade_OlderReaderGetsARestoreRecord: what an agent that predates the
// key AND the kind does with a restore.commit record this build wrote. It
// decodes it (json.Unmarshal ignores the unknown key; the kind is a string the
// journal never checked), its closed phase set accepts it — so it does NOT
// refuse to serve — and when it writes the record back at its next start the
// key is gone. The older schema is the one journal_compat_test.go keeps.
func TestDowngrade_OlderReaderGetsARestoreRecord(t *testing.T) {
	j := newTestJournal(t)
	if err := j.Write(restoreRecord(RestoreStageCommitting)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(j.Dir(), ulidA+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"restore_stage": "committing"`) {
		t.Fatalf("record does not carry the key:\n%s", raw)
	}
	var old preRollbackArmedRecord
	if uerr := json.Unmarshal(raw, &old); uerr != nil {
		t.Fatalf("older schema cannot decode the record: %v", uerr)
	}
	if _, ok := validPhases[old.Phase]; !ok {
		t.Errorf("older reader sees unknown phase %q and would refuse to serve", old.Phase)
	}
	if old.Kind != "restore.commit" || old.OpID != ulidA {
		t.Errorf("older reader lost fields: %+v", old)
	}
	rewritten, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rewritten), "restore_stage") {
		t.Errorf("the older schema kept a key it does not know: %s", rewritten)
	}
	// This build then reads what the older one wrote back: no stage.
	if werr := os.WriteFile(filepath.Join(j.Dir(), ulidA+".json"), rewritten, 0o600); werr != nil {
		t.Fatal(werr)
	}
	back, found, err := j.Read(ulidA)
	if err != nil || !found || back.RestoreStage != "" || back.Kind != "restore.commit" {
		t.Errorf("after a downgrade round trip: %+v found=%v err=%v", back, found, err)
	}
}

// TestRead_UnknownRestoreStageIsNotCorrupt: a stage from a NEWER agent does not
// stop this one from serving (an unknown phase does: TestReadRejectsUnknownPhase).
// It reads as the one value that claims nothing, and the record stays writable.
func TestRead_UnknownRestoreStageIsNotCorrupt(t *testing.T) {
	j := newTestJournal(t)
	const id = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
	body := `{"op_id":"` + id + `","kind":"restore.commit","phase":"admitted","restore_stage":"verifying_restore",` +
		`"started_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:01Z"}`
	if err := os.WriteFile(filepath.Join(j.Dir(), id+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, found, err := j.Read(id)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if rec.RestoreStage != RestoreStageUnknown {
		t.Errorf("restore_stage = %q, want %q", rec.RestoreStage, RestoreStageUnknown)
	}
	if recs, lerr := j.List(); lerr != nil || len(recs) != 1 {
		t.Errorf("List: %d records, err=%v", len(recs), lerr)
	}
	if werr := j.Write(*rec); werr != nil {
		t.Errorf("the record cannot be written back: %v", werr)
	}
}
