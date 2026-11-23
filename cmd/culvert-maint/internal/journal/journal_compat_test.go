package journal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// preRollbackArmedRecord is the Record schema of an agent that predates the
// RollbackArmed key (the schema at lifecycle-final-running-evidence). It stands
// in for an OLDER agent reading a record this build wrote, i.e. a downgrade.
type preRollbackArmedRecord struct {
	OpID             string     `json:"op_id"`
	Kind             string     `json:"kind"`
	Mode             string     `json:"mode,omitempty"`
	Phase            Phase      `json:"phase"`
	TargetRef        string     `json:"target_ref,omitempty"`
	TargetDigest     string     `json:"target_digest,omitempty"`
	TargetImageID    string     `json:"target_image_id,omitempty"`
	PriorRef         string     `json:"prior_ref,omitempty"`
	PriorDigest      string     `json:"prior_digest,omitempty"`
	PriorImageID     string     `json:"prior_image_id,omitempty"`
	Actor            string     `json:"actor,omitempty"`
	StartedAt        time.Time  `json:"started_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	InterruptedAt    *time.Time `json:"interrupted_at,omitempty"`
	InterruptedSeen  int        `json:"interrupted_seen,omitempty"`
	InterruptAudited bool       `json:"interrupt_audited,omitempty"`
}

// TestDowngrade_OlderReaderIgnoresRollbackArmed: a record carrying
// rollback_armed decodes with the older schema exactly as the older Read does
// (json.Unmarshal, then the closed phase set): no error, the phase is still a
// known one, and every other field survives. This is why the marker is a key
// and not a new Phase (an older agent refuses to serve on an unknown phase:
// TestReadRejectsUnknownPhase).
func TestDowngrade_OlderReaderIgnoresRollbackArmed(t *testing.T) {
	j := newTestJournal(t)
	rec := sampleRecord()
	rec.RollbackArmed = true
	if err := j.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(j.Dir(), ulidA+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"rollback_armed": true`) {
		t.Fatalf("record does not carry the key:\n%s", raw)
	}
	var old preRollbackArmedRecord
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatalf("older schema cannot decode the record: %v", err)
	}
	if _, ok := validPhases[old.Phase]; !ok {
		t.Errorf("older reader sees unknown phase %q", old.Phase)
	}
	if old.Phase != rec.Phase || old.TargetRef != rec.TargetRef || old.PriorRef != rec.PriorRef ||
		old.PriorDigest != rec.PriorDigest || !old.StartedAt.Equal(rec.StartedAt) {
		t.Errorf("older reader lost fields: %+v", old)
	}
}

// TestRollbackArmed_OmittedWhenUnset: a record that never armed a rollback is
// byte-compatible with the older schema (no new key is written).
func TestRollbackArmed_OmittedWhenUnset(t *testing.T) {
	j := newTestJournal(t)
	if err := j.Write(sampleRecord()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(j.Dir(), ulidA+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "rollback_armed") {
		t.Errorf("unset marker was written:\n%s", raw)
	}
	back, _, err := j.Read(ulidA)
	if err != nil || back.RollbackArmed {
		t.Errorf("read: armed=%v err=%v", back != nil && back.RollbackArmed, err)
	}
}

// TestRead_ToleratesUnknownKeys: a record written by a NEWER agent with keys
// this build does not know reads normally (forward compatibility), and the
// known RollbackArmed key round-trips.
func TestRead_ToleratesUnknownKeys(t *testing.T) {
	j := newTestJournal(t)
	const id = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
	body := `{"op_id":"` + id + `","kind":"upgrades.apply","phase":"restarted","rollback_armed":true,` +
		`"some_future_key":{"nested":[1,2]},"started_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:01Z"}`
	if err := os.WriteFile(filepath.Join(j.Dir(), id+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, found, err := j.Read(id)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if !rec.RollbackArmed || rec.Phase != PhaseRestarted {
		t.Errorf("got armed=%v phase=%q", rec.RollbackArmed, rec.Phase)
	}
	if recs, lerr := j.List(); lerr != nil || len(recs) != 1 {
		t.Errorf("List: %d records, err=%v", len(recs), lerr)
	}
}
