package journal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Valid 26-char Crockford-base32 ULIDs for op_ids.
const (
	ulidA = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	ulidB = "01BX5ZZKBKACTAV9WEVGEMMVRZ"
)

func newTestJournal(t *testing.T) *Journal {
	t.Helper()
	j, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return j
}

func sampleRecord() Record {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return Record{
		OpID:         ulidA,
		Kind:         "upgrades.apply",
		Phase:        PhaseRestarting,
		TargetRef:    "ghcr.io/kidcarmi/culvert@sha256:aaaa",
		TargetDigest: "aaaa",
		PriorRef:     "ghcr.io/kidcarmi/culvert@sha256:bbbb",
		PriorDigest:  "bbbb",
		Actor:        "uid=1000,user=cp",
		StartedAt:    now,
		UpdatedAt:    now,
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	j := newTestJournal(t)
	want := sampleRecord()
	if err := j.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, found, err := j.Read(ulidA)
	if err != nil || !found {
		t.Fatalf("Read: found=%v err=%v", found, err)
	}
	if got.Phase != want.Phase || got.TargetDigest != want.TargetDigest ||
		got.PriorDigest != want.PriorDigest || got.Kind != want.Kind ||
		!got.StartedAt.Equal(want.StartedAt) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", *got, want)
	}
}

func TestReadMissingIsNotFound(t *testing.T) {
	j := newTestJournal(t)
	rec, found, err := j.Read(ulidB)
	if err != nil || found || rec != nil {
		t.Fatalf("missing read = (%v,%v,%v), want (nil,false,nil)", rec, found, err)
	}
}

func TestListReturnsAll(t *testing.T) {
	j := newTestJournal(t)
	a := sampleRecord()
	b := sampleRecord()
	b.OpID = ulidB
	b.Phase = PhasePulled
	if err := j.Write(a); err != nil {
		t.Fatal(err)
	}
	if err := j.Write(b); err != nil {
		t.Fatal(err)
	}
	recs, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("List returned %d, want 2", len(recs))
	}
}

func TestListFailsClosedOnCorruptRecord(t *testing.T) {
	j := newTestJournal(t)
	if err := j.Write(sampleRecord()); err != nil {
		t.Fatal(err)
	}
	// Drop a garbage <ulid>.json file (bit-rot / torn write of a complete record).
	corrupt := filepath.Join(j.Dir(), ulidB+".json")
	if err := os.WriteFile(corrupt, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := j.List()
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("List must fail closed on a corrupt record: err=%v", err)
	}
	if recs != nil {
		t.Error("List must return no partial list on corruption")
	}
}

func TestReadCorruptRecord(t *testing.T) {
	j := newTestJournal(t)
	if err := os.WriteFile(filepath.Join(j.Dir(), ulidA+".json"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, found, err := j.Read(ulidA)
	if !errors.Is(err, ErrCorruptRecord) || !found {
		t.Fatalf("corrupt read = (found=%v, err=%v), want (true, ErrCorruptRecord)", found, err)
	}
}

func TestRemoveThenAbsent(t *testing.T) {
	j := newTestJournal(t)
	if err := j.Write(sampleRecord()); err != nil {
		t.Fatal(err)
	}
	if err := j.Remove(ulidA); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	_, found, _ := j.Read(ulidA)
	if found {
		t.Error("record still present after Remove")
	}
	// Removing an absent record is not an error (idempotent).
	if err := j.Remove(ulidA); err != nil {
		t.Errorf("Remove of absent record must be nil, got %v", err)
	}
}

func TestInvalidOpIDRejected(t *testing.T) {
	j := newTestJournal(t)
	// Path-traversal / non-ULID op_ids must be rejected before any path join.
	for _, bad := range []string{"../evil", "not-a-ulid", "", "01ARZ3NDEKTSV4RRFFQ69G5FA/x"} {
		if err := j.Write(Record{OpID: bad, Phase: PhaseAdmitted}); err == nil {
			t.Errorf("Write with invalid op_id %q must error", bad)
		}
		if _, _, err := j.Read(bad); err == nil {
			t.Errorf("Read with invalid op_id %q must error", bad)
		}
	}
}

func TestInvalidPhaseRejected(t *testing.T) {
	j := newTestJournal(t)
	r := sampleRecord()
	r.Phase = "bogus"
	if err := j.Write(r); err == nil {
		t.Error("Write with an unknown phase must error")
	}
}

func TestWriteIsAtomicReplace(t *testing.T) {
	j := newTestJournal(t)
	r := sampleRecord()
	r.Phase = PhaseAdmitted
	if err := j.Write(r); err != nil {
		t.Fatal(err)
	}
	// Overwrite with a later phase — Read must see the new value, no partial mix.
	r.Phase = PhaseVerified
	r.TargetDigest = "cccc"
	if err := j.Write(r); err != nil {
		t.Fatal(err)
	}
	got, _, err := j.Read(ulidA)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != PhaseVerified || got.TargetDigest != "cccc" {
		t.Errorf("atomic overwrite not applied: %+v", *got)
	}
	// Exactly one record on disk (temp files cleaned up).
	recs, _ := j.List()
	if len(recs) != 1 {
		t.Errorf("expected 1 record after overwrite, got %d", len(recs))
	}
}
