package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func newULID() string { return ulid.Make().String() }

// A corrupt record must be QUARANTINED (renamed aside) and the readable ones
// returned — never a fail-closed error that would crash-loop the agent.
func TestListQuarantining_MovesCorruptAsideAndContinues(t *testing.T) {
	j, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	good := newULID()
	now := time.Now().UTC()
	if err := j.Write(Record{OpID: good, Kind: "upgrades.apply", Phase: PhaseAdmitted, StartedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	bad := newULID()
	if err := os.WriteFile(filepath.Join(j.Dir(), bad+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(j.Dir(), "not-a-ulid.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Fail-closed List still refuses (the orchestrator-era contract is untouched).
	if _, lerr := j.List(); lerr == nil {
		t.Fatal("List must fail closed on a corrupt record")
	}
	recs, quarantined, err := j.ListQuarantining(now)
	if err != nil {
		t.Fatalf("ListQuarantining: %v", err)
	}
	if len(recs) != 1 || recs[0].OpID != good {
		t.Fatalf("recs: %+v want only %s", recs, good)
	}
	if len(quarantined) != 2 {
		t.Fatalf("quarantined: %v want 2 entries", quarantined)
	}
	// The originals are gone; the moved-aside files exist and are invisible to List.
	for _, q := range quarantined {
		if _, serr := os.Stat(filepath.Join(j.Dir(), q)); serr == nil {
			t.Errorf("%s must have been moved aside", q)
		}
	}
	if _, lerr := j.List(); lerr != nil {
		t.Fatalf("List after quarantine: %v", lerr)
	}
	qs, err := j.Quarantined()
	if err != nil {
		t.Fatal(err)
	}
	if len(qs) != 2 {
		t.Fatalf("Quarantined: %v", qs)
	}
	for _, q := range qs {
		if !strings.Contains(q, ".corrupt.") || strings.HasSuffix(q, ".json") {
			t.Errorf("quarantined name %q must carry .corrupt.<stamp> and not end in .json", q)
		}
	}
}

// Verdict sidecars live in a subdirectory: writing one never makes the record
// reader see a second "record", and the lifecycle is write → read → remove.
func TestVerdictSidecar_RoundTripAndInvisibleToList(t *testing.T) {
	j, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := newULID()
	type v struct {
		Verdict  string `json:"verdict"`
		Attempts int    `json:"attempts"`
	}
	var got v
	if found, rerr := j.ReadVerdict(id, &got); found || rerr != nil {
		t.Fatalf("absent verdict: found=%v err=%v", found, rerr)
	}
	if err := j.WriteVerdict(id, v{Verdict: "reup", Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	if found, rerr := j.ReadVerdict(id, &got); !found || rerr != nil || got.Verdict != "reup" || got.Attempts != 1 {
		t.Fatalf("read verdict: found=%v err=%v got=%+v", found, rerr, got)
	}
	recs, qs, err := j.ListQuarantining(time.Now())
	if err != nil || len(recs) != 0 || len(qs) != 0 {
		t.Fatalf("a verdict must never be read as a record: recs=%v qs=%v err=%v", recs, qs, err)
	}
	if err := j.RemoveVerdict(id); err != nil {
		t.Fatal(err)
	}
	if err := j.RemoveVerdict(id); err != nil {
		t.Fatalf("RemoveVerdict must be idempotent: %v", err)
	}
	if found, _ := j.ReadVerdict(id, &got); found {
		t.Fatal("verdict must be gone")
	}
	if err := j.WriteVerdict("../../etc/passwd", v{}); err == nil {
		t.Fatal("non-ULID op_id must be refused")
	}
}
