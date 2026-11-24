package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"
)

// schema1Phases is the closed phase set of every agent released before
// ADR-0062 (journal.go validPhases at 03241de8f). It is frozen here on
// purpose: it stands for an OLDER binary, not for this one.
var schema1Phases = map[Phase]struct{}{
	"admitted": {}, "captured": {}, "resolved": {}, "pulled": {},
	"restarting": {}, "restarted": {}, "verified": {},
}

// olderAgentList is List as every agent before ADR-0062 runs it: strict-ULID
// file names, json.Unmarshal, the closed phase set, fail-closed on the first
// failure, no knowledge of the fence. initJournal refuses to serve when it
// returns an error.
func olderAgentList(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), fileExt) {
			continue
		}
		id := strings.TrimSuffix(e.Name(), fileExt)
		if _, err := ulid.ParseStrict(id); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- test temp dir
		if err != nil {
			return err
		}
		var old preRollbackArmedRecord
		if err := json.Unmarshal(data, &old); err != nil {
			return fmt.Errorf("%w: %v", ErrCorruptRecord, err)
		}
		if _, ok := schema1Phases[old.Phase]; !ok {
			return fmt.Errorf("%w: unknown phase %q", ErrCorruptRecord, old.Phase)
		}
	}
	return nil
}

func writeRaw(t *testing.T, j *Journal, id string, body map[string]any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(j.Dir(), id+fileExt), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func rawRecord(extra map[string]any) map[string]any {
	m := map[string]any{
		"op_id": ulidA, "kind": "upgrades.apply", "phase": "restarted",
		"started_at": "2026-11-24T10:00:00Z", "updated_at": "2026-11-24T10:00:00Z",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// TestRewrite_KeepsKeysThisBuildDoesNotKnow: a record a newer agent wrote with
// keys this build does not declare keeps them through a Read → Write cycle
// (startup rewrites every record it finds). Before ADR-0062 encoding/json
// dropped them.
func TestRewrite_KeepsKeysThisBuildDoesNotKnow(t *testing.T) {
	j := newTestJournal(t)
	writeRaw(t, j, ulidA, rawRecord(map[string]any{
		"checkpoint":   map[string]any{"step": "gate:target", "intent_at": "2026-11-24T10:00:01Z"},
		"future_flag":  true,
		"future_count": 3,
	}))
	rec, found, err := j.Read(ulidA)
	if err != nil || !found {
		t.Fatalf("Read: found=%v err=%v", found, err)
	}
	rec.InterruptedSeen = 1 // what startup's rewrite changes
	if err := j.Write(*rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(j.Dir(), ulidA+fileExt))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	cp, _ := got["checkpoint"].(map[string]any)
	if cp["step"] != "gate:target" || got["future_flag"] != true || got["future_count"] != float64(3) {
		t.Errorf("unknown keys lost on rewrite:\n%s", raw)
	}
	if got["interrupted_seen"] != float64(1) {
		t.Errorf("the rewrite itself did not land:\n%s", raw)
	}
}

// TestRewrite_RecordWithoutUnknownKeysIsUnchanged: a record this build wrote
// encodes exactly as before ADR-0062: no "schema" key, same bytes on rewrite.
func TestRewrite_RecordWithoutUnknownKeysIsUnchanged(t *testing.T) {
	j := newTestJournal(t)
	if err := j.Write(sampleRecord()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(j.Dir(), ulidA+fileExt)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, []byte(`"schema"`)) {
		t.Errorf("a schema-1 record gained a schema key:\n%s", first)
	}
	want, err := json.MarshalIndent(recordAlias(sampleRecord()), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, want) {
		t.Errorf("encoding changed:\n got %s\nwant %s", first, want)
	}
	rec, _, err := j.Read(ulidA)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Write(*rec); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("rewrite changed the bytes:\n%s\n---\n%s", first, second)
	}
}

// TestRewrite_KeepsAnUnknownRestoreStage: Read reports a restore stage it does
// not know as "unknown"; a rewrite must still write the original value back.
// A running restore that advances the stage writes its own value.
func TestRewrite_KeepsAnUnknownRestoreStage(t *testing.T) {
	j := newTestJournal(t)
	writeRaw(t, j, ulidA, rawRecord(map[string]any{"kind": "restore.commit", "phase": "admitted", "restore_stage": "verifying_volume"}))
	rec, _, err := j.Read(ulidA)
	if err != nil {
		t.Fatal(err)
	}
	if rec.RestoreStage != RestoreStageUnknown {
		t.Fatalf("Read stage = %q, want unknown", rec.RestoreStage)
	}
	if err := j.Write(*rec); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(j.Dir(), ulidA+fileExt))
	if !bytes.Contains(raw, []byte(`"restore_stage": "verifying_volume"`)) {
		t.Errorf("unknown stage not written back:\n%s", raw)
	}
	rec.RestoreStage = RestoreStageStarted
	if err := j.Write(*rec); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(j.Dir(), ulidA+fileExt))
	if !bytes.Contains(raw, []byte(`"restore_stage": "started"`)) {
		t.Errorf("an advanced stage was overwritten by the old unknown value:\n%s", raw)
	}
}

// TestNewerSchema_IsNeverRewrittenOrRemoved: a record from a newer agent is
// read and reported, but Write and Remove refuse it, so nothing that writes
// or removes a record before acting (write-ahead, retire) can act on it.
func TestNewerSchema_IsNeverRewrittenOrRemoved(t *testing.T) {
	j := newTestJournal(t)
	writeRaw(t, j, ulidA, rawRecord(map[string]any{"schema": SchemaCurrent + 1}))
	recs, err := j.List()
	if err != nil || len(recs) != 1 {
		t.Fatalf("List: %v %v (a newer record must still be listed and reported)", recs, err)
	}
	if !recs[0].FromNewerAgent() {
		t.Fatal("record not recognised as newer")
	}
	recs[0].InterruptedSeen = 1
	if err := j.Write(recs[0]); !errors.Is(err, ErrNewerSchema) {
		t.Errorf("Write = %v, want ErrNewerSchema", err)
	}
	if err := j.Remove(ulidA); !errors.Is(err, ErrNewerSchema) {
		t.Errorf("Remove = %v, want ErrNewerSchema", err)
	}
	if _, found, _ := j.Read(ulidA); !found {
		t.Error("the newer record was removed")
	}
}

// TestFence_GuardsFencedRecordsAgainstOlderAgents: writing a record that needs
// schema 2 first writes the fence; an agent released before ADR-0062 then
// refuses to serve on this directory (its List fails closed on the fence's
// phase), while this build lists only the operation. Removing the last such
// record releases the fence, and an older agent can serve again.
func TestFence_GuardsFencedRecordsAgainstOlderAgents(t *testing.T) {
	j := newTestJournal(t)
	if _, err := ulid.ParseStrict(fenceOpID); err != nil {
		t.Fatalf("fence name must pass an older agent's strict-ULID check: %v", err)
	}
	plain := sampleRecord()
	if err := j.Write(plain); err != nil {
		t.Fatal(err)
	}
	if on, _ := j.FenceActive(); on {
		t.Fatal("a schema-1 record raised the fence")
	}
	if err := olderAgentList(j.Dir()); err != nil {
		t.Fatalf("an older agent must still serve on schema-1 records: %v", err)
	}

	fenced := sampleRecord()
	fenced.OpID, fenced.Schema = ulidB, SchemaFenced
	if err := j.Write(fenced); err != nil {
		t.Fatal(err)
	}
	if on, _ := j.FenceActive(); !on {
		t.Fatal("no fence after a schema-2 record")
	}
	if err := olderAgentList(j.Dir()); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("older agent's List = %v, want it to fail closed (refuse to serve)", err)
	}
	recs, err := j.List()
	if err != nil || len(recs) != 2 {
		t.Fatalf("this build must list both operations and skip the fence: %v %v", recs, err)
	}

	if err := j.Remove(ulidA); err != nil {
		t.Fatal(err)
	}
	if on, _ := j.FenceActive(); !on {
		t.Fatal("fence released while a schema-2 record remains")
	}
	if err := j.Remove(ulidB); err != nil {
		t.Fatal(err)
	}
	if on, _ := j.FenceActive(); on {
		t.Fatal("fence kept after the last schema-2 record was removed")
	}
	if err := olderAgentList(j.Dir()); err != nil {
		t.Fatalf("an older agent must serve again once the fence is gone: %v", err)
	}
}
