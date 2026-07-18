package filetxn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBeginDetachesCandidateBytes(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact")
	candidate := []byte("new")
	tx, err := Begin(filepath.Join(dir, "bundle.txn"), "test", []Write{{Path: artifact, Data: candidate, Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	candidate[0] = 'X'
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, artifact); got != "new" {
		t.Fatalf("artifact = %q, want detached candidate", got)
	}
}

func TestBeginRejectsJournalArtifactCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collision")
	if _, err := Begin(path, "test", []Write{{Path: path, Data: []byte("payload"), Mode: 0o600}}); err == nil {
		t.Fatal("journal/artifact path collision accepted")
	}
}

func TestRecoverUncommittedRestoresAllOldArtifacts(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mustWrite(t, a, "old-a")
	mustWrite(t, b, "old-b")
	journal := filepath.Join(dir, "bundle.txn")

	tx, err := Begin(journal, "test", []Write{{Path: a, Data: []byte("new-a"), Mode: 0o600}, {Path: b, Data: []byte("new-b"), Mode: 0o600}}, WithBoundaryHook(func(point string) error {
		if point == "after-write-0" {
			return ErrSimulatedCrash
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); !errors.Is(err, ErrSimulatedCrash) {
		t.Fatalf("Apply = %v, want simulated crash", err)
	}
	if got := mustRead(t, a); got != "new-a" {
		t.Fatalf("a before recovery = %q", got)
	}
	if err := Recover(journal); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, a); got != "old-a" {
		t.Fatalf("a after recovery = %q", got)
	}
	if got := mustRead(t, b); got != "old-b" {
		t.Fatalf("b after recovery = %q", got)
	}
}

func TestRecoverCommittedKeepsCompleteNewGeneration(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mustWrite(t, a, "old-a")
	mustWrite(t, b, "old-b")
	journal := filepath.Join(dir, "bundle.txn")

	tx, err := Begin(journal, "test", []Write{{Path: a, Data: []byte("new-a"), Mode: 0o600}, {Path: b, Data: []byte("new-b"), Mode: 0o600}}, WithBoundaryHook(func(point string) error {
		if point == "after-commit" {
			return ErrSimulatedCrash
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); !errors.Is(err, ErrSimulatedCrash) {
		t.Fatalf("Commit = %v, want simulated crash", err)
	}
	if err := Recover(journal); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, a); got != "new-a" {
		t.Fatalf("a after recovery = %q", got)
	}
	if got := mustRead(t, b); got != "new-b" {
		t.Fatalf("b after recovery = %q", got)
	}
}

func TestApplyFailureRestoresOldGeneration(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	mustWrite(t, a, "old")
	bad := filepath.Join(dir, "missing", "b")
	tx, err := Begin(filepath.Join(dir, "bundle.txn"), "test", []Write{{Path: a, Data: []byte("new"), Mode: 0o600}, {Path: bad, Data: []byte("new"), Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err == nil {
		t.Fatal("Apply succeeded")
	}
	if got := mustRead(t, a); got != "old" {
		t.Fatalf("a after failed apply = %q", got)
	}
}

func TestRecoverRejectsTamperedJournalState(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact")
	journal := filepath.Join(dir, "bundle.txn")
	mustWrite(t, artifact, "old")
	tx, err := Begin(journal, "test", []Write{{Path: artifact, Data: []byte("new"), Mode: 0o600}}, WithBoundaryHook(func(point string) error {
		if point == "after-write-0" {
			return ErrSimulatedCrash
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); !errors.Is(err, ErrSimulatedCrash) {
		t.Fatalf("Apply = %v, want simulated crash", err)
	}
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Committed = true
	raw, err = json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Recover(journal); err == nil {
		t.Fatal("tampered transaction state accepted")
	}
}

func TestRecoverRejectsTamperedBeforeImage(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact")
	journal := filepath.Join(dir, "bundle.txn")
	mustWrite(t, artifact, "old")
	tx, err := Begin(journal, "test", []Write{{Path: artifact, Data: []byte("new"), Mode: 0o600}}, WithBoundaryHook(func(point string) error {
		if point == "after-write-0" {
			return ErrSimulatedCrash
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); !errors.Is(err, ErrSimulatedCrash) {
		t.Fatalf("Apply = %v, want simulated crash", err)
	}
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Files[0].Before[0] = 'X'
	raw, err = json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Recover(journal); err == nil {
		t.Fatal("tampered before-image accepted")
	}
	if got := mustRead(t, artifact); got != "new" {
		t.Fatalf("tampered recovery mutated artifact to %q", got)
	}
}

func TestRecoverRejectsCommittedModeMismatch(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "bundle.txn")
	artifact := filepath.Join(dir, "secret")
	mustWrite(t, artifact, "old")
	tx, err := Begin(journal, "test", []Write{{Path: artifact, Data: []byte("new"), Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Recover(journal); err == nil {
		t.Fatal("committed artifact mode mismatch accepted")
	}
}

func TestRecoverRejectsMalformedJournalAndCommittedDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "bundle.txn")
	mustWrite(t, journal, "not-json")
	if err := Recover(journal); err == nil {
		t.Fatal("malformed journal accepted")
	}

	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(dir, "a")
	mustWrite(t, a, "old")
	tx, err := Begin(journal, "test", []Write{{Path: a, Data: []byte("new"), Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, a, "tampered")
	if err := Recover(journal); err == nil {
		t.Fatal("committed digest mismatch accepted")
	}
}

func mustWrite(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
