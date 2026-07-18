package filetxn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// --- Preserved crash-matrix guarantees (no regression to single-file / bundle
// publication behavior). ---

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

// TestSingleFilePublicationRoundTrip exercises the full lifecycle including
// Finish, which drives durableWrite/durableRemove on a real directory — the A2
// path that must not double-fsync or spuriously fail. No regression proof.
func TestSingleFilePublicationRoundTrip(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "policy.json")
	journal := filepath.Join(dir, "policy.json.txn")
	mustWrite(t, artifact, "old")

	tx, err := Begin(journal, "policy", []Write{{Path: artifact, Data: []byte("new"), Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if got := mustRead(t, artifact); got != "new" {
		t.Fatalf("artifact after publish = %q, want new", got)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal survived Finish: stat err = %v", err)
	}
	// Recover after a clean Finish is a no-op (idempotent / deterministic).
	if err := Recover(journal); err != nil {
		t.Fatalf("Recover after Finish = %v, want nil", err)
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

// --- A1: no journal state may permanently wedge startup. ---

// TestRecoverSupersededCommittedByNewerWrite is the headline A1 fix: a journal
// that committed, then had its artifact overwritten by a newer authoritative
// write (e.g. an inline policy save over the same policy.json) must degrade to
// cleanup — never a fatal error that wedges boot on every restart.
func TestRecoverSupersededCommittedByNewerWrite(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "policy.json")
	journal := filepath.Join(dir, "config_apply.txn")
	mustWrite(t, artifact, "gen-old")

	tx, err := Begin(journal, "config", []Write{{Path: artifact, Data: []byte("gen-txn"), Mode: 0o600}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err) // committed but not Finished: crash-before-cleanup state.
	}

	// A newer authoritative write supersedes the committed generation.
	mustWrite(t, artifact, "gen-newer-inline")

	if err := Recover(journal); err != nil {
		t.Fatalf("Recover of superseded committed journal = %v, want nil (no wedge)", err)
	}
	if got := mustRead(t, artifact); got != "gen-newer-inline" {
		t.Fatalf("recovery clobbered the newer generation: %q", got)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded journal not cleaned up: stat err = %v", err)
	}
	// Deterministic + idempotent: the next boot's Recover is a clean no-op.
	if err := Recover(journal); err != nil {
		t.Fatalf("second Recover = %v, want nil", err)
	}
}

// TestRecoverCommittedArtifactRemoved: the committed artifact was deleted after
// commit. There is nothing to keep or restore; recovery must clean up, not fail.
func TestRecoverCommittedArtifactRemoved(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "a")
	journal := filepath.Join(dir, "bundle.txn")
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
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if err := Recover(journal); err != nil {
		t.Fatalf("Recover with removed committed artifact = %v, want nil", err)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal not cleaned up: stat err = %v", err)
	}
}

// TestRecoverCorruptJournalQuarantined: an unparseable journal is moved aside
// (observable via ErrJournalQuarantined and the .corrupt sidecar) and never
// wedges boot — a subsequent Recover finds a clean slate.
func TestRecoverCorruptJournalQuarantined(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "bundle.txn")
	mustWrite(t, journal, "not-json-at-all")

	err := Recover(journal)
	if !errors.Is(err, ErrJournalQuarantined) {
		t.Fatalf("Recover of corrupt journal = %v, want ErrJournalQuarantined", err)
	}
	if _, statErr := os.Stat(journal); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("corrupt journal not moved aside: stat err = %v", statErr)
	}
	if got := mustRead(t, journal+quarantineSuffix); got != "not-json-at-all" {
		t.Fatalf("quarantine sidecar = %q, want original bytes preserved", got)
	}
	// Self-healing: the wedge is broken because the next Recover is a no-op.
	if err := Recover(journal); err != nil {
		t.Fatalf("second Recover after quarantine = %v, want nil", err)
	}
}

// TestRecoverTamperedJournalNotObeyed: a journal whose fields were edited
// without recomputing the checksum is untrusted — it must be quarantined, and
// its (possibly malicious) before-image must NOT be written back over the
// artifact.
func TestRecoverTamperedJournalNotObeyed(t *testing.T) {
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
	// Tamper: flip the before-image without recomputing the record checksum.
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
	if err := Recover(journal); !errors.Is(err, ErrJournalQuarantined) {
		t.Fatalf("Recover of tampered journal = %v, want ErrJournalQuarantined", err)
	}
	if got := mustRead(t, artifact); got != "new" {
		t.Fatalf("tampered recovery mutated artifact to %q", got)
	}
}

// TestRecoverCommittedModeMismatchQuarantined: content matches the committed
// generation but the on-disk mode does not — an anomaly, surfaced observably
// and non-fatally rather than trusted or fataled.
func TestRecoverCommittedModeMismatchQuarantined(t *testing.T) {
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
	if err := Recover(journal); !errors.Is(err, ErrJournalQuarantined) {
		t.Fatalf("Recover with committed mode mismatch = %v, want ErrJournalQuarantined", err)
	}
	if _, statErr := os.Stat(journal); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("mode-mismatch journal not quarantined: stat err = %v", statErr)
	}
}

// TestRecoverIdempotent: running recovery twice over an uncommitted journal
// converges to all-old and the second pass is a clean no-op.
func TestRecoverIdempotent(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	mustWrite(t, a, "old")
	journal := filepath.Join(dir, "bundle.txn")
	tx, err := Begin(journal, "test", []Write{{Path: a, Data: []byte("new"), Mode: 0o600}}, WithBoundaryHook(func(point string) error {
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
	if err := Recover(journal); err != nil {
		t.Fatalf("first Recover = %v", err)
	}
	if got := mustRead(t, a); got != "old" {
		t.Fatalf("a after first recovery = %q", got)
	}
	if err := Recover(journal); err != nil {
		t.Fatalf("second Recover = %v, want nil no-op", err)
	}
	if got := mustRead(t, a); got != "old" {
		t.Fatalf("a after second recovery = %q", got)
	}
}

// TestBeginToleratesQuarantinedPriorJournal: an untrusted leftover journal must
// not block a caller from starting a fresh transaction — Begin quarantines it
// and proceeds.
func TestBeginToleratesQuarantinedPriorJournal(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "a")
	journal := filepath.Join(dir, "bundle.txn")
	mustWrite(t, artifact, "old")
	mustWrite(t, journal, "corrupt-leftover")

	tx, err := Begin(journal, "test", []Write{{Path: artifact, Data: []byte("new"), Mode: 0o600}})
	if err != nil {
		t.Fatalf("Begin over a quarantinable prior journal = %v, want success", err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Finish(); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, artifact); got != "new" {
		t.Fatalf("artifact = %q, want new after fresh txn", got)
	}
	if got := mustRead(t, journal+quarantineSuffix); got != "corrupt-leftover" {
		t.Fatalf("prior journal not quarantined for forensics: %q", got)
	}
}

// --- A2: directory-fsync tolerance is classified correctly; unsupported sync
// semantics do not masquerade as success, and real failures are not hidden. ---

func TestIsBenignDirSyncErr(t *testing.T) {
	benign := []error{syscall.EINVAL, syscall.ENOTSUP, syscall.EOPNOTSUPP}
	for _, e := range benign {
		if !isBenignDirSyncErr(e) {
			t.Errorf("isBenignDirSyncErr(%v) = false, want true (unsupported-fs is not a durability failure)", e)
		}
		// Must also match when wrapped, as os returns *PathError.
		if !isBenignDirSyncErr(&os.PathError{Op: "sync", Path: "/d", Err: e}) {
			t.Errorf("isBenignDirSyncErr(wrapped %v) = false, want true", e)
		}
	}
	fatal := []error{syscall.EIO, syscall.ENOSPC, syscall.EACCES}
	for _, e := range fatal {
		if isBenignDirSyncErr(e) {
			t.Errorf("isBenignDirSyncErr(%v) = true, want false (a real I/O failure must not be swallowed)", e)
		}
	}
}

// TestSyncDirOnSupportedDir: a real, supported directory syncs without error and
// does not fail spuriously (the A2 path exercised on the local filesystem).
func TestSyncDirOnSupportedDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir on a supported dir = %v, want nil", err)
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
