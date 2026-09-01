package logstore

// resilient_test.go — CHAOS-57 gates for OpenResilientTTL.
//
// The mechanism itself (markers, locking, quarantine) is proven by
// internal/catdb's suite, which runs unchanged against the shared
// internal/badgerguard implementation. What is proven HERE is the part that is
// specific to this store and that the shared code cannot know about:
//
//   - the encryption-key divergence, in both directions. This is the gate that
//     stops a future edit from destroying an operator's history because they
//     mistyped a passphrase.
//   - that the guard is actually wired into this store's constructor, which is
//     the whole defect: OpenTTL reaches badger.Open from the admin API.
//
// TestOpenResilientTTL_SurvivesUncatchablePanicOnNextOpen proves the panic
// claim live rather than asserting it from documentation.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/badgerguard"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func openPlain(t *testing.T, dir string) (*Store, Recovery, error) {
	t.Helper()
	return OpenResilientTTL(dir, time.Hour, 0, nil, nil)
}

// seedHistory creates a populated, cleanly-closed store and returns its path.
func seedHistory(t *testing.T, dir string, entries int, encKey []byte) {
	t.Helper()
	s, err := OpenTTL(dir, time.Hour, 0, encKey, nil)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	for i := 0; i < entries; i++ {
		s.Add(Entry{Host: "seed.example.com", Method: "GET"})
	}
	if err := s.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
}

func garbleFile(t *testing.T, p string, from int) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	for i := from; i < len(b); i++ {
		b[i] ^= 0xA5
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

// garbleTables scrambles every .sst — the fault that makes badger PANIC rather
// than return an error.
func garbleTables(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	n := 0
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".sst" {
			garbleFile(t, filepath.Join(dir, e.Name()), 0)
			n++
		}
	}
	return n
}

// ── the divergence: an encryption mismatch is NEVER corruption here ──────────

// This is the gate that protects an operator's history from their own typo.
//
// The shared corruption list contains "encryption key mismatch" because for the
// community category store — which is never opened with a key — that message
// can only mean KEYREGISTRY damage. This store IS opened with a key, so the same
// message means the passphrase changed or the .salt sidecar was lost: a
// recoverable configuration mistake with a documented remedy, not damage. If it
// were classified as corruption, the store would be moved aside at the exact
// moment the operator was trying to fix the passphrase.
//
// The control half matters as much as the assertion: it pins that the DEFAULT
// policy really does classify this as corruption, so the test would notice if
// Without() silently stopped removing anything.
func TestHistoryPolicy_EncryptionMismatchIsNeverCorruption(t *testing.T) {
	err := errors.New("Encryption key mismatch")

	if got := badgerguard.Classify(err, badgerguard.DefaultPolicy()); got != badgerguard.ClassCorrupt {
		t.Fatalf("control: default policy classified an encryption mismatch as %v, want ClassCorrupt — "+
			"this test can no longer detect a regression to the default", got)
	}
	if got := badgerguard.Classify(err, historyStorePolicy()); got == badgerguard.ClassCorrupt {
		t.Error("history policy classified an encryption-key mismatch as corruption — " +
			"a passphrase typo would move the operator's entire saved history aside")
	}
}

// Everything else in the shared corruption list must still apply: narrowing the
// policy must not disarm recovery for real damage.
func TestHistoryPolicy_RealCorruptionStillRecovers(t *testing.T) {
	for _, msg := range []string{
		"MANIFEST file might be corrupted",
		"manifest has bad magic",
		"checksum mismatch",
		"file does not exist for table",
		"log truncate required",
	} {
		if got := badgerguard.Classify(errors.New(msg), historyStorePolicy()); got != badgerguard.ClassCorrupt {
			t.Errorf("Classify(%q) = %v, want ClassCorrupt", msg, got)
		}
	}
}

// Environmental faults must still win: a full or read-only volume is not a
// reason to rename anybody's store.
func TestHistoryPolicy_EnvironmentalWinsOverCorruption(t *testing.T) {
	err := errors.New("checksum mismatch: no space left on device")
	if got := badgerguard.Classify(err, historyStorePolicy()); got != badgerguard.ClassEnvironment {
		t.Errorf("Classify = %v, want ClassEnvironment (a full disk must never trigger a rename)", got)
	}
}

// The end-to-end form of the same rule, through real badger: a store written
// under one key and reopened under another must come back as ErrEncMismatch
// with the store STILL THERE. Losing history to a passphrase mistake would be a
// data-loss bug introduced by a resilience feature.
func TestOpenResilientTTL_EncryptionMismatchPreservesTheStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logstore")
	keyA := []byte("0123456789abcdef0123456789abcdef")
	keyB := []byte("fedcba9876543210fedcba9876543210")
	seedHistory(t, dir, 20, keyA)

	s, rec, err := OpenResilientTTL(dir, time.Hour, 0, keyB, nil)
	if err == nil {
		_ = s.Close()
		t.Fatal("opening with the wrong key succeeded; the fixture no longer exercises the mismatch")
	}
	if !errors.Is(err, ErrEncMismatch) {
		t.Fatalf("err = %v, want ErrEncMismatch (the admin API keys its guidance on this sentinel)", err)
	}
	if rec.Quarantined {
		t.Fatalf("the store was quarantined over a key mismatch (moved to %s) — a passphrase typo must not reset history", rec.QuarantinePath)
	}
	if len(QuarantinedCopies(dir)) != 0 {
		t.Error("a .corrupt.* copy exists after a key mismatch; the store should have been left untouched")
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Errorf("the original store is gone after a key mismatch: %v", statErr)
	}
	// And the remedy the UI offers still works: the original key reopens it.
	back, _, berr := OpenResilientTTL(dir, time.Hour, 0, keyA, nil)
	if berr != nil {
		t.Fatalf("the store did not reopen with its original key: %v", berr)
	}
	_ = back.Close()
}

// ── the guard is wired in ────────────────────────────────────────────────────

func TestOpenResilientTTL_CleanOpenLeavesNoTrace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logstore")
	seedHistory(t, dir, 10, nil)

	s, rec, err := openPlain(t, dir)
	if err != nil {
		t.Fatalf("clean open: %v", err)
	}
	defer s.Close() //nolint:errcheck // test cleanup

	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Errorf("a healthy store was disturbed: %+v", rec)
	}
	if len(QuarantinedCopies(dir)) != 0 {
		t.Error("a healthy store produced a quarantined copy")
	}
	m, _ := filepath.Glob(badgerguard.StoreBase(dir) + badgerguard.MarkerSuffix + "*")
	if len(m) != 0 {
		t.Errorf("open markers left behind: %v", m)
	}
}

func TestOpenResilientTTL_CorruptManifestQuarantinesAndRecovers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logstore")
	seedHistory(t, dir, 50, nil)
	garbleFile(t, filepath.Join(dir, "MANIFEST"), 8)

	s, rec, err := openPlain(t, dir)
	if err != nil {
		t.Fatalf("OpenResilientTTL must recover a corrupt MANIFEST, got: %v", err)
	}
	defer s.Close() //nolint:errcheck // test cleanup

	if rec.Trigger != badgerguard.TriggerOpenError || !rec.Quarantined {
		t.Fatalf("damaged store was not quarantined: %+v", rec)
	}
	if _, err := os.Stat(rec.QuarantinePath); err != nil {
		t.Errorf("quarantined copy is not on disk (evidence destroyed): %v", err)
	}
}

// A marker with no live owner is the on-disk state a process that died inside
// badger.Open leaves behind. It must trigger a quarantine BEFORE badger is
// handed the directory again — that ordering is the entire fix, because the
// fault it recovers from is one badger will not let a caller catch.
func TestOpenResilientTTL_PoisonMarkerQuarantinesBeforeOpening(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logstore")
	seedHistory(t, dir, 10, nil)

	marker := badgerguard.StoreBase(dir) + badgerguard.MarkerSuffix + "1234-5678"
	if err := os.WriteFile(marker, []byte("pid=1234\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}

	s, rec, err := openPlain(t, dir)
	if err != nil {
		t.Fatalf("open after a poison marker: %v", err)
	}
	defer s.Close() //nolint:errcheck // test cleanup

	if rec.Trigger != badgerguard.TriggerPoisonMarker || !rec.Quarantined {
		t.Fatalf("poison marker did not trigger a quarantine: %+v", rec)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("the acted-on marker was not cleared; the next open would quarantine again")
	}
}

// A store another process is actively using must never be renamed away, even
// when a poison marker is present: renaming a live store is destructive, and
// rename(2) does not consult flocks.
func TestOpenResilientTTL_NeverQuarantinesAStoreAnotherOpenerHolds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logstore")
	seedHistory(t, dir, 10, nil)

	holder, err := OpenTTL(dir, time.Hour, 0, nil, nil)
	if err != nil {
		t.Fatalf("holder open: %v", err)
	}
	defer holder.Close() //nolint:errcheck // test cleanup

	marker := badgerguard.StoreBase(dir) + badgerguard.MarkerSuffix + "1234-5678"
	if err := os.WriteFile(marker, []byte("pid=1234\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}

	s, rec, err := openPlain(t, dir)
	if err == nil {
		_ = s.Close()
	}
	if rec.Quarantined {
		t.Fatalf("a live store was quarantined out from under its owner (moved to %s)", rec.QuarantinePath)
	}
	if rec.Skipped == "" {
		t.Error("the refusal was not recorded; an operator cannot tell recovery was declined")
	}
}

// ── the uncatchable panic, proven live ───────────────────────────────────────

// The defect this whole file exists for. A corrupt .sst panics out of a
// goroutine badger spawns, so no recover() at the call site helps:
//
//	open 1 — the process dies inside badger.Open, leaving a flocked marker
//	         whose lock the kernel releases
//	open 2 — the marker triggers a quarantine before badger is touched, and
//	         the store comes up
//
// Without the marker, open 2 is byte-identical to open 1. On the boot path that
// is a crash loop; from the admin API it is a serving gateway killed by a
// toggle.
func TestOpenResilientTTL_SurvivesUncatchablePanicOnNextOpen(t *testing.T) {
	if dir := os.Getenv("CULVERT_LOGSTORE_PANIC_CHILD"); dir != "" {
		runPanicChild(dir)
		return
	}

	dir := filepath.Join(t.TempDir(), "logstore")
	seedHistory(t, dir, 3000, nil)
	if n := garbleTables(t, dir); n == 0 {
		t.Skip("seed did not flush an .sst table; nothing to corrupt")
	}

	first, firstErr := runChildOpen(t, dir)
	if strings.Contains(first, "child: recovered") {
		t.Error("the panic was catchable at the call site — the marker mechanism is no longer needed; simplify")
	}
	if firstErr == nil || strings.Contains(first, "child: returned") {
		t.Skipf("badger no longer panics on a corrupt table (returned instead): %s", first)
	}
	if got := badgerguard.AbandonedMarkers(dir); len(got) != 1 {
		t.Fatalf("abandoned markers after the panic = %v, want exactly 1 — the next open cannot recover", got)
	}

	second, secondErr := runChildOpen(t, dir)
	if secondErr != nil {
		t.Fatalf("open 2 did not recover from the poisoned store: %v\n%s", secondErr, second)
	}
	if !strings.Contains(second, "quarantined=true trigger=poison_marker") {
		t.Errorf("open 2 did not recover via the poison marker; output:\n%s", second)
	}
}

func runPanicChild(dir string) {
	defer func() {
		// Proves the panic is NOT recoverable here. If this ever fires, the
		// assertion above turns it into a failure so the mechanism can be
		// simplified deliberately rather than by accident.
		if v := recover(); v != nil {
			os.Stdout.WriteString("child: recovered\n")
		}
	}()
	s, rec, err := OpenResilientTTL(dir, time.Hour, 0, nil, nil)
	e := "<nil>"
	if err != nil {
		e = err.Error()
	}
	q := "false"
	if rec.Quarantined {
		q = "true"
	}
	os.Stdout.WriteString("child: returned err=" + e + " quarantined=" + q + " trigger=" + string(rec.Trigger) + "\n")
	if s != nil {
		_ = s.Close()
	}
}

func runChildOpen(t *testing.T, dir string) (string, error) {
	t.Helper()
	// The child is this same test binary with a literal flag and no external
	// input; a subprocess is the only way to observe a panic badger raises from
	// its own goroutine without killing the parent test process.
	cmd := exec.CommandContext(t.Context(), os.Args[0], // #nosec G204,G702 -- this test binary + a fixed flag, not external/user input
		"-test.run", "TestOpenResilientTTL_SurvivesUncatchablePanicOnNextOpen")
	cmd.Env = append(os.Environ(), "CULVERT_LOGSTORE_PANIC_CHILD="+dir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
