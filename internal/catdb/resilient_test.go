package catdb

// resilient_test.go — CHAOS-50 gates for OpenResilient.
//
// Every scenario here was first reproduced against the pre-fix engine; the
// fault → badger-message table the classifier is built on is captured in
// TestClassifyOpenError_EmpiricalBadgerMessages, and the uncatchable-panic
// claim is proven live (not asserted from documentation) by
// TestOpenResilient_SurvivesUncatchableOpenPanicOnNextBoot.

// CHAOS-57 note: the machinery these gates exercise moved to
// `internal/storeguard` so the request-history store could reuse it. The gates
// themselves are unchanged and still run against the REAL community store — the
// aliases below only re-point the identifiers at their new home, so what is
// asserted, and the store it is asserted against, are exactly what they were.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/storeguard"
)

// ── the machinery under test, at its new address ─────────────────────────────

type openErrClass = storeguard.OpenErrClass

const (
	classUnknown         = storeguard.ClassUnknown
	classEnvironment     = storeguard.ClassEnvironment
	classCorrupt         = storeguard.ClassCorrupt
	markerSuffix         = storeguard.MarkerSuffix
	markerTempSuffix     = storeguard.MarkerTempSuffix
	quarantineSuffix     = storeguard.QuarantineSuffix
	maxQuarantinedCopies = storeguard.MaxQuarantinedCopies
)

var (
	lockStore           = storeguard.LockStore
	quarantineDir       = storeguard.QuarantineDir
	abandonedMarkers    = storeguard.AbandonedMarkers
	beginAttempt        = storeguard.BeginAttempt
	errStoreLockNotHeld = storeguard.ErrStoreLockNotHeld
	trimSep             = func(p string) string { return strings.TrimSuffix(p, string(os.PathSeparator)) }
)

// classifyOpenError classifies under THIS store's policy, which is the empty
// one — see communityStorePolicy.
func classifyOpenError(err error) openErrClass {
	return storeguard.ClassifyOpenError(err, communityStorePolicy)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// seedStore creates a populated, cleanly-closed store and returns its path.
func seedStore(t *testing.T, entries int) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	m := make(map[string]string, entries)
	for i := 0; i < entries; i++ {
		m[hostFor(i)] = "Social"
	}
	if err := db.BulkWrite(m); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	return dir
}

func hostFor(i int) string {
	return string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26)) + ".example.com"
}

// garbleFile XORs a file from offset `from` — a torn/scrambled write.
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

// garbleTables scrambles every .sst in the store. This is the fault that makes
// badger PANIC rather than return an error.
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
	if n == 0 {
		t.Fatalf("no .sst files in %s — seed did not flush a table", dir)
	}
	return n
}

// plantAbandonedMarker writes a marker with no live owner — the on-disk state a
// process that died inside badger.Open leaves behind (the kernel releases its
// flock, the file stays).
func plantAbandonedMarker(t *testing.T, dir string) string {
	t.Helper()
	p := trimSep(dir) + markerSuffix + "1234-5678"
	if err := os.WriteFile(p, []byte("pid=1234\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}
	return p
}

// markerFiles lists every open-attempt marker beside dir, live or abandoned.
func markerFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(trimSep(dir) + markerSuffix + "*")
	if err != nil {
		t.Fatalf("glob markers: %v", err)
	}
	return m
}

// ── the core contract ────────────────────────────────────────────────────────

func TestOpenResilient_CleanOpenLeavesNoTrace(t *testing.T) {
	dir := seedStore(t, 50)
	db, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Errorf("clean open recovered something: %+v", rec)
	}
	if m := markerFiles(t, dir); len(m) != 0 {
		t.Errorf("open markers left behind after a successful open: %v", m)
	}
	if q := QuarantinedCopies(dir); len(q) != 0 {
		t.Errorf("clean open quarantined %v", q)
	}
	if cat, ok := db.Lookup(hostFor(0)); !ok || cat != "Social" {
		t.Errorf("existing data lost on a clean open: %q %v", cat, ok)
	}
}

func TestOpenResilient_FirstRunCreatesTheStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Errorf("first run recovered something: %+v", rec)
	}
}

// A corrupt MANIFEST is the classic unclean-kill fault: badger RETURNS an
// error, so recovery completes within a single boot.
func TestOpenResilient_CorruptManifestQuarantinesAndRecoversInOneBoot(t *testing.T) {
	dir := seedStore(t, 50)
	garbleFile(t, filepath.Join(dir, "MANIFEST"), 8)

	db, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("OpenResilient must recover a corrupt MANIFEST, got: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	if rec.Trigger != TriggerOpenError {
		t.Errorf("Trigger = %q, want %q", rec.Trigger, TriggerOpenError)
	}
	if !rec.Quarantined || rec.QuarantinePath == "" {
		t.Fatalf("damaged store was not quarantined: %+v", rec)
	}
	if !strings.Contains(rec.QuarantinePath, quarantineSuffix) {
		t.Errorf("quarantine path %q does not use the .corrupt.<ts> convention", rec.QuarantinePath)
	}
	if _, err := os.Stat(rec.QuarantinePath); err != nil {
		t.Errorf("quarantined copy is not on disk (evidence destroyed): %v", err)
	}
	// The replacement is a fresh, empty store the syncer refills.
	if _, ok := db.Lookup(hostFor(0)); ok {
		t.Error("re-created store still serves data from the damaged copy")
	}
	if m := markerFiles(t, dir); len(m) != 0 {
		t.Errorf("open markers left behind after recovery: %v", m)
	}
}

// The poison marker is the ONLY signal available for a fault badger does not
// return from. A marker present at open time means a previous process entered
// badger.Open and never came back out, so the directory is moved aside BEFORE
// badger is allowed near it again.
//
// This deliberately quarantines a store that may be perfectly healthy (a
// SIGKILL that happened to land inside Open). That trade is accepted because
// the store holds no authoritative state: the cost is one feed re-sync, and the
// copy is preserved rather than deleted.
func TestOpenResilient_PoisonMarkerQuarantinesBeforeTouchingTheStore(t *testing.T) {
	dir := seedStore(t, 50)
	plantAbandonedMarker(t, dir)

	db, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("open after a poison marker: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	if rec.Trigger != TriggerPoisonMarker {
		t.Errorf("Trigger = %q, want %q", rec.Trigger, TriggerPoisonMarker)
	}
	if !rec.Quarantined {
		t.Fatalf("marker did not trigger a quarantine: %+v", rec)
	}
	if _, ok := db.Lookup(hostFor(0)); ok {
		t.Error("store was not actually replaced")
	}
	if m := markerFiles(t, dir); len(m) != 0 {
		t.Errorf("abandoned marker was not cleared — it would re-fire every boot: %v", m)
	}
}

// THE safety gate. A concurrent boot that is still inside its own Open holds
// the store's flock. Renaming the directory out from under it would be
// destructive, so a live lock holder must veto the quarantine even when the
// poison marker says the store is suspect.
func TestOpenResilient_NeverQuarantinesAStoreAnotherProcessHolds(t *testing.T) {
	dir := seedStore(t, 50)
	holder, err := Open(dir)
	if err != nil {
		t.Fatalf("holder open: %v", err)
	}
	defer holder.Close() //nolint:errcheck // test cleanup

	planted := plantAbandonedMarker(t, dir)

	db, rec, err := OpenResilient(dir)
	if err == nil {
		db.Close() //nolint:errcheck // test cleanup
		t.Fatal("second open of a locked store unexpectedly succeeded")
	}
	if rec.Quarantined {
		t.Fatalf("QUARANTINED A LIVE STORE: %+v", rec)
	}
	if rec.Skipped == "" {
		t.Error("skip reason not recorded")
	}
	if q := QuarantinedCopies(dir); len(q) != 0 {
		t.Errorf("a .corrupt.* copy was created for a live store: %v", q)
	}
	// The holder's data must be untouched.
	if cat, ok := holder.Lookup(hostFor(0)); !ok || cat != "Social" {
		t.Errorf("live store was damaged: %q %v", cat, ok)
	}
	// And the breadcrumb must SURVIVE. A skipped quarantine leaves the poison
	// condition unresolved, so clearing the marker here would mean the next boot
	// walks into the corrupt store again — the crash loop this file exists to
	// break would persist through its own mechanism.
	if _, err := os.Stat(planted); err != nil {
		t.Errorf("abandoned marker was cleared despite the quarantine being skipped: %v", err)
	}
}

// Environmental faults must degrade, never destroy: renaming fixes none of
// them, and on some of them it is actively harmful.
func TestOpenResilient_EnvironmentalFailureDegradesWithoutQuarantine(t *testing.T) {
	base := t.TempDir()
	p := filepath.Join(base, "notadir")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, rec, err := OpenResilient(p)
	if err == nil {
		db.Close() //nolint:errcheck // test cleanup
		t.Fatal("opening a regular file as a store unexpectedly succeeded")
	}
	if rec.Quarantined {
		t.Errorf("environmental failure quarantined: %+v", rec)
	}
	if q := QuarantinedCopies(p); len(q) != 0 {
		t.Errorf("environmental failure created %v", q)
	}
	if m := markerFiles(t, p); len(m) != 0 {
		t.Errorf("open markers left behind after an environmental failure: %v", m)
	}
}

// A store that can be gigabytes must not accumulate copies without bound on a
// host that keeps producing corruption.
func TestOpenResilient_QuarantinedCopiesAreBounded(t *testing.T) {
	dir := seedStore(t, 50)
	for i := 0; i < 4; i++ {
		garbleFile(t, filepath.Join(dir, "MANIFEST"), 8)
		db, rec, err := OpenResilient(dir)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if !rec.Quarantined {
			t.Fatalf("round %d did not quarantine: %+v", i, rec)
		}
		if err := db.BulkWrite(map[string]string{hostFor(0): "Social"}); err != nil {
			t.Fatalf("round %d write: %v", i, err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("round %d close: %v", i, err)
		}
	}
	if got := len(QuarantinedCopies(dir)); got > maxQuarantinedCopies {
		t.Errorf("quarantined copies = %d, want <= %d (unbounded evidence fills the volume)", got, maxQuarantinedCopies)
	}
}

// The marker is a SIBLING of the store, so a quarantine cannot carry it into
// the moved-aside directory and lose the breadcrumb.
func TestOpenResilient_MarkerIsASiblingNotAChild(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	a := beginAttempt(dir)
	defer a.End()
	if a.Path == "" {
		t.Fatal("marker could not be armed")
	}
	if filepath.Dir(a.Path) != filepath.Dir(dir) {
		t.Errorf("marker %q is not a sibling of %q", a.Path, dir)
	}
	if strings.HasPrefix(a.Path, dir+string(filepath.Separator)) {
		t.Errorf("marker %q lives INSIDE the store — a quarantine would carry it away", a.Path)
	}
	// A trailing separator must not produce a nested marker either.
	b := beginAttempt(dir + string(filepath.Separator))
	defer b.End()
	if filepath.Dir(b.Path) != filepath.Dir(dir) {
		t.Errorf("marker %q for a trailing-separator path is not a sibling", b.Path)
	}
}

func TestOpenResilient_ResidualQuarantinesAreReported(t *testing.T) {
	dir := seedStore(t, 20)
	garbleFile(t, filepath.Join(dir, "MANIFEST"), 8)
	db, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(rec.ResidualQuarantines) != 1 {
		t.Fatalf("ResidualQuarantines = %v, want 1", rec.ResidualQuarantines)
	}
	// The next boot is clean, but the evidence is still on the volume and must
	// stay visible — the in-memory record does not survive a restart.
	db2, rec2, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer db2.Close() //nolint:errcheck // test cleanup
	if rec2.Quarantined {
		t.Error("a healthy store was quarantined on the following boot")
	}
	if len(rec2.ResidualQuarantines) != 1 {
		t.Errorf("residual quarantine went unreported on the next boot: %v", rec2.ResidualQuarantines)
	}
}

// ── classifier ───────────────────────────────────────────────────────────────

// The exact strings badger v4.9.6 produced for each injected fault. Recorded
// here because none of them are reachable through errors.Is — badger wraps with
// y.Wrapf, which implements no Unwrap — so this table IS the contract, and a
// badger upgrade that changes the wording must fail here rather than silently
// stop recovering.
func TestClassifyOpenError_EmpiricalBadgerMessages(t *testing.T) {
	tests := []struct {
		fault string
		msg   string
		want  openErrClass
	}{
		{"MANIFEST scrambled", `Buffer length: 4294967295 greater than file size: 30. Manifest file might be corrupted`, classCorrupt},
		{"MANIFEST truncated", `manifest has bad magic`, classCorrupt},
		{"MANIFEST emptied", `manifest has bad magic`, classCorrupt},
		{"MANIFEST checksum", `manifest has checksum mismatch`, classCorrupt},
		{"table missing", `file does not exist for table 1`, classCorrupt},
		{"KEYREGISTRY scrambled", `Encryption key mismatch`, classCorrupt},
		{"value-log truncation needed", `Log truncate required to run DB. This might result in data loss`, classCorrupt},
		{"block checksum", `checksum mismatch actual: 1 expected: 2`, classCorrupt},

		{"dir lock held", `Cannot acquire directory lock on "/data/catfeeddb".  Another process is using this Badger database. err: resource temporarily unavailable`, classEnvironment},
		{"path is a file", `Cannot write pid file "/data/catfeeddb/LOCK" err: open /data/catfeeddb/LOCK: not a directory`, classEnvironment},
		{"read-only volume", `open /data/catfeeddb/LOCK: read-only file system`, classEnvironment},
		{"no permission", `open /data/catfeeddb/LOCK: permission denied`, classEnvironment},
		{"volume full", `write /data/catfeeddb/000001.vlog: no space left on device`, classEnvironment},
		{"fd exhaustion", `open /data/catfeeddb/MANIFEST: too many open files`, classEnvironment},
		{"failing device", `read /data/catfeeddb/MANIFEST: input/output error`, classEnvironment},

		{"unrecognised", `something nobody has seen before`, classUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.fault, func(t *testing.T) {
			if got := classifyOpenError(errString(tc.msg)); got != tc.want {
				t.Errorf("classify(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}

// The lock message contains the substring "directory lock", but the
// environmental deny-list is consulted BEFORE the corruption allow-list, so a
// message that happens to contain both can never authorise a rename.
func TestClassifyOpenError_EnvironmentalWinsOverCorruption(t *testing.T) {
	mixed := errString(`Another process is using this Badger database; manifest has bad magic`)
	if got := classifyOpenError(mixed); got != classEnvironment {
		t.Errorf("classify = %v, want classEnvironment (deny-list must win)", got)
	}
}

func TestClassifyOpenError_NilIsUnknown(t *testing.T) {
	if got := classifyOpenError(nil); got != classUnknown {
		t.Errorf("classify(nil) = %v, want classUnknown", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// ── the uncatchable panic ────────────────────────────────────────────────────

// A corrupt `.sst` makes badger.Open PANIC from a goroutine badger itself
// spawns (table.OpenTable ← newLevelsController), so no recover() at any call
// site can contain it. This test proves both halves live, in child processes:
//
//	boot 1 — the process dies and recover() never fires, but the marker survives
//	boot 2 — the marker triggers a quarantine before badger is touched, and the
//	         process comes up
//
// Without the marker, boot 2 is byte-identical to boot 1 and the appliance
// never comes up again.
func TestOpenResilient_SurvivesUncatchableOpenPanicOnNextBoot(t *testing.T) {
	if dir := os.Getenv("CULVERT_CATDB_PANIC_CHILD"); dir != "" {
		runPanicRecoveryChild(dir)
		return
	}

	dir := seedStore(t, 3000)
	garbleTables(t, dir)

	first, firstErr := runChildBoot(t, dir)
	if strings.Contains(first, "child: recovered") {
		t.Error("the panic was catchable at the call site — the marker mechanism is no longer needed; simplify")
	}
	if firstErr == nil || strings.Contains(first, "child: returned") {
		t.Skipf("badger no longer panics on a corrupt table (returned instead): %s", first)
	}
	// The dead child's marker must survive AND be recognised as abandoned: the
	// kernel released its flock when the process died, which is exactly what
	// distinguishes it from a marker a live opener still owns.
	if got := abandonedMarkers(dir); len(got) != 1 {
		t.Fatalf("abandoned markers after the panic = %v, want exactly 1 — the next boot cannot recover", got)
	}

	second, secondErr := runChildBoot(t, dir)
	if secondErr != nil {
		t.Fatalf("boot 2 did not recover from the poisoned store: %v\n%s", secondErr, second)
	}
	if !strings.Contains(second, "child: returned err=<nil> quarantined=true trigger=poison_marker") {
		t.Errorf("boot 2 did not recover via the poison marker; output:\n%s", second)
	}
	if got := QuarantinedCopies(dir); len(got) != 1 {
		t.Errorf("quarantined copies after recovery = %v, want exactly 1", got)
	}
}

func runPanicRecoveryChild(dir string) {
	defer func() {
		// Proves the panic is NOT recoverable here. If this ever fires, the
		// assertion above turns it into a failure so the mechanism can be
		// simplified deliberately rather than by accident.
		if v := recover(); v != nil {
			os.Stdout.WriteString("child: recovered\n")
		}
	}()
	db, rec, err := OpenResilient(dir)
	e := "<nil>"
	if err != nil {
		e = err.Error()
	}
	q := "false"
	if rec.Quarantined {
		q = "true"
	}
	os.Stdout.WriteString("child: returned err=" + e + " quarantined=" + q + " trigger=" + string(rec.Trigger) + "\n")
	if db != nil {
		_ = db.Close()
	}
}

func runChildBoot(t *testing.T, dir string) (string, error) {
	t.Helper()
	// #nosec G204,G702 -- re-exec of THIS test binary (os.Args[0]) with a fixed,
	// literal flag and no external input; the child process is the only way to
	// observe a panic badger raises from its own goroutine without killing the parent.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "TestOpenResilient_SurvivesUncatchableOpenPanicOnNextBoot")
	cmd.Env = append(os.Environ(), "CULVERT_CATDB_PANIC_CHILD="+dir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// A directory at the marker path is not a poison signal. os.Remove cannot clear
// one, so treating it as a signal would quarantine a healthy store on every boot
// forever — the opposite of the self-healing this file exists to provide.
func TestOpenResilient_NonRegularMarkerIsIgnored(t *testing.T) {
	dir := seedStore(t, 20)
	if err := os.Mkdir(trimSep(dir)+markerSuffix+"adir", 0o700); err != nil {
		t.Fatalf("mkdir marker: %v", err)
	}
	db, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	if rec.Quarantined || rec.Trigger != TriggerNone {
		t.Errorf("a directory at the marker path was treated as poison: %+v", rec)
	}
	if cat, ok := db.Lookup(hostFor(0)); !ok || cat != "Social" {
		t.Errorf("healthy store was replaced: %q %v", cat, ok)
	}
}

// A store on a path whose parent does not exist yet must still be protected on
// its very first open: the marker is a sibling and is written before badger
// gets a chance to MkdirAll the store directory.
func TestOpenResilient_FreshNestedPathIsProtectedFromTheFirstBoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "deeper", "catfeeddb")
	db, _, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("first open on a nested path: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Simulate the process dying inside the next open.
	plantAbandonedMarker(t, dir)
	if len(abandonedMarkers(dir)) != 1 {
		t.Fatal("marker could not be armed on a nested path — the first boot would run unprotected")
	}
	db2, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("recovery open: %v", err)
	}
	defer db2.Close() //nolint:errcheck // test cleanup
	if !rec.Quarantined {
		t.Errorf("nested path did not recover: %+v", rec)
	}
}

// The store lock must be HELD ACROSS THE RENAME, not probed and released before
// it. Probing and letting go leaves a window in which another process acquires
// badger's directory lock and begins opening, only to have its live directory
// renamed underneath it — rename does not consult flocks. This pins the
// primitive: while the handle is held, a competing open is refused; once
// released, it succeeds.
func TestOpenResilient_HeldStoreLockRefusesACompetingOpen(t *testing.T) {
	dir := seedStore(t, 20)

	lock, err := lockStore(dir)
	if err != nil || lock == nil {
		t.Fatalf("lockStore = (%v, %v), want a held lock", lock, err)
	}

	// A second attempt must see it as taken, not free.
	other, oerr := lockStore(dir)
	if oerr != nil || other != nil {
		if other != nil {
			other.Release()
		}
		t.Fatalf("a held store lock was reported free: (%v, %v)", other, oerr)
	}

	// And badger itself must be refused for the whole window.
	if db, derr := Open(dir); derr == nil {
		_ = db.Close()
		lock.Release()
		t.Fatal("badger opened a store whose lock the quarantine path was holding — the rename window is not closed")
	}

	lock.Release()

	db, derr := Open(dir)
	if derr != nil {
		t.Fatalf("store did not open after the lock was released: %v", derr)
	}
	_ = db.Close()
}

// applyQuarantine must not leak the lock it takes: the quarantined copy has to
// be openable afterwards (an operator inspecting the evidence) and the
// replacement has to be openable by this very process on the retry.
func TestOpenResilient_QuarantineReleasesTheStoreLock(t *testing.T) {
	dir := seedStore(t, 20)
	garbleFile(t, filepath.Join(dir, "MANIFEST"), 8)

	db, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !rec.Quarantined {
		t.Fatalf("expected a quarantine: %+v", rec)
	}
	lock, lerr := lockStore(rec.QuarantinePath)
	if lerr != nil || lock == nil {
		t.Fatalf("quarantined copy is still locked — the rename leaked its handle: (%v, %v)", lock, lerr)
	}
	lock.Release()
}

// A marker whose owner is still inside badger.Open must never be treated as
// abandoned: the flock is what distinguishes a live attempt from a dead one.
func TestOpenResilient_LiveAttemptMarkerIsNotAbandoned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")

	live := beginAttempt(dir)
	if live.Path == "" {
		t.Fatal("could not arm a marker")
	}
	if got := abandonedMarkers(dir); len(got) != 0 {
		t.Errorf("a LIVE attempt's marker was reported abandoned: %v", got)
	}
	// Once the owner is gone the same file becomes the poison signal.
	live.Lock.Release()
	if got := abandonedMarkers(dir); len(got) != 1 {
		t.Errorf("abandoned markers after the owner released = %v, want 1", got)
	}
	_ = os.Remove(live.Path)
}

// Temp markers left by a death during arming are litter, not a poison signal:
// their owner never reached badger.Open.
func TestOpenResilient_LeakedTempMarkerIsReapedNotTreatedAsPoison(t *testing.T) {
	dir := seedStore(t, 20)
	leaked := trimSep(dir) + markerTempSuffix + "999-1"
	if err := os.WriteFile(leaked, []byte("pid=999\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	db, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	if rec.Quarantined || rec.Trigger != TriggerNone {
		t.Errorf("a leaked temp marker triggered a recovery: %+v", rec)
	}
	if _, err := os.Stat(leaked); err == nil {
		t.Error("leaked temp marker was not reaped")
	}
	if cat, ok := db.Lookup(hostFor(0)); !ok || cat != "Social" {
		t.Errorf("healthy store was replaced: %q %v", cat, ok)
	}
}

// The "lock held across the rename" invariant is carried by the type, not by a
// comment: quarantineDir refuses a lock that has already been released, so a
// refactor that goes back to probe-then-let-go cannot silently reopen the
// window in which a live store gets renamed out from under its owner.
func TestQuarantineDir_RefusesWithoutAHeldLock(t *testing.T) {
	dir := seedStore(t, 10)

	if _, err := quarantineDir(nil, dir); !errors.Is(err, errStoreLockNotHeld) {
		t.Errorf("quarantineDir(nil) = %v, want errStoreLockNotHeld", err)
	}

	lock, err := lockStore(dir)
	if err != nil || lock == nil {
		t.Fatalf("lockStore = (%v, %v)", lock, err)
	}
	lock.Release()
	if _, err := quarantineDir(lock, dir); !errors.Is(err, errStoreLockNotHeld) {
		t.Errorf("quarantineDir(released) = %v, want errStoreLockNotHeld", err)
	}
	if q := QuarantinedCopies(dir); len(q) != 0 {
		t.Errorf("a rename happened without the lock: %v", q)
	}

	// The happy path still works while the lock is genuinely held.
	lock2, err := lockStore(dir)
	if err != nil || lock2 == nil {
		t.Fatalf("re-lock = (%v, %v)", lock2, err)
	}
	defer lock2.Release()
	if _, err := quarantineDir(lock2, dir); err != nil {
		t.Errorf("quarantineDir with a held lock: %v", err)
	}
}

// An attempt must never make its OWN marker look abandoned. end() removes the
// file before releasing the lock; the reverse order leaves a window in which a
// concurrently booting process samples a marker that is present and unlocked.
func TestOpenAttempt_EndRemovesTheMarkerBeforeReleasingIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	a := beginAttempt(dir)
	if a.Path == "" {
		t.Fatal("could not arm a marker")
	}
	a.End()
	if _, err := os.Stat(a.Path); err == nil {
		t.Error("marker still on disk after end()")
	}
	if got := abandonedMarkers(dir); len(got) != 0 {
		t.Errorf("a finished attempt left an abandoned-looking marker: %v", got)
	}
}
