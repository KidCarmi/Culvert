package logstore

// resilient_chaos_test.go — CHAOS-57 gates for OpenResilientTTL.
//
// The headline claim (badger.Open panics from a goroutine badger spawns, so no
// recover() at the call site can contain it) is proven LIVE against THIS store's
// option set — encryption on, 128 MiB value log — rather than inherited from
// the CHAOS-50 review's measurements of a differently-configured store. The
// proof is a child process, because there is no way to observe that panic from
// the parent without dying with it.
//
// The encryption gates are the reason storeguard.Policy exists: badger reports
// KEYREGISTRY damage, a changed passphrase and a lost salt with the SAME error,
// so the shared corruption table's "encryption key mismatch ⇒ corrupt" rule —
// correct for a store never opened with a key — would move a healthy history
// store aside over an ordinary configuration change.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/storeguard"
)

const chaosPass = "correct horse battery staple"

// seedHistory creates a populated, cleanly-closed ENCRYPTED store and returns
// its directory. Encryption is on because that is the configuration the
// interesting divergences live in.
func seedHistory(t *testing.T, entries int) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "history")
	key, err := EncKey(dir, chaosPass)
	if err != nil {
		t.Fatalf("seed enckey: %v", err)
	}
	s, err := OpenTTL(dir, 0, 0, key, nil)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	for i := 0; i < entries; i++ {
		s.Add(Entry{Host: "example.com", Method: "GET", Status: "OK"})
	}
	if err := s.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	return dir
}

// openHistory is the production call under test, with the key derived the way
// the composition root derives it.
func openHistory(t *testing.T, dir string) (*Store, storeguard.Recovery, error) {
	t.Helper()
	key, err := EncKey(dir, chaosPass)
	if err != nil {
		return nil, storeguard.Recovery{}, err
	}
	return OpenResilientTTL(dir, 0, 0, key, nil)
}

func garbleTables(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	n := 0
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".sst" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, rerr := os.ReadFile(p) //nolint:gosec // test fixture under t.TempDir()
		if rerr != nil {
			t.Fatalf("read %s: %v", p, rerr)
		}
		for i := range b {
			b[i] ^= 0xFF
		}
		if werr := os.WriteFile(p, b, 0o600); werr != nil { //nolint:gosec // G703: test fixture under t.TempDir()
			t.Fatalf("write %s: %v", p, werr)
		}
		n++
	}
	if n == 0 {
		t.Fatalf("no .sst files in %s — seed did not flush a table", dir)
	}
	return n
}

// ── the headline: an uncatchable panic must not be a permanent crash loop ────

// The fault this whole file exists for, end to end:
//
//	run 1 — badger panics from its own goroutine; the process dies; the marker
//	        this attempt armed survives with its flock released by the kernel
//	run 2 — the marker triggers a quarantine before badger is touched, and the
//	        store opens
//
// Without the marker, run 2 is byte-identical to run 1. For THIS store that is
// worse than for the category store: the enable toggle is durable in
// admin_settings.json and re-applied on every boot, so run 2 is not a
// hypothetical — it is what `restart: unless-stopped` does, forever, with no
// admin UI left to turn the setting back off.
func TestChaos57_SurvivesUncatchableOpenPanicOnNextRun(t *testing.T) {
	if dir := os.Getenv("CULVERT_LOGSTORE_PANIC_CHILD"); dir != "" {
		runHistoryPanicChild(dir)
		return
	}

	dir := seedHistory(t, 3000)
	garbleTables(t, dir)

	first, firstErr := runHistoryChild(t, dir)
	if strings.Contains(first, "child: recovered") {
		t.Error("the panic was catchable at the call site — the marker mechanism is no longer needed; simplify")
	}
	if firstErr == nil || strings.Contains(first, "child: returned") {
		t.Skipf("badger no longer panics on a corrupt table (returned instead): %s", first)
	}

	// The dead child's marker must survive AND be recognised as abandoned: the
	// kernel released its flock when the process died, which is exactly what
	// distinguishes it from a marker a live opener still owns.
	if got := storeguard.AbandonedMarkers(dir); len(got) != 1 {
		t.Fatalf("abandoned markers after the panic = %v, want exactly 1 — the next run cannot recover", got)
	}

	second, secondErr := runHistoryChild(t, dir)
	if secondErr != nil {
		t.Fatalf("run 2 did not recover from the poisoned store: %v\n%s", secondErr, second)
	}
	if !strings.Contains(second, "child: returned err=<nil> quarantined=true trigger=poison_marker") {
		t.Errorf("run 2 did not recover via the poison marker; output:\n%s", second)
	}
	if got := QuarantinedCopies(dir); len(got) != 1 {
		t.Errorf("quarantined copies after recovery = %v, want exactly 1", got)
	}
}

// The DEFECT PROOF, kept permanently: plain OpenTTL — the call the composition
// root used to make — dies on a corrupt table even with a recover() in the
// frame directly above it. If badger ever starts returning this error instead,
// this test fails, and the gate above can no longer quietly prove less than it
// claims.
func TestChaos57_BareOpenTTLPanicIsUncatchableAtTheCallSite(t *testing.T) {
	if dir := os.Getenv("CULVERT_LOGSTORE_BAREOPEN_CHILD"); dir != "" {
		runBareOpenChild(dir)
		return
	}
	dir := seedHistory(t, 3000)
	garbleTables(t, dir)

	out, err := runChild(t, "TestChaos57_BareOpenTTLPanicIsUncatchableAtTheCallSite", "CULVERT_LOGSTORE_BAREOPEN_CHILD", dir)
	if err == nil {
		t.Fatalf("bare OpenTTL survived a corrupt table — badger's behaviour changed; re-derive the guard's premise.\n%s", out)
	}
	if strings.Contains(out, "child: recovered") {
		t.Fatalf("the panic WAS catchable at the call site — the poison-marker mechanism is no longer required.\n%s", out)
	}
	if !strings.Contains(out, "newLevelsController") {
		t.Errorf("panic did not come from badger's own goroutine; the premise may have changed:\n%s", out)
	}
}

func runHistoryPanicChild(dir string) {
	defer func() {
		if v := recover(); v != nil {
			os.Stdout.WriteString("child: recovered\n")
		}
	}()
	key, err := EncKey(dir, chaosPass)
	if err != nil {
		os.Stdout.WriteString("child: enckey err=" + err.Error() + "\n")
		return
	}
	s, rec, err := OpenResilientTTL(dir, 0, 0, key, nil)
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

func runBareOpenChild(dir string) {
	defer func() {
		if v := recover(); v != nil {
			os.Stdout.WriteString("child: recovered\n")
		}
	}()
	key, err := EncKey(dir, chaosPass)
	if err != nil {
		os.Stdout.WriteString("child: enckey err=" + err.Error() + "\n")
		return
	}
	s, err := OpenTTL(dir, 0, 0, key, nil)
	e := "<nil>"
	if err != nil {
		e = err.Error()
	}
	os.Stdout.WriteString("child: returned err=" + e + "\n")
	if s != nil {
		_ = s.Close()
	}
}

func runHistoryChild(t *testing.T, dir string) (string, error) {
	t.Helper()
	return runChild(t, "TestChaos57_SurvivesUncatchableOpenPanicOnNextRun", "CULVERT_LOGSTORE_PANIC_CHILD", dir)
}

func runChild(t *testing.T, testName, envKey, dir string) (string, error) {
	t.Helper()
	// #nosec G204,G702 -- re-exec of THIS test binary (os.Args[0]) with a fixed,
	// literal flag and no external input; a child process is the only way to
	// observe a panic badger raises from its own goroutine without killing the
	// parent.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", testName)
	cmd.Env = append(os.Environ(), envKey+"="+dir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ── the returned-corruption path ─────────────────────────────────────────────

// A torn MANIFEST is returned, not panicked. It must be identified as
// corruption, quarantined, and the store re-created so history resumes.
func TestChaos57_TornManifestIsQuarantinedAndReopened(t *testing.T) {
	dir := seedHistory(t, 50)
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("scramble manifest: %v", err)
	}
	s, rec, err := openHistory(t, dir)
	if err != nil {
		t.Fatalf("open after torn MANIFEST: %v", err)
	}
	defer s.Close() //nolint:errcheck // test cleanup
	if !rec.Quarantined || rec.Trigger != storeguard.TriggerOpenError {
		t.Fatalf("torn MANIFEST was not recovered via quarantine: %+v", rec)
	}
	if got := QuarantinedCopies(dir); len(got) != 1 {
		t.Errorf("quarantined copies = %v, want exactly 1", got)
	}
}

// The quarantine MOVES ASIDE, it does not delete: history has evidentiary
// value. And because the salt sidecar is a SIBLING of the store directory, the
// rename leaves it in place — so the evidence the operator is handed is
// evidence they can actually read, with the key they already have.
func TestChaos57_QuarantinedHistoryStaysReadableWithTheSameSalt(t *testing.T) {
	dir := seedHistory(t, 50)
	saltBefore, err := os.ReadFile(dir + ".salt")
	if err != nil {
		t.Fatalf("read salt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("scramble manifest: %v", err)
	}
	s, rec, err := openHistory(t, dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close replacement: %v", err)
	}
	if !rec.Quarantined {
		t.Fatalf("expected a quarantine, got %+v", rec)
	}

	saltAfter, err := os.ReadFile(dir + ".salt")
	if err != nil {
		t.Fatalf("salt sidecar disappeared with the quarantine: %v", err)
	}
	if !bytes.Equal(saltBefore, saltAfter) {
		t.Fatal("salt sidecar changed across the quarantine — the quarantined copy is now undecryptable")
	}
	if strings.HasPrefix(dir+".salt", rec.QuarantinePath+string(filepath.Separator)) {
		t.Fatal("salt sidecar was carried INTO the quarantined directory")
	}
	// The quarantined copy is damaged (that is why it was moved aside), so the
	// contract under test is that the KEY still applies to it — proven by the
	// failure being about the store's contents, never about the key.
	key, err := EncKey(dir, chaosPass)
	if err != nil {
		t.Fatalf("re-derive key: %v", err)
	}
	if q, qerr := OpenTTL(rec.QuarantinePath, 0, 0, key, nil); qerr != nil {
		if errors.Is(qerr, ErrEncMismatch) {
			t.Fatalf("quarantined copy is no longer decryptable with the surviving salt: %v", qerr)
		}
	} else {
		_ = q.Close()
	}
}

// ── the policy divergence: encryption conditions are NEVER corruption ────────

// An operator changing the history passphrase must not cost them their history.
// badger reports it identically to KEYREGISTRY damage, and the shared
// corruption table lists that message — so without this store's policy
// exemption a configuration change would move the store aside and re-create it
// empty, which for a store the operator is keeping ON PURPOSE is data loss
// caused by the recovery mechanism.
func TestChaos57_ChangedPassphraseIsNeverQuarantined(t *testing.T) {
	dir := seedHistory(t, 50)

	key, err := EncKey(dir, "a completely different passphrase")
	if err != nil {
		t.Fatalf("enckey: %v", err)
	}
	s, rec, err := OpenResilientTTL(dir, 0, 0, key, nil)
	if s != nil {
		_ = s.Close()
	}
	if err == nil {
		t.Fatal("a changed passphrase opened the store — the encryption contract is broken")
	}
	if !errors.Is(err, ErrEncMismatch) {
		t.Errorf("err = %v, want ErrEncMismatch (the actionable sentinel the API maps to a 409)", err)
	}
	if rec.Quarantined {
		t.Fatalf("a CHANGED PASSPHRASE quarantined the store — an ordinary configuration change destroyed history: %+v", rec)
	}
	if got := QuarantinedCopies(dir); len(got) != 0 {
		t.Fatalf("quarantined copies = %v, want none", got)
	}
	if _, serr := os.Stat(dir); serr != nil {
		t.Fatalf("store directory was moved aside: %v", serr)
	}
}

// The same message also covers genuine KEYREGISTRY damage, and this store
// declines to auto-heal it. That is a deliberate, recorded trade: the three
// conditions are indistinguishable, and of the four possible outcomes the only
// unacceptable one is destroying intact history on a config change. A real
// KEYREGISTRY fault therefore degrades loudly (see the operator-contract row)
// and the operator purges — one manual step, no silent data loss.
func TestChaos57_ScrambledKeyRegistryDegradesRatherThanQuarantining(t *testing.T) {
	dir := seedHistory(t, 50)
	kr := filepath.Join(dir, "KEYREGISTRY")
	b, err := os.ReadFile(kr) //nolint:gosec // test fixture under t.TempDir()
	if err != nil {
		t.Fatalf("read KEYREGISTRY: %v", err)
	}
	for i := range b {
		b[i] ^= 0xFF
	}
	if err := os.WriteFile(kr, b, 0o600); err != nil {
		t.Fatalf("write KEYREGISTRY: %v", err)
	}

	s, rec, err := openHistory(t, dir)
	if s != nil {
		_ = s.Close()
	}
	if err == nil {
		t.Fatal("a scrambled KEYREGISTRY opened cleanly")
	}
	if rec.Quarantined {
		t.Fatalf("quarantined on an encryption-flavoured error: %+v", rec)
	}
}

// The exemption is expressed at two layers on purpose. OpenTTL currently
// rewrites every encryption-flavoured badger error into ErrEncMismatch, so the
// structural exemption is the one that fires today; the textual one covers the
// raw badger message, so a future change to that rewrite cannot silently
// re-arm a quarantine over a passphrase change.
func TestChaos57_BothPolicyLayersExemptEncryptionErrors(t *testing.T) {
	if got := storeguard.ClassifyOpenError(ErrEncMismatch, historyStorePolicy); got == storeguard.ClassCorrupt {
		t.Error("the sentinel exemption does not hold: ErrEncMismatch classifies as corruption")
	}
	raw := errors.New("Encryption key mismatch")
	if got := storeguard.ClassifyOpenError(raw, historyStorePolicy); got == storeguard.ClassCorrupt {
		t.Error("the text exemption does not hold: a raw badger encryption error classifies as corruption")
	}
	// Control: the SAME raw error is still corruption for a store that is never
	// opened with a key. If this stops holding, the shared table has been
	// weakened for every store rather than for this one.
	if got := storeguard.ClassifyOpenError(raw, storeguard.Policy{}); got != storeguard.ClassCorrupt {
		t.Errorf("unkeyed-store classification of %q = %v, want ClassCorrupt", raw, got)
	}
	// A policy can only ever SUBTRACT: real corruption signals are untouched.
	tornManifest := errors.New("manifest has bad magic")
	if got := storeguard.ClassifyOpenError(tornManifest, historyStorePolicy); got != storeguard.ClassCorrupt {
		t.Errorf("the policy weakened an unrelated corruption signal: %v", got)
	}
}

// An environmental fault must never move the store: renaming fixes none of
// them, and on the lock case it would move a LIVE store out from under its
// owner.
func TestChaos57_LiveOwnerIsNeverQuarantined(t *testing.T) {
	dir := seedHistory(t, 20)
	held, _, err := openHistory(t, dir)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	defer held.Close() //nolint:errcheck // test cleanup

	key, kerr := EncKey(dir, chaosPass)
	if kerr != nil {
		t.Fatalf("enckey: %v", kerr)
	}
	s, rec, oerr := OpenResilientTTL(dir, 0, 0, key, nil)
	if s != nil {
		_ = s.Close()
	}
	if oerr == nil {
		t.Fatal("a second concurrent open succeeded — badger's directory lock is not in force")
	}
	if rec.Quarantined {
		t.Fatalf("quarantined a store a live process was using: %+v", rec)
	}
	if _, serr := os.Stat(dir); serr != nil {
		t.Fatalf("live store directory was moved aside: %v", serr)
	}
}

// A healthy store must be byte-identical to the pre-change behaviour: opened,
// nothing moved, nothing reported.
func TestChaos57_HealthyStoreIsUntouched(t *testing.T) {
	dir := seedHistory(t, 20)
	s, rec, err := openHistory(t, dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close() //nolint:errcheck // test cleanup
	if rec.Quarantined || rec.Trigger != storeguard.TriggerNone || rec.Skipped != "" {
		t.Errorf("a healthy store reported a recovery: %+v", rec)
	}
	if got := QuarantinedCopies(dir); len(got) != 0 {
		t.Errorf("quarantined copies = %v, want none", got)
	}
}
