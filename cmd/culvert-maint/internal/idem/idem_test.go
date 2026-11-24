package idem

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// logSink collects the store's log lines.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...interface{}) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *logSink) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func open(t *testing.T, dir string, c *clock, mut ...func(*Options)) (*Store, *logSink) {
	t.Helper()
	sink := &logSink{}
	opt := Options{Now: c.now, Logf: sink.logf}
	for _, m := range mut {
		m(&opt)
	}
	s, err := Open(dir, opt)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, sink
}

func rec(c *clock, actor, kind, key, opID string, params map[string]interface{}) Record {
	fp, err := Fingerprint(kind, params)
	if err != nil {
		panic(err)
	}
	return Record{Actor: actor, Kind: kind, IdempotencyKey: key, Fingerprint: fp, OpID: opID, AdmittedAt: c.now(), Params: params}
}

func finish(c *clock, r Record, state string, result map[string]interface{}) Record {
	now := c.now()
	r.State = state
	r.FinishedAt = &now
	r.Result = result
	return r
}

func recordFiles(t *testing.T, s *Store, ext string) []string {
	t.Helper()
	entries, err := os.ReadDir(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ext) {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestAdmitIsWriteAhead: when Admit returns, the record is on disk in state
// "admitted" — before the caller has run anything — and a second store over
// the same directory (a restarted agent) sees it.
func TestAdmitIsWriteAhead(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	r := rec(c, "uid=1", "backup.create", "k1", "01OP", map[string]interface{}{"filename": "a.tar.gz"})
	if err := s.Admit(r); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	files := recordFiles(t, s, fileExt)
	if len(files) != 1 {
		t.Fatalf("want 1 record file, got %v", files)
	}
	raw, err := os.ReadFile(filepath.Join(s.Dir(), files[0]))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Record
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.State != StateAdmitted || onDisk.OpID != "01OP" || onDisk.FinishedAt != nil {
		t.Fatalf("on-disk admission record wrong: %+v", onDisk)
	}
	if tmp := recordFiles(t, s, ".tmp"); len(tmp) != 0 {
		t.Errorf("temp files left behind: %v", tmp)
	}
	// The same process sees its own running op as admitted, not interrupted.
	got, found, err := s.Lookup("uid=1", "backup.create", "k1")
	if err != nil || !found || got.Terminal() {
		t.Fatalf("Lookup in the admitting process: found=%v err=%v rec=%+v", found, err, got)
	}
}

// TestCompleteThenReopenReplaysOutcome: the terminal outcome survives a
// restart and is returned unchanged, by key and by op id.
func TestCompleteThenReopenReplaysOutcome(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	r := rec(c, "uid=1", "backup.create", "k1", "01OP", map[string]interface{}{"filename": "a.tar.gz"})
	if err := s.Admit(r); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute)
	done := finish(c, r, StateSucceeded, map[string]interface{}{"archive": "a.tar.gz"})
	done.Progress = []Stage{{Name: "run_cli_backup", State: StateSucceeded}}
	if err := s.Complete(done); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	s2, sink := open(t, dir, c)
	if s2.InterruptedAtOpen() != 0 {
		t.Errorf("a completed record was counted as interrupted; log: %s", sink.all())
	}
	got, found, err := s2.Lookup("uid=1", "backup.create", "k1")
	if err != nil || !found {
		t.Fatalf("Lookup after reopen: found=%v err=%v", found, err)
	}
	if got.State != StateSucceeded || got.OpID != "01OP" || got.Result["archive"] != "a.tar.gz" || got.Interrupted {
		t.Fatalf("replayed record differs: %+v", got)
	}
	if len(got.Progress) != 1 || got.Progress[0].Name != "run_cli_backup" {
		t.Errorf("progress not preserved: %+v", got.Progress)
	}
	byID, ok := s2.ByOpID("01OP")
	if !ok || byID.State != StateSucceeded {
		t.Fatalf("ByOpID after reopen: ok=%v rec=%+v", ok, byID)
	}
}

// TestReopenMarksAdmittedAsInterruptedUnknown: a record with no outcome when a
// new process opens the store becomes failed(agent_restart_interrupted) with
// outcome "unknown" — never succeeded — and the verdict is persisted.
func TestReopenMarksAdmittedAsInterruptedUnknown(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	r := rec(c, "uid=1", "backup.create", "k1", "01OP", nil)
	if err := s.Admit(r); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute)

	s2, sink := open(t, dir, c)
	if s2.InterruptedAtOpen() != 1 {
		t.Fatalf("InterruptedAtOpen = %d, want 1", s2.InterruptedAtOpen())
	}
	if !strings.Contains(sink.all(), "no recorded outcome") {
		t.Errorf("startup did not log the interruption: %q", sink.all())
	}
	got, found, err := s2.Lookup("uid=1", "backup.create", "k1")
	if err != nil || !found {
		t.Fatalf("Lookup: found=%v err=%v", found, err)
	}
	if got.State != StateFailed || got.FailureReason != ReasonInterrupted || !got.Interrupted {
		t.Fatalf("want failed(%s) interrupted, got %+v", ReasonInterrupted, got)
	}
	if got.Result["outcome"] != "unknown" {
		t.Fatalf("result.outcome = %v, want unknown", got.Result["outcome"])
	}
	// Persisted: a third process reads the same answer and does not recount it.
	s3, _ := open(t, dir, c)
	if s3.InterruptedAtOpen() != 0 {
		t.Errorf("interruption was not persisted (recounted at the next open)")
	}
	again, _, _ := s3.Lookup("uid=1", "backup.create", "k1")
	if again == nil || again.State != StateFailed || !again.FinishedAt.Equal(*got.FinishedAt) {
		t.Fatalf("third open disagrees: %+v vs %+v", again, got)
	}
}

// TestInterruptedVerdictHoldsWhenItCannotBePersisted: if the interruption
// could not be written back at startup (read-only or full state directory),
// the record on disk still says "admitted". The store must answer
// "interrupted" anyway. The failed write-back is modelled by restoring the
// admitted bytes after Open, which works for any uid.
func TestInterruptedVerdictHoldsWhenItCannotBePersisted(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	if err := s.Admit(rec(c, "uid=1", "backup.create", "k1", "01OP", nil)); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(s.Dir(), scopeHash("uid=1", "backup.create", "k1")+fileExt)
	admitted, err := os.ReadFile(file) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}

	s2, _ := open(t, dir, c)
	// The write-back "never happened".
	if err := os.WriteFile(file, admitted, 0o600); err != nil { // #nosec G703 -- test-owned temp dir
		t.Fatal(err)
	}
	got, found, err := s2.Lookup("uid=1", "backup.create", "k1")
	if err != nil || !found || got.State != StateFailed || got.Result["outcome"] != "unknown" {
		t.Fatalf("found=%v err=%v rec=%+v", found, err, got)
	}
	byID, ok := s2.ByOpID("01OP")
	if !ok || byID.FailureReason != ReasonInterrupted {
		t.Fatalf("ByOpID: ok=%v rec=%+v", ok, byID)
	}
}

// TestScopeIsActorKindKey: the same key under another actor or another kind is
// a different record.
func TestScopeIsActorKindKey(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	if err := s.Admit(rec(c, "uid=1", "backup.create", "k", "01A", nil)); err != nil {
		t.Fatal(err)
	}
	for _, sc := range [][2]string{{"uid=2", "backup.create"}, {"uid=1", "restore.commit"}} {
		if _, found, err := s.Lookup(sc[0], sc[1], "k"); found || err != nil {
			t.Errorf("scope %v: found=%v err=%v, want independent", sc, found, err)
		}
		if s.Has(sc[0], sc[1], "k") {
			t.Errorf("scope %v: Has = true", sc)
		}
	}
	if !s.Has("uid=1", "backup.create", "k") {
		t.Error("Has = false for the admitted scope")
	}
	// Field boundaries cannot be shifted to collide two scopes.
	if scopeHash("a", "bc", "k") == scopeHash("ab", "c", "k") {
		t.Error("scope hash is not boundary-safe")
	}
}

// TestFingerprint: order-independent, payload-sensitive, kind-sensitive.
func TestFingerprint(t *testing.T) {
	a, _ := Fingerprint("backup.create", map[string]interface{}{"filename": "a", "encrypt": false, "n": map[string]interface{}{"x": 1, "y": 2}})
	b, _ := Fingerprint("backup.create", map[string]interface{}{"n": map[string]interface{}{"y": 2, "x": 1}, "encrypt": false, "filename": "a"})
	if a != b {
		t.Error("same content, different key order → different fingerprint")
	}
	cDiff, _ := Fingerprint("backup.create", map[string]interface{}{"filename": "b", "encrypt": false, "n": map[string]interface{}{"x": 1, "y": 2}})
	if a == cDiff {
		t.Error("different payload → same fingerprint")
	}
	k, _ := Fingerprint("restore.commit", map[string]interface{}{"filename": "a", "encrypt": false, "n": map[string]interface{}{"x": 1, "y": 2}})
	if a == k {
		t.Error("different kind → same fingerprint")
	}
	if len(a) != 64 {
		t.Errorf("fingerprint is not hex SHA-256: %q", a)
	}
	if _, err := Fingerprint("k", map[string]interface{}{"bad": make(chan int)}); err == nil {
		t.Error("unmarshalable params must be an error, not a fingerprint")
	}
}

// TestFingerprintStoredAndComparable: the record keeps the fingerprint of the
// admitted payload across a restart so a caller can detect a mismatching retry.
func TestFingerprintStoredAndComparable(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	r := rec(c, "uid=1", "backup.create", "k", "01A", map[string]interface{}{"filename": "a"})
	if err := s.Admit(r); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(finish(c, r, StateSucceeded, nil)); err != nil {
		t.Fatal(err)
	}
	s2, _ := open(t, dir, c)
	got, _, _ := s2.Lookup("uid=1", "backup.create", "k")
	same, _ := Fingerprint("backup.create", map[string]interface{}{"filename": "a"})
	other, _ := Fingerprint("backup.create", map[string]interface{}{"filename": "b"})
	if got.Fingerprint != same || got.Fingerprint == other {
		t.Fatalf("stored fingerprint %q: same=%q other=%q", got.Fingerprint, same, other)
	}
}

// TestTTL: a terminal record stops answering at admitted+TTL and its file is
// swept at the next admission and at the next open.
func TestTTL(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c, func(o *Options) { o.TTL = time.Hour })
	r := rec(c, "uid=1", "backup.create", "old", "01OLD", nil)
	if err := s.Admit(r); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(finish(c, r, StateSucceeded, nil)); err != nil {
		t.Fatal(err)
	}
	c.advance(59 * time.Minute)
	if _, found, _ := s.Lookup("uid=1", "backup.create", "old"); !found {
		t.Fatal("record expired before its TTL")
	}
	c.advance(2 * time.Minute)
	if _, found, _ := s.Lookup("uid=1", "backup.create", "old"); found {
		t.Fatal("record still answers past its TTL")
	}
	if _, ok := s.ByOpID("01OLD"); ok {
		t.Fatal("ByOpID still answers past the TTL")
	}
	if s.Has("uid=1", "backup.create", "old") {
		t.Fatal("Has still true past the TTL")
	}
	// Swept on the next admission.
	if err := s.Admit(rec(c, "uid=1", "backup.create", "new", "01NEW", nil)); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 || len(recordFiles(t, s, fileExt)) != 1 {
		t.Fatalf("expired record not swept on admission: len=%d files=%v", s.Len(), recordFiles(t, s, fileExt))
	}
	// Swept at open: the surviving record is now interrupted (terminal); age it out.
	c.advance(2 * time.Hour)
	s2, _ := open(t, dir, c, func(o *Options) { o.TTL = time.Hour })
	if s2.Len() != 0 || len(recordFiles(t, s2, fileExt)) != 0 {
		t.Fatalf("expired record not swept at open: len=%d", s2.Len())
	}
}

// TestExpiredKeyCanBeAdmittedAgainAndOldOpCannotOverwrite: once a key's record
// expired a new admission takes the scope; a late Complete from the first op
// must not replace the second op's record.
func TestExpiredKeyCanBeAdmittedAgainAndOldOpCannotOverwrite(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c, func(o *Options) { o.TTL = time.Hour })
	first := rec(c, "uid=1", "backup.create", "k", "01FIRST", nil)
	if err := s.Admit(first); err != nil {
		t.Fatal(err)
	}
	c.advance(2 * time.Hour) // first op still "running", its record past the TTL
	second := rec(c, "uid=1", "backup.create", "k", "01SECOND", nil)
	if err := s.Admit(second); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(finish(c, first, StateSucceeded, nil)); err != nil {
		t.Fatalf("late Complete should be a silent no-op, got %v", err)
	}
	got, found, _ := s.Lookup("uid=1", "backup.create", "k")
	if !found || got.OpID != "01SECOND" || got.Terminal() {
		t.Fatalf("second op's record was overwritten: %+v", got)
	}
	if _, ok := s.ByOpID("01FIRST"); ok {
		t.Error("first op is still indexed by id")
	}
}

// TestCapEvictsOldestTerminalFirst: at the cap the oldest-finished terminal
// record goes; a running op's record is never evicted.
func TestCapEvictsOldestTerminalFirst(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c, func(o *Options) { o.MaxRecords = 3 })
	running := rec(c, "uid=1", "backup.list", "running", "01RUN", nil)
	if err := s.Admit(running); err != nil { // oldest of all, but not terminal
		t.Fatal(err)
	}
	for _, k := range []string{"t1", "t2"} {
		c.advance(time.Minute)
		r := rec(c, "uid=1", "backup.list", k, "01"+k, nil)
		if err := s.Admit(r); err != nil {
			t.Fatal(err)
		}
		if err := s.Complete(finish(c, r, StateSucceeded, nil)); err != nil {
			t.Fatal(err)
		}
	}
	c.advance(time.Minute)
	if err := s.Admit(rec(c, "uid=1", "backup.list", "t3", "01t3", nil)); err != nil {
		t.Fatalf("Admit at cap: %v", err)
	}
	if s.Len() != 3 || len(recordFiles(t, s, fileExt)) != 3 {
		t.Fatalf("cap not enforced: len=%d files=%d", s.Len(), len(recordFiles(t, s, fileExt)))
	}
	if s.Has("uid=1", "backup.list", "t1") {
		t.Error("oldest terminal record t1 was not the one evicted")
	}
	for _, k := range []string{"running", "t2", "t3"} {
		if !s.Has("uid=1", "backup.list", k) {
			t.Errorf("record %q was evicted", k)
		}
	}
}

// TestCapRefusesWhenNothingIsEvictable: every record belongs to a running op.
func TestCapRefusesWhenNothingIsEvictable(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c, func(o *Options) { o.MaxRecords = 2 })
	for _, k := range []string{"a", "b"} {
		if err := s.Admit(rec(c, "uid=1", "backup.list", k, "01"+k, nil)); err != nil {
			t.Fatal(err)
		}
	}
	err := s.Admit(rec(c, "uid=1", "backup.list", "c", "01c", nil))
	if !errors.Is(err, ErrFull) {
		t.Fatalf("want ErrFull, got %v", err)
	}
	if s.Has("uid=1", "backup.list", "c") {
		t.Error("a refused admission left a record")
	}
}

// TestCorruptRecordIsQuarantinedAndItsKeyRefused: an unreadable record is set
// aside without its contents being logged, the rest of the store keeps
// working, and that exact key is refused rather than re-admitted.
func TestCorruptRecordIsQuarantinedAndItsKeyRefused(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	good := rec(c, "uid=1", "backup.create", "good", "01GOOD", nil)
	bad := rec(c, "uid=1", "backup.create", "bad", "01BAD", nil)
	for _, r := range []Record{good, bad} {
		if err := s.Admit(r); err != nil {
			t.Fatal(err)
		}
		if err := s.Complete(finish(c, r, StateSucceeded, nil)); err != nil {
			t.Fatal(err)
		}
	}
	const secretish = "SENTINEL-CONTENT-do-not-log"
	badFile := filepath.Join(s.Dir(), scopeHash("uid=1", "backup.create", "bad")+fileExt)
	if err := os.WriteFile(badFile, []byte(`{"v":1,"actor":"`+secretish+`", not json`), 0o600); err != nil {
		t.Fatal(err)
	}

	// The quarantine ages from the file's mtime; put it on the test clock.
	if err := os.Chtimes(badFile, c.now(), c.now()); err != nil {
		t.Fatal(err)
	}

	s2, sink := open(t, dir, c)
	if strings.Contains(sink.all(), secretish) {
		t.Fatalf("log printed record content: %q", sink.all())
	}
	if !strings.Contains(sink.all(), "set aside") {
		t.Errorf("no quarantine log line: %q", sink.all())
	}
	if q := recordFiles(t, s2, corruptExt); len(q) != 1 {
		t.Fatalf("want 1 quarantined file, got %v", q)
	}
	if _, found, err := s2.Lookup("uid=1", "backup.create", "bad"); !found || !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("corrupt key: found=%v err=%v, want ErrCorruptRecord", found, err)
	}
	if !s2.Has("uid=1", "backup.create", "bad") {
		t.Error("Has = false for a quarantined key (it would be admitted as new work)")
	}
	if got, found, err := s2.Lookup("uid=1", "backup.create", "good"); err != nil || !found || got.OpID != "01GOOD" {
		t.Fatalf("a healthy record was affected: found=%v err=%v", found, err)
	}
	// A third open still refuses the key (the quarantine file carries it).
	s3, _ := open(t, dir, c)
	if _, _, err := s3.Lookup("uid=1", "backup.create", "bad"); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("quarantine did not survive a restart: %v", err)
	}
	// After the TTL the key is free again and the quarantine file is swept.
	c.advance(DefaultTTL + time.Hour)
	s4, _ := open(t, dir, c)
	if _, found, err := s4.Lookup("uid=1", "backup.create", "bad"); found || err != nil {
		t.Fatalf("quarantine outlived the TTL: found=%v err=%v", found, err)
	}
	if q := recordFiles(t, s4, corruptExt); len(q) != 0 {
		t.Errorf("quarantine file not swept: %v", q)
	}
}

// TestRecordWithForeignScopeIsCorrupt: a record whose content names another
// scope than its file name (copied or tampered) is not trusted.
func TestRecordWithForeignScopeIsCorrupt(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	r := rec(c, "uid=1", "backup.create", "k", "01A", nil)
	if err := s.Admit(r); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(s.Dir(), scopeHash("uid=1", "backup.create", "k")+fileExt)
	raw, err := os.ReadFile(src) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	foreign := scopeHash("uid=2", "backup.create", "k")
	if err := os.WriteFile(filepath.Join(s.Dir(), foreign+fileExt), raw, 0o600); err != nil { // #nosec G703 -- test-owned temp dir
		t.Fatal(err)
	}
	s2, _ := open(t, dir, c)
	if _, _, err := s2.Lookup("uid=2", "backup.create", "k"); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("a record planted under another actor's scope was accepted: %v", err)
	}
}

// TestOversizedFileIsCorrupt: the read is bounded.
func TestOversizedFileIsCorrupt(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	hash := scopeHash("uid=1", "backup.create", "big")
	if err := os.WriteFile(filepath.Join(s.Dir(), hash+fileExt), bytes.Repeat([]byte("x"), MaxRecordBytes+10), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, sink := open(t, dir, c)
	if _, _, err := s2.Lookup("uid=1", "backup.create", "big"); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("oversized file accepted: %v", err)
	}
	if !strings.Contains(sink.all(), "exceeds size bound") {
		t.Errorf("log: %q", sink.all())
	}
}

// TestSizeBoundReducesInsteadOfFailing: an oversized result is omitted, the
// write succeeds, and the record still carries its outcome and fingerprint.
func TestSizeBoundReducesInsteadOfFailing(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	r := rec(c, "uid=1", "backup.list", "k", "01A", map[string]interface{}{"p": "v"})
	if err := s.Admit(r); err != nil {
		t.Fatal(err)
	}
	done := finish(c, r, StateFailed, map[string]interface{}{"blob": strings.Repeat("r", 3*MaxRecordBytes)})
	done.FailureReason = "cli_error"
	done.Progress = []Stage{{Name: "s1", State: StateFailed, Output: strings.Repeat("o", 4096)}}
	if err := s.Complete(done); err != nil {
		t.Fatalf("Complete with an oversized result must not fail: %v", err)
	}
	files := recordFiles(t, s, fileExt)
	fi, err := os.Stat(filepath.Join(s.Dir(), files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > MaxRecordBytes {
		t.Fatalf("record is %d bytes, bound is %d", fi.Size(), MaxRecordBytes)
	}
	s2, _ := open(t, dir, c)
	got, found, err := s2.Lookup("uid=1", "backup.list", "k")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if !got.Truncated || got.State != StateFailed || got.FailureReason != "cli_error" || got.Fingerprint != r.Fingerprint {
		t.Fatalf("reduced record lost its outcome: %+v", got)
	}
	if got.Result["result_omitted"] != true {
		t.Errorf("result not replaced by the omission marker: %v", got.Result)
	}
	if len(got.Progress) != 1 || len(got.Progress[0].Output) > maxStageOutput+32 {
		t.Errorf("stage output not truncated: %d bytes", len(got.Progress[0].Output))
	}
	if got.Params["p"] != "v" {
		t.Errorf("params were shed although the record fit without that: %v", got.Params)
	}
}

// TestStageOutputAloneIsTruncatedFirst: when cutting stage output is enough,
// the result is kept.
func TestStageOutputAloneIsTruncatedFirst(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	r := rec(c, "uid=1", "backup.list", "k", "01A", nil)
	if err := s.Admit(r); err != nil {
		t.Fatal(err)
	}
	done := finish(c, r, StateSucceeded, map[string]interface{}{"keep": "me"})
	done.Progress = []Stage{{Name: "s1", State: StateSucceeded, Output: strings.Repeat("o", 2*MaxRecordBytes)}}
	if err := s.Complete(done); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Lookup("uid=1", "backup.list", "k")
	if got.Result["keep"] != "me" || !got.Truncated {
		t.Fatalf("got %+v", got)
	}
}

// TestUnavailableStoreRefusesKeyedWork: the stand-in installed when Open fails.
func TestUnavailableStoreRefusesKeyedWork(t *testing.T) {
	s := Unavailable(errors.New("disk on fire"))
	c := newClock()
	if _, _, err := s.Lookup("a", "k", "key"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Lookup: %v", err)
	}
	if err := s.Admit(rec(c, "a", "k", "key", "01A", nil)); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Admit: %v", err)
	}
	if !s.Has("a", "k", "key") {
		t.Error("Has must be true so the caller does not reserve an execution slot for a refusal")
	}
	if _, ok := s.ByOpID("01A"); ok {
		t.Error("ByOpID answered from an unavailable store")
	}
}

// TestOpenFailsOnUnusableStateDir: Open reports, it does not pretend.
func TestOpenFailsOnUnusableStateDir(t *testing.T) {
	dir := t.TempDir()
	// A regular file where the store directory must be.
	if err := os.WriteFile(filepath.Join(dir, dirName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

// TestAdmitFailsClosedWhenRecordCannotBeWritten: no record, no admission. The
// directory is removed under the store so the write fails for any uid.
func TestAdmitFailsClosedWhenRecordCannotBeWritten(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	if err := os.RemoveAll(s.Dir()); err != nil {
		t.Fatal(err)
	}
	err := s.Admit(rec(c, "uid=1", "backup.create", "k", "01A", nil))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if s.Has("uid=1", "backup.create", "k") || s.Len() != 0 {
		t.Error("a failed admission was indexed")
	}
}

// TestCompleteFailureLeavesAdmittedAndIsLogged: an outcome that cannot be
// written is reported, and a restart then reads "unknown", not "succeeded".
func TestCompleteFailureLeavesAdmittedAndIsLogged(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, sink := open(t, dir, c)
	r := rec(c, "uid=1", "backup.create", "k", "01A", nil)
	if err := s.Admit(r); err != nil {
		t.Fatal(err)
	}
	hash := scopeHash("uid=1", "backup.create", "k")
	saved, err := os.ReadFile(filepath.Join(s.Dir(), hash+fileExt)) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(s.Dir()); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(finish(c, r, StateSucceeded, nil)); err == nil {
		t.Fatal("Complete reported success without writing")
	}
	if !strings.Contains(sink.all(), "could not be recorded") {
		t.Errorf("failure not logged: %q", sink.all())
	}
	// Put back what was durably on disk before the failed write, and restart.
	if err := os.MkdirAll(s.Dir(), dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir(), hash+fileExt), saved, 0o600); err != nil { // #nosec G703 -- test-owned temp dir
		t.Fatal(err)
	}
	s2, _ := open(t, dir, c)
	got, found, lerr := s2.Lookup("uid=1", "backup.create", "k")
	if lerr != nil || !found || got.State != StateFailed || got.Result["outcome"] != "unknown" {
		t.Fatalf("after restart: found=%v err=%v rec=%+v", found, lerr, got)
	}
}

// TestLeftoverTempFilesAreRemovedAtOpen and are never read as records.
func TestLeftoverTempFilesAreRemovedAtOpen(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	if err := os.WriteFile(filepath.Join(s.Dir(), ".idem-123.tmp"), []byte("{half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir(), "notes.txt"), []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, _ := open(t, dir, c)
	if s2.Len() != 0 {
		t.Errorf("non-record files were indexed: %d", s2.Len())
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), ".idem-123.tmp")); !os.IsNotExist(err) {
		t.Errorf("temp file not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), "notes.txt")); err != nil {
		t.Errorf("an unrelated file was touched: %v", err)
	}
}

// TestFileModesAndNames: 0640 files in a 0750 directory, named only by hash.
func TestFileModesAndNames(t *testing.T) {
	dir, c := t.TempDir(), newClock()
	s, _ := open(t, dir, c)
	if err := s.Admit(rec(c, "uid=1,user=../../etc", "backup.create", "../../../k", "01A", nil)); err != nil {
		t.Fatal(err)
	}
	files := recordFiles(t, s, fileExt)
	if len(files) != 1 || !validHash(strings.TrimSuffix(files[0], fileExt)) {
		t.Fatalf("file name is not a bare hash: %v", files)
	}
	fi, err := os.Stat(filepath.Join(s.Dir(), files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != fileMode {
		t.Errorf("file mode %o, want %o", fi.Mode().Perm(), fileMode)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != dirName {
		t.Errorf("something was written outside %s/: %v", dirName, entries)
	}
}
