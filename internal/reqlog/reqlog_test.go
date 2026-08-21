package reqlog

// Engine tests, consolidated in-package from package main's store_test.go
// (ring order/capacity — previously exercised against a local
// reimplementation, now against the real ring via SwapRingForTest),
// final_coverage_test.go (Add truncation), coverage_boost_test.go (Init +
// the H1 persistent-read suite), events_livefeed_test.go (write-error /
// corrupt-line counters, TTL read cache), and loguri_test.go
// (LevelForStatus tab mapping) with the extraction (ADR-0002, store.go
// decomposition Phase C).

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLevelForStatus_BlockedTab(t *testing.T) {
	for _, s := range []string{"DPI_BLOCKED", "POLYGLOT_BLOCKED", "CDR_BLOCKED", "CDR_SANITIZED", "POLICY_DEFAULT_DENY"} {
		if got := LevelForStatus(s); got != "WARN" {
			t.Errorf("LevelForStatus(%q) = %q, want WARN", s, got)
		}
	}
	if got := LevelForStatus("AUTH_FAIL"); got != "ERROR" {
		t.Errorf("LevelForStatus(AUTH_FAIL) = %q, want ERROR", got)
	}
	if got := LevelForStatus("OK"); got != "INFO" {
		t.Errorf("LevelForStatus(OK) = %q, want INFO", got)
	}
}

func TestAdd_OrderedMostRecentFirst(t *testing.T) {
	restore := SwapRingForTest()
	defer restore()

	Add(Entry{TS: 1, Host: "first"})
	Add(Entry{TS: 2, Host: "second"})
	Add(Entry{TS: 3, Host: "third"})

	got := Get()
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	if got[0].Host != "third" {
		t.Errorf("most recent entry should be first, got %q", got[0].Host)
	}
}

func TestAdd_RingTruncation(t *testing.T) {
	restore := SwapRingForTest()
	defer restore()

	for i := 0; i < MaxRing+50; i++ {
		Add(Entry{TS: int64(i), Host: "trunctest.example.com", Status: "OK"})
	}
	if got := Get(); len(got) != MaxRing {
		t.Errorf("expected MaxRing=%d entries, got %d", MaxRing, len(got))
	}
}

func TestInit(t *testing.T) {
	t.Cleanup(ResetForTest)
	restore := SwapRingForTest()
	defer restore()

	path := filepath.Join(t.TempDir(), "request.log")
	if err := Init(path, 10); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !PersistActive() {
		t.Fatal("Init did not wire the persistent closer")
	}
	if FilePath() != path {
		t.Errorf("FilePath() = %q, want %q", FilePath(), path)
	}

	Add(Entry{
		TS: time.Now().UnixMilli(), Time: time.Now().Format("15:04:05"),
		IP: "10.0.0.1", Method: "GET", Host: "example.com", Status: "OK", Level: "INFO",
	})
	Sync() // persistence is async; wait for the drain goroutine

	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("request log file is empty after Add")
	}
}

func TestInit_EmptyPath(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := Init("", 10); err != nil {
		t.Fatalf("Init empty path should succeed: %v", err)
	}
	if PersistActive() {
		t.Error("Init(\"\") must not wire persistence")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestAdd_CountsWriteErrors(t *testing.T) {
	restoreRing := SwapRingForTest()
	defer restoreRing()
	restoreWriter := SetWriterForTest(failingWriter{})
	defer restoreWriter()

	before := WriteErrors()
	Add(Entry{TS: 1, Method: "GET", Host: "x.example.com", Status: "OK"})
	Sync() // persistence is async; wait for the drain goroutine
	if got := WriteErrors(); got != before+1 {
		t.Errorf("WriteErrors() = %d, want %d", got, before+1)
	}
}

func TestReadPersistent_NewestFirst(t *testing.T) {
	t.Cleanup(ResetForTest)
	restore := SwapRingForTest()
	defer restore()

	path := filepath.Join(t.TempDir(), "request.jsonl")
	if err := Init(path, 10); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base := time.Now().UnixMilli()
	for i := 0; i < 50; i++ {
		e := Entry{
			TS:       base + int64(i),
			Time:     "12:00:00",
			IP:       "10.0.0.1",
			Identity: "alice",
			Method:   "GET",
			Host:     "example.com",
			Status:   "OK",
			Level:    "INFO",
		}
		if i%2 == 0 {
			e.Host = "blocked.example.com"
			e.Status = "BLOCKED"
			e.Level = "WARN"
		}
		Add(e)
	}

	entries, err := ReadPersistent()
	if err != nil {
		t.Fatalf("ReadPersistent: %v", err)
	}
	if len(entries) != 50 {
		t.Fatalf("expected 50 entries, got %d", len(entries))
	}
	// Newest-first: first entry should have the highest TS (= base+49).
	if entries[0].TS != base+49 {
		t.Errorf("newest entry TS = %d, want %d", entries[0].TS, base+49)
	}
	if entries[len(entries)-1].TS != base {
		t.Errorf("oldest entry TS = %d, want %d", entries[len(entries)-1].TS, base)
	}
	// Ordering strictly monotonically descending.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].TS < entries[i].TS {
			t.Errorf("entries not newest-first at idx %d: %d < %d", i, entries[i-1].TS, entries[i].TS)
			break
		}
	}
}

func TestReadPersistent_EmptyPath(t *testing.T) {
	restore := SetFilePathForTest("")
	t.Cleanup(restore)

	entries, err := ReadPersistent()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil when no path, got %d entries", len(entries))
	}
}

func TestReadPersistent_MissingFile(t *testing.T) {
	restore := SetFilePathForTest(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	t.Cleanup(restore)

	entries, err := ReadPersistent()
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil for missing file, got %d entries", len(entries))
	}
}

func TestReadPersistent_CapEnforced(t *testing.T) {
	t.Cleanup(ResetForTest)
	restore := SwapRingForTest()
	defer restore()

	path := filepath.Join(t.TempDir(), "request.jsonl")
	// Use a large rotation cap so the single file holds all entries.
	if err := Init(path, 200); err != nil {
		t.Fatalf("Init: %v", err)
	}

	total := MaxPersistentReturn + 500
	for i := 0; i < total; i++ {
		Add(Entry{
			TS: int64(i), Method: "GET", Host: "h.example.com", Status: "OK", Level: "INFO",
		})
	}

	entries, err := ReadPersistent()
	if err != nil {
		t.Fatalf("ReadPersistent: %v", err)
	}
	if len(entries) != MaxPersistentReturn {
		t.Fatalf("expected cap=%d entries, got %d", MaxPersistentReturn, len(entries))
	}
	// Newest-first: first entry TS should be total-1, last should be total-cap.
	if entries[0].TS != int64(total-1) {
		t.Errorf("newest TS = %d, want %d", entries[0].TS, total-1)
	}
	if entries[len(entries)-1].TS != int64(total-MaxPersistentReturn) {
		t.Errorf("oldest TS = %d, want %d", entries[len(entries)-1].TS, total-MaxPersistentReturn)
	}
}

func TestReadPersistent_CountsCorruptLines(t *testing.T) {
	good1, _ := json.Marshal(Entry{TS: 1, Host: "a.example.com", Status: "OK"})
	good2, _ := json.Marshal(Entry{TS: 2, Host: "b.example.com", Status: "OK"})
	content := bytes.Join([][]byte{good1, []byte("{corrupt-not-json"), good2, nil}, []byte("\n"))

	path := filepath.Join(t.TempDir(), "request.jsonl")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	restore := SetFilePathForTest(path)
	t.Cleanup(restore)

	before := SkippedLines()
	entries, err := ReadPersistent()
	if err != nil {
		t.Fatalf("ReadPersistent: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("parsed %d entries, want 2 (corrupt line skipped)", len(entries))
	}
	if got := SkippedLines(); got != before+1 {
		t.Errorf("SkippedLines() = %d, want %d", got, before+1)
	}
}

func TestReadPersistent_CachedWithinTTL(t *testing.T) {
	t.Cleanup(ResetForTest)
	restore := SwapRingForTest()
	defer restore()

	path := filepath.Join(t.TempDir(), "request.jsonl")
	if err := Init(path, 10); err != nil {
		t.Fatalf("Init: %v", err)
	}
	Add(Entry{TS: 1, Host: "a.example.com", Status: "OK"})

	first, err := ReadPersistent()
	if err != nil || len(first) != 1 {
		t.Fatalf("first read: entries=%d err=%v, want 1 entry", len(first), err)
	}

	// Pin the cache expiry far into the future so the "cached" assertion below
	// can't flake if a slow CI host lets the 2 s TTL lapse between statements.
	PinCacheForTest()

	// A write inside the TTL window is intentionally not visible yet.
	Add(Entry{TS: 2, Host: "b.example.com", Status: "OK"})
	cached, err := ReadPersistent()
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if len(cached) != 1 {
		t.Fatalf("cached read returned %d entries, want 1 (TTL cache)", len(cached))
	}

	// Expire the cache → fresh parse sees both entries.
	ExpireCacheForTest()
	fresh, err := ReadPersistent()
	if err != nil {
		t.Fatalf("fresh read: %v", err)
	}
	if len(fresh) != 2 {
		t.Fatalf("fresh read returned %d entries, want 2 after cache expiry", len(fresh))
	}
}

func TestSetHistory_CalledOnAdd(t *testing.T) {
	restore := SwapRingForTest()
	defer restore()

	var got []Entry
	SetHistory(func(e Entry) { got = append(got, e) })
	defer SetHistory(nil)

	Add(Entry{TS: 7, Host: "hook.example.com"})
	if len(got) != 1 || got[0].TS != 7 {
		t.Fatalf("history hook saw %+v, want the single added entry", got)
	}
}

func TestClose_NilSafe(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()
	if err := Close(); err != nil {
		t.Errorf("Close with no persistence = %v, want nil", err)
	}
}
