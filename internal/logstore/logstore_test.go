package logstore

// Engine tests, moved in-package from package main's logstore_test.go and the
// deletion-pass tests of logguard_test.go with the extraction (ADR-0002).
// Lifecycle (enable/disable/purge), API-handler, and disk-guard orchestration
// tests stay in main.

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// drainLogStore waits until the async writer has persisted at least want
// entries (via a query), or fails after a short deadline. The store batches
// writes on a 500ms timer, so tests must not assume synchronous persistence.
func drainLogStore(t *testing.T, s *Store, want int) []Entry {
	t.Helper()
	// Generous deadline: Add() is async (buffered channel → background writer
	// goroutine → Badger), and under the shuffled determinism gate's CPU
	// saturation that writer can be starved for several seconds before it
	// flushes, so reads transiently see fewer than `want` entries.
	deadline := time.Now().Add(15 * time.Second)
	for {
		got, total, err := s.Query(0, 0, 0, 100000, nil)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if total >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d entries; have %d", want, total)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLowPriority(t *testing.T) {
	for _, l := range []string{"INFO", "DEBUG", ""} {
		if !LowPriority(l) {
			t.Errorf("LowPriority(%q) = false, want true", l)
		}
	}
	for _, l := range []string{"WARN", "ERROR"} {
		if LowPriority(l) {
			t.Errorf("LowPriority(%q) = true, want false", l)
		}
	}
}

func TestLogStore_EncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, err := EncKey(dir, "correct horse battery staple")
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	if len(key) != encKeyLen {
		t.Fatalf("key len = %d, want %d", len(key), encKeyLen)
	}
	s, err := OpenTTL(dir, 0, 0, key, nil)
	if err != nil {
		t.Fatalf("open encrypted: %v", err)
	}
	if !s.Encrypted() {
		t.Error("store should report encrypted")
	}
	s.Add(Entry{TS: time.Now().UnixMilli(), Host: "secret.example.com", Status: "OK"})
	got := drainLogStore(t, s, 1)
	if len(got) != 1 || got[0].Host != "secret.example.com" {
		t.Fatalf("encrypted read-back failed: %+v", got)
	}
	_ = s.Close()

	// Reopening the SAME dir with the SAME passphrase+salt works.
	key2, _ := EncKey(dir, "correct horse battery staple")
	s2, err := OpenTTL(dir, 0, 0, key2, nil)
	if err != nil {
		t.Fatalf("reopen encrypted: %v", err)
	}
	if _, total, _ := s2.Query(0, 0, 0, 10, nil); total != 1 {
		t.Errorf("reopen total = %d, want 1", total)
	}
	_ = s2.Close()

	// Wrong passphrase → mismatch sentinel.
	wrong, _ := EncKey(dir, "wrong passphrase")
	if _, err := OpenTTL(dir, 0, 0, wrong, nil); !errors.Is(err, ErrEncMismatch) {
		t.Errorf("wrong key err = %v, want ErrEncMismatch", err)
	}

	// "Lost passphrase": opening an encrypted store with NO key must be rejected
	// (not silently read ciphertext as plaintext).
	if _, err := OpenTTL(dir, 0, 0, nil, nil); !errors.Is(err, ErrEncMismatch) {
		t.Errorf("no-key open of encrypted store err = %v, want ErrEncMismatch (must not open as plaintext)", err)
	}
}

func TestLogStore_WriteQueryNewestFirst(t *testing.T) {
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	base := time.Now().UnixMilli()
	for i := 0; i < 50; i++ {
		s.Add(Entry{TS: base + int64(i), Host: "h.example.com", Status: "OK"})
	}
	got := drainLogStore(t, s, 50)
	if len(got) < 50 {
		t.Fatalf("got %d entries, want >=50", len(got))
	}
	// Newest-first.
	for i := 1; i < len(got); i++ {
		if got[i-1].TS < got[i].TS {
			t.Fatalf("not newest-first at %d: %d < %d", i, got[i-1].TS, got[i].TS)
		}
	}
	if got[0].TS != base+49 {
		t.Errorf("newest TS = %d, want %d", got[0].TS, base+49)
	}
}

func TestLogStore_OffsetPagination(t *testing.T) {
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	base := time.Now().UnixMilli()
	for i := 0; i < 100; i++ {
		s.Add(Entry{TS: base + int64(i), Host: "h", Status: "OK"})
	}
	drainLogStore(t, s, 100)

	// Two non-overlapping pages of 10 over a frozen window.
	page1, total, _ := s.Query(0, 0, 0, 10, nil)
	page2, _, _ := s.Query(0, 0, 10, 10, nil)
	if total != 100 {
		t.Errorf("total = %d, want 100", total)
	}
	if len(page1) != 10 || len(page2) != 10 {
		t.Fatalf("page sizes = %d,%d, want 10,10", len(page1), len(page2))
	}
	// page1 newest (base+99..base+90), page2 next (base+89..base+80).
	if page1[0].TS != base+99 {
		t.Errorf("page1[0].TS = %d, want %d", page1[0].TS, base+99)
	}
	if page2[0].TS != base+89 {
		t.Errorf("page2[0].TS = %d, want %d", page2[0].TS, base+89)
	}
}

func TestLogStore_FilterAndTimeRange(t *testing.T) {
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	base := time.Now().UnixMilli()
	for i := 0; i < 30; i++ {
		host := "good.example.com"
		if i%3 == 0 {
			host = "bad.example.com"
		}
		s.Add(Entry{TS: base + int64(i), Host: host, Status: "OK"})
	}
	drainLogStore(t, s, 30)

	// Host filter.
	_, total, _ := s.Query(0, 0, 0, 1000, func(e *Entry) bool { return e.Host == "bad.example.com" })
	if total != 10 {
		t.Errorf("filtered total = %d, want 10", total)
	}

	// Time-range slice: only entries with TS in [base+10, base+19].
	_, rngTotal, _ := s.Query(base+10, base+19, 0, 1000, nil)
	if rngTotal != 10 {
		t.Errorf("range total = %d, want 10", rngTotal)
	}
}

func TestLogStore_AgeRetentionTTL(t *testing.T) {
	// Short TTL: entries must be gone from reads shortly after expiry. The TTL is
	// 5s (not 1s) so the 20 entries reliably COEXIST in reads long enough for the
	// initial drain to observe all of them even when the async writer goroutine is
	// starved and flushes them a few seconds late under the determinism gate's
	// parallel load — with a 1s TTL the earliest entries could expire before the
	// last were written, so the drain never saw 20 at once ("have 0" flake).
	const ttl = 5 * time.Second
	s, err := OpenTTL(t.TempDir(), ttl, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	base := time.Now().UnixMilli()
	for i := 0; i < 20; i++ {
		s.Add(Entry{TS: base + int64(i), Host: "h", Status: "OK"})
	}
	drainLogStore(t, s, 20)

	// Badger filters TTL-expired entries at read time, so once the TTL passes
	// Query returns total=0. Poll up to a generous deadline (well beyond the TTL)
	// instead of a single fixed sleep, so slow expiry detection under parallel
	// load does not flake.
	deadline := time.Now().Add(ttl + 15*time.Second)
	var total int
	for {
		var qerr error
		if _, total, qerr = s.Query(0, 0, 0, 1000, nil); qerr != nil {
			t.Fatalf("Query after expiry: %v", qerr)
		}
		if total == 0 {
			break // all entries expired out of reads — success
		}
		if time.Now().After(deadline) {
			t.Fatalf("after TTL expiry total = %d, want 0 (entries did not expire within deadline)", total)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestLogStore_SizeRetentionPrunesOldest(t *testing.T) {
	// maxBytes=1 forces the janitor to prune on every pass; a small batch makes
	// the prune partial so we can prove it drops the OLDEST entries first.
	old := pruneBatch
	pruneBatch = 10
	defer func() { pruneBatch = old }()

	s, err := OpenTTL(t.TempDir(), 0, 1, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	base := time.Now().UnixMilli()
	for i := 0; i < 50; i++ {
		s.Add(Entry{TS: base + int64(i), Host: "h", Status: "OK"})
	}
	drainLogStore(t, s, 50)

	before := Pruned()
	_, count, _ := s.RunRetention()
	if count != 10 {
		t.Errorf("RunRetention count = %d, want 10", count)
	}
	if got := Pruned(); got != before+10 {
		t.Errorf("pruned counter delta = %d, want 10", got-before)
	}

	got, total, _ := s.Query(0, 0, 0, 1000, nil)
	if total != 40 {
		t.Errorf("after prune total = %d, want 40", total)
	}
	// The 10 oldest (base..base+9) should be gone; oldest remaining is base+10.
	if len(got) > 0 && got[len(got)-1].TS != base+10 {
		t.Errorf("oldest remaining TS = %d, want %d (oldest pruned first)", got[len(got)-1].TS, base+10)
	}
}

func TestLogStore_Stats(t *testing.T) {
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	base := time.Now().UnixMilli()
	for i := 0; i < 25; i++ {
		s.Add(Entry{TS: base + int64(i), Host: "h", Status: "OK"})
	}
	drainLogStore(t, s, 25)

	st := s.Stats()
	if st.Count != 25 {
		t.Errorf("Stats.Count = %d, want 25", st.Count)
	}
	if st.OldestMs != base {
		t.Errorf("Stats.OldestMs = %d, want %d", st.OldestMs, base)
	}
}

// TestLogStore_AddCloseRace exercises concurrent Add during Close — under -race
// this fails if the send/close synchronization regresses (no send on a closed
// channel, no panic).
func TestLogStore_AddCloseRace(t *testing.T) {
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				s.Add(Entry{TS: int64(i), Host: "h", Status: "OK"})
			}
		}()
	}
	time.Sleep(2 * time.Millisecond) // let some Adds get in flight
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	wg.Wait() // must complete without a panic
}

func TestLogStore_NilSafe(t *testing.T) {
	var s *Store
	s.Add(Entry{TS: 1})
	if _, count, _ := s.RunRetention(); count != 0 {
		t.Errorf("nil RunRetention count = %d, want 0", count)
	}
	if _, total, err := s.Query(0, 0, 0, 10, nil); err != nil || total != 0 {
		t.Errorf("nil Query = (%d,%v), want (0,nil)", total, err)
	}
	if st := s.Stats(); st.Bytes != 0 || st.Count != 0 {
		t.Errorf("nil Stats = %+v, want zero", st)
	}
	if err := s.Close(); err != nil {
		t.Errorf("nil Close = %v", err)
	}
	if s.BytesUsed() != 0 {
		t.Error("nil BytesUsed should be 0")
	}
}

// ── Priority-aware cleanup (moved from main's logguard_test.go) ──────────────

// newTestStore opens an unencrypted store directly (no janitor goroutine) so
// tests can drive cleanup deterministically.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("OpenTTL: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestCleanupBytes_PriorityOrder proves low-priority (INFO) entries are deleted
// before high-priority security (WARN/ERROR) entries when freeing space.
func TestCleanupBytes_PriorityOrder(t *testing.T) {
	s := newTestStore(t)

	base := time.Now().UnixMilli()
	// Interleave low and high priority so pass-1 (low-only) must skip the high
	// ones rather than just deleting the oldest block.
	const n = 40
	for i := 0; i < n; i++ {
		lvl := "INFO"
		if i%2 == 0 {
			lvl = "WARN"
		}
		s.Add(Entry{TS: base + int64(i), Level: lvl, Host: "example.com", Method: "GET"})
	}
	drainLogStore(t, s, n)

	// Ask to free a large amount so pass-1 deletes ALL low-priority entries but
	// pass-2 should not be reached unless pass-1 was insufficient.
	freed, count, levels := s.CleanupBytes(1 << 40)
	if count == 0 {
		t.Fatal("CleanupBytes freed nothing")
	}
	if freed <= 0 {
		t.Fatalf("freed = %d, want > 0", freed)
	}
	// The hard invariant: querying for remaining INFO == 0.
	remaining, _, err := s.Query(0, 0, 0, 100000, func(e *Entry) bool { return e.Level == "INFO" })
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("expected all INFO deleted, %d remain", len(remaining))
	}
	if levels["INFO"] == 0 {
		t.Error("expected INFO entries in cleanup breakdown")
	}
}

// TestCleanupBytes_KeepsSecurityWhenLowFrees proves that if deleting just the
// low-priority entries frees enough, the high-priority security logs survive.
func TestCleanupBytes_KeepsSecurityWhenLowFrees(t *testing.T) {
	s := newTestStore(t)

	base := time.Now().UnixMilli()
	const lows, highs = 30, 10
	for i := 0; i < lows; i++ {
		s.Add(Entry{TS: base + int64(i), Level: "INFO", Host: "a.com"})
	}
	for i := 0; i < highs; i++ {
		s.Add(Entry{TS: base + int64(1000+i), Level: "ERROR", Host: "threat.com"})
	}
	drainLogStore(t, s, lows+highs)

	// Free a small amount — a handful of entries' worth. Pass-1 (low only) should
	// satisfy it, leaving every ERROR security log intact.
	_, count, levels := s.CleanupBytes(200)
	if count == 0 {
		t.Fatal("CleanupBytes freed nothing")
	}
	if levels["ERROR"] != 0 || levels["WARN"] != 0 {
		t.Errorf("security logs were deleted in low-pressure cleanup: %v", levels)
	}
	sec, _, err := s.Query(0, 0, 0, 100000, func(e *Entry) bool { return e.Level == "ERROR" })
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(sec) != highs {
		t.Errorf("expected %d ERROR logs preserved, got %d", highs, len(sec))
	}
}

// TestAdd_MinimalHook verifies the injected minimal-mode hook: while it
// reports true, low-priority entries are dropped and security entries persist.
func TestAdd_MinimalHook(t *testing.T) {
	minimal := true
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, func() bool { return minimal })
	if err != nil {
		t.Fatalf("OpenTTL: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	base := time.Now().UnixMilli()
	s.Add(Entry{TS: base, Level: "INFO", Host: "traffic.com"})   // should drop
	s.Add(Entry{TS: base + 1, Level: "WARN", Host: "block.com"}) // should persist
	s.Add(Entry{TS: base + 2, Level: "ERROR", Host: "auth.com"}) // should persist

	got := drainLogStore(t, s, 2)
	for i := range got {
		if LowPriority(got[i].Level) {
			t.Errorf("low-priority entry persisted with minimal hook active: %+v", got[i])
		}
	}

	minimal = false
	s.Add(Entry{TS: base + 3, Level: "INFO", Host: "traffic2.com"}) // persists again
	drainLogStore(t, s, 3)
}
