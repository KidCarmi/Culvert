package audit

// Engine tests, consolidated in-package from package main's
// distributed_rl_test.go (DP push queue), edge_audit_test.go
// (GetMemory), and final_coverage_test.go (Add file/no-file paths, ring
// truncation, Init with oversized existing data) with the extraction
// (ADR-0002, store.go decomposition Phase B).

import (
	"os"
	"testing"
	"time"
)

func TestDPQueue_QueueDrainRequeue(t *testing.T) {
	// Drain any existing events.
	Drain()

	queueForCluster(Entry{Action: "test1"})
	queueForCluster(Entry{Action: "test2"})

	events := Drain()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Action != "test1" || events[1].Action != "test2" {
		t.Fatal("events out of order")
	}

	// Second drain should be empty.
	if events = Drain(); events != nil {
		t.Fatalf("expected nil after drain, got %d events", len(events))
	}

	// Requeue prepends before newer arrivals.
	queueForCluster(Entry{Action: "newer"})
	Requeue([]Entry{{Action: "retried"}})
	events = Drain()
	if len(events) != 2 || events[0].Action != "retried" || events[1].Action != "newer" {
		t.Fatalf("requeue order wrong: %+v", events)
	}
}

func TestGetMemory(t *testing.T) {
	restore := SwapRingForTest()
	defer restore()

	now := time.Now().UnixMilli()
	for i := 0; i < 5; i++ {
		Add(Entry{
			TS:     now + int64(i*1000),
			Time:   time.Now().Format("15:04:05"),
			Actor:  "admin",
			Action: "test",
		})
	}

	// No filter.
	entries, total := GetMemory(0, 100, 0, 0)
	if total != 5 || len(entries) != 5 {
		t.Errorf("no filter: total=%d len=%d, want 5/5", total, len(entries))
	}
	// Newest-first.
	if entries[0].TS != now+4000 {
		t.Errorf("entries[0].TS = %d, want %d (newest first)", entries[0].TS, now+4000)
	}
	// Time window keeps the middle three.
	_, total = GetMemory(0, 100, now+1000, now+3000)
	if total != 3 {
		t.Errorf("time filter total = %d, want 3", total)
	}
	// Pagination.
	page, total := GetMemory(2, 2, 0, 0)
	if total != 5 || len(page) != 2 {
		t.Errorf("pagination: total=%d len=%d, want 5/2", total, len(page))
	}
	// Offset past the end.
	page, _ = GetMemory(99, 2, 0, 0)
	if page != nil {
		t.Errorf("offset past end should return nil, got %d", len(page))
	}
}

func TestAdd_NoFileNoSIEM_NoPanic(_ *testing.T) {
	restore := ResetForTest()
	defer restore()

	// Add should not panic when neither persistence nor SIEM is wired.
	Add(Entry{TS: 1, Action: "test.action", Actor: "testactor"})
}

func TestAdd_WritesToFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "auditadd*.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	restore := SetPersistForTest(f)
	defer restore()

	Add(Entry{TS: 1, Action: "test.file.write", Actor: "testactor"})

	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, _ := f.Read(buf)
	if n == 0 {
		t.Error("Add should write to the file when persistence is wired")
	}
	f.Close()
}

func TestAdd_RingTruncation(t *testing.T) {
	restore := ResetForTest()
	defer restore()

	for i := 0; i < MaxRing+10; i++ {
		Add(Entry{TS: int64(i), Action: "test"})
	}
	if n := len(Get()); n > MaxRing {
		t.Errorf("Add should cap the ring at %d, got %d", MaxRing, n)
	}
}

func TestInit_TruncatesOversizedExistingData(t *testing.T) {
	restore := ResetForTest()
	defer restore()

	f, err := os.CreateTemp(t.TempDir(), "auditinit*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxRing+5; i++ {
		_, _ = f.WriteString(`{"ts":` + string(rune('0'+i%10)) + `,"action":"test"}` + "\n")
	}
	f.Close()

	if err := Init(f.Name()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = Close(); ClearPersistForTest() }()

	if !PersistActive() {
		t.Fatal("Init did not wire the persistent closer")
	}
	if n := len(Get()); n > MaxRing {
		t.Errorf("Init should truncate loaded ring at %d, got %d", MaxRing, n)
	}
}

func TestClose_NilSafe(t *testing.T) {
	restore := ResetForTest()
	defer restore()
	if err := Close(); err != nil {
		t.Errorf("Close with no persistence = %v, want nil", err)
	}
}
