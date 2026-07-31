package fileutil

// persist_test.go — CHAOS-27 durable-write accounting.
//
// Every case forces a REAL AtomicWrite failure rather than stubbing one: the
// target's parent directory does not exist, so os.CreateTemp fails with ENOENT.
// That is uid-independent — a chmod-based unwritable directory would not fail
// for a root-owned test runner (containers routinely run tests as root), which
// is exactly the kind of test that passes locally and proves nothing.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// badPath returns a path whose parent directory does not exist.
func badPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "no-such-dir", "state.json")
}

func TestAtomicWriteTracked_FailureIsRecordedAndReported(t *testing.T) {
	ResetPersistTrackingForTest()
	t.Cleanup(ResetPersistTrackingForTest)

	var got []PersistEvent
	SetPersistFailureReporter(func(ev PersistEvent) { got = append(got, ev) })

	err := AtomicWriteTracked("policy_rules", badPath(t), []byte("x"), 0o600)
	if err == nil {
		t.Fatal("AtomicWriteTracked returned nil error for an unwritable path")
	}

	if n := PersistFailureTotal(); n != 1 {
		t.Errorf("PersistFailureTotal = %d, want 1", n)
	}
	failing := PersistFailures()
	if len(failing) != 1 || failing[0].Store != "policy_rules" {
		t.Fatalf("PersistFailures = %+v, want one policy_rules entry", failing)
	}
	if failing[0].Consecutive != 1 || failing[0].Total != 1 {
		t.Errorf("consecutive=%d total=%d, want 1/1", failing[0].Consecutive, failing[0].Total)
	}
	if failing[0].Err == "" {
		t.Error("recorded failure carries no error text")
	}
	if len(got) != 1 || got[0].Err == nil || got[0].Recovered {
		t.Fatalf("reporter events = %+v, want one failure event", got)
	}
	if got[0].Consecutive != 1 {
		t.Errorf("reported Consecutive = %d, want 1 (the transition edge)", got[0].Consecutive)
	}
}

func TestAtomicWriteTracked_ConsecutiveThenRecovery(t *testing.T) {
	ResetPersistTrackingForTest()
	t.Cleanup(ResetPersistTrackingForTest)

	var got []PersistEvent
	SetPersistFailureReporter(func(ev PersistEvent) { got = append(got, ev) })

	bad := badPath(t)
	for i := 0; i < 3; i++ {
		if err := AtomicWriteTracked("blocklist", bad, []byte("x"), 0o600); err == nil {
			t.Fatalf("write %d unexpectedly succeeded", i)
		}
	}
	if len(got) != 3 {
		t.Fatalf("want 3 failure events, got %d", len(got))
	}
	var want uint64
	for i, ev := range got {
		want++
		if ev.Consecutive != want {
			t.Errorf("event %d Consecutive = %d, want %d", i, ev.Consecutive, want)
		}
	}

	// Only the first is the transition edge — that is what package main alerts
	// on, so a permanently broken disk cannot emit a webhook per save.
	edges := 0
	for _, ev := range got {
		if ev.Err != nil && ev.Consecutive == 1 {
			edges++
		}
	}
	if edges != 1 {
		t.Errorf("transition-edge events = %d, want exactly 1", edges)
	}

	// Recovery: a successful write to a good path clears the failing state and
	// reports exactly one recovery event.
	good := filepath.Join(t.TempDir(), "state.json")
	if err := AtomicWriteTracked("blocklist", good, []byte("ok"), 0o600); err != nil {
		t.Fatalf("recovery write: %v", err)
	}
	if f := PersistFailures(); len(f) != 0 {
		t.Errorf("PersistFailures after recovery = %+v, want empty", f)
	}
	last := got[len(got)-1]
	if !last.Recovered || last.Err != nil {
		t.Fatalf("last event = %+v, want a recovery event", last)
	}
	// Totals stay monotonic across recovery (rate() must not go backwards).
	if PersistFailureTotals()["blocklist"] != 3 {
		t.Errorf("per-store total = %d, want 3 after recovery", PersistFailureTotals()["blocklist"])
	}

	// A second success must NOT re-report — recovery is an edge, not a state.
	before := len(got)
	if err := AtomicWriteTracked("blocklist", good, []byte("ok"), 0o600); err != nil {
		t.Fatalf("second good write: %v", err)
	}
	if len(got) != before {
		t.Errorf("a healthy write emitted an event: %+v", got[before:])
	}
}

func TestPersistFailuresSince_WindowsAttributeCorrectly(t *testing.T) {
	ResetPersistTrackingForTest()
	t.Cleanup(ResetPersistTrackingForTest)

	bad := badPath(t)
	// A failure BEFORE the window must not be attributed to it.
	_ = AtomicWriteTracked("ssl_bypass", bad, []byte("x"), 0o600)

	seq := PersistFailureSeq()
	if got := PersistFailuresSince(seq); len(got) != 0 {
		t.Fatalf("PersistFailuresSince(now) = %v, want empty", got)
	}

	// Failures inside the window are named, sorted, deduplicated by store.
	_ = AtomicWriteTracked("policy_rules", bad, []byte("x"), 0o600)
	_ = AtomicWriteTracked("category_groups", bad, []byte("x"), 0o600)
	_ = AtomicWriteTracked("policy_rules", bad, []byte("x"), 0o600)

	got := PersistFailuresSince(seq)
	if len(got) != 2 || got[0] != "category_groups" || got[1] != "policy_rules" {
		t.Fatalf("PersistFailuresSince = %v, want [category_groups policy_rules]", got)
	}

	// A store that failed inside the window but has since RECOVERED is no
	// longer reported — the window answers "what is stale on disk now".
	good := filepath.Join(t.TempDir(), "cg.json")
	if err := AtomicWriteTracked("category_groups", good, []byte("ok"), 0o600); err != nil {
		t.Fatalf("recovery write: %v", err)
	}
	if got := PersistFailuresSince(seq); len(got) != 1 || got[0] != "policy_rules" {
		t.Fatalf("after recovery PersistFailuresSince = %v, want [policy_rules]", got)
	}
}

func TestAtomicWriteTracked_SuccessPathIsUnchanged(t *testing.T) {
	ResetPersistTrackingForTest()
	t.Cleanup(ResetPersistTrackingForTest)

	fired := false
	SetPersistFailureReporter(func(PersistEvent) { fired = true })

	path := filepath.Join(t.TempDir(), "state.json")
	if err := AtomicWriteTracked("url_categories", path, []byte("payload"), 0o600); err != nil {
		t.Fatalf("AtomicWriteTracked: %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil || string(data) != "payload" {
		t.Fatalf("file content = %q err=%v, want %q", data, err, "payload")
	}
	if fired {
		t.Error("reporter fired on a healthy write")
	}
	if PersistFailureTotal() != 0 || len(PersistFailures()) != 0 {
		t.Error("healthy write recorded a failure")
	}
}

func TestSetPersistFailureReporter_NilAndPanicSafety(t *testing.T) {
	ResetPersistTrackingForTest()
	t.Cleanup(ResetPersistTrackingForTest)

	// No reporter installed: accounting still works, nothing panics.
	if err := AtomicWriteTracked("content_scan", badPath(t), []byte("x"), 0o600); err == nil {
		t.Fatal("want an error")
	}
	if PersistFailureTotal() != 1 {
		t.Errorf("total = %d, want 1 with no reporter installed", PersistFailureTotal())
	}

	// Installing then clearing must not leave a dangling hook.
	SetPersistFailureReporter(func(PersistEvent) { t.Error("cleared reporter was called") })
	SetPersistFailureReporter(nil)
	if err := AtomicWriteTracked("content_scan", badPath(t), []byte("x"), 0o600); err == nil {
		t.Fatal("want an error")
	}
}

func TestAtomicWriteTracked_ErrorIsTheAtomicWriteError(t *testing.T) {
	ResetPersistTrackingForTest()
	t.Cleanup(ResetPersistTrackingForTest)

	bad := badPath(t)
	tracked := AtomicWriteTracked("file_block", bad, []byte("x"), 0o600)
	plain := AtomicWrite(bad, []byte("x"), 0o600)
	if tracked == nil || plain == nil {
		t.Fatal("both writes should fail")
	}
	if !errors.Is(tracked, os.ErrNotExist) || !errors.Is(plain, os.ErrNotExist) {
		t.Fatalf("tracked=%v plain=%v, want both to wrap ErrNotExist", tracked, plain)
	}
}
