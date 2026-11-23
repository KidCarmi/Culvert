package authposture

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

// osWrite is a plain (non-atomic) writer: the package's contract is only that
// it calls the injected writer; durability is the writer's job.
func osWrite(path string, data []byte, perm fs.FileMode) error { return os.WriteFile(path, data, perm) }

func failingWrite(string, []byte, fs.FileMode) error { return errors.New("disk full") }

func mustEncode(t *testing.T, rec Record) []byte {
	t.Helper()
	b, err := Encode(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func establishedBytes(t *testing.T) []byte {
	return mustEncode(t, Record{Version: 1, Established: true, Since: t0.Format(time.RFC3339), By: "test"})
}

func freshBytes(t *testing.T) []byte {
	return mustEncode(t, Record{Version: 1, EvaluatedAt: t0.Format(time.RFC3339)})
}

// TestOpen_Outcomes: only a missing file or a valid fresh record leaves the
// ratchet unestablished; every corrupt or unreadable marker establishes it
// (fail closed) and names the problem.
func TestOpen_Outcomes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		content     func(t *testing.T) []byte // nil: no file
		dir         bool                      // a directory where the file should be
		want        Outcome
		established bool
		problem     Problem
		pending     bool
	}{
		{name: "missing", want: OutcomeMissing, pending: true},
		{name: "fresh", content: freshBytes, want: OutcomeFresh},
		{name: "established", content: establishedBytes, want: OutcomeEstablished, established: true},
		{name: "empty file", content: func(*testing.T) []byte { return []byte{} }, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "truncated json", content: func(*testing.T) []byte { return []byte(`{"version":1,"establ`) }, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "garbage", content: func(*testing.T) []byte { return []byte("\x00\xff not json") }, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "unknown version", content: func(*testing.T) []byte {
			return []byte(`{"version":2,"established":false,"evaluated_at":"2026-11-23T10:00:00Z"}`)
		}, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "unknown field", content: func(*testing.T) []byte {
			return []byte(`{"version":1,"established":false,"evaluated_at":"2026-11-23T10:00:00Z","x":1}`)
		}, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "trailing data", content: func(t *testing.T) []byte { return append(freshBytes(t), []byte(`{}`)...) }, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "established without since", content: func(*testing.T) []byte { return []byte(`{"version":1,"established":true,"by":"x"}`) }, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "fresh without timestamp", content: func(*testing.T) []byte { return []byte(`{"version":1,"established":false}`) }, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "fresh carrying by", content: func(*testing.T) []byte {
			return []byte(`{"version":1,"established":false,"evaluated_at":"2026-11-23T10:00:00Z","by":"x"}`)
		}, want: OutcomeCorrupt, established: true, problem: ProblemCorrupt},
		{name: "directory in its place", dir: true, want: OutcomeUnreadable, established: true, problem: ProblemUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "marker.json")
			switch {
			case tc.dir:
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case tc.content != nil:
				if err := os.WriteFile(path, tc.content(t), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var r Ratchet
			got, err := r.Open(path, osWrite, nil)
			if got != tc.want {
				t.Fatalf("outcome %d, want %d (err %v)", got, tc.want, err)
			}
			if (err != nil) != (tc.problem != "") {
				t.Errorf("err = %v, want an error iff the marker is corrupt/unreadable", err)
			}
			if r.Established() != tc.established {
				t.Errorf("Established() = %v, want %v", r.Established(), tc.established)
			}
			if st := r.Status(); st.Problem != tc.problem || st.Established != tc.established {
				t.Errorf("status %+v, want established=%v problem=%q", st, tc.established, tc.problem)
			}
			if r.MigrationPending() != tc.pending {
				t.Errorf("MigrationPending() = %v, want %v", r.MigrationPending(), tc.pending)
			}
		})
	}
}

// TestOpen_ReadErrorIsUnreadable: a permission (or any non-ENOENT) read error
// is fail-closed. Injected, because the test may run as root.
func TestOpen_ReadErrorIsUnreadable(t *testing.T) {
	var r Ratchet
	got, err := r.Open("/nonexistent/marker.json", osWrite, func(string) ([]byte, error) { return nil, fs.ErrPermission })
	if got != OutcomeUnreadable || err == nil || !r.Established() || r.Status().Problem != ProblemUnreadable {
		t.Fatalf("permission error: outcome %d err %v established %v status %+v", got, err, r.Established(), r.Status())
	}
}

// TestEstablish_WriteAhead: the marker is on disk before the flag is raised,
// and a failed write raises nothing.
func TestEstablish_WriteAhead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker.json")
	var r Ratchet
	if _, err := r.Open(path, failingWrite, nil); err != nil {
		t.Fatal(err)
	}
	changed, err := r.Establish("admin-api", t0)
	if err == nil || changed || r.Established() {
		t.Fatalf("a failed write must leave the ratchet unestablished: changed=%v err=%v established=%v", changed, err, r.Established())
	}
	if !r.MigrationPending() {
		t.Error("a failed Establish must not settle a pending migration")
	}

	var observedDuringWrite bool
	var r2 Ratchet
	write := func(p string, data []byte, perm fs.FileMode) error {
		observedDuringWrite = r2.Established()
		return osWrite(p, data, perm)
	}
	if _, err := r2.Open(path, write, nil); err != nil {
		t.Fatal(err)
	}
	changed, err = r2.Establish("admin-api", t0)
	if err != nil || !changed || !r2.Established() {
		t.Fatalf("Establish: changed=%v err=%v established=%v", changed, err, r2.Established())
	}
	if observedDuringWrite {
		t.Error("the flag was raised before the marker write completed (not write-ahead)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Decode(data)
	if err != nil || !rec.Established || rec.By != "admin-api" || rec.Since != t0.Format(time.RFC3339) {
		t.Fatalf("marker on disk = %+v (%v)", rec, err)
	}
	// Idempotent: a second activation writes nothing and reports no change.
	r2.write = failingWrite
	if changed, err := r2.Establish("later", t0.Add(time.Hour)); changed || err != nil {
		t.Errorf("second Establish: changed=%v err=%v, want a no-op", changed, err)
	}
	if st := r2.Status(); st.By != "admin-api" {
		t.Errorf("the first establishment's origin must be kept, got %+v", st)
	}
}

// TestEstablishFailClosed_RaisesAndRetries: an activation that cannot be
// refused raises the flag anyway, reports not_durable, and the next Establish
// repairs the marker while keeping the original origin.
func TestEstablishFailClosed_RaisesAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker.json")
	var r Ratchet
	if _, err := r.Open(path, failingWrite, nil); err != nil {
		t.Fatal(err)
	}
	changed, err := r.EstablishFailClosed("startup", t0)
	if err == nil || !changed || !r.Established() || r.Status().Problem != ProblemNotDurable {
		t.Fatalf("fail-closed: changed=%v err=%v established=%v status=%+v", changed, err, r.Established(), r.Status())
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("nothing must be on disk yet: %v", err)
	}
	// Still failing: stays established, still not durable.
	if _, err := r.Establish("again", t0.Add(time.Minute)); err == nil || !r.Established() {
		t.Fatal("a failed retry must keep the flag and report the error")
	}
	r.write = osWrite
	if changed, err := r.Establish("repair", t0.Add(time.Hour)); err != nil || !changed {
		t.Fatalf("retry: changed=%v err=%v", changed, err)
	}
	st := r.Status()
	if st.Problem != "" || st.By != "startup" || st.Since != t0.Format(time.RFC3339) {
		t.Errorf("after the repair: %+v, want the original origin and no problem", st)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if rec, err := Decode(data); err != nil || !rec.Established || rec.By != "startup" {
		t.Errorf("repaired marker = %+v (%v)", rec, err)
	}
}

// TestRatchet_NeverLowers: no sequence of calls clears the flag. Open on a
// ratchet already established in memory keeps it established whatever the
// file says (missing, fresh).
func TestRatchet_NeverLowers(t *testing.T) {
	dir := t.TempDir()
	var r Ratchet
	if _, err := r.Establish("in-memory", t0); err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{nil, freshBytes(t)} {
		path := filepath.Join(dir, "m.json")
		_ = os.Remove(path)
		if content != nil {
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.Open(path, osWrite, nil); err != nil {
			t.Fatal(err)
		}
		if !r.Established() {
			t.Fatalf("Open lowered an established ratchet (file content %q)", content)
		}
		if err := r.RecordFresh(t0); err != nil || !r.Established() {
			t.Fatalf("RecordFresh lowered it: %v", err)
		}
	}
}

// TestRecordFresh: settles a pending migration exactly once, and only when
// pending.
func TestRecordFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker.json")
	var r Ratchet
	if got, _ := r.Open(path, failingWrite, nil); got != OutcomeMissing {
		t.Fatalf("outcome %d", got)
	}
	if err := r.RecordFresh(t0); err == nil || !r.MigrationPending() {
		t.Fatal("a failed fresh write must keep the migration pending")
	}
	r.write = osWrite
	if err := r.RecordFresh(t0); err != nil || r.MigrationPending() || r.Established() {
		t.Fatalf("RecordFresh: err=%v pending=%v established=%v", err, r.MigrationPending(), r.Established())
	}
	var reopened Ratchet
	if got, err := reopened.Open(path, osWrite, nil); got != OutcomeFresh || err != nil || reopened.MigrationPending() {
		t.Fatalf("a fresh record must not re-run the migration: outcome %d err %v", got, err)
	}
	// A fresh record is upgraded by a later activation, never the reverse.
	if _, err := reopened.Establish("idp", t0); err != nil {
		t.Fatal(err)
	}
	var third Ratchet
	if got, _ := third.Open(path, osWrite, nil); got != OutcomeEstablished {
		t.Fatalf("after establishment the marker reads %d", got)
	}
}

// TestInMemoryRatchet: with no file the ratchet still works, and never writes.
func TestInMemoryRatchet(t *testing.T) {
	var r Ratchet
	if r.Established() {
		t.Fatal("zero value must not be established")
	}
	if changed, err := r.Establish("x", t0); err != nil || !changed || !r.Established() {
		t.Fatalf("in-memory Establish: changed=%v err=%v", changed, err)
	}
}

// TestMergeForRestore: a restore can set the posture, never clear it.
func TestMergeForRestore(t *testing.T) {
	est, fresh, corrupt := establishedBytes(t), freshBytes(t), []byte("{")
	other := mustEncode(t, Record{Version: 1, Established: true, Since: t0.Add(time.Hour).Format(time.RFC3339), By: "archive"})
	for _, tc := range []struct {
		name              string
		current, incoming []byte
		want              []byte
		keep              bool
	}{
		{"neither", nil, nil, nil, false},
		{"archive establishes a fresh node", nil, other, other, true},
		{"archive establishes over a fresh record", fresh, other, other, true},
		{"current established, archive absent", est, nil, est, true},
		{"current established, archive fresh", est, fresh, est, true},
		{"current established wins over archive established", est, other, est, true},
		{"current corrupt is kept (fail closed)", corrupt, fresh, corrupt, true},
		{"archive corrupt establishes", nil, corrupt, corrupt, true},
		{"fresh is never carried over", fresh, fresh, nil, false},
		{"fresh current, archive absent", fresh, nil, nil, false},
		{"archive fresh, current absent", nil, fresh, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, keep := MergeForRestore(tc.current, tc.incoming)
			if keep != tc.keep || !bytes.Equal(got, tc.want) {
				t.Fatalf("MergeForRestore = (%q, %v), want (%q, %v)", got, keep, tc.want, tc.keep)
			}
		})
	}
}

// TestEstablished_AllocFree: the hot-path read allocates nothing.
func TestEstablished_AllocFree(t *testing.T) {
	var r Ratchet
	if _, err := r.Establish("x", t0); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = r.Established() }); n != 0 {
		t.Fatalf("Established allocates %.1f per call, want 0", n)
	}
}

// TestRatchet_ConcurrentEstablish: many activations racing many readers raise
// the flag exactly once and write exactly one marker (run with -race).
func TestRatchet_ConcurrentEstablish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker.json")
	var writes, changes int
	var mu sync.Mutex
	write := func(p string, data []byte, perm fs.FileMode) error {
		mu.Lock()
		writes++
		mu.Unlock()
		return osWrite(p, data, perm)
	}
	var r Ratchet
	if _, err := r.Open(path, write, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if changed, err := r.Establish("racer", t0); err != nil {
				t.Error(err)
			} else if changed {
				mu.Lock()
				changes++
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			seen := false
			for j := 0; j < 100; j++ {
				now := r.Established()
				if seen && !now {
					t.Error("the flag was observed lowered")
				}
				seen = seen || now
			}
		}()
	}
	wg.Wait()
	if writes != 1 || changes != 1 || !r.Established() {
		t.Fatalf("writes=%d changes=%d established=%v, want 1/1/true", writes, changes, r.Established())
	}
}

// TestBoundBy keeps the origin description bounded and never empty.
func TestBoundBy(t *testing.T) {
	if got := boundBy(""); got != "unspecified" {
		t.Errorf("empty by = %q", got)
	}
	if got := boundBy(strings.Repeat("x", 500)); len(got) != maxByLen {
		t.Errorf("long by kept %d bytes", len(got))
	}
}
