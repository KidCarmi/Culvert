package uploadqueue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportupload"
)

// engine_test.go: what the move added (IM-029). The tests in queue_test.go
// came from the root package; these cover the properties an instance has that
// the package-level engine could not be asked about, and compare Attempt and
// the retry ladder with frozen copies of the bodies main had.

// frozenRetryBackoff is uploadRetryBackoff as it stood in main `155df0944`.
func frozenRetryBackoff(attempts int) time.Duration {
	const base, ceiling = 2 * time.Second, 10 * time.Minute
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 20 {
		return ceiling
	}
	d := base << (attempts - 1)
	if d <= 0 || d > ceiling {
		return ceiling
	}
	return d
}

// frozenDrain is drainUploadEntry as it stood in main `155df0944`, with the
// root constants (6 attempts, 256 bytes) and the sanitizer written in.
func frozenDrain(e Entry, rec *supportupload.Receipt, uploadID string, err error, now time.Time) Entry {
	nowStr := now.UTC().Format(time.RFC3339)
	e.State = StateUploading
	e.UpdatedAt = nowStr
	if uploadID != "" {
		e.UploadID = uploadID
	}
	if err == nil {
		e.State = StateUploaded
		e.Receipt = rec
		e.NextRetryAt = 0
		e.LastError = ""
		e.UpdatedAt = nowStr
		return e
	}
	e.Attempts++
	s := testSanitize(err.Error())
	if len(s) > 256 {
		s = s[:256] + "…"
	}
	e.LastError = s
	e.UpdatedAt = nowStr
	var ge *supportupload.GatewayError
	if errors.As(err, &ge) && ge.Status >= 400 && ge.Status < 500 {
		e.State = StateRejected
		e.NextRetryAt = 0
		return e
	}
	if e.Attempts >= 6 {
		e.State = StateDeferred
		e.NextRetryAt = 0
		return e
	}
	e.State = StateQueued
	e.NextRetryAt = now.Add(frozenRetryBackoff(e.Attempts)).Unix()
	return e
}

func TestRetryBackoff_MatchesFrozenLadder(t *testing.T) {
	for attempts := -3; attempts <= 80; attempts++ {
		if got, want := retryBackoff(attempts), frozenRetryBackoff(attempts); got != want {
			t.Errorf("retryBackoff(%d) = %s, frozen %s", attempts, got, want)
		}
	}
	// The ladder itself, so both copies cannot drift together unnoticed.
	want := []time.Duration{2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600}
	for i, w := range want {
		if got := retryBackoff(i + 1); got != w*time.Second {
			t.Errorf("retryBackoff(%d) = %s, want %ds", i+1, got, w)
		}
	}
}

// attemptErrors is the error half of the differential table.
func attemptErrors() map[string]error {
	long := strings.Repeat("é", 200) // 400 bytes: the bound cuts inside the text
	errs := map[string]error{
		"success":         nil,
		"transient":       errors.New("connection refused"),
		"control bytes":   errors.New("a\r\nb\x00c\x1b[0m\x7f"),
		"long":            errors.New(long),
		"exactly bound":   errors.New(strings.Repeat("x", 256)),
		"bound plus one":  errors.New(strings.Repeat("x", 257)),
		"context":         context.DeadlineExceeded,
		"wrapped gateway": fmt.Errorf("complete: %w", &supportupload.GatewayError{Status: 409, Body: "hash"}),
	}
	for _, status := range []int{0, 200, 302, 399, 400, 403, 404, 429, 499, 500, 502, 503, 599} {
		errs[fmt.Sprintf("gateway %d", status)] = &supportupload.GatewayError{Status: status, Body: "b\nody"}
	}
	return errs
}

// attemptAgainstFrozen runs one input through Attempt and the frozen body and
// returns the state both must agree on.
func attemptAgainstFrozen(t *testing.T, q *Queue, name string, in Entry, uploadID string, err error, now time.Time) State {
	t.Helper()
	var rec *supportupload.Receipt
	if err == nil {
		rec = &supportupload.Receipt{BundleSHA256: "h", Sig: "sig"}
	}
	var sawState State
	got := q.Attempt(context.Background(), in, func(_ context.Context, e Entry) (*supportupload.Receipt, string, error) {
		sawState = e.State
		return rec, uploadID, err
	}, now)
	if sawState != StateUploading {
		t.Fatalf("%s: the transfer saw state %q, want uploading", name, sawState)
	}
	if want := frozenDrain(in, rec, uploadID, err, now); !reflect.DeepEqual(got, want) {
		t.Errorf("%s attempts=%d id=%q prior=%q:\n got  %+v\n want %+v", name, in.Attempts, uploadID, in.UploadID, got, want)
	}
	return got.State
}

func TestAttempt_MatchesFrozenClassification(t *testing.T) {
	q := newTestQueue(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	errs := attemptErrors()
	seen := map[State]int{}
	cases := 0
	for name, err := range errs {
		for attempts := 0; attempts <= 8; attempts++ {
			for _, ids := range [][2]string{{"", ""}, {"", "sess-old"}, {"sess-new", ""}, {"sess-new", "sess-old"}} {
				in := Entry{
					BundleID: csbID("d"), CaseID: "C", State: StateQueued, Attempts: attempts,
					NextRetryAt: 5, UploadID: ids[1], LastError: "previous", CreatedAt: "c", UpdatedAt: "u",
				}
				seen[attemptAgainstFrozen(t, q, name, in, ids[0], err, now)]++
				cases++
			}
		}
	}
	// Anti-vacuity: the table reaches every outcome Attempt can produce.
	for _, s := range []State{StateUploaded, StateRejected, StateDeferred, StateQueued} {
		if seen[s] == 0 {
			t.Errorf("no case ended %q", s)
		}
	}
	if seen[StateUploading] != 0 {
		t.Errorf("%d cases were left uploading", seen[StateUploading])
	}
	if cases != len(errs)*9*4 {
		t.Fatalf("ran %d cases, want %d", cases, len(errs)*9*4)
	}
}

// TestQueues_AreIndependent: two queues share nothing. Entries, capacity and
// bounds of one are invisible to the other.
func TestQueues_AreIndependent(t *testing.T) {
	a := newTestQueue(t, func(o *Options) { o.MaxPending = 1 })
	b := newTestQueue(t, func(o *Options) { o.MaxAttempts = 1; o.MaxErrLen = 4 })
	now := time.Unix(1_700_000_000, 0).UTC()

	if _, err := a.Enqueue(csbID("a"), "C", "", "h", now); err != nil {
		t.Fatalf("a enqueue: %v", err)
	}
	if _, err := a.Enqueue(csbID("b"), "C", "", "h", now); !errors.Is(err, errFull) {
		t.Fatalf("a is at its bound of 1, second enqueue err = %v", err)
	}
	// b has its own (larger) bound and none of a's entries.
	for _, seed := range []string{"a", "b", "c"} {
		if _, err := b.Enqueue(csbID(seed), "C", "", "h", now); err != nil {
			t.Fatalf("b enqueue %s: %v", seed, err)
		}
	}
	if na, nb := len(a.List()), len(b.List()); na != 1 || nb != 3 {
		t.Fatalf("a lists %d and b lists %d, want 1 and 3", na, nb)
	}
	if _, ok := a.Load(csbID("c")); ok {
		t.Fatal("a answered for an entry only b holds")
	}
	fail := func(context.Context, Entry) (*supportupload.Receipt, string, error) {
		return nil, "", errors.New("refused")
	}
	if got := a.Attempt(context.Background(), Entry{}, fail, now); got.State != StateQueued || got.LastError != "refused" {
		t.Fatalf("a (6 attempts, 256 bytes) = %q %q", got.State, got.LastError)
	}
	if got := b.Attempt(context.Background(), Entry{}, fail, now); got.State != StateDeferred || got.LastError != "refu…" {
		t.Fatalf("b (1 attempt, 4 bytes) = %q %q", got.State, got.LastError)
	}
}

// TestQueue_DirIsAskedOnEveryCall: the owner may move the data directory
// between calls, as main's tests do.
func TestQueue_DirIsAskedOnEveryCall(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	dir := first
	o := testOptions("")
	o.Dir = func() string { return dir }
	q := New(o)
	id := csbID("mv")
	if _, err := q.Enqueue(id, "C", "", "h", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if got, want := q.Path(id), filepath.Join(first, id+".json"); got != want {
		t.Fatalf("Path = %q, want %q", got, want)
	}
	dir = second
	if n := len(q.List()); n != 0 {
		t.Fatalf("the second directory lists %d entries", n)
	}
	if got, want := q.Path(id), filepath.Join(second, id+".json"); got != want {
		t.Fatalf("Path = %q, want %q", got, want)
	}
}

// TestNew_MissingOptionsFailClosed: nothing is defaulted. Each gap refuses
// the operation that needed it and writes nothing.
func TestNew_MissingOptionsFailClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	id := csbID("gap")
	wrote := func(dir string) int {
		des, _ := os.ReadDir(dir) //nolint:errcheck // an absent directory is zero files
		return len(des)
	}
	for name, edit := range map[string]func(*Options){
		"no Dir":      func(o *Options) { o.Dir = nil },
		"no ValidID":  func(o *Options) { o.ValidID = nil },
		"no Mkdir":    func(o *Options) { o.Mkdir = nil },
		"no Write":    func(o *Options) { o.Write = nil },
		"zero bound":  func(o *Options) { o.MaxPending = 0 },
		"minus bound": func(o *Options) { o.MaxPending = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			o := testOptions(dir)
			edit(&o)
			q := New(o)
			if _, err := q.Enqueue(id, "C", "", "h", now); err == nil {
				t.Error("Enqueue succeeded")
			}
			if n := wrote(dir); n != 0 {
				t.Errorf("%d files written", n)
			}
		})
	}
	t.Run("zero Options", func(t *testing.T) {
		q := New(Options{})
		if _, err := q.Enqueue(id, "C", "", "h", now); !errors.Is(err, errInvalidID) {
			t.Errorf("Enqueue err = %v, want invalid id", err)
		}
		if err := q.Save(Entry{BundleID: id}); !errors.Is(err, errInvalidID) {
			t.Errorf("Save err = %v, want invalid id", err)
		}
		if _, ok := q.Load(id); ok {
			t.Error("Load answered")
		}
		if q.List() != nil || q.Due(now) != nil {
			t.Error("List or Due answered")
		}
	})
	t.Run("no Mkdir or Write is named", func(t *testing.T) {
		o := testOptions(t.TempDir())
		o.Write = nil
		if err := New(o).Save(Entry{BundleID: id}); !errors.Is(err, errNotWired) {
			t.Errorf("Save err = %v, want not wired", err)
		}
	})
	t.Run("no Sanitize withholds the text", func(t *testing.T) {
		o := testOptions(t.TempDir())
		o.Sanitize = nil
		q := New(o)
		got := q.Attempt(context.Background(), Entry{}, func(context.Context, Entry) (*supportupload.Receipt, string, error) {
			return nil, "", errors.New("raw\r\nremote text")
		}, now)
		if got.LastError != errTextWithheld || strings.Contains(got.LastError, "raw") {
			t.Errorf("LastError = %q, want the text withheld", got.LastError)
		}
	})
	t.Run("zero MaxAttempts defers at once", func(t *testing.T) {
		q := newTestQueue(t, func(o *Options) { o.MaxAttempts = 0 })
		got := q.Attempt(context.Background(), Entry{}, func(context.Context, Entry) (*supportupload.Receipt, string, error) {
			return nil, "", errors.New("refused")
		}, now)
		if got.State != StateDeferred {
			t.Errorf("state = %q, want deferred", got.State)
		}
	})
}

// TestEnqueue_ZeroOrNegativeTerminalBoundKeepsNone: MaxTerminal is not
// defaulted either. Zero retains no delivered record, and a negative value is
// read as zero instead of indexing with it.
func TestEnqueue_ZeroOrNegativeTerminalBoundKeepsNone(t *testing.T) {
	for _, bound := range []int{0, -1, -300} {
		q := newTestQueue(t, func(o *Options) { o.MaxTerminal = bound })
		for i, seed := range []string{"za", "zb"} {
			if _, err := q.Enqueue(csbID(seed), "C", "", "h", ruleBase.Add(time.Duration(i)*time.Second)); err != nil {
				t.Fatal(err)
			}
			markEntry(t, q, csbID(seed), func(e *Entry) { e.State = StateUploaded })
		}
		if _, err := q.Enqueue(csbID("live"), "C", "", "h", ruleBase.Add(time.Minute)); err != nil {
			t.Fatalf("bound %d: %v", bound, err)
		}
		if list := q.List(); len(list) != 1 || list[0].BundleID != csbID("live") {
			t.Fatalf("bound %d: list = %+v, want only the live entry", bound, list)
		}
	}
}

// TestQueue_OnlyValidIDsNameFiles: ValidID is the only thing between an id
// and a path, for every operation that takes one, and a file whose name it
// refuses is never read back.
func TestQueue_OnlyValidIDsNameFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "queue")
	q := New(testOptions(dir))
	now := time.Unix(1_700_000_000, 0).UTC()
	good := csbID("ok")
	for _, bad := range []string{"", ".", "..", "../" + good, good + "/x", "a/../" + good, strings.ToUpper(good), good + "\x00", good + ".json"} {
		if _, err := q.Enqueue(bad, "C", "", "h", now); !errors.Is(err, errInvalidID) {
			t.Errorf("Enqueue(%q) err = %v", bad, err)
		}
		if err := q.Save(Entry{BundleID: bad, State: StateQueued}); !errors.Is(err, errInvalidID) {
			t.Errorf("Save(%q) err = %v", bad, err)
		}
		if _, ok := q.Load(bad); ok {
			t.Errorf("Load(%q) answered", bad)
		}
	}
	if des, _ := os.ReadDir(root); len(des) != 0 { //nolint:errcheck // root exists
		t.Fatalf("refused ids created %d entries under the root", len(des))
	}
	// A well-formed record under a name the rule refuses is skipped on list.
	if _, err := q.Enqueue(good, "C", "", "h", now); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(q.Path(good))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"notabundle.json", good + ".json.bak", "x" + good + ".json"} {
		// #nosec G703 -- test fixture: a fixed name under the test's own TempDir.
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, csbID("dir")+".json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if list := q.List(); len(list) != 1 || list[0].BundleID != good {
		t.Fatalf("List = %+v, want only %s", list, good)
	}
}

// TestQueue_WritesGoThroughOptions: every byte the queue commits and the
// directory it creates go through the owner's two functions, with the
// directory first.
func TestQueue_WritesGoThroughOptions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "queue")
	var calls []string
	o := testOptions(dir)
	o.Mkdir = func(d string, perm os.FileMode) error {
		calls = append(calls, fmt.Sprintf("mkdir %s %o", filepath.Base(d), perm))
		return os.MkdirAll(d, perm)
	}
	o.Write = func(path string, data []byte) error {
		calls = append(calls, "write "+filepath.Base(path))
		return os.WriteFile(path, data, 0o600)
	}
	q := New(o)
	id := csbID("w")
	e, err := q.Enqueue(id, "C", "", "h", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Save(e); err != nil {
		t.Fatal(err)
	}
	want := []string{"mkdir queue 700", "write " + id + ".json", "mkdir queue 700", "write " + id + ".json"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	// A failing owner write is the caller's error, and Enqueue reports no entry.
	boom := errors.New("disk full")
	o.Write = func(string, []byte) error { return boom }
	if got, err := New(o).Enqueue(csbID("f"), "C", "", "h", time.Unix(1, 0)); !errors.Is(err, boom) || got.BundleID != "" {
		t.Fatalf("Enqueue over a failing write = %+v, %v", got, err)
	}
	o.Mkdir = func(string, os.FileMode) error { return boom }
	if err := New(o).Save(e); !errors.Is(err, boom) {
		t.Fatalf("Save over a failing mkdir = %v", err)
	}
}

// TestQueue_ConcurrentUseIsSerialized runs every locked operation from many
// goroutines against one queue; under -race this is the mutex's test, and the
// bound must hold however the enqueues interleave.
func TestQueue_ConcurrentUseIsSerialized(t *testing.T) {
	const bound = 5
	q := newTestQueue(t, func(o *Options) { o.MaxPending = bound })
	now := time.Unix(1_700_000_000, 0).UTC()
	var wg sync.WaitGroup
	for i := 0; i < 26; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := csbID("c" + "abcdefghijklmnopqrstuvwxyz"[i:i+1])
			if e, err := q.Enqueue(id, "C", "", "h", now); err == nil {
				_ = q.Save(e) //nolint:errcheck // exercised for the race detector
			}
			q.List()
			q.Due(now)
			q.Load(id)
		}(i)
	}
	wg.Wait()
	if n := len(q.List()); n != bound {
		t.Fatalf("%d entries after 26 concurrent enqueues, want the bound %d", n, bound)
	}
}

// TestAttempt_DoesNotHoldTheLock: the transfer does network I/O, so the queue
// must stay usable from inside it.
func TestAttempt_DoesNotHoldTheLock(t *testing.T) {
	q := newTestQueue(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	e, err := q.Enqueue(csbID("lk"), "C", "", "h", now)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan Entry, 1)
	go func() {
		done <- q.Attempt(context.Background(), e, func(_ context.Context, in Entry) (*supportupload.Receipt, string, error) {
			q.List()
			if err := q.Save(in); err != nil {
				return nil, "", err
			}
			return &supportupload.Receipt{Sig: "s"}, "", nil
		}, now)
	}()
	select {
	case got := <-done:
		if got.State != StateUploaded {
			t.Fatalf("state = %q", got.State)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Attempt held the queue lock across the transfer")
	}
	// The in-flight state the transfer saved is what a crash would leave.
	if got, _ := q.Load(e.BundleID); got.State != StateUploading {
		t.Fatalf("persisted in-flight state = %q, want uploading", got.State)
	}
}

// TestEntry_PersistedForm pins the file an entry becomes: field names, order,
// omitted fields and indentation. Main pins the same bytes through its own
// wiring by digest; this is the readable copy.
func TestEntry_PersistedForm(t *testing.T) {
	q := newTestQueue(t)
	id := csbID("form")
	now := time.Unix(1_700_000_000, 0).UTC()
	e, err := q.Enqueue(id, "CASE-1", "tac-2026", "deadbeef", now)
	if err != nil {
		t.Fatal(err)
	}
	read := func() string {
		b, err := os.ReadFile(q.Path(id))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	const queued = `{
  "bundle_id": "csb_formaaaaaaaaaaaaaaaaaaaaaa",
  "case_id": "CASE-1",
  "key_id": "tac-2026",
  "bundle_sha256": "deadbeef",
  "state": "queued",
  "attempts": 0,
  "created_at": "2023-11-14T22:13:20Z",
  "updated_at": "2023-11-14T22:13:20Z"
}`
	if got := read(); got != queued {
		t.Fatalf("queued entry:\n%s\nwant:\n%s", got, queued)
	}
	e = q.Attempt(context.Background(), e, func(context.Context, Entry) (*supportupload.Receipt, string, error) {
		return nil, "sess-1", errors.New("reset\nby peer")
	}, now.Add(time.Second))
	if err := q.Save(e); err != nil {
		t.Fatal(err)
	}
	const retried = `{
  "bundle_id": "csb_formaaaaaaaaaaaaaaaaaaaaaa",
  "case_id": "CASE-1",
  "key_id": "tac-2026",
  "bundle_sha256": "deadbeef",
  "state": "queued",
  "attempts": 1,
  "next_retry_at": 1700000003,
  "upload_id": "sess-1",
  "created_at": "2023-11-14T22:13:20Z",
  "updated_at": "2023-11-14T22:13:21Z",
  "last_error": "reset_by peer"
}`
	if got := read(); got != retried {
		t.Fatalf("retried entry:\n%s\nwant:\n%s", got, retried)
	}
}

// TestState_Values pins the five persisted words.
func TestState_Values(t *testing.T) {
	for s, want := range map[State]string{
		StateQueued: "queued", StateUploading: "uploading", StateUploaded: "uploaded",
		StateDeferred: "deferred", StateRejected: "rejected",
	} {
		if string(s) != want {
			t.Errorf("state %q, want %q", s, want)
		}
	}
}

// The tests below cover rules the moved tests did not reach; each was found
// by a mutation that passed.

// ruleBase is the instant those tests count from.
var ruleBase = time.Unix(1_700_000_000, 0).UTC()

// markEntry loads one entry, edits it and saves it back.
func markEntry(t *testing.T, q *Queue, id string, edit func(*Entry)) {
	t.Helper()
	e, ok := q.Load(id)
	if !ok {
		t.Fatalf("no entry %s", id)
	}
	edit(&e)
	if err := q.Save(e); err != nil {
		t.Fatal(err)
	}
}

// TestEnqueue_DeferredAndInFlightHoldCapacity: a deferred entry holds capacity.
func TestEnqueue_DeferredAndInFlightHoldCapacity(t *testing.T) {
	base := ruleBase
	q := newTestQueue(t, func(o *Options) { o.MaxPending = 1 })
	if _, err := q.Enqueue(csbID("a"), "C", "", "h", base); err != nil {
		t.Fatal(err)
	}
	markEntry(t, q, csbID("a"), func(e *Entry) { e.State = StateDeferred })
	if _, err := q.Enqueue(csbID("b"), "C", "", "h", base); !errors.Is(err, errFull) {
		t.Fatalf("enqueue beside a deferred entry at the bound: %v", err)
	}
	markEntry(t, q, csbID("a"), func(e *Entry) { e.State = StateUploading })
	if _, err := q.Enqueue(csbID("b"), "C", "", "h", base); !errors.Is(err, errFull) {
		t.Fatalf("enqueue beside an in-flight entry at the bound: %v", err)
	}
	markEntry(t, q, csbID("a"), func(e *Entry) { e.State = StateUploaded })
	if _, err := q.Enqueue(csbID("b"), "C", "", "h", base); err != nil {
		t.Fatalf("a delivered entry must not hold capacity: %v", err)
	}
}

// TestEnqueue_ReArmDropsOldSessionAndReceipt: a re-arm drops the old session and receipt.
func TestEnqueue_ReArmDropsOldSessionAndReceipt(t *testing.T) {
	base := ruleBase
	q := newTestQueue(t)
	id := csbID("r")
	if _, err := q.Enqueue(id, "C1", "k1", "h1", base); err != nil {
		t.Fatal(err)
	}
	markEntry(t, q, id, func(e *Entry) {
		e.State = StateRejected
		e.UploadID = "sess-old"
		e.NextRetryAt = 99
		e.Receipt = &supportupload.Receipt{Sig: "old"}
	})
	got, err := q.Enqueue(id, "C2", "k2", "h2", base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{
		BundleID: id, CaseID: "C2", KeyID: "k2", BundleSHA256: "h2", State: StateQueued,
		CreatedAt: "2023-11-14T22:13:20Z", UpdatedAt: "2023-11-14T22:14:20Z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("re-armed entry = %+v, want %+v", got, want)
	}
	if onDisk, _ := q.Load(id); !reflect.DeepEqual(onDisk, want) {
		t.Fatalf("persisted re-armed entry = %+v", onDisk)
	}
	// An uploaded entry is not re-armed: the call is a no-op.
	markEntry(t, q, id, func(e *Entry) { e.State = StateUploaded; e.UploadID = "sess-done" })
	if again, err := q.Enqueue(id, "C3", "k3", "h3", base.Add(time.Hour)); err != nil || again.CaseID != "C2" || again.UploadID != "sess-done" {
		t.Fatalf("enqueue of a delivered bundle = %+v, %v", again, err)
	}
}

// TestEnqueue_PrunesOldestAndListsOldestFirst: pruning removes the oldest and the list is oldest first.
func TestEnqueue_PrunesOldestAndListsOldestFirst(t *testing.T) {
	base := ruleBase
	q := newTestQueue(t, func(o *Options) { o.MaxTerminal = 2 })
	for i, seed := range []string{"pd", "pb", "pa", "pc"} { // creation order is not name order
		if _, err := q.Enqueue(csbID(seed), "C", "", "h", base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
		markEntry(t, q, csbID(seed), func(e *Entry) { e.State = StateUploaded })
	}
	if _, err := q.Enqueue(csbID("live"), "C", "", "h", base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range q.List() {
		got = append(got, e.BundleID)
	}
	if want := []string{csbID("pa"), csbID("pc"), csbID("live")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after pruning: %v, want the two newest delivered and the live one, oldest first: %v", got, want)
	}
}

// TestDue_AtItsRetrySecond: an entry is due at its retry second.
func TestDue_AtItsRetrySecond(t *testing.T) {
	base := ruleBase
	q := newTestQueue(t)
	id := csbID("due")
	if _, err := q.Enqueue(id, "C", "", "h", base); err != nil {
		t.Fatal(err)
	}
	markEntry(t, q, id, func(e *Entry) { e.NextRetryAt = base.Unix() + 10 })
	if n := len(q.Due(base.Add(9 * time.Second))); n != 0 {
		t.Fatalf("due one second early: %d", n)
	}
	if n := len(q.Due(base.Add(10 * time.Second))); n != 1 {
		t.Fatalf("not due at its retry second: %d", n)
	}
}

// TestLoad_RefusesWellFormedFileUnderRefusedName: load refuses an id the rule refuses even when its file is well formed.
func TestLoad_RefusesWellFormedFileUnderRefusedName(t *testing.T) {
	dir := t.TempDir()
	q := New(testOptions(dir))
	const bad = "notabundle"
	body := `{"bundle_id":"notabundle","state":"queued","created_at":"c","updated_at":"u"}`
	if err := os.WriteFile(filepath.Join(dir, bad+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if e, ok := q.Load(bad); ok {
		t.Fatalf("Load answered %+v", e)
	}
	if list := q.List(); len(list) != 0 {
		t.Fatalf("List answered %+v", list)
	}
}
