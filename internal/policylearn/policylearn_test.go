package policylearn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testClock is the injected deterministic clock.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)}
}
func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestEngine(t *testing.T, dir string, clk *testClock, mutate func(*Config)) *Engine {
	t.Helper()
	cfg := Config{Now: clk.now}
	if dir != "" {
		cfg.StorePath = filepath.Join(dir, "policy_learning.json")
		// Mirror production wiring: the durable pseudonym key lives alongside
		// (but separate from) the session store, so restarts keep subject-token
		// identity. Key-loss semantics are covered by a dedicated test.
		cfg.SubjectKeyPath = filepath.Join(dir, "policy_learning_subject.key")
	}
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestLifecycle_StartStopCancel(t *testing.T) {
	clk := newTestClock()
	e := newTestEngine(t, "", clk, nil)

	if _, ok := e.ActiveSession(); ok {
		t.Fatal("fresh engine has an active session")
	}
	if _, err := e.StopSession("op"); !errors.Is(err, ErrNoActiveSession) {
		t.Fatalf("Stop with none active: %v, want ErrNoActiveSession", err)
	}

	s, err := e.StartSession("admin@10.0.0.1")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.State != StateLearning || s.ID == "" || s.CreatedBy != "admin@10.0.0.1" {
		t.Fatalf("started session malformed: %+v", s)
	}

	// One-active-session invariant.
	if _, err := e.StartSession("second"); !errors.Is(err, ErrActiveSession) {
		t.Fatalf("second Start: %v, want ErrActiveSession", err)
	}

	clk.advance(2 * time.Hour)
	done, err := e.StopSession("op@10.0.0.2")
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if done.State != StateCompleted || done.StoppedBy != "op@10.0.0.2" || done.StoppedAt == "" {
		t.Fatalf("stopped session malformed: %+v", done)
	}
	if _, ok := e.ActiveSession(); ok {
		t.Fatal("session still active after Stop")
	}

	// Cancel path on a fresh session.
	if _, err := e.StartSession("a"); err != nil {
		t.Fatalf("re-Start: %v", err)
	}
	cx, err := e.CancelSession("a")
	if err != nil || cx.State != StateCancelled {
		t.Fatalf("Cancel: %v %+v", err, cx)
	}
	// Terminal sessions retained, creation-ordered.
	if got := len(e.Sessions()); got != 2 {
		t.Fatalf("retained sessions = %d, want 2", got)
	}
}

func TestPersistence_RoundTripAndRestartGap(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, nil)
	if _, err := e.StartSession("admin"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// "Restart": a second engine over the same store.
	clk.advance(10 * time.Minute)
	e2 := newTestEngine(t, dir, clk, nil)
	act, ok := e2.ActiveSession()
	if !ok {
		t.Fatal("active session not recovered after restart")
	}
	if len(act.Gaps) != 1 || act.Gaps[0].Reason != "process_restart" {
		t.Fatalf("restart gap not recorded: %+v", act.Gaps)
	}
	// The gap was persisted at load (clean recovery is durable).
	e3 := newTestEngine(t, dir, clk, nil)
	act3, _ := e3.ActiveSession()
	if len(act3.Gaps) != 2 { // second restart appended its own gap
		t.Fatalf("gaps after second restart = %d, want 2", len(act3.Gaps))
	}
}

func TestCorruptStore_QuarantinedAndFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_learning.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var quarantined string
	var qerr error
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, func(c *Config) {
		c.Quarantine = func(p string, err error) { quarantined, qerr = p, err }
	})
	if quarantined != path || qerr == nil {
		t.Fatalf("quarantine seam not invoked: path=%q err=%v", quarantined, qerr)
	}
	if e.ReadOnly() {
		t.Fatal("corrupt store must leave the engine WRITABLE (fresh start), not read-only")
	}
	if _, err := e.StartSession("admin"); err != nil {
		t.Fatalf("Start after quarantine: %v", err)
	}
}

func TestCorruptStore_UnknownFieldAndBadState(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown_field": `{"schema_version":1,"sessions":[],"surprise":true}`,
		"trailing":      `{"schema_version":1,"sessions":[]}{"x":1}`,
		"bad_state":     `{"schema_version":1,"sessions":[{"id":"a","state":"warp","created_at":"x","started_at":"x","created_by":"y","baseline":{"policy_generation":0}}]}`,
		"zero_schema":   `{"sessions":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy_learning.json")
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			called := false
			newTestEngine(t, dir, newTestClock(), func(c *Config) {
				c.Quarantine = func(string, error) { called = true }
			})
			if !called {
				t.Errorf("%s: quarantine not invoked", name)
			}
		})
	}
}

func TestNewerSchema_FailClosedReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_learning.json")
	newer := `{"schema_version":4,"sessions":[],"future_field":{"x":1}}`
	if err := os.WriteFile(path, []byte(newer), 0o600); err != nil {
		t.Fatal(err)
	}
	var quarantined bool
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, func(c *Config) {
		c.Quarantine = func(string, error) { quarantined = true }
	})
	if quarantined {
		t.Fatal("newer schema must be READ-ONLY, never quarantined (the file is valid, just newer)")
	}
	if !e.ReadOnly() {
		t.Fatal("engine not read-only on newer schema")
	}
	if _, err := e.StartSession("admin"); !errors.Is(err, ErrStoreReadOnly) {
		t.Fatalf("Start on read-only: %v, want ErrStoreReadOnly", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The newer-schema file is byte-identical after every operation.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != newer {
		t.Fatalf("read-only store was rewritten: %s", raw)
	}
}

func TestRetention_TerminalFIFOBound(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, func(c *Config) { c.MaxRetainedSessions = 3 })
	var ids []string
	for i := 0; i < 5; i++ {
		s, err := e.StartSession("admin")
		if err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
		ids = append(ids, s.ID)
		clk.advance(time.Minute)
		if _, err := e.StopSession("admin"); err != nil {
			t.Fatalf("Stop %d: %v", i, err)
		}
	}
	got := e.Sessions()
	if len(got) != 3 {
		t.Fatalf("retained = %d, want 3", len(got))
	}
	// Oldest-first eviction: the survivors are the LAST three created.
	for i, s := range got {
		if want := ids[2+i]; s.ID != want {
			t.Errorf("retained[%d] = %s, want %s (FIFO eviction)", i, s.ID, want)
		}
	}
	// The active session is never evicted even at the bound.
	if _, err := e.StartSession("admin"); err != nil {
		t.Fatalf("Start active: %v", err)
	}
	if _, ok := e.ActiveSession(); !ok {
		t.Fatal("active session missing after prune")
	}
}

func TestExpiry_MaxDurationAutoCompletes(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, func(c *Config) { c.MaxSessionDuration = 2 * time.Hour })
	if _, err := e.StartSession("admin"); err != nil {
		t.Fatal(err)
	}
	clk.advance(119 * time.Minute)
	if _, ok := e.ActiveSession(); !ok {
		t.Fatal("session expired early")
	}
	clk.advance(2 * time.Minute) // total 121m ≥ 120m
	if _, ok := e.ActiveSession(); ok {
		t.Fatal("overdue session still active")
	}
	all := e.Sessions()
	if len(all) != 1 || all[0].State != StateCompleted || all[0].StoppedBy != "system:max-duration" {
		t.Fatalf("expiry record malformed: %+v", all)
	}
	// The lazy flip persists on Close, and survives restart.
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := newTestEngine(t, dir, clk, nil)
	all2 := e2.Sessions()
	if len(all2) != 1 || all2[0].State != StateCompleted {
		t.Fatalf("expiry not durable across restart: %+v", all2)
	}
}

func TestExpiry_OverdueAtLoadCompletesDeterministically(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, func(c *Config) { c.MaxSessionDuration = time.Hour })
	if _, err := e.StartSession("admin"); err != nil {
		t.Fatal(err)
	}
	clk.advance(3 * time.Hour)
	e2 := newTestEngine(t, dir, clk, func(c *Config) { c.MaxSessionDuration = time.Hour })
	if _, ok := e2.ActiveSession(); ok {
		t.Fatal("overdue-at-load session still active")
	}
	all := e2.Sessions()
	if len(all) != 1 || all[0].StoppedBy != "system:max-duration" {
		t.Fatalf("overdue-at-load record malformed: %+v", all)
	}
}

func TestMemoryOnly_NeverTouchesFilesystem(t *testing.T) {
	clk := newTestClock()
	e := newTestEngine(t, "", clk, nil)
	if _, err := e.StartSession("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StopSession("a"); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	// Nothing to assert on disk — StorePath was empty; the absence of any
	// path dereference is proven by no panic and by the wall test's ban on
	// wall-clock/filesystem reads outside store.go.
}

func TestStoreDocument_ShapeIsStrictAndVersioned(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, nil)
	if _, err := e.StartSession("admin"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "policy_learning.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["schema_version"] != float64(SchemaVersion) {
		t.Fatalf("schema_version = %v, want %d", m["schema_version"], SchemaVersion)
	}
	if _, ok := m["sessions"]; !ok {
		t.Fatal("sessions key missing")
	}
}

func TestConcurrency_OneActiveUnderRace(t *testing.T) {
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, nil)
	var wg sync.WaitGroup
	starts := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.StartSession("racer")
			starts <- err
		}()
	}
	wg.Wait()
	close(starts)
	okCount := 0
	for err := range starts {
		if err == nil {
			okCount++
		} else if !errors.Is(err, ErrActiveSession) {
			t.Errorf("unexpected Start error: %v", err)
		}
	}
	if okCount != 1 {
		t.Fatalf("one-active invariant violated under race: %d successful starts", okCount)
	}
	// Concurrent reads + one stop.
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.ActiveSession()
			e.Sessions()
			e.Snapshot()
		}()
	}
	if _, err := e.StopSession("racer"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	wg.Wait()
}

func TestPersistFailure_NoPhantomActiveSession(t *testing.T) {
	// Construct over a valid subdirectory, then destroy it and block the path
	// with a FILE so the next AtomicWrite fails; Start must roll back.
	dir := t.TempDir()
	sub := filepath.Join(dir, "store")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	clk := newTestClock()
	cfg := Config{Now: clk.now, StorePath: filepath.Join(sub, "store.json")}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sub, []byte("blocker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StartSession("admin"); err == nil {
		t.Fatal("Start succeeded despite persist failure")
	}
	if _, ok := e.ActiveSession(); ok {
		t.Fatal("phantom active session after failed persist")
	}
}
