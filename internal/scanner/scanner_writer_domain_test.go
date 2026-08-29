package scanner

// scanner_writer_domain_test.go — 2E-A-2 §2: the DPI patterns and bypass hosts
// share ONE durable envelope (content_scan.json) but Save() had no single
// writer domain: it snapshotted under mu.RLock and published with
// fileutil.AtomicWrite AFTER releasing the lock, so two successful
// mutation+Save sequences could publish in REVERSE order — the runtime holds
// both mutations, both callers were told success, and the file (what a restart
// trusts) holds the STALE envelope.
//
// The required invariant: mutation → snapshot → durable publication is
// serialized (saveMu), so publication order equals snapshot order and the last
// publication contains every mutation that happened-before its Save.
//
// DETERMINISM (no sleeps ordering events): the SetWriteFileForTest seam parks
// the first Save at its publication boundary. At the FIXED tree the second
// Save provably CANNOT publish while the first is parked (saveMu mutual
// exclusion makes done2-before-release impossible), so the select's valve arm
// is the only reachable one and the assertions are lock-deterministic. At the
// unserialized candidate the second Save completes without help, the done2 arm
// fires, and releasing the parked first Save lands the stale envelope LAST —
// the deterministic red. The valve duration is a liveness allowance for the
// serialized tree only; no assertion depends on it for ordering.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// parkFirstWrite installs a seam that parks the FIRST Save at its publication
// boundary until release is closed; later writes pass through. Every write
// still lands via the real fileutil.AtomicWrite in seam-invocation order.
func parkFirstWrite(s *ContentScanner) (entered, release chan struct{}) {
	entered = make(chan struct{})
	release = make(chan struct{})
	first := true
	s.SetWriteFileForTest(func(p string, data []byte) error {
		if first {
			first = false
			close(entered)
			<-release
		}
		return fileutil.AtomicWrite(p, data, 0o600)
	})
	return entered, release
}

// loadEnvelope re-reads the durable envelope the way a restart would.
func loadEnvelope(t *testing.T, path string) (patterns, bypass []string) {
	t.Helper()
	fresh := New(1 << 20)
	if err := fresh.Load(path); err != nil {
		t.Fatalf("restart load: %v", err)
	}
	return fresh.List(), fresh.BypassHosts()
}

// runReversalChoreography parks writer1's publication, applies mutate2+Save on
// a second writer, and returns after both Saves completed successfully.
func runReversalChoreography(t *testing.T, s *ContentScanner, mutate2 func()) {
	t.Helper()
	entered, release := parkFirstWrite(s)
	done1 := make(chan error, 1)
	go func() { done1 <- s.Save() }()
	<-entered // writer 1 is parked between snapshot and publication

	mutate2()
	done2 := make(chan error, 1)
	go func() { done2 <- s.Save() }()

	var err1, err2 error
	select {
	case err2 = <-done2:
		// Unserialized ordering: the second publication landed while the first
		// was parked. Releasing the first now lands its stale snapshot LAST.
		close(release)
		err1 = <-done1
	case <-time.After(3 * time.Second):
		// Serialized tree: the second Save cannot publish while the first is
		// parked (mutual exclusion makes the arm above unreachable), so
		// release the first and let both complete in snapshot order.
		close(release)
		err1 = <-done1
		err2 = <-done2
	}
	if err1 != nil || err2 != nil {
		t.Fatalf("both writers must report success (the defect is success + stale disk): save1=%v save2=%v", err1, err2)
	}
}

// ─── §2-A: interactive Add vs bypass replace ────────────────────────────────

func TestSave_ConcurrentAddAndBypassReplace_DurableTruth(t *testing.T) {
	s := New(1 << 20)
	path := filepath.Join(t.TempDir(), "content_scan.json")
	s.SetPath(path)
	if err := s.Add("p1-pattern"); err != nil {
		t.Fatalf("add: %v", err)
	}
	runReversalChoreography(t, s, func() { s.SetBypassHosts([]string{"b1.example"}) })

	patterns, bypass := loadEnvelope(t, path)
	if len(patterns) != 1 || patterns[0] != "p1-pattern" {
		t.Fatalf("restart lost the pattern mutation: %v", patterns)
	}
	if len(bypass) != 1 || bypass[0] != "b1.example" {
		t.Fatalf("restart lost a successfully-reported bypass mutation (stale envelope published last): bypass=%v", bypass)
	}
}

// ─── §2-B: Add vs Add ───────────────────────────────────────────────────────

func TestSave_ConcurrentAddAdd_DurableTruth(t *testing.T) {
	s := New(1 << 20)
	path := filepath.Join(t.TempDir(), "content_scan.json")
	s.SetPath(path)
	if err := s.Add("p1-pattern"); err != nil {
		t.Fatalf("add: %v", err)
	}
	runReversalChoreography(t, s, func() {
		if err := s.Add("p2-pattern"); err != nil {
			t.Errorf("add p2: %v", err)
		}
	})

	patterns, _ := loadEnvelope(t, path)
	seen := map[string]bool{}
	for _, p := range patterns {
		seen[p] = true
	}
	if !seen["p1-pattern"] || !seen["p2-pattern"] {
		t.Fatalf("restart lost a successfully-reported pattern (stale envelope published last): %v", patterns)
	}
}

// ─── §2-D: restart reads the truth successful management responses reported ─

// Sequential control: with no interleaving at all, the envelope round-trips
// both halves (green at both trees — proves the choreography above is what
// fails, not the envelope codec).
func TestSave_SequentialEnvelopeRoundTrip(t *testing.T) {
	s := New(1 << 20)
	path := filepath.Join(t.TempDir(), "content_scan.json")
	s.SetPath(path)
	if err := s.Add("p1-pattern"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save1: %v", err)
	}
	s.SetBypassHosts([]string{"b1.example"})
	if err := s.Save(); err != nil {
		t.Fatalf("save2: %v", err)
	}
	patterns, bypass := loadEnvelope(t, path)
	if len(patterns) != 1 || len(bypass) != 1 {
		t.Fatalf("sequential round-trip: patterns=%v bypass=%v", patterns, bypass)
	}
}

// Seam pin: nil restores the default AtomicWrite publication (control — the
// seam must never change production behavior).
func TestSetWriteFileForTest_NilRestoresDefault(t *testing.T) {
	s := New(1 << 20)
	path := filepath.Join(t.TempDir(), "content_scan.json")
	s.SetPath(path)
	called := false
	s.SetWriteFileForTest(func(p string, data []byte) error {
		called = true
		return fileutil.AtomicWrite(p, data, 0o600)
	})
	if err := s.Add("x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil || !called {
		t.Fatalf("seam not used: err=%v called=%v", err, called)
	}
	s.SetWriteFileForTest(nil)
	if err := s.Save(); err != nil {
		t.Fatalf("default publication after seam reset: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) != 1 {
		t.Fatalf("default publication content: %s (%v)", raw, err)
	}
}
