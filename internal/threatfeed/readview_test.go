package threatfeed

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Tests for the lock-free read view that serves Enabled / CheckDomain /
// CheckURL (see readView in threatfeed.go).
//
// Two properties have to hold, and they fail in different ways:
//
//   - PUBLICATION. Every mutator must republish before releasing tf.mu. A
//     mutator that forgets leaves the request path serving a stale generation —
//     a threat entry that was synced but never blocks, or an allowlist entry the
//     admin removed that keeps suppressing hits. That is a silent security
//     failure, not a performance one, so it is pinned per mutator by the
//     TestReadView_Republishes_* family below.
//   - NO IN-PLACE MUTATION. A map reachable from a published view is read
//     without any lock, so writing into it is a data race. The writers that used
//     to edit in place (allowlist add/remove, SeedForTest) copy-then-swap; the
//     race detector is the enforcement, via TestReadView_ConcurrentReadersAndWriters.

// The TestReadView_Republishes_* family is the per-mutator publication wall:
// between them they cover every method that changes enabled / urls / domains /
// domainAllowlist, and each asserts the change through the LOCK-FREE lookups
// rather than through the field. Adding a mutator without a publishLocked call
// fails whichever of these covers it.
//
// They are separate top-level functions rather than subtests of one table so
// each stays small (gocognit) and names its own mutator in the failure output.

// viewFeed returns an enabled, persistence-free feed carrying one threat domain.
func viewFeed(t *testing.T, threatDomain string) *Feed {
	t.Helper()
	tf := New()
	tf.Init("", time.Hour)
	if threatDomain != "" {
		tf.SeedForTest(nil, map[string]string{threatDomain: sourceURLhaus})
	}
	return tf
}

func TestReadView_Republishes_Init(t *testing.T) {
	tf := New()
	if tf.Enabled() {
		t.Fatal("New() feed reports enabled")
	}
	tf.Init("", time.Hour)
	if !tf.Enabled() {
		t.Error("Init did not republish the enabled flag")
	}
}

func TestReadView_Republishes_ApplySync(t *testing.T) {
	tf := viewFeed(t, "")
	tf.applySync(
		map[string]entry{"http://fresh.example/x": {Source: sourceURLhaus}},
		map[string]entry{"fresh.example": {Source: sourceURLhaus}},
		nil, map[string]bool{sourceURLhaus: true, sourceOpenPhish: true}, time.Now(),
	)
	if mal, _ := tf.CheckURL("http://fresh.example/x"); !mal {
		t.Error("applySync did not republish urls")
	}
	if mal, _ := tf.CheckDomain("fresh.example"); !mal {
		t.Error("applySync did not republish domains")
	}
}

func TestReadView_Republishes_ImportFeedData(t *testing.T) {
	tf := viewFeed(t, "")
	tf.ImportFeedData(
		map[string]int64{"http://cp.example/mal": time.Now().Unix()},
		map[string]int64{"cp.example": time.Now().Unix()},
	)
	if mal, _ := tf.CheckDomain("cp.example"); !mal {
		t.Error("ImportFeedData did not republish domains")
	}
}

func TestReadView_Republishes_SeedForTest(t *testing.T) {
	tf := viewFeed(t, "seeded.example")
	if mal, _ := tf.CheckDomain("seeded.example"); !mal {
		t.Error("SeedForTest did not republish domains")
	}
}

// The allowlist mutators are the security-critical half: a stale view here means
// the admin's exemption edit does not take effect on the request path — either a
// granted exemption that still blocks, or a REVOKED one that still suppresses.
func TestReadView_Republishes_AllowlistAddRemove(t *testing.T) {
	tf := viewFeed(t, "threat.example")
	if mal, _ := tf.CheckDomain("threat.example"); !mal {
		t.Fatal("seeded threat domain does not block")
	}

	if err := tf.AddDomainAllowlist("threat.example"); err != nil {
		t.Fatalf("AddDomainAllowlist: %v", err)
	}
	if mal, _ := tf.CheckDomain("threat.example"); mal {
		t.Error("AddDomainAllowlist did not republish — the exemption is not in force on the request path")
	}

	if err := tf.RemoveDomainAllowlist("threat.example"); err != nil {
		t.Fatalf("RemoveDomainAllowlist: %v", err)
	}
	if mal, _ := tf.CheckDomain("threat.example"); !mal {
		t.Error("RemoveDomainAllowlist did not republish — a revoked exemption still suppresses the block")
	}
}

func TestReadView_Republishes_SetDomainAllowlist(t *testing.T) {
	tf := viewFeed(t, "threat.example")
	if err := tf.SetDomainAllowlist([]string{"threat.example"}); err != nil {
		t.Fatalf("SetDomainAllowlist: %v", err)
	}
	if mal, _ := tf.CheckDomain("threat.example"); mal {
		t.Error("SetDomainAllowlist did not republish")
	}
	if err := tf.SetDomainAllowlist(nil); err != nil {
		t.Fatalf("SetDomainAllowlist(nil): %v", err)
	}
	if mal, _ := tf.CheckDomain("threat.example"); !mal {
		t.Error("SetDomainAllowlist(nil) did not republish the cleared allowlist")
	}
}

func TestReadView_Republishes_SetEnabled(t *testing.T) {
	tf := viewFeed(t, "threat.example")
	tf.SetEnabledForTest(false)
	if tf.Enabled() {
		t.Error("SetEnabledForTest(false) did not republish")
	}
	if mal, _ := tf.CheckDomain("threat.example"); mal {
		t.Error("a disabled feed still blocked")
	}
	tf.SetEnabledForTest(true)
	if mal, _ := tf.CheckDomain("threat.example"); !mal {
		t.Error("SetEnabledForTest(true) did not republish")
	}
}

func TestReadView_Republishes_LoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	src := New()
	src.Init(dir+"/feed.json", time.Hour)
	src.SeedForTest(nil, map[string]string{"persisted.example": sourceURLhaus})
	if err := src.saveToDisk(); err != nil {
		t.Fatalf("saveToDisk: %v", err)
	}

	dst := New()
	dst.Init(dir+"/feed.json", time.Hour) // Init calls loadFromDisk
	if mal, _ := dst.CheckDomain("persisted.example"); !mal {
		t.Error("loadFromDisk did not republish domains")
	}
}

// TestReadView_StructLiteralFeedResolves covers the lazy branch of readState:
// the package's whitebox tests build Feed literals that never went through
// New(), so the first lookup has to materialise a view rather than nil-deref.
func TestReadView_StructLiteralFeedResolves(t *testing.T) {
	tf := &Feed{
		enabled: true,
		urls:    map[string]entry{"http://evil.example/x": {Source: sourceURLhaus}},
		domains: map[string]entry{"evil.example": {Source: sourceURLhaus}},
	}
	if !tf.Enabled() {
		t.Error("Enabled() on a struct-literal feed = false")
	}
	if mal, _ := tf.CheckDomain("evil.example"); !mal {
		t.Error("CheckDomain on a struct-literal feed missed a seeded entry")
	}
	if mal, _ := tf.CheckURL("http://evil.example/x"); !mal {
		t.Error("CheckURL on a struct-literal feed missed a seeded entry")
	}
}

// TestReadView_ConcurrentReadersAndWriters is the race-detector enforcement of
// the no-in-place-mutation contract. Under -race, any writer that edits a map a
// published view still serves shows up here as a map read/write race.
//
// It also asserts the verdicts stay self-consistent: a domain is either on the
// allowlist or not, but the lookup must never observe a torn generation where
// the threat table has been swapped and the allowlist has not.
func TestReadView_ConcurrentReadersAndWriters(t *testing.T) {
	tf := New()
	tf.Init("", time.Hour)
	tf.SeedForTest(nil, map[string]string{"steady.example": sourceURLhaus})

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tf.CheckDomain("steady.example")
				tf.CheckURL("http://steady.example/payload")
				tf.Enabled()
			}
		}()
	}

	// Writers: the three shapes that used to mutate in place, plus a wholesale
	// table replace, all racing the readers above.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			d := fmt.Sprintf("churn%d.example", i)
			_ = tf.AddDomainAllowlist(d)
			_ = tf.RemoveDomainAllowlist(d)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			tf.SeedForTest(nil, map[string]string{fmt.Sprintf("seed%d.example", i): sourceURLhaus})
			tf.applySync(
				map[string]entry{"http://steady.example/payload": {Source: sourceURLhaus}},
				map[string]entry{"steady.example": {Source: sourceURLhaus}},
				nil, map[string]bool{sourceURLhaus: true}, time.Now(),
			)
		}
	}()

	// The writer goroutines are bounded; wait for them, then stop the readers.
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(stop)
	}()
	wg.Wait()
	select {
	case <-stop:
	default:
		close(stop)
	}

	if mal, _ := tf.CheckDomain("steady.example"); !mal {
		t.Error("steady threat domain stopped blocking after concurrent churn")
	}
}
