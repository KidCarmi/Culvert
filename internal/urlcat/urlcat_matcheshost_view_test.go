package urlcat

// Gates for the lock-free FORWARD read view behind MatchesHost /
// MatchesHostAdmin (catIndexView).
//
// The change is a COST change: every verdict must be byte-identical to the
// lock-based body it replaces, because these two are policy MEMBERSHIP
// matchers — a divergence is a silently mis-enforced Allow/Deny rule, not a
// slow request. So the correctness spine is a DIFFERENTIAL against a verbatim
// copy of the pre-change implementation (legacyMatchesHost* below), and the
// contract that makes the view safe — "every mutator republishes" — is pinned
// per mutator, structurally and behaviourally, because a mutator that forgets
// to publish fails OPEN and no behavioural test of the mutator itself would
// notice.

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// legacyMatchesHost is a VERBATIM copy of the pre-view MatchesHost body: fold
// the key, take s.mu.RLock, probe the live outer map, release, then
// exact-then-suffix membership. It is the differential oracle AND the
// benchmark baseline (urlcat_matcheshost_view_bench_test.go), so the oracle
// can never drift from what the comparison measures.
func legacyMatchesHost(s *Store, cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	s.mu.RLock()
	var hostSet map[string]bool
	if inlineOK {
		hostSet = s.index[string(inlineKey)]
	} else {
		hostSet = s.index[strKey]
	}
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
	if hostSet[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

// legacyMatchesHostAdmin is the same verbatim copy against adminIndex.
func legacyMatchesHostAdmin(s *Store, cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	s.mu.RLock()
	var hostSet map[string]bool
	if inlineOK {
		hostSet = s.adminIndex[string(inlineKey)]
	} else {
		hostSet = s.adminIndex[strKey]
	}
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
	if hostSet[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

// viewDiffStore builds a taxonomy that exercises every branch the probe has:
// mixed-case names (the inline key fold), a BuiltIn and an admin entry (the
// two indices), a trailing-dot pattern (the deliberate normalization split
// between the forward and reverse indices), an empty category, and a name
// past maxInlineCategoryKey (the allocating fallback).
func viewDiffStore() *Store {
	return New([]*Entry{
		{Name: "Social Media", BuiltIn: true, Hosts: []string{"facebook.com", "x.com"}},
		{Name: "Admin Only", Hosts: []string{"intranet.corp.example", "deep.sub.corp.example"}},
		{Name: "Trailing", Hosts: []string{"dotted.example.com."}},
		{Name: "MiXeD CaSe", Hosts: []string{"mixed.example.org"}},
		{Name: "Empty", Hosts: []string{}},
		{Name: strings.Repeat("L", maxInlineCategoryKey+8), Hosts: []string{"long.example.net"}},
		{Name: "CAFÉ", Hosts: []string{"cafe.example.net"}},
	})
}

// viewDiffProbes are the (category, host) pairs driven through both
// implementations. They cover exact hits, suffix hits, the apex, misses,
// case variation on BOTH sides, a non-existent category, and the empty string.
func viewDiffProbes() []struct{ cat, host string } {
	return []struct{ cat, host string }{
		{"Social Media", "facebook.com"},
		{"Social Media", "www.facebook.com"},
		{"Social Media", "a.b.c.facebook.com"},
		{"social media", "FACEBOOK.COM"},
		{"SOCIAL MEDIA", "facebook.com."},
		{"Social Media", "notfacebook.com"},
		{"Social Media", "facebook.com.evil.net"},
		{"Admin Only", "intranet.corp.example"},
		{"Admin Only", "deep.sub.corp.example"},
		{"Admin Only", "x.deep.sub.corp.example"},
		{"Admin Only", "corp.example"},
		{"Trailing", "dotted.example.com"},
		{"Trailing", "dotted.example.com."},
		{"MiXeD CaSe", "mixed.example.org"},
		{"mixed case", "mixed.example.org"},
		{"Empty", "anything.example"},
		{"Nonexistent", "facebook.com"},
		{strings.Repeat("L", maxInlineCategoryKey+8), "long.example.net"},
		{strings.Repeat("l", maxInlineCategoryKey+8), "sub.long.example.net"},
		{"CAFÉ", "cafe.example.net"},
		{"café", "cafe.example.net"},
		{"", ""},
		{"Social Media", ""},
		{"", "facebook.com"},
		{"Social Media", "."},
		{"Social Media", ".facebook.com"},
	}
}

// TestCatIndexView_DifferentialAgainstLegacy is the correctness spine: the
// lock-free view must answer identically to the lock-based body it replaced,
// for both entry points, across every branch shape.
func TestCatIndexView_DifferentialAgainstLegacy(t *testing.T) {
	s := viewDiffStore()
	for _, p := range viewDiffProbes() {
		if got, want := s.MatchesHost(Category(p.cat), p.host), legacyMatchesHost(s, Category(p.cat), p.host); got != want {
			t.Errorf("MatchesHost(%q, %q) = %v, legacy = %v", p.cat, p.host, got, want)
		}
		if got, want := s.MatchesHostAdmin(Category(p.cat), p.host), legacyMatchesHostAdmin(s, Category(p.cat), p.host); got != want {
			t.Errorf("MatchesHostAdmin(%q, %q) = %v, legacy = %v", p.cat, p.host, got, want)
		}
	}
}

// TestCatIndexView_DifferentialHoldsAcrossMutations re-runs the differential
// after each mutator, so the view is compared against the live indices at
// every state the store can reach — not just the one New built.
func TestCatIndexView_DifferentialHoldsAcrossMutations(t *testing.T) {
	s := viewDiffStore()
	steps := []struct {
		name string
		do   func()
	}{
		{"AddHost-admin", func() { _ = s.AddHost("Admin Only", "added.corp.example") }},
		{"AddHost-builtin", func() { _ = s.AddHost("Social Media", "added.social.example") }},
		{"RemoveHost", func() { _ = s.RemoveHost("Admin Only", "intranet.corp.example") }},
		{"Set-new", func() { _ = s.Set("Fresh", []string{"fresh.example.com"}, false) }},
		{"Set-replace", func() { _ = s.Set("Admin Only", []string{"replaced.corp.example"}, false) }},
		{"Delete", func() { _ = s.Delete("Trailing") }},
		{"ReplaceAll", func() {
			s.ReplaceAll([]Entry{
				{Name: "Only One", Hosts: []string{"only.example.com"}},
				{Name: "Social Media", BuiltIn: true, Hosts: []string{"facebook.com"}},
			})
		}},
	}
	probes := append(viewDiffProbes(),
		struct{ cat, host string }{"Fresh", "fresh.example.com"},
		struct{ cat, host string }{"Only One", "sub.only.example.com"},
		struct{ cat, host string }{"Admin Only", "added.corp.example"},
		struct{ cat, host string }{"Admin Only", "replaced.corp.example"},
		struct{ cat, host string }{"Social Media", "added.social.example"},
	)
	for _, step := range steps {
		step.do()
		for _, p := range probes {
			if got, want := s.MatchesHost(Category(p.cat), p.host), legacyMatchesHost(s, Category(p.cat), p.host); got != want {
				t.Errorf("after %s: MatchesHost(%q, %q) = %v, legacy = %v", step.name, p.cat, p.host, got, want)
			}
			if got, want := s.MatchesHostAdmin(Category(p.cat), p.host), legacyMatchesHostAdmin(s, Category(p.cat), p.host); got != want {
				t.Errorf("after %s: MatchesHostAdmin(%q, %q) = %v, legacy = %v", step.name, p.cat, p.host, got, want)
			}
		}
	}
}

// forwardMutators enumerates every exported path that changes index or
// adminIndex. The inventory is the point: a new mutator must be classified
// here, and TestCatIndexView_MutatorInventoryIsComplete fails until it is.
func forwardMutators() []struct {
	name string
	// apply mutates s so that probe(cat, host) MUST flip from before to after.
	apply func(s *Store) error
	cat   string
	host  string
	// want is the verdict the probe must return AFTER apply.
	want  bool
	admin bool
} {
	return []struct {
		name  string
		apply func(s *Store) error
		cat   string
		host  string
		want  bool
		admin bool
	}{
		{"AddHost", func(s *Store) error { return s.AddHost("Alpha", "new.alpha.example") }, "Alpha", "new.alpha.example", true, true},
		{"AddHostDurable", func(s *Store) error { return s.AddHostDurable(nil, "Alpha", "dur.alpha.example") }, "Alpha", "dur.alpha.example", true, true},
		{"RemoveHost", func(s *Store) error { return s.RemoveHost("Alpha", "a.alpha.example") }, "Alpha", "a.alpha.example", false, true},
		{"RemoveHostDurable", func(s *Store) error { return s.RemoveHostDurable(nil, "Alpha", "a.alpha.example") }, "Alpha", "a.alpha.example", false, true},
		{"Set", func(s *Store) error { return s.Set("Gamma", []string{"g.gamma.example"}, false) }, "Gamma", "g.gamma.example", true, true},
		{"CreateDurable", func(s *Store) error { return s.CreateDurable(nil, "Delta", []string{"d.delta.example"}) }, "Delta", "d.delta.example", true, true},
		{"ReplaceHostsDurable", func(s *Store) error { return s.ReplaceHostsDurable(nil, "Alpha", []string{"r.alpha.example"}) }, "Alpha", "r.alpha.example", true, true},
		{"Delete", func(s *Store) error { return s.Delete("Alpha") }, "Alpha", "a.alpha.example", false, true},
		{"DeleteDurable", func(s *Store) error { return s.DeleteDurable(nil, "Alpha") }, "Alpha", "a.alpha.example", false, true},
		{"ReplaceAll", func(s *Store) error {
			s.ReplaceAll([]Entry{{Name: "Omega", Hosts: []string{"o.omega.example"}}})
			return nil
		}, "Omega", "o.omega.example", true, true},
		{"ReplaceAllChecked", func(s *Store) error {
			return s.ReplaceAllChecked([]Entry{{Name: "Omega", Hosts: []string{"o.omega.example"}}})
		}, "Omega", "o.omega.example", true, true},
	}
}

func mutatorStore(t testing.TB) *Store {
	t.Helper()
	s := New([]*Entry{
		{Name: "Alpha", Hosts: []string{"a.alpha.example"}},
		{Name: "Beta", BuiltIn: true, Hosts: []string{"b.beta.example"}},
	})
	s.SetPathForTest("")
	return s
}

// TestCatIndexView_EveryMutatorRepublishes is the contract wall. For each
// mutator it asserts the view reflects the change IMMEDIATELY — which is the
// only way to detect a missing publishForwardLocked, because the mutator's own
// return value, the persisted file and All() would all be correct while the
// request path kept enforcing the pre-mutation taxonomy (fail-OPEN for a
// Deny rule).
func TestCatIndexView_EveryMutatorRepublishes(t *testing.T) {
	for _, m := range forwardMutators() {
		t.Run(m.name, func(t *testing.T) {
			s := mutatorStore(t)
			if err := m.apply(s); err != nil {
				t.Fatalf("%s: %v", m.name, err)
			}
			if got := s.MatchesHost(Category(m.cat), m.host); got != m.want {
				t.Errorf("after %s, MatchesHost(%q, %q) = %v, want %v — the forward view was not republished", m.name, m.cat, m.host, got, m.want)
			}
			if m.admin {
				if got := s.MatchesHostAdmin(Category(m.cat), m.host); got != m.want {
					t.Errorf("after %s, MatchesHostAdmin(%q, %q) = %v, want %v — the admin forward view was not republished", m.name, m.cat, m.host, got, m.want)
				}
			}
			// The view must also AGREE with the authoritative indices.
			if got, want := s.MatchesHost(Category(m.cat), m.host), legacyMatchesHost(s, Category(m.cat), m.host); got != want {
				t.Errorf("after %s, view says %v but the live index says %v", m.name, got, want)
			}
		})
	}
}

// TestCatIndexView_MutatorInventoryIsComplete fails when a new exported method
// that could change the forward indices appears without being classified in
// forwardMutators. Behavioural coverage cannot find such a method on its own —
// an unpublishing mutator passes every test of its own behaviour.
func TestCatIndexView_MutatorInventoryIsComplete(t *testing.T) {
	classified := map[string]bool{}
	for _, m := range forwardMutators() {
		classified[m.name] = true
	}
	// Exported methods that do NOT change index/adminIndex, with the reason.
	exempt := map[string]string{
		"Revision": "reads the mutation counter", "ContentFingerprint": "derived read",
		"Load": "startup-only, before listeners; rebuildIndex publishes",
		"Save": "persistence only", "SaveErr": "persistence only",
		"BuiltInFlag": "read", "All": "read", "SnapshotWithRevision": "read",
		"GetByName": "read", "MatchesHost": "read", "MatchesHostAdmin": "read",
		"LookupHost": "read", "LookupHostAdmin": "read",
		"BuiltInHostCategories": "read", "BuiltInHostMemberships": "read",
		"Path": "read", "SetPathForTest": "test seam; touches no index",
	}
	st := reflect.TypeOf(&Store{})
	for i := 0; i < st.NumMethod(); i++ {
		name := st.Method(i).Name
		if classified[name] {
			continue
		}
		if _, ok := exempt[name]; ok {
			continue
		}
		t.Errorf("exported Store method %q is neither classified in forwardMutators nor exempt — if it can change index/adminIndex it MUST call publishForwardLocked; add it to one list with a reason", name)
	}
}

// TestCatIndexView_MutatorsStillTakeTheWriteLock is the CONTROL for the
// structural benchgate below: a gate proving the readers need no lock would
// also pass if the write side simply stopped locking, which would be far worse
// than the defect. It asserts a mutator genuinely excludes a concurrent
// holder of s.mu.
func TestCatIndexView_MutatorsStillTakeTheWriteLock(t *testing.T) {
	s := mutatorStore(t)
	s.mu.Lock()
	done := make(chan struct{})
	go func() {
		_ = s.Set("Gamma", []string{"g.gamma.example"}, false)
		close(done)
	}()
	select {
	case <-done:
		s.mu.Unlock()
		t.Fatal("Set completed while s.mu was held for writing — the mutator no longer takes the store lock")
	case <-time.After(150 * time.Millisecond):
	}
	s.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Set did not complete after releasing s.mu")
	}
}

// TestBenchGate_MatchesHostTakesNoStoreLock is STRUCTURAL, not timing-based:
// it holds the WRITE lock and requires both entry points to answer anyway.
// A return to a lock-guarded read path fails deterministically on any
// hardware, at any load, with or without -race — the repo's standing rule for
// hot-path gates (a gate that can flake gets muted).
func TestBenchGate_MatchesHostTakesNoStoreLock(t *testing.T) {
	s := New([]*Entry{
		{Name: "Alpha", Hosts: []string{"a.alpha.example"}},
		{Name: "Beta", Hosts: []string{"b.beta.example"}},
	})

	s.mu.Lock()
	defer s.mu.Unlock()

	answered := make(chan [4]bool, 1)
	go func() {
		answered <- [4]bool{
			s.MatchesHost("Alpha", "a.alpha.example"),
			s.MatchesHost("Alpha", "nope.example"),
			s.MatchesHostAdmin("Beta", "x.b.beta.example"),
			s.MatchesHostAdmin("Alpha", "nope.example"),
		}
	}()
	select {
	case got := <-answered:
		want := [4]bool{true, false, true, false}
		if got != want {
			t.Fatalf("answers under a held write lock = %v, want %v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MatchesHost/MatchesHostAdmin blocked while s.mu was held for writing — the per-rule reader lock is back")
	}
}

// TestCatIndexView_ConcurrentReadersAndMutators is the no-in-place-mutation
// half of the contract, enforced by the race detector: the readers walk maps
// reached from a published view with no lock, so any writer that edits a
// published map instead of replacing it is a data race.
func TestCatIndexView_ConcurrentReadersAndMutators(t *testing.T) {
	s := mutatorStore(t)
	stop := make(chan struct{})
	var readers sync.WaitGroup

	for r := 0; r < runtime.GOMAXPROCS(0)+2; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = s.MatchesHost("Alpha", "a.alpha.example")
				_ = s.MatchesHost("Beta", "deep.sub.b.beta.example")
				_ = s.MatchesHostAdmin("Alpha", "nope.example")
			}
		}()
	}

	// The mutator runs to completion on THIS goroutine, then the readers are
	// told to stop and joined. Waiting on the readers before closing stop
	// would deadlock — they only exit once it is closed.
	for i := 0; i < 400; i++ {
		_ = s.AddHost("Alpha", fmt.Sprintf("h%d.alpha.example", i))
		if i%25 == 0 {
			_ = s.Set("Gamma", []string{fmt.Sprintf("g%d.gamma.example", i)}, false)
			_ = s.RemoveHost("Alpha", fmt.Sprintf("h%d.alpha.example", i))
		}
		if i%97 == 0 {
			s.ReplaceAll([]Entry{
				{Name: "Alpha", Hosts: []string{"a.alpha.example"}},
				{Name: "Beta", BuiltIn: true, Hosts: []string{"b.beta.example"}},
			})
		}
	}

	close(stop)
	readers.Wait()
}

// TestCatIndexView_ZeroValueStoreIsSafe pins that a Store that was never
// mutated — no published view at all — answers exactly as the nil maps it
// mirrors did: no category, no match, no panic. &Store{} is used by this
// package's own tests, so this is a reachable shape.
func TestCatIndexView_ZeroValueStoreIsSafe(t *testing.T) {
	var s Store
	if s.forwardView() != nil {
		t.Fatal("zero-value Store published a view")
	}
	if s.MatchesHost("Anything", "example.com") {
		t.Error("zero-value Store matched a host")
	}
	if s.MatchesHostAdmin("Anything", "example.com") {
		t.Error("zero-value Store matched a host on the admin index")
	}
	if got, want := s.MatchesHost("Anything", "example.com"), legacyMatchesHost(&s, "Anything", "example.com"); got != want {
		t.Errorf("zero-value view %v disagrees with the legacy body %v", got, want)
	}
}

// TestCatIndexView_PublishAliasesInnerSets pins the property that makes the
// view affordable: publishing shares every inner host set by pointer, so a
// publish is O(categories) and never O(total host patterns). If a future
// change deep-copies the sets, the publish cost becomes proportional to the
// 2 M-host taxonomy cap and this must be reconsidered, not silently paid.
func TestCatIndexView_PublishAliasesInnerSets(t *testing.T) {
	s := mutatorStore(t)
	v := s.forwardView()
	if v == nil {
		t.Fatal("no view published by New")
	}
	s.mu.RLock()
	live := s.index["beta"]
	s.mu.RUnlock()
	if live == nil {
		t.Fatal("missing live host set for beta")
	}
	if reflect.ValueOf(v.index["beta"]).Pointer() != reflect.ValueOf(live).Pointer() {
		t.Error("published view copied an inner host set instead of aliasing it — publish is no longer O(categories)")
	}

	// An AddHost to Alpha must not reallocate Beta's set either.
	before := reflect.ValueOf(s.forwardView().index["beta"]).Pointer()
	if err := s.AddHost("Alpha", "fold.alpha.example"); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if after := reflect.ValueOf(s.forwardView().index["beta"]).Pointer(); before != after {
		t.Error("the incremental fold reallocated an untouched category's host set — the fold is no longer incremental")
	}
}
