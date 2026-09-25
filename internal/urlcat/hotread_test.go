package urlcat

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Gates for the sharded category-membership read lock (see hotread.go).
//
// Three layers, mirroring internal/blocklist's hot-read suite:
//
//  1. CORRECTNESS. A writer must still exclude every reader, and the real
//     readers must stay race-free against every real mutator under -race.
//  2. The WIRING, pinned STRUCTURALLY. Which readers take the hot path is what
//     can silently regress — a future edit that "tidies" MatchesHost back to
//     s.mu.RLock() restores the ceiling and changes no verdict, so no
//     behavioural test can see it. An AST wall is deterministic on any
//     hardware, at any load, with or without -race; this repo has twice
//     rejected scaling-RATIO gates for this path class (internal/connlimit,
//     metrics.go) because their margin narrows until they flake, and a gate
//     that flakes gets muted.
//  3. The COST. BenchmarkMatchesHostScaling reports the real probe and
//     BenchmarkMatchesHostScaling_Baseline runs the VERBATIM pre-fix
//     single-RWMutex shape in the SAME binary, so the before/after comparison
//     stays reproducible in-tree without checking out the parent commit — the
//     convention internal/blocklist's *_Baseline arms already set.

// ── 1. Correctness ────────────────────────────────────────────────────────────

// TestHotRW_WriteLockExcludesCategoryProbes is the mutual-exclusion contract. A
// writer holds EVERY shard, so it does not matter which shard the reader draws —
// that is what makes this deterministic rather than a 1-in-ShardCount coin flip.
func TestHotRW_WriteLockExcludesCategoryProbes(t *testing.T) {
	s := New([]*Entry{{Name: "Social Media", Hosts: []string{"example.com"}}})

	done := make(chan bool, 1)
	s.mu.Lock()
	go func() { done <- s.MatchesHost("Social Media", "a.example.com") }()

	select {
	case <-done:
		s.mu.Unlock()
		t.Fatal("MatchesHost completed while the write lock was held: a writer no longer excludes the hot read path")
	case <-time.After(100 * time.Millisecond):
	}

	s.mu.Unlock()
	select {
	case got := <-done:
		if !got {
			t.Fatal("MatchesHost returned false for a listed host")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MatchesHost never completed after the write lock was released")
	}
}

// TestHotRW_ConcurrentProbesAndMutators is the safety net that matters: the real
// request-path readers against every real mutator that touches a map they read.
// Under -race any break in the exclusion shows up as a concurrent map
// read/write, which is exactly what a sharded lock would introduce if a writer
// ever stopped taking all the shards.
func TestHotRW_ConcurrentProbesAndMutators(t *testing.T) {
	s := New([]*Entry{{Name: "Social Media", Hosts: []string{"example.com"}}})

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
				s.MatchesHost("Social Media", "a.example.com")
				s.MatchesHostAdmin("Social Media", "a.example.com")
				s.LookupHost("a.example.com")
				s.LookupHostAdmin("a.example.com")
			}
		}()
	}

	for i := 0; i < 300; i++ {
		_ = s.addHostMem("Social Media", fmt.Sprintf("h%d.example.net", i))
		_ = s.setMem(fmt.Sprintf("Cat %d", i), []string{"x.example.org"}, false)
		_ = s.removeHostMem("Social Media", fmt.Sprintf("h%d.example.net", i))
		_ = s.deleteMem(fmt.Sprintf("Cat %d", i))
	}
	s.ReplaceAll([]Entry{{Name: "Social Media", Hosts: []string{"example.com"}}})

	close(stop)
	wg.Wait()

	if !s.MatchesHost("Social Media", "a.example.com") {
		t.Fatal("store lost its seeded membership under concurrent mutation")
	}
}

// ── 2. The wiring, pinned structurally ───────────────────────────────────────

// requestPathReaders are the four entry points reached from the proxy request
// path: matchesCategory calls one of the first two once per category-scoped
// access rule, and resolveFusion calls one of the last two once per scan
// (policy_hostcat.go). Each MUST take the sharded hot path.
var requestPathReaders = []string{
	"MatchesHost",
	"MatchesHostAdmin",
	"LookupHost",
	"LookupHostAdmin",
}

// coldReaders are read paths that are NOT on the request path and must keep the
// plain shard-0 RLock. This is the CONTROL: without it, "everything takes
// RLockHot" would pass the gate above while making every admin and persist
// surface pay for a shard draw it has no use for.
var coldReaders = []string{
	"All",
	"GetByName",
	"snapshotEntries",
	"BuiltInFlag",
	"BuiltInHostMemberships",
	"Path",
}

// readerLockCalls parses urlcat.go and reports, per method name, which lock
// helpers its body calls.
func readerLockCalls(t *testing.T) map[string]map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "urlcat.go", nil, 0)
	if err != nil {
		t.Fatalf("parse urlcat.go: %v", err)
	}
	out := map[string]map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil {
			continue
		}
		calls := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Match s.mu.<Name> regardless of how the result is used.
			inner, ok := sel.X.(*ast.SelectorExpr)
			if ok && inner.Sel.Name == "mu" {
				calls[sel.Sel.Name] = true
			}
			return true
		})
		out[fn.Name.Name] = calls
	}
	return out
}

func TestHotRW_RequestPathReadersTakeTheShardedLock(t *testing.T) {
	calls := readerLockCalls(t)
	for _, name := range requestPathReaders {
		got, ok := calls[name]
		if !ok {
			t.Fatalf("%s not found in urlcat.go: this gate has gone vacuous, update requestPathReaders", name)
		}
		if !got["RLockHot"] {
			t.Errorf("%s does not call s.mu.RLockHot(): it is on the proxy request path (once per category-scoped rule for the membership probes), so a plain RLock restores the throughput ceiling hotread.go documents", name)
		}
		if got["RLock"] {
			t.Errorf("%s calls the COLD s.mu.RLock(): request-path readers must not serialise on shard 0", name)
		}
	}
}

func TestHotRW_ColdReadersKeepThePlainLock(t *testing.T) {
	calls := readerLockCalls(t)
	checked := 0
	for _, name := range coldReaders {
		got, ok := calls[name]
		if !ok {
			t.Fatalf("%s not found in urlcat.go: this gate has gone vacuous, update coldReaders", name)
		}
		if got["RLockHot"] {
			t.Errorf("%s calls s.mu.RLockHot(): it is an admin/persist surface, not a request-path reader, and has no reason to pay for shard selection", name)
		}
		checked++
	}
	if checked < len(coldReaders) {
		t.Fatalf("checked only %d cold readers", checked)
	}
}

// TestHotRW_StoreUsesTheSharedEngine pins that this package consumes
// internal/hotlock rather than growing a second copy of the mechanism — the rule
// that moved the badger recovery engine to internal/storeguard and the CIDR
// machinery to security.go's prefixSet.
func TestHotRW_StoreUsesTheSharedEngine(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "urlcat.go", nil, 0)
	if err != nil {
		t.Fatalf("parse urlcat.go: %v", err)
	}
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		fld, ok := n.(*ast.Field)
		if !ok || len(fld.Names) != 1 || fld.Names[0].Name != "mu" {
			return true
		}
		if sel, ok := fld.Type.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "hotlock" && sel.Sel.Name == "HotRW" {
				found = true
			}
		}
		return true
	})
	if !found {
		t.Fatal("Store.mu is not a hotlock.HotRW: the sharded read engine must be the shared one, never a local copy")
	}
}

// ── 3. The cost ───────────────────────────────────────────────────────────────

// legacyLockedIndex is the VERBATIM pre-fix read shape: the same outer-map probe
// behind ONE process-wide sync.RWMutex. It exists so the before/after comparison
// is reproducible in this tree rather than resting on numbers in a commit
// message.
type legacyLockedIndex struct {
	mu    sync.RWMutex
	index map[string]map[string]bool
}

func (l *legacyLockedIndex) matchesHost(cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	l.mu.RLock()
	var hostSet map[string]bool
	if inlineOK {
		hostSet = l.index[string(inlineKey)]
	} else {
		hostSet = l.index[strKey]
	}
	l.mu.RUnlock()

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

// hotBenchStore returns the shipped default taxonomy (real, mixed-case category
// names) plus the legacy shape over the SAME index, so both arms probe identical
// data.
func hotBenchStore(tb testing.TB) (*Store, *legacyLockedIndex, Category) {
	tb.Helper()
	s := New(DefaultEntries())
	var cat Category
	for _, e := range DefaultEntries() {
		if e.Name != strings.ToLower(e.Name) {
			cat = Category(e.Name)
			break
		}
	}
	if cat == "" {
		tb.Fatal("no mixed-case category in the shipped taxonomy")
	}
	s.mu.RLock()
	legacy := &legacyLockedIndex{index: s.index}
	s.mu.RUnlock()
	return s, legacy, cat
}

// The MISS is the case to read: clean traffic to an uncategorized destination
// cannot short-circuit, so it is what an allowed request pays.
const hotBenchHost = "uncategorized.example.net"

// go test -run '^$' -bench 'BenchmarkMatchesHostScaling' -benchmem -cpu 1,2,4 ./internal/urlcat/
func BenchmarkMatchesHostScaling(b *testing.B) {
	s, _, cat := hotBenchStore(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each worker keeps its OWN sink: a shared package-level sink turns
		// false sharing into the thing being measured (the trap recorded on
		// internal/blocklist's hot-read benchmarks).
		var sink bool
		for pb.Next() {
			sink = s.MatchesHost(cat, hotBenchHost)
		}
		_ = sink
	})
}

func BenchmarkMatchesHostScaling_Baseline(b *testing.B) {
	_, legacy, cat := hotBenchStore(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink bool
		for pb.Next() {
			sink = legacy.matchesHost(cat, hotBenchHost)
		}
		_ = sink
	})
}

// BenchmarkHotRWWriteLockCost measures the write-side trade hotread.go records:
// a writer now takes every shard instead of one.
func BenchmarkHotRWWriteLockCost(b *testing.B) {
	b.Run("sharded", func(b *testing.B) {
		s := New(DefaultEntries())
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.mu.Lock()
			s.mu.Unlock() //nolint:staticcheck // SA2001: measuring the lock pair itself
		}
	})
	b.Run("single", func(b *testing.B) {
		var mu sync.RWMutex
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mu.Lock()
			mu.Unlock() //nolint:staticcheck // SA2001: measuring the lock pair itself
		}
	})
}
