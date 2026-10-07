package urlcat

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Gates for the lock-free forward read view (forwardView in urlcat.go).
//
//	go test -run 'TestForwardView|TestBenchGate_MatchesHost|TestBenchGate_AddHost' -race ./internal/urlcat/
//	go test -run '^$' -bench 'BenchmarkStoreMatchesHost_Parallel' -cpu 1,2,4 ./internal/urlcat/
//
// Three things are pinned, in descending order of how much they matter.
//
// 1. SEMANTICS ARE UNCHANGED. MatchesHost / MatchesHostAdmin are policy
//    MEMBERSHIP matchers: a divergence is a silently mis-enforced — or
//    silently UNENFORCED — Allow/Deny rule, so the equivalence is the
//    deliverable and the speed is the side effect. legacyMatchesHost below is
//    a VERBATIM copy of the pre-view body and is the oracle every differential
//    here runs against. It doubles as the benchmark baseline, so the oracle
//    can never drift from what the comparison measures (the
//    security_ratelimit_exempt / checkrequesturl convention).
//
// 2. THE REPUBLISH CONTRACT. A writer that mutates s.index / s.adminIndex and
//    does not publish is a SILENT SECURITY FAILURE, not a cost one: the policy
//    path keeps probing the old view, so a category host that was just added
//    never matches and a Deny rule keyed on that category fails OPEN. It is
//    pinned three ways — structurally per writer, structurally as an
//    inventory, and behaviourally through every public mutator — because no
//    one of the three can see what the others catch.
//
// 3. THE READ PATH TAKES NO LOCK. Structural, not timing-based: the gate holds
//    the WRITE lock and requires both entry points to answer anyway, so a
//    return to a lock-guarded read fails deterministically on any hardware, at
//    any load, with or without -race. A scaling-ratio gate was not written,
//    for the reason internal/connlimit, internal/rewrite and the latency
//    histogram all record: a gate that can flake gets muted.

// ---------------------------------------------------------------------------
// The frozen oracle: a VERBATIM copy of the pre-view read path.
// ---------------------------------------------------------------------------

// legacyMatchesHost is MatchesHost exactly as it read before forwardView — the
// s.mu.RLock'd probe of the live s.index. Do not "modernise" it: its whole
// value is that it is the shape being replaced.
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

// legacyMatchesHostAdmin is MatchesHostAdmin's pre-view body, verbatim.
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

// fvAgree requires both entry points to answer exactly as the frozen oracle
// does for one (category, host) pair.
func fvAgree(t *testing.T, s *Store, cat Category, host, why string) {
	t.Helper()
	if got, want := s.MatchesHost(cat, host), legacyMatchesHost(s, cat, host); got != want {
		t.Errorf("MatchesHost(%q, %q) = %v, oracle says %v [%s]", cat, host, got, want, why)
	}
	if got, want := s.MatchesHostAdmin(cat, host), legacyMatchesHostAdmin(s, cat, host); got != want {
		t.Errorf("MatchesHostAdmin(%q, %q) = %v, oracle says %v [%s]", cat, host, got, want, why)
	}
}

// ---------------------------------------------------------------------------
// 1. Semantics: the differential.
// ---------------------------------------------------------------------------

// TestForwardView_DifferentialAgainstLegacy walks the shapes where a view that
// aliased the wrong map, or probed the wrong one of the two indices, would
// diverge: the admin/built-in split, exact vs suffix matching, the trailing-dot
// normalization, case folding of both the category name and the host, and the
// inline/fallback boundary of categoryKey.
func TestForwardView_DifferentialAgainstLegacy(t *testing.T) {
	long := strings.Repeat("c", maxInlineCategoryKey+8) // forces categoryKey's fallback
	s := New([]*Entry{
		{Name: "Social Media", Hosts: []string{"example.com", "Mixed.Case.NET", "trailing.dot."}, BuiltIn: true},
		{Name: "Corp Internal", Hosts: []string{"intranet.corp.invalid", "deep.a.b.c.example.org"}},
		{Name: "CAFÉ", Hosts: []string{"cafe.example"}}, // non-ASCII name ⇒ categoryKey fallback
		{Name: long, Hosts: []string{"oversize.example"}},
		{Name: "Empty", Hosts: nil},
	})

	cats := []Category{"Social Media", "social media", "SOCIAL MEDIA", "Corp Internal",
		"CAFÉ", "café", Category(long), "Empty", "Nonexistent", ""}
	hosts := []string{
		"example.com", "a.example.com", "a.b.c.example.com", "EXAMPLE.COM",
		"notexample.com", "example.com.", "mixed.case.net", "trailing.dot",
		"trailing.dot.", "intranet.corp.invalid", "sub.intranet.corp.invalid",
		"deep.a.b.c.example.org", "cafe.example", "oversize.example",
		"uncategorized.example.net", "com", "", ".", "..", "a..b",
	}
	for _, c := range cats {
		for _, h := range hosts {
			fvAgree(t, s, c, h, "named shape")
		}
	}

	// Randomized taxonomies, so the agreement does not rest on the shapes above.
	// #nosec G404 -- deterministic seeded generator for reproducible test data
	rng := rand.New(rand.NewSource(0xC0FFEE))
	for iter := 0; iter < 200; iter++ {
		n := 1 + rng.Intn(6)
		entries := make([]*Entry, 0, n)
		for i := 0; i < n; i++ {
			hs := make([]string, 0, 4)
			for j := 0; j < rng.Intn(5); j++ {
				hs = append(hs, fvRandHost(rng))
			}
			entries = append(entries, &Entry{
				Name:    fvRandName(rng),
				Hosts:   hs,
				BuiltIn: rng.Intn(2) == 0,
			})
		}
		rs := New(entries)
		for i := 0; i < 12; i++ {
			cat := Category(fvRandName(rng))
			if len(entries) > 0 && rng.Intn(2) == 0 {
				cat = Category(entries[rng.Intn(len(entries))].Name)
			}
			fvAgree(t, rs, cat, fvRandHost(rng), fmt.Sprintf("random iter %d", iter))
		}
	}
}

func fvRandName(rng *rand.Rand) string {
	names := []string{"Social Media", "news", "NEWS", "Ad Tech", "café", "Streaming", "a", ""}
	return names[rng.Intn(len(names))]
}

func fvRandHost(rng *rand.Rand) string {
	labels := []string{"a", "b", "example", "com", "net", "CORP", "invalid", ""}
	n := 1 + rng.Intn(4)
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, labels[rng.Intn(len(labels))])
	}
	h := strings.Join(parts, ".")
	if rng.Intn(6) == 0 {
		h += "."
	}
	return h
}

// TestForwardView_ZeroValueStoreMatchesNothing pins the nil-view branch. A
// zero-value &Store{} is constructed by tests in this package and has never
// been through rebuildIndex, so the view is nil; before the view existed, the
// nil s.index map answered the same "no" and must keep doing so rather than
// panicking.
func TestForwardView_ZeroValueStoreMatchesNothing(t *testing.T) {
	s := &Store{}
	if s.forward() != nil {
		t.Fatal("zero-value Store should have no published view")
	}
	for _, c := range []Category{"", "Social Media", "Any"} {
		for _, h := range []string{"", "example.com", "a.example.com"} {
			if s.MatchesHost(c, h) {
				t.Errorf("MatchesHost(%q, %q) on a zero-value store = true", c, h)
			}
			if s.MatchesHostAdmin(c, h) {
				t.Errorf("MatchesHostAdmin(%q, %q) on a zero-value store = true", c, h)
			}
			fvAgree(t, s, c, h, "zero value")
		}
	}
}

// ---------------------------------------------------------------------------
// 2. The republish contract — structurally, per writer.
// ---------------------------------------------------------------------------

// fvIndexWriters reports, for the parsed source of one file, which functions
// assign to s.index / s.adminIndex wholesale, which ones of those also call
// publishForwardLocked, and every IN-PLACE outer assignment (`s.index[k] = v`)
// — the shape the view forbids outright, because it mutates a map concurrent
// readers are probing.
func fvIndexWriters(t *testing.T, src string) (writers, publishers, inPlace []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "urlcat.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		wrote, published, inPlaceHere := fvScanFuncBody(fn.Body)
		if inPlaceHere {
			inPlace = append(inPlace, fn.Name.Name)
		}
		if wrote {
			writers = append(writers, fn.Name.Name)
			if published {
				publishers = append(publishers, fn.Name.Name)
			}
		}
	}
	sort.Strings(writers)
	sort.Strings(publishers)
	sort.Strings(inPlace)
	return writers, publishers, inPlace
}

// fvScanFuncBody reports, for ONE function body, whether it replaces a forward
// index wholesale (`s.index = …`), whether it publishes the view, and whether
// it assigns INTO a published outer map (`s.index[k] = …`), which the view
// forbids outright.
func fvScanFuncBody(body *ast.BlockStmt) (wrote, published, inPlace bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			w, ip := fvClassifyAssign(x)
			wrote = wrote || w
			inPlace = inPlace || ip
		case *ast.CallExpr:
			if fvIsPublishCall(x) {
				published = true
			}
		}
		return true
	})
	return wrote, published, inPlace
}

// fvClassifyAssign splits one assignment into the two shapes that matter.
func fvClassifyAssign(a *ast.AssignStmt) (wrote, inPlace bool) {
	for _, lhs := range a.Lhs {
		if fvIsForwardField(lhs) {
			wrote = true
			continue
		}
		if ix, ok := lhs.(*ast.IndexExpr); ok && fvIsForwardField(ix.X) {
			inPlace = true
		}
	}
	return wrote, inPlace
}

// fvIsForwardField reports whether e names s.index or s.adminIndex.
func fvIsForwardField(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "s" {
		return false
	}
	return sel.Sel.Name == "index" || sel.Sel.Name == "adminIndex"
}

// fvIsPublishCall reports whether c is a call to publishForwardLocked.
func fvIsPublishCall(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "publishForwardLocked"
}

// TestForwardView_EveryWriterRepublishes is the structural half of the
// contract: every function that replaces a forward index must publish before
// it returns, and nothing may assign INTO a published outer map.
//
// Behavioural coverage cannot replace this. A forgotten publish is invisible to
// every test that mutates and then reads through the same code path it just
// broke only for OTHER categories, and the in-place form is a data race that
// -race observes only if a reader happens to be running.
func TestForwardView_EveryWriterRepublishes(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "urlcat.go"))
	if err != nil {
		t.Fatalf("read urlcat.go: %v", err)
	}
	writers, publishers, inPlace := fvIndexWriters(t, string(src))

	if len(writers) < 2 {
		t.Fatalf("not vacuous check: expected at least 2 forward-index writers, found %v", writers)
	}
	if len(inPlace) != 0 {
		t.Errorf("in-place assignment into a published forward index in %v; "+
			"clone the outer map and publish instead (see cloneOuter)", inPlace)
	}
	for _, w := range writers {
		found := false
		for _, p := range publishers {
			if p == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s writes a forward index but never calls publishForwardLocked: "+
				"the policy path would keep probing the old view, so a category host "+
				"it just changed would silently never match", w)
		}
	}
}

// TestForwardView_WriterInventoryIsComplete fails when a THIRD forward-index
// writer appears, so whoever adds it has to state that it publishes rather
// than inheriting a pass from the per-writer loop above.
func TestForwardView_WriterInventoryIsComplete(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "urlcat.go"))
	if err != nil {
		t.Fatalf("read urlcat.go: %v", err)
	}
	writers, _, _ := fvIndexWriters(t, string(src))
	want := []string{"addHostToIndexes", "rebuildIndex"}
	if strings.Join(writers, ",") != strings.Join(want, ",") {
		t.Errorf("forward-index writer inventory = %v, want %v.\n"+
			"A new writer must publish the view (see forwardView) and be listed here.", writers, want)
	}
}

// TestForwardView_WallRejectsThePreFixShape is the CONTROL for the wall above.
// A selector typo, or an isForwardField that matches nothing, would make the
// wall pass forever; this runs the same predicate over the verbatim pre-fix
// bodies and requires BOTH defects to be reported.
func TestForwardView_WallRejectsThePreFixShape(t *testing.T) {
	const preFix = `package urlcat

func (s *Store) rebuildIndex() {
	idx := make(map[string]map[string]bool)
	admin := make(map[string]map[string]bool)
	s.index = idx
	s.adminIndex = admin
}

func (s *Store) addHostToIndexes(ei int, e *Entry, key, host string) {
	set := make(map[string]bool)
	s.index[key] = set
	if !e.BuiltIn {
		s.adminIndex[key] = set
	}
}
`
	writers, publishers, inPlace := fvIndexWriters(t, preFix)
	if len(publishers) != 0 {
		t.Errorf("control: pre-fix source reported publishers %v, want none", publishers)
	}
	if len(writers) == 0 {
		t.Error("control: pre-fix source reported no forward-index writers — the wall's selector is broken")
	}
	if len(inPlace) == 0 {
		t.Error("control: pre-fix source reported no in-place outer assignment — the wall cannot see `s.index[key] = set`")
	}
}

// ---------------------------------------------------------------------------
// 2b. The republish contract — behaviourally, through every public mutator.
// ---------------------------------------------------------------------------

// fvMustSeed installs cat with one placeholder host, so a mutation under test
// starts from a category that EXISTS. Every `if err != nil { t.Fatal }` inlined
// into the table below counted against its cognitive complexity (gocognit, and
// the _test.go exemptions in .golangci.yml deliberately do not cover it), so
// the error handling lives in these two helpers instead of twelve copies.
func fvMustSeed(t *testing.T, s *Store, cat, host string) {
	t.Helper()
	if err := s.Set(cat, []string{host}, false); err != nil {
		t.Fatalf("seed %q: %v", cat, err)
	}
}

// fvMust fails the test if a mutator returned an error.
func fvMust(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// fvRev returns the store's current revision, for the fenced durable primitives.
func fvRev(s *Store) *string { r := s.ContentFingerprint(); return &r }

// TestForwardView_EveryMutatorRepublishes drives each PUBLIC mutator and
// requires its effect to be visible through the lock-free read path
// immediately. This is the half that catches a writer which publishes a STALE
// map (the right call, the wrong moment) — something the AST wall cannot see.
func TestForwardView_EveryMutatorRepublishes(t *testing.T) {
	const (
		cat   = "Corp Internal"
		host  = "added.example.invalid"
		other = "other.invalid"
	)

	cases := []struct {
		name   string
		mutate func(t *testing.T, s *Store)
		want   bool // expected MatchesHost(cat, host) after the mutation
	}{
		{"Set", func(t *testing.T, s *Store) {
			fvMustSeed(t, s, cat, host)
		}, true},
		{"AddHost", func(t *testing.T, s *Store) {
			fvMustSeed(t, s, cat, other)
			fvMust(t, "AddHost", s.AddHost(cat, host))
		}, true},
		{"AddHostDurable", func(t *testing.T, s *Store) {
			fvMustSeed(t, s, cat, other)
			fvMust(t, "AddHostDurable", s.AddHostDurable(fvRev(s), cat, host))
		}, true},
		{"RemoveHost", func(t *testing.T, s *Store) {
			fvMustSeed(t, s, cat, host)
			fvMust(t, "RemoveHost", s.RemoveHost(cat, host))
		}, false},
		{"RemoveHostDurable", func(t *testing.T, s *Store) {
			fvMustSeed(t, s, cat, host)
			fvMust(t, "RemoveHostDurable", s.RemoveHostDurable(fvRev(s), cat, host))
		}, false},
		{"Delete", func(t *testing.T, s *Store) {
			fvMustSeed(t, s, cat, host)
			fvMust(t, "Delete", s.Delete(cat))
		}, false},
		{"DeleteDurable", func(t *testing.T, s *Store) {
			fvMustSeed(t, s, cat, host)
			fvMust(t, "DeleteDurable", s.DeleteDurable(fvRev(s), cat))
		}, false},
		{"CreateDurable", func(t *testing.T, s *Store) {
			fvMust(t, "CreateDurable", s.CreateDurable(fvRev(s), cat, []string{host}))
		}, true},
		{"ReplaceHostsDurable", func(t *testing.T, s *Store) {
			fvMustSeed(t, s, cat, other)
			fvMust(t, "ReplaceHostsDurable", s.ReplaceHostsDurable(fvRev(s), cat, []string{host}))
		}, true},
		{"ReplaceAll", func(t *testing.T, s *Store) {
			s.ReplaceAll([]Entry{{Name: cat, Hosts: []string{host}}})
		}, true},
		{"ReplaceAllChecked", func(t *testing.T, s *Store) {
			fvMust(t, "ReplaceAllChecked", s.ReplaceAllChecked([]Entry{{Name: cat, Hosts: []string{host}}}))
		}, true},
		{"Load", func(t *testing.T, s *Store) {
			fvMust(t, "Load", s.Load(fvSeedFile(t, cat, host)))
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New([]*Entry{{Name: "Seed", Hosts: []string{"seed.invalid"}}})
			s.SetPathForTest(filepath.Join(t.TempDir(), "cats.json"))
			tc.mutate(t, s)

			if got := s.MatchesHost(cat, host); got != tc.want {
				t.Errorf("after %s: MatchesHost(%q, %q) = %v, want %v — the view was not republished",
					tc.name, cat, host, got, tc.want)
			}
			// And it must still agree with the oracle, which reads the live maps:
			// a disagreement here IS the stale view, named precisely.
			fvAgree(t, s, cat, host, "after "+tc.name)
			fvAgree(t, s, cat, "sub."+host, "subdomain after "+tc.name)
			fvAgree(t, s, "Seed", "seed.invalid", "untouched category after "+tc.name)
		})
	}
}

// fvSeedFile writes a one-category store to a temp file and returns its path,
// so the Load case above has something on disk to load.
func fvSeedFile(t *testing.T, cat, host string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cats.json")
	seed := New([]*Entry{{Name: cat, Hosts: []string{host}}})
	seed.SetPathForTest(path)
	fvMust(t, "seed SaveErr", seed.SaveErr())
	return path
}

// TestForwardView_FailedPersistRollsBackTheView pins the rollback path. A
// durable mutation whose persist fails is rolled back in memory
// (restoreEntries → rebuildIndex), and the view must roll back with it:
// otherwise a REFUSED category change stays live on the policy path, which is
// the one direction this store must never fail in.
func TestForwardView_FailedPersistRollsBackTheView(t *testing.T) {
	const cat, host = "Corp Internal", "refused.example.invalid"
	s := New([]*Entry{{Name: cat, Hosts: []string{"kept.invalid"}}})
	s.SetPathForTest(filepath.Join(t.TempDir(), "cats.json"))

	orig := writeFile
	t.Cleanup(func() { writeFile = orig })
	writeFile = func(string, []byte, os.FileMode) error { return errors.New("injected persist failure") }

	rev := s.ContentFingerprint()
	err := s.AddHostDurable(&rev, cat, host)
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("AddHostDurable error = %v, want ErrPersist", err)
	}
	if s.MatchesHost(cat, host) {
		t.Error("a REFUSED durable mutation is live on the lock-free read path: the view was not rolled back")
	}
	if !s.MatchesHost(cat, "kept.invalid") {
		t.Error("rollback lost the pre-mutation host")
	}
	fvAgree(t, s, cat, host, "after refused persist")
}

// ---------------------------------------------------------------------------
// 2c. No map reachable from a published view is mutated in place.
// ---------------------------------------------------------------------------

// TestForwardView_ConcurrentReadersAndMutators runs every real mutator against
// the real hot path. Under -race this is what catches a writer that mutates a
// published map in place rather than cloning it — the half the AST wall states
// and only the race detector can prove.
func TestForwardView_ConcurrentReadersAndMutators(t *testing.T) {
	s := New(DefaultEntries())
	s.SetPathForTest(filepath.Join(t.TempDir(), "cats.json"))

	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			cats := []Category{"Social Media", "Corp Internal", "News", "Churn"}
			// Every verdict is CONSUMED, and with an `if` rather than three
			// assignments to one variable: the latter are dead stores
			// (staticcheck SA4006), and `||` would short-circuit past the
			// later probes, which are the point — each reads a different
			// index through the view while the mutators below replace them.
			matched := 0
			for !stop.Load() {
				c := cats[n%len(cats)]
				if s.MatchesHost(c, "a.b.example.com") {
					matched++
				}
				if s.MatchesHostAdmin(c, "intranet.corp.invalid") {
					matched++
				}
				if s.MatchesHost(c, "uncategorized.example.net") {
					matched++
				}
			}
			_ = matched
		}(i)
	}

	for i := 0; i < 40; i++ {
		_ = s.Set("Churn", []string{fmt.Sprintf("h%d.invalid", i)}, i%2 == 0)
		_ = s.AddHost("Churn", fmt.Sprintf("extra%d.invalid", i))
		_ = s.AddHost("Social Media", fmt.Sprintf("saas%d.invalid", i)) // BuiltIn ⇒ admin clone skipped
		_ = s.RemoveHost("Churn", fmt.Sprintf("extra%d.invalid", i))
		if i%7 == 0 {
			_ = s.Delete("Churn")
			s.ReplaceAll([]Entry{{Name: "Corp Internal", Hosts: []string{"intranet.corp.invalid"}}})
		}
	}
	stop.Store(true)
	wg.Wait()
}

// ---------------------------------------------------------------------------
// 3. The read path takes no lock (structural), plus its control.
// ---------------------------------------------------------------------------

// TestBenchGate_MatchesHostTakesNoLock holds the WRITE lock and requires both
// entry points to answer anyway. Deterministic on any hardware.
func TestBenchGate_MatchesHostTakesNoLock(t *testing.T) {
	s := New([]*Entry{
		{Name: "Social Media", Hosts: []string{"example.com"}, BuiltIn: true},
		{Name: "Corp Internal", Hosts: []string{"intranet.corp.invalid"}},
	})

	s.mu.Lock()
	done := make(chan [2]bool, 1)
	go func() {
		done <- [2]bool{
			s.MatchesHost("Social Media", "a.example.com"),
			s.MatchesHostAdmin("Corp Internal", "sub.intranet.corp.invalid"),
		}
	}()
	select {
	case got := <-done:
		s.mu.Unlock()
		if !got[0] || !got[1] {
			t.Errorf("read path answered under the write lock but got %v, want [true true]", got)
		}
	case <-time.After(5 * time.Second):
		s.mu.Unlock()
		t.Fatal("MatchesHost/MatchesHostAdmin blocked on s.mu: the per-rule read lock is back")
	}
}

// TestBenchGate_MutatorsStillTakeTheLock is the CONTROL. Without it, a passing
// gate above could mean the write lock simply stopped being taken, which would
// be a data race rather than an optimisation.
func TestBenchGate_MutatorsStillTakeTheLock(t *testing.T) {
	s := New([]*Entry{{Name: "Corp Internal", Hosts: []string{"intranet.corp.invalid"}}})

	s.mu.Lock()
	done := make(chan struct{})
	go func() {
		_ = s.addHostMem("Corp Internal", "blocked.invalid")
		close(done)
	}()
	select {
	case <-done:
		s.mu.Unlock()
		t.Fatal("control: a mutator completed while the write lock was held — writers must still serialise")
	case <-time.After(150 * time.Millisecond):
		s.mu.Unlock()
	}
	<-done
}

// fvMapPtr returns the identity of a map's backing store, so a test can ask
// whether two map values ARE the same map rather than merely equal.
func fvMapPtr(m map[string]bool) uintptr { return reflect.ValueOf(m).Pointer() }

// TestForwardView_PublishAliasesInnerSetsRatherThanCopyingThem is the
// STRUCTURAL half of the write-amplification contract, and it is the one to
// trust: the timing gate below measures the CONSEQUENCE of this property, while
// this asserts the property itself — deterministically, on any hardware, at any
// load, with or without -race.
//
// A publish must clone the OUTER map (one entry per category) and ALIAS every
// inner host set. That is what makes it O(categories) rather than O(hosts), and
// it is what lets the legacy SaaS feed sync call AddHost once per merged host
// without the publish becoming the dominant cost.
func TestForwardView_PublishAliasesInnerSetsRatherThanCopyingThem(t *testing.T) {
	s := New([]*Entry{
		{Name: "Feed", Hosts: []string{"a.invalid"}, BuiltIn: true},
		{Name: "Other", Hosts: []string{"o.invalid"}},
		{Name: "Third", Hosts: []string{"t.invalid"}},
	})

	before := make(map[string]uintptr, len(s.index))
	for k, v := range s.index {
		before[k] = fvMapPtr(v)
	}
	if len(before) < 3 {
		t.Fatalf("not vacuous check: expected 3 categories to compare, got %d", len(before))
	}

	e := s.entries[0]
	e.Hosts = append(e.Hosts, "b.invalid")
	s.addHostToIndexes(0, e, "feed", "b.invalid")

	v := s.forward()
	if v == nil {
		t.Fatal("the fold did not publish a view")
	}
	for k, ptr := range before {
		if k == "feed" {
			continue
		}
		if got := fvMapPtr(v.index[k]); got != ptr {
			t.Errorf("category %q: its inner host set was COPIED by the publish "+
				"(%#x -> %#x); inner sets must be ALIASED, or a publish becomes "+
				"O(hosts) and the per-host SaaS feed loop becomes quadratic", k, ptr, got)
		}
	}
	// The CONTROL half, in the same test: the touched category's set must have
	// been REPLACED, never mutated in place — aliasing everything including the
	// one being changed is the other way to pass the loop above, and it is a
	// data race against concurrent readers.
	if got := fvMapPtr(v.index["feed"]); got == before["feed"] {
		t.Error("the touched category's inner set was mutated IN PLACE: " +
			"concurrent readers hold that map through the published view")
	}
	if !s.MatchesHost("Feed", "b.invalid") {
		t.Error("the folded host is not visible through the read path")
	}
}

// legacyAddHostToIndexes is addHostToIndexes' pre-view body, VERBATIM: the
// inner-set clone it has always done, plus the IN-PLACE outer assignment the
// view forbids and no publish. It is the baseline for the gate below.
//
// It is deliberately the shape the wall in this file rejects. That is safe
// here — nothing reads this store concurrently — and it is the only honest
// baseline, because the question the gate asks is what the view ADDED.
func legacyAddHostToIndexes(s *Store, ei int, e *Entry, key, host string) {
	set := make(map[string]bool, len(s.index[key])+1)
	for h := range s.index[key] {
		set[h] = true
	}
	set[strings.ToLower(strings.TrimSuffix(host, "."))] = true
	s.index[key] = set
	if !e.BuiltIn {
		s.adminIndex[key] = set
	}
	// #nosec G115 -- slice indices: non-negative and bounded by len (the
	// production body this copies carries the identical suppression)
	ref := patternRef{entry: int32(ei), host: int32(len(e.Hosts) - 1)}
	pk := strings.ToLower(host)
	if cur, dup := s.hostIndex[pk]; !dup || ref.less(cur) {
		s.hostIndex[pk] = ref
	}
	if !e.BuiltIn {
		if cur, dup := s.adminHostIndex[pk]; !dup || ref.less(cur) {
			s.adminHostIndex[pk] = ref
		}
	}
}

// TestBenchGate_AddHostPublishCostsNoMoreThanTheCodeItReplaced bounds the write
// amplification the view introduces on the ONE incremental writer.
//
// AddHost is the writer that matters here: the legacy SaaS feed sync calls it
// once per merged host (saas_feed.go), so anything the publish adds is paid per
// host with s.mu held. What the view adds is an O(categories) clone of the
// OUTER map, with the inner sets ALIASED — and this gate is what pins the
// aliasing, because a publish that deep-copied the inner sets instead would
// multiply a cost that is already the dominant term.
//
// IT IS A SAME-RUN RATIO AGAINST THE FROZEN PREDECESSOR, NOT AN ABSOLUTE OR A
// LINEARITY BOUND, and the first draft of it got that wrong in a way worth
// recording. Written as "4x the hosts must cost no more than 8x" it failed at
// 15.9x — and measured against main the pre-change body scores 15.93x, i.e.
// IDENTICAL. The quadratic is PRE-EXISTING (the inner-set clone addHostToIndexes
// has always done, O(hosts in category) per call) and is not this change's to
// carry or to fix: it is recorded as a separate finding. A gate that fails for
// a cost its change did not introduce is worse than no gate, because the only
// way to make it pass is to widen the change until it is two changes.
//
// So the property asserted is the repo's standing one — an optimisation must be
// no worse than what it replaces — timed in ONE run so it is machine-independent
// (the sanitizeLog / IsExempt / categoryKey convention: never quote a cross-run
// absolute on this box, which has been observed to drift by half again between
// rounds).
func TestBenchGate_AddHostPublishCostsNoMoreThanTheCodeItReplaced(t *testing.T) {
	const hosts = 1500

	// run drives one bulk load of `hosts` hosts into a single category through
	// `fold`, and returns the elapsed time. Persistence stays off: Save() would
	// dominate and hide the index cost entirely.
	run := func(fold func(s *Store, ei int, e *Entry, key, host string)) time.Duration {
		s := New([]*Entry{
			{Name: "Feed", Hosts: []string{"seed.invalid"}, BuiltIn: true},
			{Name: "Other", Hosts: []string{"o.invalid"}},
			{Name: "Third", Hosts: []string{"t.invalid"}},
		})
		names := make([]string, hosts)
		for i := range names {
			names[i] = fmt.Sprintf("h%d.feed.invalid", i)
		}
		e := s.entries[0]
		const key = "feed"
		start := time.Now()
		for _, h := range names {
			e.Hosts = append(e.Hosts, h)
			fold(s, 0, e, key, h)
		}
		return time.Since(start)
	}
	current := func(s *Store, ei int, e *Entry, key, host string) { s.addHostToIndexes(ei, e, key, host) }

	// GENUINELY INTERLEAVED, and ALTERNATING which arm goes first.
	//
	// An earlier draft ran all seven legacy samples and then all seven current
	// ones while its comment claimed interleaving (Codex review, PR #1577). On a
	// shared or thermally drifting runner a load change between those two
	// batches can fail unchanged code OR conceal a regression — and this box
	// was observed drifting by half again inside one session, which is the whole
	// reason this file measures ratios instead of absolutes. Grouping the arms
	// inside one process is not the same as interleaving them: it reintroduces
	// the cross-run error the ratio exists to remove.
	//
	// Each iteration takes ONE sample of each arm, swapping the order on odd
	// iterations so neither arm systematically pays for the other's cache
	// warming, and the comparison is min-vs-min — the least noise-sensitive
	// statistic for "how fast can this go", so a transient spike can only
	// discard a sample, never inflate the verdict.
	legacy, now := time.Hour, time.Hour
	keepMin := func(dst *time.Duration, d time.Duration) {
		if d < *dst {
			*dst = d
		}
	}
	for i := 0; i < 7; i++ {
		if i%2 == 0 {
			keepMin(&legacy, run(legacyAddHostToIndexes))
			keepMin(&now, run(current))
			continue
		}
		keepMin(&now, run(current))
		keepMin(&legacy, run(legacyAddHostToIndexes))
	}
	if legacy <= 0 {
		t.Skip("timer resolution too coarse to measure")
	}
	ratio := float64(now) / float64(legacy)
	t.Logf("addHostToIndexes bulk fold of %d hosts: pre-view %v, with publish %v, ratio %.3fx",
		hosts, legacy, now, ratio)

	// 1.25x of a cost whose dominant term is the pre-existing inner-set clone.
	// A publish that deep-copied the inner sets would roughly double it.
	if ratio > 1.25 {
		t.Errorf("publishing the forward view made AddHost %.3fx the pre-view cost (bound 1.25x): "+
			"a publish must be O(categories) with the inner sets ALIASED — check cloneOuter is not copying them", ratio)
	}
}

// TestBenchGate_AddHostPublishGateIsNotVacuous is the CONTROL for the gate
// above: it measures a publish that DEEP-COPIES the inner sets — the mistake
// the gate exists to catch — and requires that shape to blow the same bound.
// Without it, a `current` that had quietly stopped publishing, or a bound set
// too loose to matter, would pass forever.
func TestBenchGate_AddHostPublishGateIsNotVacuous(t *testing.T) {
	const hosts = 1500
	run := func(deepCopy bool) time.Duration {
		s := New([]*Entry{{Name: "Feed", Hosts: []string{"seed.invalid"}, BuiltIn: true}, {Name: "Other"}, {Name: "Third"}})
		names := make([]string, hosts)
		for i := range names {
			names[i] = fmt.Sprintf("h%d.feed.invalid", i)
		}
		e := s.entries[0]
		start := time.Now()
		for _, h := range names {
			e.Hosts = append(e.Hosts, h)
			if deepCopy {
				legacyAddHostToIndexes(s, 0, e, "feed", h)
				// The defect: clone the outer map AND every inner set.
				idx := make(map[string]map[string]bool, len(s.index))
				for k, v := range s.index {
					inner := make(map[string]bool, len(v))
					for h2 := range v {
						inner[h2] = true
					}
					idx[k] = inner
				}
				s.index = idx
				s.publishForwardLocked()
			} else {
				s.addHostToIndexes(0, e, "feed", h)
			}
		}
		return time.Since(start)
	}
	// Interleaved and order-alternating, for the reason the gate above records.
	shallow, deep := time.Hour, time.Hour
	keepMin := func(dst *time.Duration, d time.Duration) {
		if d < *dst {
			*dst = d
		}
	}
	for i := 0; i < 5; i++ {
		if i%2 == 0 {
			keepMin(&shallow, run(false))
			keepMin(&deep, run(true))
			continue
		}
		keepMin(&deep, run(true))
		keepMin(&shallow, run(false))
	}
	if shallow <= 0 {
		t.Skip("timer resolution too coarse to measure")
	}
	ratio := float64(deep) / float64(shallow)
	t.Logf("control: deep-copying inner sets on publish costs %.2fx the shipped publish", ratio)
	if ratio <= 1.25 {
		t.Errorf("control: a publish that deep-copies every inner host set measured only %.2fx "+
			"the shipped one, so the 1.25x bound in the gate above cannot see that defect", ratio)
	}
}
