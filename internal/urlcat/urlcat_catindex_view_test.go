package urlcat

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Gates for the FORWARD index read view (Store.catIndex).
//
// MatchesHost/MatchesHostAdmin are the per-RULE half of destination-category
// resolution — package main's hostCatScratch.matchesCategory calls one of them
// once per category-scoped access rule per proxied request — and they used to
// take s.mu.RLock purely to snapshot ONE pointer out of a map that in steady
// state never changes. Measured, that was a throughput CEILING rather than a
// constant cost: four cores delivered 0.76x the throughput of one.
//
// Three properties are pinned here and they pull in different directions,
// which is why all three are needed:
//
//	LOCK-FREEDOM  the read path must not take s.mu, or the ceiling is back.
//	              Pinned STRUCTURALLY (hold the write lock, require an answer),
//	              never as a timing ratio — a scaling gate's margin narrows
//	              under -race on a shared runner and a gate that can flake gets
//	              muted (the standing rule from internal/connlimit and the
//	              latency histogram).
//	FRESHNESS     a mutation must be visible to the next probe. A view a writer
//	              forgot to republish is not a performance bug but a silently
//	              mis-enforced policy — a category rule that stops matching a
//	              newly added host, or keeps matching a removed one.
//	COST          publishing must not put O(taxonomy) work under the write lock
//	              AddHost holds. The SaaS feed merge calls AddHost once per
//	              merged host, so a wholesale step there stalls every
//	              category-scoped evaluation on the request path once per host.

// ─── Freshness ────────────────────────────────────────────────────────────────

// TestCatIndexView_MutationIsVisibleImmediately drives every mutation KIND
// through the public API and requires the membership probes to observe it on
// the very next call. This is the behavioural half of the republish contract:
// it fails for any writer that updates s.index without publishing the view.
func TestCatIndexView_MutationIsVisibleImmediately(t *testing.T) {
	s := New([]*Entry{{Name: "Dev", Hosts: []string{"git.lab"}}})

	assert := func(label, cat, host string, want bool) {
		t.Helper()
		if got := s.MatchesHost(Category(cat), host); got != want {
			t.Fatalf("%s: MatchesHost(%q,%q)=%v want %v — the published view did not "+
				"follow the mutation (a writer of s.index skipped publishCatIndexLocked)",
				label, cat, host, got, want)
		}
	}

	assert("seed", "Dev", "git.lab", true)
	assert("seed (absent)", "Dev", "wiki.lab", false)

	if err := s.AddHost("Dev", "wiki.lab"); err != nil {
		t.Fatal(err)
	}
	assert("AddHost", "Dev", "wiki.lab", true)

	if err := s.RemoveHost("Dev", "git.lab"); err != nil {
		t.Fatal(err)
	}
	assert("RemoveHost", "Dev", "git.lab", false)

	if err := s.Set("Finance", []string{"bank.lab"}, false); err != nil {
		t.Fatal(err)
	}
	assert("Set(new)", "Finance", "bank.lab", true)

	if err := s.Set("Finance", []string{"other.lab"}, false); err != nil {
		t.Fatal(err)
	}
	assert("Set(replace) adds", "Finance", "other.lab", true)
	assert("Set(replace) drops", "Finance", "bank.lab", false)

	if err := s.Delete("Finance"); err != nil {
		t.Fatal(err)
	}
	assert("Delete", "Finance", "other.lab", false)

	s.ReplaceAll([]Entry{{Name: "Only", Hosts: []string{"only.lab"}}})
	assert("ReplaceAll adds", "Only", "only.lab", true)
	assert("ReplaceAll drops", "Dev", "wiki.lab", false)
}

// TestCatIndexView_AdminMutationIsVisibleImmediately is the same contract for
// the admin-only index, which MatchesHostAdmin serves. It is a SEPARATE gate
// because adminIndex is a distinct map with its own publish: a publish that
// copied only s.index would pass the test above and leave the signed-feed
// policy path reading a stale admin taxonomy.
func TestCatIndexView_AdminMutationIsVisibleImmediately(t *testing.T) {
	s := New([]*Entry{
		{Name: "Shipped", BuiltIn: true, Hosts: []string{"vendor.example"}},
		{Name: "Corp", BuiltIn: false, Hosts: []string{"intranet.corp.invalid"}},
	})

	if !s.MatchesHostAdmin("Corp", "intranet.corp.invalid") {
		t.Fatal("seed: admin category does not match its own host")
	}
	// A BuiltIn category must never appear in the admin index.
	if s.MatchesHostAdmin("Shipped", "vendor.example") {
		t.Fatal("seed: BuiltIn category leaked into the admin index")
	}

	if err := s.AddHost("Corp", "wiki.corp.invalid"); err != nil {
		t.Fatal(err)
	}
	if !s.MatchesHostAdmin("Corp", "wiki.corp.invalid") {
		t.Fatal("AddHost: MatchesHostAdmin did not observe the new host — the admin " +
			"half of the view was not republished")
	}

	if err := s.RemoveHost("Corp", "intranet.corp.invalid"); err != nil {
		t.Fatal(err)
	}
	if s.MatchesHostAdmin("Corp", "intranet.corp.invalid") {
		t.Fatal("RemoveHost: MatchesHostAdmin still matches a removed host")
	}
}

// ─── Lock-freedom (structural) ────────────────────────────────────────────────

// TestBenchGate_MatchesHostTakesNoStoreLock is the lock-freedom gate. It HOLDS
// the write lock and requires both membership probes to answer anyway, so a
// return to a lock-guarded read path fails deterministically — on any
// hardware, at any load, with or without -race.
func TestBenchGate_MatchesHostTakesNoStoreLock(t *testing.T) {
	s := New([]*Entry{{Name: "Social Media", BuiltIn: false, Hosts: []string{"example.com"}}})
	// Publish before locking: a probe against a never-published store falls
	// back to the lock by design, which would make this gate vacuous.
	if !s.MatchesHost("Social Media", "a.b.example.com") {
		t.Fatal("seed does not match — gate cannot run")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.MatchesHost("Social Media", "a.b.example.com")
		s.MatchesHostAdmin("Social Media", "a.b.example.com")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("REGRESSION: a per-rule membership probe (MatchesHost / MatchesHostAdmin) " +
			"blocked while the store's write lock was held — the read path has gone back to " +
			"acquiring s.mu. That reintroduces the throughput ceiling the view removed " +
			"(see Store.catIndex): per-op cost then RISES with core count, so a " +
			"category-scoped rulebase gets SLOWER as cores are added.")
	}
}

// TestBenchGate_MutatorsStillTakeTheLock is the CONTROL for the gate above.
// The cheapest way to pass a "takes no lock" assertion is for the WRITE side
// to stop locking too, which would be a data race rather than an
// optimisation. This requires a mutation to still block on a held read lock.
func TestBenchGate_MutatorsStillTakeTheLock(t *testing.T) {
	s := New([]*Entry{{Name: "Dev", Hosts: []string{"git.lab"}}})

	s.mu.RLock()
	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		_ = s.AddHost("Dev", "wiki.lab")
	}()

	select {
	case <-blocked:
		s.mu.RUnlock()
		t.Fatal("AddHost completed while a READ lock was held — the write side has stopped " +
			"taking s.mu, so the published view is being derived from state that lock-free " +
			"readers can observe mid-mutation. That is a data race, not a speed-up.")
	case <-time.After(150 * time.Millisecond):
	}
	s.mu.RUnlock()
	<-blocked
}

// TestBenchGate_MatchesHostIsStillAllocationFree re-pins the allocation
// contract across the view change. The probe spells its map key as
// idx[string(inlineKey)] on a CALLER-owned stack array, and handing that
// scratch to a helper would let keyBuf escape to the heap — reintroducing the
// per-rule allocation categoryKey exists to remove. Both the view path and the
// unpublished fallback are measured.
func TestBenchGate_MatchesHostIsStillAllocationFree(t *testing.T) {
	cat := benchCategoryName(t)
	const host = "uncategorized.example.net"

	published := New(DefaultEntries())
	_ = published.MatchesHost(cat, host) // ensure the view is live

	// A zero-value Store has never published, so this exercises the locked
	// fallback branch.
	var unpublished Store

	for _, tc := range []struct {
		name string
		run  func()
	}{
		{"view path", func() { _ = published.MatchesHost(cat, host) }},
		{"view path (admin)", func() { _ = published.MatchesHostAdmin(cat, host) }},
		{"unpublished fallback", func() { _ = unpublished.MatchesHost(cat, host) }},
	} {
		if got := testing.AllocsPerRun(200, tc.run); got != 0 {
			t.Errorf("%s: %v allocs/op, want 0 — the category key scratch is escaping to the heap, "+
				"so every category-scoped rule allocates on every proxied request", tc.name, got)
		}
	}
}

// ─── Concurrency ──────────────────────────────────────────────────────────────

// TestCatIndexView_ConcurrentReadersAndMutators runs the lock-free probes
// against every mutator kind concurrently. Under -race this is the gate for
// the half of the contract no structural check can see: that a map reachable
// from a PUBLISHED view is never mutated in place. The inner host sets are
// shared by the view and the authoritative map, so a writer that inserted into
// a live set instead of cloning it would surface here.
func TestCatIndexView_ConcurrentReadersAndMutators(t *testing.T) {
	s := New([]*Entry{
		{Name: "Dev", BuiltIn: false, Hosts: []string{"git.lab"}},
		{Name: "Shipped", BuiltIn: true, Hosts: []string{"vendor.example"}},
	})

	stop := make(chan struct{})
	var readers sync.WaitGroup

	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = s.MatchesHost("Dev", "a.b.git.lab")
				_ = s.MatchesHostAdmin("Dev", "git.lab")
				_, _, _ = s.LookupHost("git.lab")
			}
		}()
	}

	// The mutator runs on THIS goroutine, so the readers are only released
	// once it has finished. Waiting on one group that also contains the
	// readers would deadlock: they exit on stop, which closes after the wait.
	for i := range 400 {
		h := fmt.Sprintf("h%d.lab", i)
		_ = s.AddHost("Dev", h)
		_ = s.RemoveHost("Dev", h)
		if i%50 == 0 {
			_ = s.Set("Churn", []string{"c.lab"}, false)
			_ = s.Delete("Churn")
		}
	}

	close(stop)
	readers.Wait()

	// The taxonomy is back to its seed, so the seeded facts must still hold.
	if !s.MatchesHost("Dev", "git.lab") {
		t.Fatal("after concurrent churn the seeded host no longer matches")
	}
	if s.MatchesHost("Dev", "h1.lab") {
		t.Fatal("after concurrent churn a removed host still matches")
	}
}

// ─── Cost ─────────────────────────────────────────────────────────────────────

// addHostNsPerOp times AddHost on a store of the given shape, as nanoseconds
// per call.
//
// The iteration count is FIXED and small, deliberately. A testing.Benchmark
// here is the wrong instrument and measures the wrong thing: b.N grows until
// the work takes a second, every iteration appends to the SAME category, and
// addHostToIndexes clones that category's host set — so the cost per call
// climbs with the iteration count and the harness reports the average of a
// quadratic ramp it chose the length of. Bounded iterations keep the touched
// category's size inside a narrow band around hostsPer, which is the only way
// the two shapes being compared differ by CATEGORY COUNT alone.
//
// The hosts are pre-rendered so fmt.Sprintf is outside the timed region.
func addHostNsPerOp(cats, hostsPer int) int64 {
	const (
		iterations = 50 // keeps the touched category inside a narrow size band
		rounds     = 9
	)
	hosts := make([]string, iterations)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("new%d.cost.example", i)
	}
	// Best of several rounds: the MINIMUM is the least noise-contaminated
	// estimate on a shared runner, and both shapes are measured the same way
	// in the same process, which is what makes the RATIO meaningful.
	best := int64(-1)
	for range rounds {
		s := New(costTaxonomy(cats, hostsPer)) // path == "" ⇒ Save() is a no-op
		_ = s.ContentFingerprint()             // warm the memo: the live steady state
		start := time.Now()
		for _, h := range hosts {
			_ = s.AddHost("Cat0", h)
		}
		ns := time.Since(start).Nanoseconds() / int64(iterations)
		if best < 0 || ns < best {
			best = ns
		}
	}
	return best
}

// TestBenchGate_AddHostStaysIncrementalUnderPublication is the cost gate for
// the axis publishing INTRODUCES. The pre-existing
// TestFingerprint_AddHostCostIsFlatInTaxonomySize varies categories and hosts
// together and measures allocation COUNT, which a map clone barely moves — so
// it cannot see an O(categories) step. This one holds hosts-per-category fixed
// and varies the CATEGORY count 40x, in TIME, as a same-run RATIO (so it is
// machine-independent and needs no re-baselining).
//
// Publishing copies the OUTER maps — one entry per category — on a writer that
// already clones the touched category's inner host SET, so the added term is
// strictly smaller than what AddHost already paid. This gate is what keeps
// that true: the rule it protects is urlcat's own, recorded on
// invalidateFingerprintLocked — nothing O(taxonomy) may be added to AddHost
// under the write lock, because the SaaS feed merge calls it once per merged
// host while holding the lock every category lookup on the request path
// contends on.
//
// THE SHAPES ARE CHOSEN SO THE GATE CANNOT FLAKE, and the first version of it
// could. hostsPer was 200, which made the inner-set clone dominate the
// DENOMINATOR: the 5-category arm measured 8.9–15.2 µs across runs (a 1.7x
// spread) while the defect's 200-category arm was stable at 39–44 µs, so the
// ratio wandered 2.66x–4.61x and straddled the bound — the defect it had
// already caught at 4.14x then PASSED on a re-run. A gate that can flake gets
// muted, which is this repo's standing reason for preferring structural gates;
// where a ratio is the only available instrument, the shapes have to put the
// varying term in the numerator and keep the denominator cheap and stable.
// With hostsPer=100 over a 40x category range, measured 5 runs each:
//
//	slot swap (current): 0.69x 1.02x 1.05x 1.09x 1.11x   — passes 5/5
//	full republish (M6): 6.56x 8.62x 9.11x 9.84x 9.92x   — fails  5/5
//
// so the 4x bound sits an order of magnitude clear of both.
func TestBenchGate_AddHostStaysIncrementalUnderPublication(t *testing.T) {
	if testing.Short() {
		t.Skip("cost gate: timing measurement is slow under -short")
	}
	const hostsPer = 100
	few := addHostNsPerOp(10, hostsPer)
	many := addHostNsPerOp(400, hostsPer) // 40x the categories, same hosts each
	if few <= 0 {
		t.Fatalf("no time measured for the small taxonomy (%d ns/op) — the gate cannot compare", few)
	}
	t.Logf("AddHost: %d ns/op at 10 categories, %d ns/op at 400 (%.2fx)", few, many, float64(many)/float64(few))
	const maxRatio = 4.0
	if ratio := float64(many) / float64(few); ratio > maxRatio {
		t.Fatalf("AddHost cost scales with CATEGORY count: %d ns/op at 400 categories vs %d at 10 "+
			"(%.2fx, bound %.2fx).\nPublishing the forward view must stay O(categories) on a writer that "+
			"already pays O(hosts in the touched category) — an O(taxonomy) step here stalls every "+
			"category-scoped policy evaluation on the request path once per merged feed host.",
			many, few, ratio, maxRatio)
	}
}

// ─── Structural republish wall ────────────────────────────────────────────────

// TestCatIndexView_EveryWriterRepublishes is the wall. Behavioural coverage
// reaches only the mutators a test happens to drive, and the failure mode is
// invisible to every assertion that does not probe the exact category a new
// writer touched — so the contract is pinned at the SOURCE: every function
// that assigns to s.index or s.adminIndex must also call
// publishCatIndexLocked.
//
// It carries its own not-vacuous check: if the selector stops matching the
// writers it is meant to find, the gate fails rather than passing forever.
func TestCatIndexView_EveryWriterRepublishes(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "urlcat.go", nil, 0)
	if err != nil {
		t.Fatalf("parse urlcat.go: %v", err)
	}

	// writesIndex reports whether fn assigns to s.index / s.adminIndex —
	// either wholesale (s.index = x) or per key (s.index[k] = x).
	writesIndex := func(fn *ast.FuncDecl) bool {
		found := false
		ast.Inspect(fn, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				target := lhs
				if ix, isIndex := lhs.(*ast.IndexExpr); isIndex {
					target = ix.X
				}
				sel, isSel := target.(*ast.SelectorExpr)
				if !isSel {
					continue
				}
				if sel.Sel.Name == "index" || sel.Sel.Name == "adminIndex" {
					found = true
				}
			}
			return true
		})
		return found
	}

	// Either publish mechanism satisfies the contract: the O(categories)
	// key-set publish, or the O(1) single-category slot swap (which exists so
	// the incremental fold can stay incremental — see hostSetSlot).
	publishers := map[string]bool{
		"publishCatIndexLocked": true,
		"swapHostSetLocked":     true,
	}
	callsPublish := func(fn *ast.FuncDecl) bool {
		found := false
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel && publishers[sel.Sel.Name] {
				found = true
			}
			return true
		})
		return found
	}

	var writers []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// The publisher itself builds the view; it does not write the
		// authoritative maps and must not recurse.
		if fn.Name.Name == "publishCatIndexLocked" || fn.Name.Name == "swapHostSetLocked" {
			continue
		}
		if !writesIndex(fn) {
			continue
		}
		writers = append(writers, fn.Name.Name)
		if !callsPublish(fn) {
			t.Errorf("REGRESSION: %s assigns to s.index/s.adminIndex but never publishes "+
				"(publishCatIndexLocked or swapHostSetLocked).\n"+
				"MatchesHost/MatchesHostAdmin read those maps through the published view with NO lock, so an "+
				"unpublished mutation is a silently mis-enforced category rule — one that stops matching a "+
				"newly added host, or keeps matching a removed one. Publish before releasing s.mu "+
				"(see Store.catIndex).", fn.Name.Name)
		}
	}

	// Not-vacuous: the two known writers must both be found. If a refactor
	// renames or relocates them the selector above has stopped working and
	// this gate would otherwise pass against nothing.
	const wantWriters = 2
	if len(writers) < wantWriters {
		t.Fatalf("the writer selector matched %d function(s) %v, want at least %d "+
			"(rebuildIndex and addHostToIndexes) — the wall has gone vacuous and is no longer "+
			"checking the republish contract", len(writers), writers, wantWriters)
	}
	t.Logf("republish contract verified for %d writer(s): %s", len(writers), strings.Join(writers, ", "))
}

// TestCatIndexView_PublishedBeforeFirstRead pins that the ONLY constructor
// publishes, so the locked fallback in the probes is a defensive branch rather
// than the steady state. A store that served reads from the fallback would be
// correct and slow — the ceiling back, silently.
func TestCatIndexView_PublishedBeforeFirstRead(t *testing.T) {
	s := New([]*Entry{{Name: "Dev", Hosts: []string{"git.lab"}}})
	if s.catIndex.Load() == nil {
		t.Fatal("New() returned a Store with no published forward view — every membership probe " +
			"would fall back to the locked read path, reinstating the per-rule read-lock ceiling")
	}
	runtime.KeepAlive(s)
}

// TestCatIndexView_UnpublishedStoreStillAnswers pins the fallback's VERDICT.
// A zero-value Store has an empty authoritative index, so the honest answer is
// "no". What must never happen is the probe inventing an answer from a missing
// view in the other direction, or panicking on the nil map.
func TestCatIndexView_UnpublishedStoreStillAnswers(t *testing.T) {
	var s Store
	if s.MatchesHost("Dev", "git.lab") {
		t.Fatal("an empty store reported category membership")
	}
	if s.MatchesHostAdmin("Dev", "git.lab") {
		t.Fatal("an empty store reported admin category membership")
	}
}

// ─── Differential against the code it replaced ────────────────────────────────

// TestCatIndexViewDifferential_MatchesLegacyVerdict is the correctness spine.
// This is a COST change, so the verdict must be identical to the pre-view
// body for every input — and the stakes are not cosmetic: MatchesHost decides
// whether a category-scoped Allow or Deny rule fires, so a divergence is a
// silently mis-enforced policy, in one direction or the other.
//
// The oracle is legacyMatchesHost / legacyMatchesHostAdmin, the VERBATIM
// pre-view bodies kept in urlcat_catindex_view_bench_test.go — the same
// functions the before/after benchmark measures, so the oracle cannot drift
// from what the comparison claims.
func TestCatIndexViewDifferential_MatchesLegacyVerdict(t *testing.T) {
	stores := map[string]*Store{
		"shipped taxonomy": New(DefaultEntries()),
		"mixed builtin/admin": New([]*Entry{
			{Name: "Shipped", BuiltIn: true, Hosts: []string{"vendor.example", "cdn.vendor.example"}},
			{Name: "Corp", BuiltIn: false, Hosts: []string{"intranet.corp.invalid"}},
			{Name: "Overlap", BuiltIn: false, Hosts: []string{"vendor.example"}},
		}),
		"empty taxonomy":  New(nil),
		"empty host list": New([]*Entry{{Name: "Nothing", Hosts: nil}}),
		"trailing dot":    New([]*Entry{{Name: "Dotted", Hosts: []string{"dotted.example."}}}),
		"unicode name":    New([]*Entry{{Name: "CAFÉ", Hosts: []string{"cafe.example"}}}),
		"oversize name": New([]*Entry{{
			Name:  strings.Repeat("L", maxInlineCategoryKey+8),
			Hosts: []string{"long.example"},
		}}),
	}
	// A store that has been MUTATED since construction exercises the slot-swap
	// path rather than only the key-set publish.
	mutated := New([]*Entry{{Name: "Dev", BuiltIn: false, Hosts: []string{"git.lab"}}})
	if err := mutated.AddHost("Dev", "wiki.lab"); err != nil {
		t.Fatal(err)
	}
	if err := mutated.AddHost("Dev", "ci.lab"); err != nil {
		t.Fatal(err)
	}
	stores["mutated via AddHost (slot swap)"] = mutated

	hosts := []string{
		"", ".", "example.com", "vendor.example", "cdn.vendor.example",
		"a.b.cdn.vendor.example", "intranet.corp.invalid", "dotted.example",
		"dotted.example.", "cafe.example", "long.example", "git.lab",
		"wiki.lab", "ci.lab", "a.b.git.lab", "uncategorized.example.net",
		"UPPER.Example.COM", "trailing.dot.", "..double..dots..",
	}

	agreed := 0
	trueVerdicts := 0
	for label, s := range stores {
		cats := []Category{"", "nope", "Social Media", "Shipped", "Corp", "Overlap",
			"Dev", "Dotted", "CAFÉ", "Nothing",
			Category(strings.Repeat("L", maxInlineCategoryKey+8))}
		// Add the store's own real category names so hits are reachable.
		for _, e := range s.All() {
			cats = append(cats, Category(e.Name))
		}
		for _, cat := range cats {
			for _, h := range hosts {
				gotMain := s.MatchesHost(cat, h)
				wantMain := legacyMatchesHost(s, cat, h)
				if gotMain != wantMain {
					t.Fatalf("%s: MatchesHost(%q,%q)=%v, pre-view body says %v — the view diverges "+
						"from the code it replaced, so a category-scoped policy rule now fires "+
						"differently", label, cat, h, gotMain, wantMain)
				}
				gotAdmin := s.MatchesHostAdmin(cat, h)
				wantAdmin := legacyMatchesHostAdmin(s, cat, h)
				if gotAdmin != wantAdmin {
					t.Fatalf("%s: MatchesHostAdmin(%q,%q)=%v, pre-view body says %v", label, cat, h, gotAdmin, wantAdmin)
				}
				agreed++
				if wantMain || wantAdmin {
					trueVerdicts++
				}
			}
		}
	}

	// Not-vacuous, in BOTH directions. A corpus that never produced a match
	// would agree perfectly with an implementation that always returns false,
	// which is the cheapest way for this test to pass against a broken probe.
	if agreed < 500 {
		t.Fatalf("differential compared only %d verdict pairs — the corpus has collapsed", agreed)
	}
	if trueVerdicts < 20 {
		t.Fatalf("differential produced only %d TRUE verdicts out of %d pairs — a probe that "+
			"always answered false would pass, so the corpus proves nothing", trueVerdicts, agreed)
	}
	t.Logf("differential: %d verdict pairs agreed (%d of them true)", agreed, trueVerdicts)
}
