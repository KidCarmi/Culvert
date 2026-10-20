package catgroup

// Tests for the lock-free read view (readView in catgroup.go).
//
// Three independent halves, because each catches what the others cannot:
//
//   - the REPUBLISH contract, behaviourally through every public mutator: a
//     writer that publishes a STALE view (the right call at the wrong moment)
//     passes an AST check and fails here.
//   - the republish contract STRUCTURALLY, over the package AST: a forgotten
//     publish in a mutator no test drives is invisible behaviourally, and a
//     missing publish is not a crash — it is a group edit that silently never
//     reaches policy evaluation.
//   - the IMMUTABILITY contract: a published *Group edited in place is a data
//     race that -race observes only if a reader happens to be running.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. The republish contract, behaviourally.
// ---------------------------------------------------------------------------

// rvSeed installs one group and returns its id. Every mutation under test
// starts from a group that EXISTS.
func rvSeed(t *testing.T, s *Store, name, cat string) string {
	t.Helper()
	g, err := s.Add(name, []string{cat})
	if err != nil {
		t.Fatalf("seed %q: %v", name, err)
	}
	return g.ID
}

// TestReadView_EveryMutatorRepublishes drives each public mutator and requires
// its effect to be visible through the lock-free read path immediately.
func TestReadView_EveryMutatorRepublishes(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		if matched, resolved := s.MatchesCategoryByID(id, "ai"); !matched || !resolved {
			t.Fatalf("after Add: matched=%v resolved=%v, want both true", matched, resolved)
		}
		if s.GetByName("prod") == nil {
			t.Error("after Add: GetByName sees nothing")
		}
	})

	t.Run("Update", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		if err := s.Update("Prod", []string{"marketing"}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if matched, _ := s.MatchesCategoryByID(id, "ai"); matched {
			t.Error("after Update: the removed category still matches")
		}
		if matched, _ := s.MatchesCategoryByID(id, "marketing"); !matched {
			t.Error("after Update: the added category does not match")
		}
	})

	t.Run("UpdateByID", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		if err := s.UpdateByID(id, []string{"messaging"}); err != nil {
			t.Fatalf("UpdateByID: %v", err)
		}
		if matched, _ := s.MatchesCategoryByID(id, "ai"); matched {
			t.Error("after UpdateByID: the removed category still matches")
		}
		if matched, _ := s.MatchesCategoryByID(id, "messaging"); !matched {
			t.Error("after UpdateByID: the added category does not match")
		}
	})

	t.Run("Rename", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		if _, err := s.Rename(id, "Staging"); err != nil {
			t.Fatalf("Rename: %v", err)
		}
		if s.GetByName("prod") != nil {
			t.Error("after Rename: the old name still resolves")
		}
		g := s.GetByName("staging")
		if g == nil {
			t.Fatal("after Rename: the new name does not resolve")
		}
		if g.Name != "Staging" {
			t.Errorf("after Rename: published display name = %q, want %q", g.Name, "Staging")
		}
		// The ID index must survive a rename — that is what makes ID
		// addressing rename-safe.
		if _, resolved := s.MatchesCategoryByID(id, "ai"); !resolved {
			t.Error("after Rename: the id no longer resolves")
		}
	})

	t.Run("RenameCaseOnly", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		if _, err := s.Rename(id, "PROD"); err != nil {
			t.Fatalf("Rename: %v", err)
		}
		g := s.GetByName("prod")
		if g == nil {
			t.Fatal("after case-only Rename: the name does not resolve")
		}
		if g.Name != "PROD" {
			t.Errorf("after case-only Rename: display name = %q, want %q", g.Name, "PROD")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		if err := s.Delete("Prod"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, resolved := s.MatchesCategoryByID(id, "ai"); resolved {
			t.Error("after Delete: the id still resolves")
		}
		if s.GetByName("prod") != nil {
			t.Error("after Delete: the name still resolves")
		}
	})

	t.Run("DeleteByID", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		if _, err := s.DeleteByID(id); err != nil {
			t.Fatalf("DeleteByID: %v", err)
		}
		if _, resolved := s.MatchesCategoryByID(id, "ai"); resolved {
			t.Error("after DeleteByID: the id still resolves")
		}
	})

	t.Run("ReplaceAll", func(t *testing.T) {
		s := New()
		rvSeed(t, s, "Prod", "ai")
		s.ReplaceAll([]Group{{ID: "fixed-id", Name: "Only", Categories: []string{"marketing"}}})
		if s.GetByName("prod") != nil {
			t.Error("after ReplaceAll: a replaced group still resolves")
		}
		if matched, resolved := s.MatchesCategoryByID("fixed-id", "marketing"); !matched || !resolved {
			t.Fatalf("after ReplaceAll: matched=%v resolved=%v, want both true", matched, resolved)
		}
	})

	t.Run("Load", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "groups.json")
		src := New()
		rvSeed(t, src, "Prod", "ai")
		src.SetPathForTest(path)
		if err := src.SaveErr(); err != nil {
			t.Fatalf("SaveErr: %v", err)
		}
		dst := New()
		if err := dst.Load(path); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if dst.GetByName("prod") == nil {
			t.Error("after Load: the loaded group does not resolve")
		}
	})

	t.Run("restoreSnapshot", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		snap := s.List()
		if err := s.Update("Prod", []string{"marketing"}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		s.restoreSnapshot(snap, s.Version())
		if matched, _ := s.MatchesCategoryByID(id, "ai"); !matched {
			t.Error("after restoreSnapshot: the restored category does not match")
		}
		if matched, _ := s.MatchesCategoryByID(id, "marketing"); matched {
			t.Error("after restoreSnapshot: the rolled-back category still matches")
		}
	})
}

// TestReadView_FailedPersistRollsBackTheView pins the republish on the
// MutateDurable rollback path end to end: a durable failure must leave the
// LOCK-FREE readers on the pre-mutation truth, not just the authoritative map.
func TestReadView_FailedPersistRollsBackTheView(t *testing.T) {
	s := New()
	id := rvSeed(t, s, "Prod", "ai")
	// An unwritable path makes the durable publication fail.
	s.SetPathForTest(filepath.Join(t.TempDir(), "no-such-dir", "groups.json"))

	err := s.MutateDurable(nil, func() error { return s.Update("Prod", []string{"marketing"}) })
	if err == nil {
		t.Fatal("MutateDurable succeeded against an unwritable path")
	}
	if matched, _ := s.MatchesCategoryByID(id, "marketing"); matched {
		t.Error("a rolled-back mutation is visible through the lock-free read path")
	}
	if matched, _ := s.MatchesCategoryByID(id, "ai"); !matched {
		t.Error("the pre-mutation category is not visible after rollback")
	}
}

// ---------------------------------------------------------------------------
// 2. The republish contract, structurally.
// ---------------------------------------------------------------------------

// rvGroupWriters parses src and returns, from it, the names of the functions
// that WRITE the authoritative group tree (an assignment to s.groups, an
// assignment into it, or a delete from it) and the subset of those that call
// publishLocked.
func rvGroupWriters(t *testing.T, src string) (writers, publishers []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		writes, publishes := false, false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if rvIsGroupsTarget(lhs) {
						writes = true
					}
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "publishLocked" {
					publishes = true
				}
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "delete" && len(x.Args) > 0 {
					if rvIsGroupsField(x.Args[0]) {
						writes = true
					}
				}
			}
			return true
		})
		if writes {
			writers = append(writers, fn.Name.Name)
		}
		if writes && publishes {
			publishers = append(publishers, fn.Name.Name)
		}
	}
	sort.Strings(writers)
	sort.Strings(publishers)
	return writers, publishers
}

// rvIsGroupsField reports whether e is the selector `<recv>.groups`.
func rvIsGroupsField(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "groups"
}

// rvIsGroupsTarget reports whether e is `<recv>.groups` or `<recv>.groups[k]`.
func rvIsGroupsTarget(e ast.Expr) bool {
	if rvIsGroupsField(e) {
		return true
	}
	ix, ok := e.(*ast.IndexExpr)
	return ok && rvIsGroupsField(ix.X)
}

// rvPackageWriters runs rvGroupWriters over every non-test source file of the
// package.
func rvPackageWriters(t *testing.T) (writers, publishers []string) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) // #nosec G304 -- package source files from a fixed glob
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		w, p := rvGroupWriters(t, string(src))
		writers = append(writers, w...)
		publishers = append(publishers, p...)
		scanned++
	}
	if scanned == 0 {
		t.Fatal("not vacuous check: no non-test package sources found")
	}
	sort.Strings(writers)
	sort.Strings(publishers)
	return writers, publishers
}

// TestReadView_EveryWriterPublishes requires every function that writes the
// group tree to publish the view before it returns.
func TestReadView_EveryWriterPublishes(t *testing.T) {
	writers, publishers := rvPackageWriters(t)
	if len(writers) < 5 {
		t.Fatalf("not vacuous check: expected at least 5 group-tree writers, found %v", writers)
	}
	published := make(map[string]bool, len(publishers))
	for _, p := range publishers {
		published[p] = true
	}
	for _, w := range writers {
		if !published[w] {
			t.Errorf("%s writes the group tree but never calls publishLocked: the policy "+
				"path would keep probing the old view, so a group it just changed would "+
				"silently never match", w)
		}
	}
}

// TestReadView_WriterInventoryIsComplete fails when a NEW group-tree writer
// appears, so whoever adds it has to state that it publishes rather than
// inheriting a pass from the per-writer loop above.
func TestReadView_WriterInventoryIsComplete(t *testing.T) {
	writers, _ := rvPackageWriters(t)
	want := []string{
		"Add", "Delete", "DeleteByID", "Load", "Rename", "ReplaceAll",
		"Update", "UpdateByID", "restoreSnapshot",
	}
	if strings.Join(writers, ",") != strings.Join(want, ",") {
		t.Errorf("group-tree writer inventory = %v, want %v.\n"+
			"A new writer must publish the view (see readView) and be listed here.", writers, want)
	}
}

// TestReadView_WallRejectsThePreFixShape is the CONTROL for the wall above. A
// selector typo, or an rvIsGroupsTarget that matches nothing, would make the
// wall pass forever; this runs the same predicate over the verbatim pre-fix
// bodies and requires the defect to be reported.
func TestReadView_WallRejectsThePreFixShape(t *testing.T) {
	const preFix = `package catgroup

func (s *Store) Update(name string, categories []string) error {
	g, ok := s.groups[key]
	if !ok {
		return nil
	}
	g.Categories = cats
	g.catSet = buildCatSet(cats)
	s.rev.Add(1)
	return nil
}

func (s *Store) Delete(name string) error {
	delete(s.groups, key)
	s.rev.Add(1)
	return nil
}

func (s *Store) ReplaceAll(groups []Group) {
	s.groups = built
	s.order = order
	s.rev.Add(1)
}
`
	writers, publishers := rvGroupWriters(t, preFix)
	if len(publishers) != 0 {
		t.Errorf("control: pre-fix source reported publishers %v, want none", publishers)
	}
	// Update's only write is `g.Categories = cats` on a value READ out of
	// s.groups, which the wall cannot see — that defect is covered
	// behaviourally by TestReadView_PublishedGroupsAreNeverMutatedInPlace.
	if strings.Join(writers, ",") != "Delete,ReplaceAll" {
		t.Errorf("control: pre-fix writers = %v, want [Delete ReplaceAll] — "+
			"the wall cannot see a map assignment or a delete", writers)
	}
}

// ---------------------------------------------------------------------------
// 3. The immutability contract.
// ---------------------------------------------------------------------------

// TestReadView_PublishedGroupsAreNeverMutatedInPlace is the behavioural half
// the AST wall cannot cover: every mutator that changes an EXISTING group must
// install a replacement, so a pointer a reader already holds keeps describing
// the generation it was published in.
//
// Without copy-on-write this is a data race — the reader's `g.catSet` /
// `g.Name` read is unsynchronized against the writer — and the race detector
// only sees it when the two happen to overlap. Asserting the held value is
// UNCHANGED turns it into a deterministic failure.
func TestReadView_PublishedGroupsAreNeverMutatedInPlace(t *testing.T) {
	t.Run("Update", func(t *testing.T) {
		s := New()
		rvSeed(t, s, "Prod", "ai")
		held := s.GetByName("Prod")
		if err := s.Update("Prod", []string{"marketing"}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if !held.catSet["ai"] || held.catSet["marketing"] {
			t.Error("Update edited a published group in place")
		}
	})

	t.Run("UpdateByID", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		held := s.GetByName("Prod")
		if err := s.UpdateByID(id, []string{"marketing"}); err != nil {
			t.Fatalf("UpdateByID: %v", err)
		}
		if !held.catSet["ai"] || held.catSet["marketing"] {
			t.Error("UpdateByID edited a published group in place")
		}
	})

	t.Run("Rename", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		held := s.GetByName("Prod")
		if _, err := s.Rename(id, "Staging"); err != nil {
			t.Fatalf("Rename: %v", err)
		}
		if held.Name != "Prod" {
			t.Errorf("Rename edited a published group in place: held name = %q", held.Name)
		}
	})

	t.Run("RenameCaseOnly", func(t *testing.T) {
		s := New()
		id := rvSeed(t, s, "Prod", "ai")
		held := s.GetByName("Prod")
		if _, err := s.Rename(id, "PROD"); err != nil {
			t.Fatalf("Rename: %v", err)
		}
		if held.Name != "Prod" {
			t.Errorf("case-only Rename edited a published group in place: held name = %q", held.Name)
		}
	})
}

// TestReadView_ReplaceAllDoesNotAliasTheCallerSlice pins the ownership half:
// ReplaceAll used to publish pointers INTO the caller's backing array, so a
// caller that kept and edited its slice — or simply handed the same slice to
// ReplaceAll twice — wrote groups the lock-free matchers were reading.
func TestReadView_ReplaceAllDoesNotAliasTheCallerSlice(t *testing.T) {
	s := New()
	groups := []Group{{ID: "id1", Name: "Prod", Categories: []string{"ai"}}}
	s.ReplaceAll(groups)

	// The caller's element must not have been normalized in place, and editing
	// it afterwards must not reach the store.
	groups[0].Name = "Hijacked"
	groups[0].Categories = []string{"marketing"}
	if matched, resolved := s.MatchesCategoryByID("id1", "ai"); !matched || !resolved {
		t.Errorf("caller-side edit reached the store: matched=%v resolved=%v", matched, resolved)
	}
	if g := s.GetByName("prod"); g == nil || g.Name != "Prod" {
		t.Error("caller-side rename reached the published view")
	}
}

// TestReadView_StructLiteralStoreResolves pins readState's materialisation
// branch: a Store built as a struct literal (the shape this package's whitebox
// tests use) has no published view, and the lock-free readers must still work
// rather than panicking on a nil map or nil pointer.
func TestReadView_StructLiteralStoreResolves(t *testing.T) {
	s := &Store{groups: map[string]*Group{}}
	if g := s.GetByName("anything"); g != nil {
		t.Errorf("GetByName on an empty literal store = %v, want nil", g)
	}
	if _, resolved := s.MatchesCategoryByID("id", "ai"); resolved {
		t.Error("MatchesCategoryByID resolved against an empty literal store")
	}
	if s.MatchesCategory("name", "ai") {
		t.Error("MatchesCategory matched against an empty literal store")
	}
	if rev := s.Revision(); rev != 0 {
		t.Errorf("Revision on a literal store = %d, want 0", rev)
	}
}

// ---------------------------------------------------------------------------
// 4. Differential oracle + concurrency.
// ---------------------------------------------------------------------------

// rvScanByID is the PRE-FIX implementation of MatchesCategoryByID, verbatim:
// RLock plus a linear scan of the authoritative map. It is the oracle the
// indexed view is compared against, so a byID index that is built wrongly (a
// missed group, a wrong key, a stale publication) is a test failure rather
// than a silently different policy verdict.
func rvScanByID(s *Store, id, category string) (matched, resolved bool) {
	if id == "" {
		return false, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.groups {
		if g.ID == id {
			if category == "" {
				return false, true
			}
			return g.catSet[strings.ToLower(category)], true
		}
	}
	return false, false
}

// TestReadView_ByIDDifferentialAgainstTheScan compares the indexed answer with
// the pre-fix scan over a corpus that includes the cases an index gets wrong:
// an empty id, an unknown id, an empty category, mixed case, a group with no
// id at all, and the state after each mutator.
func TestReadView_ByIDDifferentialAgainstTheScan(t *testing.T) {
	s := New()
	s.ReplaceAll([]Group{
		{ID: "id-a", Name: "Alpha", Categories: []string{"ai", "Marketing"}},
		{ID: "id-b", Name: "Beta", Categories: []string{"messaging"}},
		{ID: "", Name: "NoID", Categories: []string{"social"}},
	})

	ids := []string{"", "id-a", "id-b", "id-missing", "ID-A"}
	cats := []string{"", "ai", "AI", "marketing", "messaging", "social", "unknown"}

	check := func(stage string) {
		t.Helper()
		for _, id := range ids {
			for _, cat := range cats {
				gotM, gotR := s.MatchesCategoryByID(id, cat)
				wantM, wantR := rvScanByID(s, id, cat)
				if gotM != wantM || gotR != wantR {
					t.Errorf("%s: MatchesCategoryByID(%q, %q) = (%v, %v), scan oracle = (%v, %v)",
						stage, id, cat, gotM, gotR, wantM, wantR)
				}
			}
		}
	}

	check("after ReplaceAll")
	if err := s.UpdateByID("id-a", []string{"social"}); err != nil {
		t.Fatalf("UpdateByID: %v", err)
	}
	check("after UpdateByID")
	if _, err := s.Rename("id-b", "Beta Renamed"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	check("after Rename")
	if _, err := s.DeleteByID("id-a"); err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}
	check("after DeleteByID")
	if _, err := s.Add("Gamma", []string{"ai"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	check("after Add")
}

// TestReadView_ConcurrentReadersAndMutators is the -race instrument: lock-free
// readers against every writer class at once. It asserts no verdict (the
// interleaving decides it); it exists so the race detector has something to
// observe, and so a reader can never see a torn or nil view.
func TestReadView_ConcurrentReadersAndMutators(t *testing.T) {
	s := New()
	s.ReplaceAll([]Group{{ID: "id1", Name: "Prod", Categories: []string{"ai"}}})

	var wg sync.WaitGroup
	stop := make(chan struct{})

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
				_, _ = s.MatchesCategoryByID("id1", "ai")
				_ = s.MatchesCategory("Prod", "ai")
				_ = s.GetByName("prod")
				_ = s.GetByID("id1")
				_ = s.Revision()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			switch i % 5 {
			case 0:
				_ = s.Update("Prod", []string{"ai", "marketing"})
			case 1:
				_ = s.UpdateByID("id1", []string{"ai"})
			case 2:
				_, _ = s.Rename("id1", "Prod")
			case 3:
				s.ReplaceAll([]Group{{ID: "id1", Name: "Prod", Categories: []string{"ai"}}})
			case 4:
				_, _ = s.Add("Transient", []string{"social"})
				_ = s.Delete("Transient")
			}
		}
		close(stop)
	}()

	wg.Wait()
}
