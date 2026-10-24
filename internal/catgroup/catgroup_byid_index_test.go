package catgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Gates for the byID index (stable ID → current lowercase name key) that makes
// MatchesCategoryByID an O(1) probe instead of a walk of every group, and for
// the catSet probe moving inside the read lock.
//
// MatchesCategoryByID is on the PROXY REQUEST PATH — categoryGroupMatchesHostScratch
// calls it once per category-group access rule per proxied request — so the
// properties under test are a cost bound, an equivalence, and a race. The
// CONTROLS matter as much as the defect gates: the cheapest way to make a
// resolve "flat in group count" is to stop resolving, which would report every
// category-group rule as unresolved and silently fall back to the mutable
// denormalized name (or match nothing at all) — fail-open for a Deny rule.

// linearResolveLegacy is a VERBATIM copy of the pre-index resolve body. It is
// the equivalence oracle AND the before-arm of the cost comparison, kept in
// tree so the comparison stays reproducible rather than living in a commit
// message (the BenchmarkPolicyDecisionLine_Legacy convention).
func linearResolveLegacy(s *Store, id, category string) (matched, resolved bool) {
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

// derivedIndex recomputes byID from groups the way reindexByIDLocked must.
func derivedIndex(s *Store) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.groups))
	for key, g := range s.groups {
		if g.ID == "" {
			continue
		}
		if cur, dup := out[g.ID]; !dup || key < cur {
			out[g.ID] = key
		}
	}
	return out
}

// assertIndexInLockstep fails unless byID is exactly what groups implies.
func assertIndexInLockstep(t *testing.T, s *Store, after string) {
	t.Helper()
	want := derivedIndex(s)
	s.mu.RLock()
	got := make(map[string]string, len(s.byID))
	for k, v := range s.byID {
		got[k] = v
	}
	s.mu.RUnlock()
	if len(got) != len(want) {
		t.Fatalf("after %s: index has %d entries, groups imply %d (%v vs %v)", after, len(got), len(want), got, want)
	}
	for id, key := range want {
		if got[id] != key {
			t.Fatalf("after %s: index[%q] = %q, want %q", after, id, got[id], key)
		}
	}
}

func seedGroups(t *testing.T, n int) (store *Store, ids []string) {
	t.Helper()
	store = New()
	ids = make([]string, 0, n)
	for i := 0; i < n; i++ {
		g, err := store.Add(fmt.Sprintf("group-%d", i), []string{fmt.Sprintf("Category %d", i), "Social Media"})
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		ids = append(ids, g.ID)
	}
	return store, ids
}

// ── Equivalence ──────────────────────────────────────────────────────────────

// The indexed resolve must agree with the linear scan on every shape. A
// divergence here is a category-group rule matching the wrong group's
// categories, i.e. a mis-enforced Allow/Deny.
func TestByIDIndex_AgreesWithLinearScan(t *testing.T) {
	s, ids := seedGroups(t, 8)
	if _, err := s.Add("Mixed Case Group", []string{"News", "AI & ML"}); err != nil {
		t.Fatal(err)
	}
	mixed := s.GetByName("Mixed Case Group")
	if mixed == nil {
		t.Fatal("seed group missing")
	}

	cases := []struct{ id, cat string }{
		{ids[0], "Social Media"},       // hit
		{ids[0], "social media"},       // already-lowercase hit
		{ids[0], "SOCIAL MEDIA"},       // upper hit
		{ids[0], "Category 3"},         // member of a different group
		{ids[0], ""},                   // resolved, no category asked
		{ids[7], "Category 7"},         // last-seeded
		{mixed.ID, "AI & ML"},          // mixed-case category name
		{mixed.ID, "Nonexistent"},      // resolved, miss
		{"", "Social Media"},           // empty id
		{"nosuchid00", "Social Media"}, // unresolved
		{"nosuchid00", ""},             // unresolved, no category
	}
	for _, c := range cases {
		wantM, wantR := linearResolveLegacy(s, c.id, c.cat)
		gotM, gotR := s.MatchesCategoryByID(c.id, c.cat)
		if gotM != wantM || gotR != wantR {
			t.Errorf("MatchesCategoryByID(%q,%q) = (%v,%v), linear scan = (%v,%v)",
				c.id, c.cat, gotM, gotR, wantM, wantR)
		}
	}
}

// CONTROL: the resolve must still RESOLVE and still MATCH. A store that
// reported everything unresolved would pass every cost and flatness gate while
// disabling category-group enforcement.
func TestByIDIndex_ControlResolvesAndMatches(t *testing.T) {
	s, ids := seedGroups(t, 32)
	for i, id := range ids {
		m, resolved := s.MatchesCategoryByID(id, "Social Media")
		if !resolved {
			t.Fatalf("group %d (id %q) did not resolve", i, id)
		}
		if !m {
			t.Fatalf("group %d (id %q) should match its own category", i, id)
		}
	}
	if m, resolved := s.MatchesCategoryByID(ids[0], "Category 9"); !resolved || m {
		t.Fatalf("cross-group category: got (%v,%v), want (false,true)", m, resolved)
	}
}

// ── Lockstep across every mutator ────────────────────────────────────────────

// The index is DERIVED state, so the property that matters is that no mutator
// can leave it disagreeing with groups. Behavioural coverage, driving each
// public mutator in turn, is what catches a writer added later that does not
// route through the chokepoint.
func TestByIDIndex_EveryMutatorKeepsLockstep(t *testing.T) {
	s, ids := seedGroups(t, 5)
	assertIndexInLockstep(t, s, "Add")

	if err := s.Update("group-0", []string{"News"}); err != nil {
		t.Fatal(err)
	}
	assertIndexInLockstep(t, s, "Update")

	if err := s.UpdateByID(ids[1], []string{"News", "Finance"}); err != nil {
		t.Fatal(err)
	}
	assertIndexInLockstep(t, s, "UpdateByID")

	if _, err := s.Rename(ids[2], "group-2-renamed"); err != nil {
		t.Fatal(err)
	}
	assertIndexInLockstep(t, s, "Rename (new key)")
	if m, resolved := s.MatchesCategoryByID(ids[2], "Category 2"); !resolved || !m {
		t.Fatalf("renamed group lost its ID binding: (%v,%v)", m, resolved)
	}

	if _, err := s.Rename(ids[2], "GROUP-2-RENAMED"); err != nil {
		t.Fatal(err)
	}
	assertIndexInLockstep(t, s, "Rename (case-only)")

	if err := s.Delete("group-0"); err != nil {
		t.Fatal(err)
	}
	assertIndexInLockstep(t, s, "Delete")
	if _, resolved := s.MatchesCategoryByID(ids[0], "News"); resolved {
		t.Fatal("deleted group still resolves by ID")
	}

	if _, err := s.DeleteByID(ids[1]); err != nil {
		t.Fatal(err)
	}
	assertIndexInLockstep(t, s, "DeleteByID")
	if _, resolved := s.MatchesCategoryByID(ids[1], "News"); resolved {
		t.Fatal("ID-deleted group still resolves by ID")
	}

	s.ReplaceAll([]Group{
		{ID: "bulkid00001", Name: "Bulk A", Categories: []string{"Social Media"}},
		{Name: "Bulk B", Categories: []string{"News"}}, // no ID: backfilled
	})
	assertIndexInLockstep(t, s, "ReplaceAll")
	if m, resolved := s.MatchesCategoryByID("bulkid00001", "Social Media"); !resolved || !m {
		t.Fatalf("bulk-installed group not resolvable by its ID: (%v,%v)", m, resolved)
	}

	if _, resolved := s.MatchesCategoryByID(ids[3], "Category 3"); resolved {
		t.Fatal("group replaced away still resolves by ID")
	}
}

// A rollback restores contents, so it must restore the index with them.
func TestByIDIndex_LockstepAfterDurableRollback(t *testing.T) {
	dir := t.TempDir()
	s := New()
	if err := s.Load(filepath.Join(dir, "groups.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	g, err := s.Add("keeper", []string{"Social Media"})
	if err != nil {
		t.Fatal(err)
	}
	assertIndexInLockstep(t, s, "Add before rollback")

	// A mutation that applies and then fails forces restoreSnapshot.
	wantErr := fmt.Errorf("induced")
	err = s.MutateDurable(nil, func() error {
		if _, addErr := s.Add("doomed", []string{"News"}); addErr != nil {
			return addErr
		}
		return wantErr
	})
	if err == nil {
		t.Fatal("expected the induced failure to surface")
	}
	assertIndexInLockstep(t, s, "MutateDurable rollback")
	if m, resolved := s.MatchesCategoryByID(g.ID, "Social Media"); !resolved || !m {
		t.Fatalf("surviving group lost its binding after rollback: (%v,%v)", m, resolved)
	}
}

// Load backfills IDs for pre-ID groups, so the index must cover the backfilled
// values and not the empty strings they replaced.
func TestByIDIndex_LockstepAfterLoadWithIDBackfill(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "groups.json")
	if err := os.WriteFile(path, []byte(
		`[{"name":"Legacy A","categories":["Social Media"]},`+
			`{"name":"Legacy B","categories":["News"]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertIndexInLockstep(t, s, "Load with ID backfill")

	for _, name := range []string{"Legacy A", "Legacy B"} {
		g := s.GetByName(name)
		if g == nil || g.ID == "" {
			t.Fatalf("%s: expected a backfilled ID, got %+v", name, g)
		}
		if _, resolved := s.MatchesCategoryByID(g.ID, "Social Media"); !resolved {
			t.Fatalf("%s: backfilled ID %q does not resolve", name, g.ID)
		}
	}
}

// A group persisted with no ID and never backfilled stays name-addressable and
// must not land in the index under the empty key (where it would answer every
// id == "" probe).
func TestByIDIndex_SkipsEmptyIDs(t *testing.T) {
	s := New()
	s.mu.Lock()
	s.groups["no-id"] = &Group{Name: "no-id", Categories: []string{"news"}, catSet: buildCatSet([]string{"news"})}
	s.order = append(s.order, "no-id")
	s.bumpRevLocked()
	s.mu.Unlock()

	s.mu.RLock()
	_, present := s.byID[""]
	s.mu.RUnlock()
	if present {
		t.Fatal("empty ID indexed: an id==\"\" probe could resolve to a real group")
	}
	if _, resolved := s.MatchesCategoryByID("", "news"); resolved {
		t.Fatal("empty id must never resolve")
	}
	if !s.MatchesCategory("no-id", "news") {
		t.Fatal("an ID-less group must stay addressable by name")
	}
}

// ── Race ─────────────────────────────────────────────────────────────────────

// MatchesCategory used to resolve through GetByName (which releases the lock
// before returning the live *Group) and then read g.catSet unlocked, while
// Update reassigns that field under the write lock. The race detector reported
// it; this gate is the wall. Reachable in production as proxy traffic
// evaluating an un-migrated category-group rule concurrent with an admin edit.
//
// Run under -race; it is a no-op otherwise.
func TestByIDIndex_NoRaceBetweenMatchAndMutate(t *testing.T) {
	s, ids := seedGroups(t, 4)

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
					_ = s.MatchesCategory("group-0", "Social Media")
					_, _ = s.MatchesCategoryByID(ids[0], "Social Media")
					_ = s.GetByID(ids[1])
				}
			}
		}()
	}
	for i := 0; i < 500; i++ {
		if err := s.Update("group-0", []string{"Social Media", "News"}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateByID(ids[0], []string{"Social Media", "Finance"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Rename(ids[1], fmt.Sprintf("group-1-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

// ── Structural wall ──────────────────────────────────────────────────────────

// The revision bump and the index rebuild are two derived signals that must
// describe the same store state, so they share ONE chokepoint. A writer that
// spells a bare s.rev.Add(1) advances the revision while leaving the index
// stale — and a stale index degrades to "not resolved", which is invisible to
// every behavioural test that does not happen to drive that writer. Pin it in
// the source instead.
func TestByIDIndex_WallRevisionBumpIsChokepointed(t *testing.T) {
	src, err := os.ReadFile("catgroup.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(src), "\n")

	inChokepoint := false
	bare := 0
	offenders := []string{}
	fnStart := regexp.MustCompile(`^func `)
	for i, ln := range lines {
		if fnStart.MatchString(ln) {
			inChokepoint = strings.Contains(ln, "func (s *Store) bumpRevLocked()")
		}
		code := ln
		if idx := strings.Index(code, "//"); idx >= 0 {
			code = code[:idx] // comments mention the call by name on purpose
		}
		if !strings.Contains(code, "s.rev.Add(1)") {
			continue
		}
		bare++
		if !inChokepoint {
			offenders = append(offenders, fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(ln)))
		}
	}
	if bare == 0 {
		t.Fatal("not-vacuous check: found no s.rev.Add(1) at all — the selector has stopped matching")
	}
	if len(offenders) > 0 {
		t.Fatalf("s.rev.Add(1) outside bumpRevLocked (advances the revision without rebuilding byID):\n%s",
			strings.Join(offenders, "\n"))
	}
}

// No ID-addressed operation may walk the group set. Behavioural coverage cannot
// see a reintroduced scan — it returns the same answer, just slower.
func TestByIDIndex_WallNoLinearIDScanSurvives(t *testing.T) {
	src, err := os.ReadFile("catgroup.go")
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`(?m)^\s*if g\.ID == id \{`).FindAllString(string(src), -1); len(m) > 0 {
		t.Fatalf("found %d linear `if g.ID == id` scan(s); ID addressing goes through groupByIDLocked", len(m))
	}
	if !strings.Contains(string(src), "func (s *Store) groupByIDLocked(") {
		t.Fatal("not-vacuous check: groupByIDLocked is gone, so this wall is guarding nothing")
	}
}

// ── Cost-shape gates ─────────────────────────────────────────────────────────
//
// The WALL-CLOCK ratio gate for the resolve lives in
// catgroup_byid_benchgate_test.go, behind the `benchgate` build tag, because a
// timing comparison is not a property an ordinary, race or determinism run can
// decide: measured under load it failed 2 of 8 runs against an unchanged
// implementation. What stays here is deterministic.

// TestByIDIndex_BulkInstallReindexesOnce guards what the fix COSTS, by counting
// mutations instead of timing them.
//
// Every content mutation rebuilds the index wholesale, so a caller that loops a
// single-group mutator pays O(N^2) to install N groups — the trap recorded
// against IPFilter.Add (closed by AddAll) and RateLimiter.AddExemption (closed
// by AddExemptions), where per-mutation publication turned a legitimate
// enterprise-sized config into a boot or snapshot-apply stall.
//
// Culvert does not reach it today: the only Add caller creates ONE group per
// admin HTTP request (ui_policy.go), and every bulk path — config import in
// both modes, config-version rollback, and the CP→DP snapshot apply — goes
// through ReplaceAll, which reindexes exactly once.
//
// THE REVISION COUNTER IS THE EXACT INVARIANT, not a proxy for it. reindexing
// happens only in bumpRevLocked, which also advances rev, so "ReplaceAll
// reindexed once" and "ReplaceAll advanced rev by one" are the same statement —
// and it holds for ANY group count, on any hardware, under any load. This
// replaced a wall-clock ratio (ReplaceAll at 250 vs 1000 groups, bound 8x) that
// was measuring the same property through a noisy instrument: it read 3.5x–4.0x
// idle but 11.22x and 15.75x under CPU contention, i.e. it failed a correct
// tree a quarter of the time.
func TestByIDIndex_BulkInstallReindexesOnce(t *testing.T) {
	for _, n := range []int{0, 1, 250, 1000} {
		s := New()
		groups := make([]Group, 0, n)
		for i := 0; i < n; i++ {
			groups = append(groups, Group{
				ID:         fmt.Sprintf("bulk%08d", i),
				Name:       fmt.Sprintf("group-%d", i),
				Categories: []string{fmt.Sprintf("Category %d", i), "Social Media"},
			})
		}
		before := s.Revision()
		s.ReplaceAll(groups)
		if got := s.Revision() - before; got != 1 {
			t.Errorf("ReplaceAll(%d groups) advanced rev by %d, want exactly 1: the bulk "+
				"path is reindexing per group instead of once (O(N^2) install)", n, got)
		}
		assertIndexInLockstep(t, s, fmt.Sprintf("ReplaceAll(%d)", n))
	}
}

// TestByIDIndex_LoopedAddIsTheShapeTheBulkGateRejects is the NEGATIVE half of
// the gate above: it pins that per-call mutators really do reindex per call, so
// "ReplaceAll advances rev once" is a meaningful distinction rather than a
// statement that would hold however the store were written.
//
// This is not a defect — Add is correctly per-request — it is the measurement
// that gives the bulk assertion its teeth.
func TestByIDIndex_LoopedAddIsTheShapeTheBulkGateRejects(t *testing.T) {
	s := New()
	const n = 25
	before := s.Revision()
	for i := 0; i < n; i++ {
		if _, err := s.Add(fmt.Sprintf("looped-%d", i), []string{"Social Media"}); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	if got := s.Revision() - before; got != n {
		t.Fatalf("looped Add advanced rev by %d, want %d — the bulk gate's contrast is "+
			"vacuous if a per-call mutator does not reindex per call", got, n)
	}
}

// CONTROL for the bulk-install gates above: the cheapest way to make a bulk
// install cheap is to stop doing the work. A store installed in bulk must still
// resolve every ID it was handed and still answer membership correctly — a
// silently unresolved rule falls back to the mutable denormalized name, or
// matches nothing, which is fail-open for a Deny rule.
//
// Deliberately NOT named TestBenchGate_*: it carries no timing and belongs in
// the ordinary suite. Claiming the benchgate prefix without the build tag is
// the exact mislabeling that let the wall-clock gates run in every race and
// determinism suite (see catgroup_byid_benchgate_test.go).
func TestByIDIndex_ControlBulkInstalledGroupsStillResolve(t *testing.T) {
	s := New()
	const n = 250
	groups := make([]Group, 0, n)
	for i := 0; i < n; i++ {
		groups = append(groups, Group{
			ID:         fmt.Sprintf("bulk%08d", i),
			Name:       fmt.Sprintf("group-%d", i),
			Categories: []string{fmt.Sprintf("Category %d", i), "Social Media"},
		})
	}
	s.ReplaceAll(groups)
	assertIndexInLockstep(t, s, "ReplaceAll (control)")

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("bulk%08d", i)
		m, resolved := s.MatchesCategoryByID(id, fmt.Sprintf("Category %d", i))
		if !resolved {
			t.Fatalf("bulk group %d (%q) did not resolve", i, id)
		}
		if !m {
			t.Fatalf("bulk group %d (%q) should match its own category", i, id)
		}
		if m, _ := s.MatchesCategoryByID(id, "Nonexistent Category"); m {
			t.Fatalf("bulk group %d matched a category it does not hold", i)
		}
	}
}

// A DERIVED index that disagreed with groups must degrade to "not resolved" —
// the fail-closed answer categoryGroupMatchesHostScratch already handles by
// falling back to the name — and never to a confident WRONG group, which would
// match another group's categories and mis-enforce the rule.
//
// No supported path produces a stale index (bumpRevLocked rebuilds it inside
// the same critical section that publishes the contents, and the wall above
// pins that), so this corrupts it directly. It is what makes the g.ID != id
// recheck in groupByIDLocked non-vacuous: with a correct index that branch is
// unreachable, so nothing else can observe its removal.
func TestByIDIndex_StaleIndexFailsClosedNotWrongGroup(t *testing.T) {
	s, ids := seedGroups(t, 3)

	// Point group 0's ID at group 1's name key.
	s.mu.Lock()
	s.byID[ids[0]] = "group-1"
	s.mu.Unlock()

	m, resolved := s.MatchesCategoryByID(ids[0], "Category 1")
	if resolved {
		t.Fatalf("a stale index resolved to the wrong group (matched=%v): the resolve must "+
			"report not-resolved so the caller falls back to the name", m)
	}
	if m {
		t.Fatal("a stale index must never report a match")
	}

	// An ID pointing at a key that no longer exists is the same verdict.
	s.mu.Lock()
	s.byID[ids[1]] = "vanished"
	s.mu.Unlock()
	if _, resolved := s.MatchesCategoryByID(ids[1], "Category 1"); resolved {
		t.Fatal("an index entry pointing at a missing key must not resolve")
	}

	// And the untouched entry still works, so the gate is not just asserting
	// that everything fails.
	if m, resolved := s.MatchesCategoryByID(ids[2], "Category 2"); !resolved || !m {
		t.Fatalf("intact entry stopped resolving: (%v,%v)", m, resolved)
	}
}

// buildCatSet must refuse an empty category name.
//
// That property is what makes categoryGroupMatchesHostScratch's uncategorized
// short-circuit equivalent: the guard answers false without resolving the
// group, which is only correct if no group can hold "" as a member.
//
// It is pinned HERE, against buildCatSet directly, because it is NOT reachable
// from outside the package: normCats drops empties on every caller's path, so
// an end-to-end test through Add/ReplaceAll passes whether buildCatSet filters
// or not (measured — that test was vacuous and this one replaced it). The
// uncovered path is restoreSnapshot, which rebuilds from a List() value copy
// without re-normalizing; no supported input reaches it with an empty
// category, so this is the layer that holds the invariant up rather than
// inheriting it from a caller.
func TestBuildCatSet_RefusesEmptyCategory(t *testing.T) {
	set := buildCatSet([]string{"", "Social Media", "   ", "NEWS", ""})

	if set[""] {
		t.Error(`buildCatSet admitted "": a group would report the uncategorized ` +
			`host as a member, and categoryGroupMatchesHostScratch's short-circuit ` +
			`would stop being equivalent`)
	}
	// Whitespace-only names are NOT trimmed here — normCats owns trimming, and
	// reproducing it would change which names are members. Pinned so the
	// division of labour is explicit rather than assumed.
	if !set["   "] {
		t.Error("buildCatSet dropped a whitespace-only name: trimming belongs to normCats")
	}
	if !set["social media"] || !set["news"] {
		t.Error("buildCatSet lost a real category or stopped lowercasing")
	}
	if len(set) != 3 {
		t.Errorf("buildCatSet produced %d members, want 3 (two real + one whitespace): %v", len(set), set)
	}
}
