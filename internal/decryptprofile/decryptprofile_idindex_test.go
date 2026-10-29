package decryptprofile

// decryptprofile_idindex_test.go — the stable-ID index (reindexLocked) that
// turns GetByID / FailOpenScopeByID from an O(profiles) walk over the
// name-keyed map into an O(1) lookup.
//
// The deterministic half of the gate lives here. The WALL-CLOCK ratio gate is
// in decryptprofile_idindex_benchgate_test.go, behind the `benchgate` tag, for
// the reason catgroup recorded when its own byID ratio gate failed 2 of 8 runs
// against an unchanged tree under load: a timing comparison is not a property
// an ordinary, race or determinism run can decide.

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// assertIndexInLockstep rebuilds the ID index from s.profiles the way
// reindexLocked does and asserts the live index agrees with it, entry for
// entry AND pointer for pointer.
//
// The pointer identity is the part that matters: Update and UpdateByID install
// a NEW *Profile at the same name key with the same ID, so an index that was
// merely "present and the right size" would keep serving the pre-edit content
// forever. Comparing len() or IDs alone would pass on exactly that bug.
func assertIndexInLockstep(t *testing.T, s *Store, after string) {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()

	want := make(map[string]*Profile, len(s.profiles))
	add := func(p *Profile) {
		if p.ID == "" {
			return
		}
		if _, dup := want[p.ID]; dup {
			return
		}
		want[p.ID] = p
	}
	for _, key := range s.order { // insertion order decides duplicate IDs
		if p, ok := s.profiles[key]; ok {
			add(p)
		}
	}
	for _, p := range s.profiles { // completeness sweep: see reindexLocked
		add(p)
	}
	if len(s.byID) != len(want) {
		t.Fatalf("after %s: index holds %d ids, derived %d — the index is stale",
			after, len(s.byID), len(want))
	}
	for id, wp := range want {
		gp, ok := s.byID[id]
		if !ok {
			t.Fatalf("after %s: id %q missing from the index", after, id)
		}
		if gp != wp {
			t.Fatalf("after %s: id %q indexes a DIFFERENT *Profile than the name map holds "+
				"(indexed name=%q, stored name=%q): a mutation replaced the stored pointer "+
				"without reindexing, so reads serve pre-edit content", after, id, gp.Name, wp.Name)
		}
	}
}

// TestIDIndex_ConsistentAfterEveryMutation walks EVERY public mutator and
// asserts the index is still derivable from s.profiles afterwards.
//
// This is the test that makes the whole-rebuild design safe to rely on. The
// index is a second structure over the same content, so the standing failure
// mode is a writer that changes s.profiles and forgets reindexLocked —
// s.order already carries a scar from precisely that bug class (Rename's
// re-key, which silently dropped a renamed profile from the list, the file and
// the CP→DP snapshot). A new mutator added without a reindex fails here as
// soon as it is given a case below; the case is the part a future author must
// remember, which is why the list is exhaustive and named per mutator.
func TestIDIndex_ConsistentAfterEveryMutation(t *testing.T) {
	seed := func(t *testing.T) *Store {
		t.Helper()
		s := New()
		s.ReplaceAll([]Profile{
			{ID: "aaaaaaaaaaaa", Name: "alpha", OnInspectError: "fail-open", StallTimeoutSecs: 30},
			{ID: "bbbbbbbbbbbb", Name: "bravo", CertVerification: "strict"},
			{ID: "cccccccccccc", Name: "charlie", MinTLSVersion: "1.3"},
		})
		return s
	}

	cases := []struct {
		name string
		run  func(t *testing.T, s *Store)
	}{
		{"ReplaceAll", func(t *testing.T, s *Store) {
			s.ReplaceAll([]Profile{{ID: "dddddddddddd", Name: "delta"}})
		}},
		{"ReplaceAll-empty", func(t *testing.T, s *Store) { s.ReplaceAll(nil) }},
		{"Add", func(t *testing.T, s *Store) {
			if _, err := s.Add(Profile{ID: "eeeeeeeeeeee", Name: "echo"}); err != nil {
				t.Fatalf("add: %v", err)
			}
		}},
		{"Add-backfilled-id", func(t *testing.T, s *Store) {
			if _, err := s.Add(Profile{Name: "foxtrot"}); err != nil {
				t.Fatalf("add: %v", err)
			}
		}},
		{"Update", func(t *testing.T, s *Store) {
			if err := s.Update(Profile{Name: "alpha", MinTLSVersion: "1.3"}); err != nil {
				t.Fatalf("update: %v", err)
			}
		}},
		{"UpdateByID", func(t *testing.T, s *Store) {
			if err := s.UpdateByID("bbbbbbbbbbbb", Profile{Name: "bravo", MaxTLSVersion: "1.3"}); err != nil {
				t.Fatalf("updateByID: %v", err)
			}
		}},
		{"Delete", func(t *testing.T, s *Store) {
			if err := s.Delete("bravo"); err != nil {
				t.Fatalf("delete: %v", err)
			}
		}},
		{"DeleteByID", func(t *testing.T, s *Store) {
			if _, err := s.DeleteByID("cccccccccccc"); err != nil {
				t.Fatalf("deleteByID: %v", err)
			}
		}},
		{"Rename-rekey", func(t *testing.T, s *Store) {
			if _, err := s.Rename("aaaaaaaaaaaa", "alpha-renamed"); err != nil {
				t.Fatalf("rename: %v", err)
			}
		}},
		{"Rename-case-only", func(t *testing.T, s *Store) {
			// Mutates the stored *Profile IN PLACE (same pointer, same key, same
			// ID), which is why this branch deliberately does NOT reindex. The
			// assertion below is what makes that reasoning checkable rather than
			// a comment.
			if _, err := s.Rename("aaaaaaaaaaaa", "ALPHA"); err != nil {
				t.Fatalf("rename: %v", err)
			}
		}},
		{"Load", func(t *testing.T, s *Store) {
			path := t.TempDir() + "/profiles.json"
			if err := os.WriteFile(path, []byte(`[{"id":"999999999999","name":"golf"}]`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := s.Load(path); err != nil {
				t.Fatalf("load: %v", err)
			}
		}},
		{"MutateDurable-rollback", func(t *testing.T, s *Store) {
			// The restoreSnapshot path: fn fails, the pre-mutation content is
			// reinstalled, and the index must follow it back.
			err := s.MutateDurable(nil, func() error {
				if _, aerr := s.Add(Profile{ID: "hhhhhhhhhhhh", Name: "hotel"}); aerr != nil {
					return aerr
				}
				return fmt.Errorf("forced rollback")
			})
			if err == nil {
				t.Fatal("expected the forced rollback error")
			}
			if s.GetByID("hhhhhhhhhhhh") != nil {
				t.Fatal("rolled-back profile is still resolvable by id")
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := seed(t)
			assertIndexInLockstep(t, s, "seed")
			tc.run(t, s)
			assertIndexInLockstep(t, s, tc.name)
		})
	}
}

// TestIDIndex_ResolvesSameProfileAsTheWalk is the differential oracle: for
// every id in a store built the way a real config install builds one, the
// index must answer exactly what the replaced linear walk answered.
func TestIDIndex_ResolvesSameProfileAsTheWalk(t *testing.T) {
	s := New()
	profiles := make([]Profile, 0, 64)
	for i := 0; i < 64; i++ {
		profiles = append(profiles, Profile{
			ID:               fmt.Sprintf("id-%09d", i),
			Name:             fmt.Sprintf("profile-%04d", i),
			OnInspectError:   map[bool]string{true: "fail-open", false: "fail-close"}[i%3 == 0],
			StallTimeoutSecs: 10 + i,
		})
	}
	s.ReplaceAll(profiles)

	walk := func(id string) *Profile { // verbatim shape of the replaced scan
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, p := range s.profiles {
			if p.ID == id {
				return p
			}
		}
		return nil
	}

	for i := range profiles {
		id := profiles[i].ID
		want := walk(id)
		got := s.GetByID(id)
		if want == nil || got == nil {
			t.Fatalf("id %q: walk=%v index=%v", id, want, got)
		}
		if got.Name != want.Name || got.StallTimeoutSecs != want.StallTimeoutSecs {
			t.Errorf("id %q: index resolved %+v, walk resolved %+v", id, got, want)
		}
		// FailOpenScopeByID's resolved/scope contract must be unchanged too.
		scope, gen, resolved := s.FailOpenScopeByID(id)
		if !resolved {
			t.Errorf("id %q: FailOpenScopeByID reports unresolved", id)
		}
		if want.OnInspectError == "fail-open" {
			if scope != id || gen == "" {
				t.Errorf("id %q: fail-open profile gave scope=%q gen=%q", id, scope, gen)
			}
		} else if scope != "" {
			t.Errorf("id %q: fail-close profile leaked scope %q", id, scope)
		}
	}
	// Misses stay misses — the index must not invent a resolution.
	if p := s.GetByID("nope"); p != nil {
		t.Errorf("unknown id resolved to %+v", p)
	}
	if _, _, resolved := s.FailOpenScopeByID("nope"); resolved {
		t.Error("unknown id reported resolved: the name fallback would be skipped")
	}
	if p := s.GetByID(""); p != nil {
		t.Errorf("empty id resolved to %+v", p)
	}
}

// TestIDIndex_DuplicateIDResolvesDeterministically pins the one behavior this
// change deliberately alters.
//
// replaceContents de-duplicates by NAME, not by ID, so a config import or a
// CP→DP snapshot can install two differently-named profiles carrying the same
// ID. The replaced walk ranged a Go map, so it returned whichever of them the
// randomized iteration order reached first — a different answer on different
// calls within one process. The index resolves to the FIRST in insertion
// order, which is the tie-break replaceContents already applies to duplicate
// names. Nondeterministic → deterministic is the intent; WHICH of the two wins
// is not a contract either form could offer.
func TestIDIndex_DuplicateIDResolvesDeterministically(t *testing.T) {
	s := New()
	s.ReplaceAll([]Profile{
		{ID: "shared-id-00", Name: "first", StallTimeoutSecs: 11},
		{ID: "shared-id-00", Name: "second", StallTimeoutSecs: 22},
	})
	first := s.GetByID("shared-id-00")
	if first == nil {
		t.Fatal("duplicate id resolved to nothing; both profiles were installed")
	}
	if first.Name != "first" {
		t.Errorf("duplicate id resolved to %q, want the first in insertion order (%q)",
			first.Name, "first")
	}
	for i := 0; i < 200; i++ { // map-order randomness would surface well inside this
		if got := s.GetByID("shared-id-00"); got == nil || got.Name != first.Name {
			t.Fatalf("iteration %d resolved %v, want a stable %q", i, got, first.Name)
		}
	}
	// Both profiles remain addressable by their own names — the index decides
	// only the ID question.
	if s.GetByName("second") == nil {
		t.Error("the second profile fell out of the name map")
	}
}

// TestIDIndex_SweepCoversAnEntryMissingFromOrder pins the second half of
// reindexLocked.
//
// The index could have been derived from s.order alone — that is where the
// deterministic duplicate-ID tie-break comes from. It is not, because the
// replaced walk ranged s.profiles: a profile present in the name map but
// absent from s.order was findable by the walk, and an order-only index would
// newly hide it from GetByID. That divergence is not hypothetical in kind —
// Rename's re-key once left s.order stale and silently dropped a renamed
// profile from List, Save and the CP→DP snapshot.
//
// The state is reached directly rather than through a public mutator, because
// no mutator produces it today. That is the point: the sweep is insurance
// against a future one, so the test has to construct the hazard itself.
func TestIDIndex_SweepCoversAnEntryMissingFromOrder(t *testing.T) {
	s := New()
	s.ReplaceAll([]Profile{{ID: "aaaaaaaaaaaa", Name: "alpha"}})

	s.mu.Lock()
	orphan := &Profile{ID: "orphan000000", Name: "orphan"}
	s.profiles["orphan"] = orphan // deliberately NOT appended to s.order
	s.reindexLocked()
	s.mu.Unlock()

	got := s.GetByID("orphan000000")
	if got == nil {
		t.Fatal("a profile in the name map but missing from s.order fell out of the ID " +
			"index; the replaced walk would still have found it")
	}
	if got.Name != "orphan" {
		t.Errorf("resolved %q, want %q", got.Name, "orphan")
	}
	if s.GetByID("aaaaaaaaaaaa") == nil {
		t.Error("the ordered entry was lost while indexing the orphan")
	}
}

// TestIDIndex_BulkInstallReindexesOnce guards what the fix COSTS.
//
// Every mutation rebuilds the index wholesale, so a caller that loops a
// single-profile mutator pays O(N^2) to install N profiles — the trap recorded
// against IPFilter.Add (closed by AddAll) and RateLimiter.AddExemption (closed
// by AddExemptions). Culvert does not reach it: the only Add callers create
// ONE profile per admin HTTP request (ui_policy.go) or seed one preset at
// startup (decryptprofile_vars.go), and every bulk path — disk Load, config
// import, config-version rollback and the CP→DP snapshot apply — goes through
// replaceContents, which reindexes exactly once.
//
// The version counter is the exact invariant rather than a proxy: ReplaceAll
// bumps it once per install, so "ReplaceAll reindexed once" and "ReplaceAll
// advanced version by one" are the same statement — true for ANY profile
// count, on any hardware, under any load.
func TestIDIndex_BulkInstallReindexesOnce(t *testing.T) {
	for _, n := range []int{0, 1, 250, 1000} {
		s := New()
		profiles := make([]Profile, 0, n)
		for i := 0; i < n; i++ {
			profiles = append(profiles, Profile{
				ID:   fmt.Sprintf("bulk%08d", i),
				Name: fmt.Sprintf("profile-%d", i),
			})
		}
		before := s.Version()
		s.ReplaceAll(profiles)
		if got := s.Version() - before; got != 1 {
			t.Errorf("ReplaceAll(%d profiles) advanced version by %d, want exactly 1: the "+
				"bulk path is reindexing per profile instead of once (O(N^2) install)", n, got)
		}
		assertIndexInLockstep(t, s, fmt.Sprintf("ReplaceAll(%d)", n))
	}
}

// TestIDIndex_WallNoLinearIDScanSurvives fails the build if an ID-keyed READ
// goes back to ranging the name map. It is the deterministic stand-in for the
// wall-clock ratio gate, which can only run under the `benchgate` tag.
//
// The WRITE paths (UpdateByID, Rename, DeleteByID) still walk deliberately:
// they need the name KEY as well as the profile, they run under the write lock
// on admin mutations that are rare and already O(profiles) for the persist
// that follows, and converting them would buy nothing measurable while
// coupling the key to strings.ToLower(p.Name). So the wall counts the walks
// rather than banning them, and the count is the three writers.
func TestIDIndex_WallNoLinearIDScanSurvives(t *testing.T) {
	src, err := os.ReadFile("decryptprofile.go")
	if err != nil {
		t.Fatal(err)
	}
	// Match a `range s.profiles` whose very next line compares an ID — the
	// scan shape itself, not every iteration over the map (reindexLocked
	// ranges it too, and must not be counted).
	const wantWalks = 3 // UpdateByID, Rename, DeleteByID
	walks := regexp.MustCompile(`(?m)^\s*for .* := range s\.profiles \{\n\s*if \w+\.ID [!=]= id \{`).
		FindAllString(string(src), -1)
	if len(walks) != wantWalks {
		t.Errorf("found %d linear ID scan(s) over s.profiles, want exactly %d (the write "+
			"paths UpdateByID/Rename/DeleteByID): an ID-keyed READ has gone back to the "+
			"linear scan, or a write path was converted without updating this wall",
			len(walks), wantWalks)
	}
	if !strings.Contains(string(src), "func (s *Store) reindexLocked()") {
		t.Fatal("not-vacuous check: reindexLocked is gone, so this wall is guarding nothing")
	}
	if !strings.Contains(string(src), "p := s.byID[id]") {
		t.Fatal("not-vacuous check: no read path looks up s.byID, so the index is unused")
	}
}
