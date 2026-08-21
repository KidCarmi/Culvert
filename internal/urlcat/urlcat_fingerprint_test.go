package urlcat

import (
	"path/filepath"
	"sync"
	"testing"
)

// QB-2 corrective slice: ContentFingerprint is the restart-stable SEMANTIC
// identity of the taxonomy consumed by the policy-learning category epoch
// (scheme v2). Contract under test: same effective admin taxonomy ⇒ same
// identity across restart/reload; different effective taxonomy ⇒ different
// identity; insertion/map order, no-op mutations, and display-only state
// never change it.

func fpStore(t *testing.T) *Store {
	t.Helper()
	s := New([]*Entry{})
	s.SetPathForTest(filepath.Join(t.TempDir(), "categories.json"))
	return s
}

// (1) A fresh store and a reload of identical persisted taxonomy yield the
// identical fingerprint; (7) the save/load roundtrip preserves identity.
func TestFingerprint_ReloadIdenticalTaxonomyIsIdentical(t *testing.T) {
	s := fpStore(t)
	if err := s.Set("Dev Tools", []string{"gitlab.lab", "ci.lab"}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("Finance", []string{"bank.lab"}, false); err != nil {
		t.Fatal(err)
	}
	want := s.ContentFingerprint()
	if want == "" {
		t.Fatal("empty fingerprint")
	}
	// "Restart": a brand-new Store loading the same persisted file.
	s2 := &Store{}
	if err := s2.Load(s.Path()); err != nil {
		t.Fatal(err)
	}
	if got := s2.ContentFingerprint(); got != want {
		t.Fatalf("reload changed identity: %q -> %q", want, got)
	}
}

// (3) Insertion order cannot affect the fingerprint.
func TestFingerprint_InsertionOrderIrrelevant(t *testing.T) {
	a := fpStore(t)
	for _, c := range [][2]string{{"Alpha", "a.lab"}, {"Beta", "b.lab"}, {"Gamma", "c.lab"}} {
		if err := a.Set(c[0], []string{c[1]}, false); err != nil {
			t.Fatal(err)
		}
	}
	b := fpStore(t)
	for _, c := range [][2]string{{"Gamma", "c.lab"}, {"Alpha", "a.lab"}, {"Beta", "b.lab"}} {
		if err := b.Set(c[0], []string{c[1]}, false); err != nil {
			t.Fatal(err)
		}
	}
	if a.ContentFingerprint() != b.ContentFingerprint() {
		t.Fatal("insertion order changed the fingerprint")
	}
	// Host-list order within an entry is equally irrelevant.
	c1, c2 := fpStore(t), fpStore(t)
	if err := c1.Set("X", []string{"one.lab", "two.lab"}, false); err != nil {
		t.Fatal(err)
	}
	if err := c2.Set("X", []string{"two.lab", "one.lab"}, false); err != nil {
		t.Fatal(err)
	}
	if c1.ContentFingerprint() != c2.ContentFingerprint() {
		t.Fatal("host order changed the fingerprint")
	}
}

// (4) Every effective admin taxonomy mutation used by the resolver changes
// the fingerprint.
func TestFingerprint_EverySemanticMutationChangesIt(t *testing.T) {
	s := fpStore(t)
	if err := s.Set("Dev Tools", []string{"gitlab.lab"}, false); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{"init": s.ContentFingerprint()}
	step := func(name string, mutate func() error) {
		t.Helper()
		if err := mutate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fp := s.ContentFingerprint()
		for prev, v := range seen {
			if v == fp {
				t.Fatalf("%s did not change the fingerprint (equal to %s)", name, prev)
			}
		}
		seen[name] = fp
	}
	step("add-category", func() error { return s.Set("Finance", []string{"bank.lab"}, false) })
	step("add-host", func() error { return s.AddHost("Dev Tools", "ci.lab") })
	step("remove-host", func() error { return s.RemoveHost("Dev Tools", "gitlab.lab") })
	step("replace-hosts", func() error { return s.Set("Finance", []string{"payroll.lab"}, false) })
	step("delete-category", func() error { return s.Delete("Finance") })
	// BuiltIn flag flips admin-tier membership — resolution-relevant.
	step("builtin-flag", func() error {
		s.ReplaceAll([]Entry{{Name: "Dev Tools", Hosts: []string{"ci.lab"}, BuiltIn: true}})
		return nil
	})
	// Name case is returned verbatim by the resolvers — resolution-relevant.
	step("name-case", func() error {
		s.ReplaceAll([]Entry{{Name: "DEV TOOLS", Hosts: []string{"ci.lab"}, BuiltIn: true}})
		return nil
	})
}

// (5) A semantic no-op does not change the fingerprint.
func TestFingerprint_SemanticNoOpsDoNotChangeIt(t *testing.T) {
	s := fpStore(t)
	if err := s.Set("Dev Tools", []string{"gitlab.lab", "ci.lab"}, false); err != nil {
		t.Fatal(err)
	}
	want := s.ContentFingerprint()
	if err := s.AddHost("Dev Tools", "gitlab.lab"); err != nil { // already present
		t.Fatal(err)
	}
	if err := s.AddHost("Dev Tools", "GitLab.LAB"); err != nil { // case-only duplicate
		t.Fatal(err)
	}
	if err := s.Set("Dev Tools", []string{"gitlab.lab", "ci.lab"}, false); err != nil { // identical content
		t.Fatal(err)
	}
	if err := s.Set("Dev Tools", []string{"ci.lab", "gitlab.lab"}, false); err != nil { // reordered content
		t.Fatal(err)
	}
	if got := s.ContentFingerprint(); got != want {
		t.Fatalf("semantic no-op changed identity: %q -> %q", want, got)
	}
}

// (6) Add then remove restoring the original taxonomy restores the original
// fingerprint.
func TestFingerprint_AddRemoveRestoresIdentity(t *testing.T) {
	s := fpStore(t)
	if err := s.Set("Dev Tools", []string{"gitlab.lab"}, false); err != nil {
		t.Fatal(err)
	}
	want := s.ContentFingerprint()
	if err := s.AddHost("Dev Tools", "wiki.lab"); err != nil {
		t.Fatal(err)
	}
	if s.ContentFingerprint() == want {
		t.Fatal("add-host did not change identity")
	}
	if err := s.RemoveHost("Dev Tools", "wiki.lab"); err != nil {
		t.Fatal(err)
	}
	if got := s.ContentFingerprint(); got != want {
		t.Fatalf("restored taxonomy did not restore identity: %q -> %q", want, got)
	}
	// Same for a whole category.
	if err := s.Set("Temp", []string{"t.lab"}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("Temp"); err != nil {
		t.Fatal(err)
	}
	if got := s.ContentFingerprint(); got != want {
		t.Fatalf("category add+delete did not restore identity: %q -> %q", want, got)
	}
}

// (11) Concurrent reads and mutations are race-clean (run under -race).
func TestFingerprint_ConcurrentReadsAndMutations(t *testing.T) {
	s := fpStore(t)
	if err := s.Set("Dev Tools", []string{"gitlab.lab"}, false); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if s.ContentFingerprint() == "" {
					t.Error("empty fingerprint")
					return
				}
			}
		}()
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.AddHost("Dev Tools", "x.lab")
				_ = s.RemoveHost("Dev Tools", "x.lab")
			}
		}(i)
	}
	wg.Wait()
}

// The zero-value store (pre-Load window) answers deterministically too.
func TestFingerprint_ZeroValueStoreIsStable(t *testing.T) {
	var a, b Store
	if a.ContentFingerprint() != b.ContentFingerprint() || a.ContentFingerprint() == "" {
		t.Fatal("zero-value fingerprint not stable")
	}
}
