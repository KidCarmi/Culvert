package pac

import (
	"errors"
	"path/filepath"
	"testing"
)

// The store generation and the compare-and-swap commit (2F-E correction
// round 4): a candidate built at generation g commits only while the store is
// still at g; an intervening Set is detected atomically and nothing is
// written.
func TestProfileStore_SetIfGeneration(t *testing.T) {
	s := &ProfileStore{}
	if err := s.Load(filepath.Join(t.TempDir(), "pac_profiles.json")); err != nil {
		t.Fatal(err)
	}
	cfg, g := s.GetWithGeneration()
	cfg.Pools = append(cfg.Pools, Pool{ID: "a", Name: "A", Endpoints: []PoolEndpoint{{Host: "a.example", Port: 8080}}})
	if err := s.SetIfGeneration(cfg, g); err != nil {
		t.Fatalf("commit at the same generation: %v", err)
	}
	if s.Generation() != g+1 {
		t.Fatalf("generation must advance on commit: %d → %d", g, s.Generation())
	}
	stale, g2 := s.GetWithGeneration()
	// another writer lands
	other := s.Get()
	other.Pools = append(other.Pools, Pool{ID: "b", Name: "B", Endpoints: []PoolEndpoint{{Host: "b.example", Port: 8080}}})
	if err := s.Set(other); err != nil {
		t.Fatal(err)
	}
	stale.Pools = append(stale.Pools, Pool{ID: "c", Name: "C", Endpoints: []PoolEndpoint{{Host: "c.example", Port: 8080}}})
	err := s.SetIfGeneration(stale, g2)
	if !errors.Is(err, ErrProfilesChanged) {
		t.Fatalf("a candidate built on a superseded generation must be refused, got %v", err)
	}
	if _, ok := s.PoolMap()["c"]; ok {
		t.Fatal("a refused commit must write nothing")
	}
	if _, ok := s.PoolMap()["b"]; !ok {
		t.Fatal("the intervening write must survive")
	}
	if s.Generation() != g2+1 {
		t.Fatalf("a refused commit must not advance the generation: %d", s.Generation())
	}
}
