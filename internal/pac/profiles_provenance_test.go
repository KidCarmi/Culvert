package pac

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Per-profile writer provenance (2F-E correction round 6): the rule the
// reconciler depends on, pinned at the store.
func TestProfileStore_ProvenanceIsPerProfileAndPreservedAcrossUnrelatedWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pac_profiles.json")
	var s ProfileStore
	s.Restore(ProfileState{Path: path})
	seed := ProfilesConfig{
		Profiles: []Profile{
			{ID: "a", Name: "A", Enabled: true, PoolID: "p", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeSecure, Revision: 1},
			{ID: "b", Name: "B", Enabled: true, PoolID: "p", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeSecure, Revision: 1},
		},
		Pools: []Pool{{ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "x.example", Port: 8080}}}},
	}
	if err := s.Set(seed); err != nil {
		t.Fatal(err)
	}
	a0, b0 := s.ProfileWriteID("a"), s.ProfileWriteID("b")
	if a0 == "" || b0 == "" || a0 == b0 {
		t.Fatalf("every changed profile gets its own fresh identity: a=%q b=%q", a0, b0)
	}
	// A lifecycle commit of "a" stamps its operationId on "a" only.
	cfg, gen := s.GetWithGeneration()
	cfg.Profiles[0].Name, cfg.Profiles[0].Revision = "A committed", 2
	if err := s.CommitIfGeneration(cfg, gen, "a", "op-x"); err != nil {
		t.Fatal(err)
	}
	if s.ProfileWriteID("a") != "op-x" || s.ProfileWriteID("b") != b0 {
		t.Fatalf("commit provenance: a=%q (want op-x) b=%q (want %q)", s.ProfileWriteID("a"), s.ProfileWriteID("b"), b0)
	}
	// A pool-only write preserves every profile's provenance.
	cfg = s.Get()
	cfg.Pools[0].Name = "P renamed"
	if err := s.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if s.ProfileWriteID("a") != "op-x" || s.ProfileWriteID("b") != b0 {
		t.Fatalf("a pool-only write must not erase profile provenance: a=%q b=%q", s.ProfileWriteID("a"), s.ProfileWriteID("b"))
	}
	// A write that changes only "b" (nil vs empty rules on "a" is not a
	// change) re-stamps "b" and preserves "a".
	cfg = s.Get()
	cfg.Profiles[0].Rules = []Rule{}
	cfg.Profiles[1].Name, cfg.Profiles[1].Revision = "B changed", 2
	if err := s.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if s.ProfileWriteID("a") != "op-x" || s.ProfileWriteID("b") == b0 || s.ProfileWriteID("b") == "" {
		t.Fatalf("unrelated-profile write: a=%q (want op-x) b=%q (want fresh, not %q)", s.ProfileWriteID("a"), s.ProfileWriteID("b"), b0)
	}
	// A write that changes "a" (another writer) replaces the commit's identity.
	cfg = s.Get()
	cfg.Profiles[0].Name, cfg.Profiles[0].Revision = "A by someone else", 3
	if err := s.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if w := s.ProfileWriteID("a"); w == "op-x" || w == "" {
		t.Fatalf("a writer that changes the target must update its provenance, got %q", w)
	}
	// Durable: the provenance is in the same file and survives a reload.
	var reloaded ProfileStore
	if err := reloaded.Load(path); err != nil {
		t.Fatal(err)
	}
	if reloaded.ProfileWriteID("a") != s.ProfileWriteID("a") || reloaded.ProfileWriteID("b") != s.ProfileWriteID("b") {
		t.Fatal("provenance must survive a reload from the durable file")
	}
	// A removed profile drops its entry; a file without provenance loads unknown.
	cfg = s.Get()
	cfg.Profiles = cfg.Profiles[:1]
	if err := s.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if s.ProfileWriteID("b") != "" {
		t.Fatal("a removed profile must drop its provenance")
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var legacy ProfileStore
	if err := legacy.Load(path); err != nil {
		t.Fatal(err)
	}
	if legacy.ProfileWriteID("a") != "" {
		t.Fatalf("a file that predates provenance loads as unknown, got %q", legacy.ProfileWriteID("a"))
	}
	// Unknown stays unknown across an unrelated write (never invented).
	cfg = legacy.Get()
	cfg.Pools[0].Name = "P again"
	if err := legacy.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if legacy.ProfileWriteID("a") != "" {
		t.Fatal("an identity must never be invented for content nobody changed")
	}
}
