package scanexcl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceAndIsHashExcluded(t *testing.T) {
	s := New()
	s.Replace([]string{"ABCDEF123", "  "}, []string{"Example.com", ""})

	if !s.IsHashExcluded("abcdef123") {
		t.Error("hash should be excluded (lowercased)")
	}
	if !s.IsHashExcluded("ABCDEF123") {
		t.Error("hash should be excluded regardless of input case")
	}
	if s.IsHashExcluded("deadbeef") {
		t.Error("unknown hash should not match")
	}

	if !s.IsHostExcluded("example.com") {
		t.Error("host should be excluded")
	}
	if !s.IsHostExcluded("EXAMPLE.COM:443") {
		t.Error("host with port should be excluded (case-insensitive)")
	}
	if s.IsHostExcluded("other.com") {
		t.Error("false positive on host")
	}
	if s.IsHostExcluded("") {
		t.Error("empty host should not match")
	}
}

func TestNilReceiver(t *testing.T) {
	var s *Store
	if s.IsHashExcluded("x") {
		t.Error("nil receiver hash")
	}
	if s.IsHostExcluded("example.com") {
		t.Error("nil receiver host")
	}
}

func TestLists_Sorted(t *testing.T) {
	s := New()
	s.Replace([]string{"beef", "dead", "cafe"}, []string{"c.com", "a.com", "b.com"})
	hashes, hosts := s.Lists()
	if len(hashes) != 3 || hashes[0] != "beef" || hashes[1] != "cafe" || hashes[2] != "dead" {
		t.Errorf("hashes not sorted: %v", hashes)
	}
	if len(hosts) != 3 || hosts[0] != "a.com" || hosts[1] != "b.com" || hosts[2] != "c.com" {
		t.Errorf("hosts not sorted: %v", hosts)
	}
}

func TestLoadSave_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "excl.json")

	s1 := New()
	// Load missing file is not an error.
	if err := s1.Load(path); err != nil {
		t.Fatalf("load missing: %v", err)
	}

	s1.Replace([]string{"h1", "h2"}, []string{"host1.example", "host2.example"})
	if err := s1.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh store reloads from disk.
	s2 := New()
	if err := s2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !s2.IsHashExcluded("h1") || !s2.IsHashExcluded("h2") {
		t.Error("hashes not roundtripped")
	}
	if !s2.IsHostExcluded("host1.example") || !s2.IsHostExcluded("host2.example") {
		t.Error("hosts not roundtripped")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "excl.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New()
	if err := s.Load(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestSave_NoPath(t *testing.T) {
	s := New()
	s.Replace([]string{"x"}, []string{"y"})
	// No path configured → Save is a no-op, no error.
	if err := s.Save(); err != nil {
		t.Errorf("Save without path should be no-op: %v", err)
	}
}

func TestLoad_ValidEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "excl.json")
	env := exclusionsFile{
		Hashes: []string{"AAA", "BBB"},
		Hosts:  []string{"Foo.Example"},
	}
	data, _ := json.Marshal(env)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.IsHashExcluded("aaa") || !s.IsHashExcluded("bbb") {
		t.Error("hashes not loaded/lowercased")
	}
	if !s.IsHostExcluded("foo.example") {
		t.Error("host not loaded/lowercased")
	}
}

func TestSortStrings(t *testing.T) {
	in := []string{"c", "a", "b", "a"}
	sortStrings(in)
	if in[0] != "a" || in[1] != "a" || in[2] != "b" || in[3] != "c" {
		t.Errorf("sortStrings = %v", in)
	}

	sortStrings(nil) // should not panic
	sortStrings([]string{"only"})
}
