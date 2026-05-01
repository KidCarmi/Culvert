package main

// D1.2a cold-start tests for cluster.json (ClusterStore).
//
// The existing TestClusterStore_LoadCorruptedFile in enrollment_test.go
// covers one corruption case. This file fills the remaining cold-start
// gaps: missing file (documented "first run, start empty" behavior),
// empty file (zero bytes), and empty JSON object (which produces a
// fully zero-valued ClusterState that the loader then auto-initializes
// the embedded maps for).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestColdStart_ClusterStore_MissingFile(t *testing.T) {
	// First-run convention: missing file is not an error; the store
	// remains empty and ready for fresh enrollment.
	dir := t.TempDir()
	cs := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	if err := cs.Load(filepath.Join(dir, "cluster.json")); err != nil {
		t.Fatalf("Load (missing file): %v", err)
	}
	if len(cs.ListNodes()) != 0 {
		t.Errorf("expected 0 nodes on missing file, got %d", len(cs.ListNodes()))
	}
}

func TestColdStart_ClusterStore_EmptyFile(t *testing.T) {
	// Zero-byte file fails to unmarshal — distinct from missing.
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	cs := &ClusterStore{}
	err := cs.Load(path)
	if err == nil {
		t.Fatal("expected error on empty file")
	}
	if !strings.Contains(err.Error(), "parse cluster state") {
		t.Errorf("error should mention parse cluster state, got: %v", err)
	}
}

func TestColdStart_ClusterStore_EmptyJSONObject(t *testing.T) {
	// `{}` unmarshals into a zero-valued ClusterState. The loader's
	// post-unmarshal nil-checks initialize Nodes / Tokens / Revoked
	// to non-nil empty containers. Net result: a clean empty state,
	// no error. This is documented behavior; pinning it as a
	// regression guard.
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write empty obj: %v", err)
	}

	cs := &ClusterStore{}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load (empty JSON object): %v", err)
	}
	if len(cs.ListNodes()) != 0 {
		t.Errorf("expected 0 nodes from `{}`, got %d", len(cs.ListNodes()))
	}
}

func TestColdStart_ClusterStore_GarbageBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, []byte("not json at all"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	cs := &ClusterStore{}
	err := cs.Load(path)
	if err == nil {
		t.Fatal("expected error on garbage bytes")
	}
	if !strings.Contains(err.Error(), "parse cluster state") {
		t.Errorf("error should mention parse cluster state, got: %v", err)
	}
}
