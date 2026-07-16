package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPolicyStoreSaveSerializesSnapshotThroughMetaPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	ps := &PolicyStore{path: path}
	ps.Add(PolicyRule{Name: "first", Action: ActionAllow})

	// Hold the persistence-order lock so both Save calls are known to be waiting
	// before the second mutation is published. Once released, each save must take
	// its snapshot inside the same serialized critical section.
	ps.saveMu.Lock()
	started := make(chan struct{}, 2)
	done := make(chan struct{}, 2)
	startSave := func() {
		started <- struct{}{}
		_ = ps.Save() // ordering, not persistence failure, is under test
		done <- struct{}{}
	}
	go startSave()
	<-started

	ps.Add(PolicyRule{Name: "second", Action: ActionDrop})
	go startSave()
	<-started

	select {
	case <-done:
		ps.saveMu.Unlock()
		t.Fatal("Save completed while persistence-order lock was held")
	case <-time.After(20 * time.Millisecond):
	}
	ps.saveMu.Unlock()
	<-done
	<-done

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var rules []PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if len(rules) != 2 || rules[0].Name != "first" || rules[1].Name != "second" {
		t.Fatalf("persisted rules = %+v, want latest two-rule revision", rules)
	}

	metaData, err := os.ReadFile(path + ".meta")
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var meta policyMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	version, updatedAt := ps.policyVersion()
	if meta.Version != version || meta.UpdatedAt != updatedAt {
		t.Fatalf("persisted metadata = %+v, want version=%d updated_at=%q", meta, version, updatedAt)
	}
}

func TestPolicyStoreFailedLoadDoesNotRetargetSave(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "policy.json")
	invalidPath := filepath.Join(dir, "invalid.json")
	ps := &PolicyStore{}
	if err := ps.Load(originalPath); err != nil {
		t.Fatalf("establish original path: %v", err)
	}
	ps.Add(PolicyRule{Name: "first", Action: ActionAllow})
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	invalid := []byte(`{"broken":`)
	if err := os.WriteFile(invalidPath, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ps.Load(invalidPath); err == nil {
		t.Fatal("invalid reload unexpectedly succeeded")
	}
	ps.Add(PolicyRule{Name: "second", Action: ActionDrop})
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	gotInvalid, err := os.ReadFile(invalidPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotInvalid, invalid) {
		t.Fatalf("failed reload target was overwritten: got %q want %q", gotInvalid, invalid)
	}
	data, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	var rules []PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("original save path has %d rules, want 2", len(rules))
	}
}

func TestPolicyStoreLoadNeverRegressesNewerMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	rules := []PolicyRule{{ID: newRuleID(), Name: "loaded", Action: ActionAllow}}
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	oldMeta := policyMeta{Version: 3, UpdatedAt: "2025-01-01T00:00:00Z"}
	metaData, err := json.Marshal(oldMeta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".meta", metaData, 0o600); err != nil {
		t.Fatal(err)
	}

	ps := &PolicyStore{version: 10, updatedAt: "2026-01-01T00:00:00Z"}
	if err := ps.Load(path); err != nil {
		t.Fatal(err)
	}
	version, updatedAt := ps.policyVersion()
	if version < 10 || updatedAt == "2020-01-01T00:00:00Z" {
		t.Fatalf("metadata regressed to version=%d updated_at=%q", version, updatedAt)
	}
}

func TestPolicyStoreSaveReportsMetadataPublicationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	ps := &PolicyStore{path: path}
	ps.Add(PolicyRule{Name: "published", Action: "Allow"})

	if err := os.Mkdir(path+".meta", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ps.Save(); err == nil {
		t.Fatal("Save succeeded despite an unreplaceable metadata path")
	}
}

func TestPolicyStoreLoadRejectsTornPolicyMetadataPair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	ps := &PolicyStore{path: path}
	ps.Add(PolicyRule{Name: "old", Action: "Allow"})
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	oldMeta, err := os.ReadFile(path + ".meta")
	if err != nil {
		t.Fatal(err)
	}

	ps.Add(PolicyRule{Name: "new", Action: "Drop"})
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".meta", oldMeta, 0o600); err != nil {
		t.Fatal(err)
	}

	fresh := &PolicyStore{rules: []*PolicyRule{{Name: "live", Action: "Allow"}}, path: "live.json", version: 99}
	if err := fresh.Load(path); err == nil {
		t.Fatal("Load accepted policy bytes paired with stale digest-bound metadata")
	}
	if fresh.path != "live.json" || fresh.version != 99 || len(fresh.rules) != 1 || fresh.rules[0].Name != "live" {
		t.Fatalf("failed Load mutated live state: path=%q version=%d rules=%+v", fresh.path, fresh.version, fresh.rules)
	}
}

func TestPolicyStoreLoadRebindsLegacyMetadataBeforePublication(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data := []byte(`[{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","name":"legacy","action":"Allow"}]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".meta", []byte(`{"version":42,"updated_at":"2026-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	ps := &PolicyStore{}
	if err := ps.Load(path); err != nil {
		t.Fatal(err)
	}
	version, _ := ps.policyVersion()
	if version <= 42 {
		t.Fatalf("legacy generation was reused: %d", version)
	}
	meta, ok, err := readPolicyMeta(path)
	if err != nil || !ok {
		t.Fatalf("read rebound metadata: ok=%v err=%v", ok, err)
	}
	if meta.PolicySHA256 != policySHA256(data) || meta.Version != version {
		t.Fatalf("metadata not bound to loaded policy: %+v", meta)
	}
	var rules []PolicyRule
	persisted, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(persisted, &rules) != nil {
		t.Fatalf("policy array compatibility lost: err=%v bytes=%s", err, persisted)
	}
}

func TestPolicyStoreLoadRejectsMalformedMetadataWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data := []byte(`[{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","name":"disk","action":"Allow"}]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".meta", []byte(`{"version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{rules: []*PolicyRule{{Name: "live", Action: ActionAllow}}, path: "live.json", version: 7}

	if err := ps.Load(path); err == nil {
		t.Fatal("Load accepted malformed policy metadata")
	}
	if ps.path != "live.json" || ps.version != 7 || len(ps.rules) != 1 || ps.rules[0].Name != "live" {
		t.Fatalf("failed Load mutated live state: path=%q version=%d rules=%+v", ps.path, ps.version, ps.rules)
	}
}

func TestPolicyStoreLoadRestoresMatchingDigestGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data := []byte(`[{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","name":"bound","action":"Allow"}]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	want := policyMeta{Version: 1234, UpdatedAt: "2026-01-02T03:04:05Z", PolicySHA256: policySHA256(data)}
	metaData, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".meta", metaData, 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{}

	if err := ps.Load(path); err != nil {
		t.Fatal(err)
	}
	version, updatedAt := ps.policyVersion()
	if version != want.Version || updatedAt != want.UpdatedAt {
		t.Fatalf("loaded generation = (%d, %q), want (%d, %q)", version, updatedAt, want.Version, want.UpdatedAt)
	}
}

func TestPolicyStoreLoadRejectsUnrepresentableFreshGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data := []byte(`[{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","name":"legacy-max","action":"Allow"}]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"version":` + fmt.Sprint(math.MaxInt64) + `,"updated_at":"2026-01-01T00:00:00Z"}`)
	if err := os.WriteFile(path+".meta", meta, 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{rules: []*PolicyRule{{Name: "live", Action: ActionAllow}}, path: "live.json", version: 7}

	if err := ps.Load(path); err == nil {
		t.Fatal("Load reused MaxInt64 legacy generation instead of failing closed")
	}
	if ps.path != "live.json" || ps.version != 7 || len(ps.rules) != 1 || ps.rules[0].Name != "live" {
		t.Fatalf("failed Load mutated live state: path=%q version=%d rules=%+v", ps.path, ps.version, ps.rules)
	}
	persistedMeta, err := os.ReadFile(path + ".meta")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persistedMeta, meta) {
		t.Fatalf("failed Load rewrote legacy metadata: got %s want %s", persistedMeta, meta)
	}
}

func TestPolicyStoreConcurrentLoadSaveKeepsPathAndMetadataRaceFree(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")}
	for i, path := range paths {
		rules := []PolicyRule{{ID: newRuleID(), Name: string(rune('a' + i)), Action: ActionAllow}}
		data, err := json.Marshal(rules)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		metaData, err := json.Marshal(policyMeta{Version: int64(i + 1), UpdatedAt: "2026-01-01T00:00:00Z"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".meta", metaData, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ps := &PolicyStore{}
	if err := ps.Load(paths[0]); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		path := paths[i%len(paths)]
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := ps.Load(path); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			_ = ps.Save() // concurrent ordering is asserted after all workers finish
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Load: %v", err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var rules []PolicyRule
		if err := json.Unmarshal(data, &rules); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if _, ok, err := readPolicyMeta(path); err != nil || !ok {
			t.Fatalf("invalid metadata for %s: %v", path, err)
		}
	}
}

func TestPolicyLoadRecoversInterruptedSaveOverLegacyMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	seed := &PolicyStore{path: path}
	seed.Add(PolicyRule{Name: "old", Action: ActionAllow})
	if err := seed.Save(); err != nil {
		t.Fatal(err)
	}
	oldPolicy, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	legacyMeta, err := json.Marshal(policyMeta{Version: 7, UpdatedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path+".meta", legacyMeta, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := beginPolicySave(path); err != nil {
		t.Fatal(err)
	}
	candidate, err := json.MarshalIndent([]PolicyRule{{Name: "failed-candidate", Action: ActionDrop}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, candidate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path+".meta", []byte(`{"version":8}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash before the transaction commit marker is written.
	loaded := &PolicyStore{}
	if err := loaded.Load(path); err != nil {
		t.Fatalf("recover interrupted save: %v", err)
	}
	rules := loaded.List()
	if len(rules) != 1 || rules[0].Name != "old" {
		t.Fatalf("recovered rules = %#v, want old policy", rules)
	}
	recovered, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, oldPolicy) {
		t.Fatal("interrupted save did not restore previous policy bytes")
	}
	if _, err := os.Stat(path + ".txn"); !os.IsNotExist(err) {
		t.Fatalf("transaction record not cleaned up: %v", err)
	}
}

func TestPolicyLoadIDMigrationFailureDoesNotPublishCandidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data, err := json.MarshalIndent([]PolicyRule{{Name: "legacy", Action: ActionAllow}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := policyMeta{Version: 7, UpdatedAt: time.Now().UTC().Format(time.RFC3339), PolicySHA256: policySHA256(data)}
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".meta", metaData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".txn", 0o700); err != nil {
		t.Fatal(err)
	}

	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Name: "old-live", Action: ActionAllow}})
	before, beforeVersion := ps.snapshotWithVersion()
	if err := ps.Load(path); err == nil {
		t.Fatal("expected ID migration persistence failure")
	}
	after, afterVersion := ps.snapshotWithVersion()
	if !sameRuleSet(before, after) || afterVersion != beforeVersion {
		t.Fatalf("failed Load published candidate: before=%v/v%d after=%v/v%d", before, beforeVersion, after, afterVersion)
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if ps.path != "" {
		t.Fatalf("failed Load retargeted store path to %q", ps.path)
	}
}
