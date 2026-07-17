package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		ps.Save()
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
