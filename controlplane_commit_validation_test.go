package main

// controlplane_commit_validation_test.go — P1 commit-time validation.
//
// The CP must reject an over-cap snapshot at the publish/commit boundary instead
// of committing it and letting every DP silently reject it wholesale (freezing
// the fleet on stale config with no clear signal). ConfigStore.Update validates
// first: an over-cap snapshot is NOT published, the version does not advance, and
// the reason is retained for LastPublishError.

import (
	"strings"
	"testing"
)

func TestConfigStore_Update_RejectsOverCapAtCommit(t *testing.T) {
	s := &ConfigStore{}

	// A valid snapshot publishes and advances the version.
	if err := s.Update(ConfigSnapshot{BlockedHosts: []string{"a.example"}}); err != nil {
		t.Fatalf("valid publish rejected: %v", err)
	}
	if s.Get().Version != 1 {
		t.Fatalf("valid publish did not advance version: got %d", s.Get().Version)
	}
	if msg, _ := s.LastPublishError(); msg != "" {
		t.Fatalf("LastPublishError set after a valid publish: %q", msg)
	}

	// An over-cap snapshot is REJECTED: not published, version frozen, error named.
	over := ConfigSnapshot{BlockedHosts: make([]string, maxSnapBlockedHosts+1)}
	err := s.Update(over)
	if err == nil {
		t.Fatal("over-cap publish was accepted; commit-time validation must reject it")
	}
	if !strings.Contains(err.Error(), "blocked_hosts") {
		t.Errorf("rejection error must name the offending collection; got %v", err)
	}
	if s.Get().Version != 1 {
		t.Errorf("rejected publish advanced the version to %d — the fleet must stay on the last valid config", s.Get().Version)
	}
	if len(s.Get().BlockedHosts) != 1 {
		t.Error("rejected publish mutated the published snapshot")
	}
	if msg, ts := s.LastPublishError(); msg == "" || ts == "" {
		t.Errorf("LastPublishError not recorded after rejection: msg=%q ts=%q", msg, ts)
	}

	// A subsequent valid publish clears the rejection status and advances again.
	if err := s.Update(ConfigSnapshot{BlockedHosts: []string{"b.example"}}); err != nil {
		t.Fatalf("recovery publish rejected: %v", err)
	}
	if s.Get().Version != 2 {
		t.Errorf("recovery publish version = %d, want 2", s.Get().Version)
	}
	if msg, _ := s.LastPublishError(); msg != "" {
		t.Errorf("LastPublishError not cleared after a valid publish: %q", msg)
	}
}
