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

// TestConfigStore_Update_RejectsByteOversizeAtCommit covers the byte-budget
// gate: a snapshot within the per-slice and aggregate ENTRY caps but whose
// marshaled size exceeds the wire budget (long strings) must be rejected at
// commit — otherwise it commits on the CP and fails every DP fetch with an
// opaque ResourceExhausted, freezing the fleet with no signal.
func TestConfigStore_Update_RejectsByteOversizeAtCommit(t *testing.T) {
	s := &ConfigStore{}
	if err := s.Update(ConfigSnapshot{BlockedHosts: []string{"a.example"}}); err != nil {
		t.Fatalf("valid publish rejected: %v", err)
	}
	// 200k entries (well under the 2M/3M count caps) of ~700 bytes each ⇒
	// ~140 MiB marshaled, past the 120 MiB byte budget.
	const n, width = 200_000, 700
	long := strings.Repeat("x", width)
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = long
	}
	err := s.Update(ConfigSnapshot{BlockedHosts: hosts})
	if err == nil {
		t.Fatal("byte-oversized publish accepted; the commit byte gate must reject it")
	}
	if !strings.Contains(err.Error(), "wire size") {
		t.Errorf("rejection should name the byte overflow; got %v", err)
	}
	if s.Get().Version != 1 {
		t.Errorf("byte-oversized publish advanced the version to %d — fleet must stay on the last valid config", s.Get().Version)
	}
	if msg, _ := s.LastPublishError(); !strings.Contains(msg, "wire size") {
		t.Errorf("LastPublishError should record the byte overflow; got %q", msg)
	}
}

// TestConfigSnapshotSizeMetrics_AllSlices pins that the utilization metric emits
// EVERY capped slice (not just blocked_hosts) plus the aggregate and
// url_category_hosts bounds, sourced from the sizes cached at publish.
func TestConfigSnapshotSizeMetrics_AllSlices(t *testing.T) {
	recordPublishedSnapshotSizes(ConfigSnapshot{
		BlockedHosts: []string{"a", "b"},
		IPList:       []string{"1.2.3.4"},
	})
	var w strings.Builder
	writeConfigSnapshotSizeMetrics(&w)
	out := w.String()
	for _, want := range []string{
		`culvert_config_snapshot_slice_entries{slice="blocked_hosts"} 2`,
		`culvert_config_snapshot_slice_entries{slice="ip_list"} 1`,
		`culvert_config_snapshot_slice_entries{slice="url_category_hosts"}`,
		`culvert_config_snapshot_slice_entries{slice="aggregate_host_scale"} 3`,
		`culvert_config_snapshot_slice_cap{slice="blocked_hosts"} 2000000`,
		`culvert_config_snapshot_slice_cap{slice="aggregate_host_scale"} 3000000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n---\n%s", want, out)
		}
	}
}

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
