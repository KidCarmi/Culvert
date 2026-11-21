//go:build benchgate

package main

import "testing"

// Allocation-regression gates for the Control Plane's centralized audit ring
// (clusterAuditLog, controlplane.go), in the repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v .
//
// Root is already named by the benchgate job in pr-fast-gate.yml, so these need
// no workflow edit and benchgate_ci_registration_test.go stays satisfied.
//
// These are ALLOCATION gates, never timing ratios — the shape this repository
// has repeatedly had to abandon because a gate that can flake gets muted. An
// allocation count is exact and machine-independent, so they fail
// deterministically on any runner, under load, with or without -race.
//
// The structural wall that actually prevents reintroduction —
// TestClusterAuditLog_BufferNeverGrows — and the differential against the
// frozen pre-change implementation live in controlplane_cluster_audit_test.go
// and run in the NORMAL suite, where they belong.
//
// Measured on a 4-core Xeon @2.10GHz at the production maxSize of 5000
// (controlplane_cluster_audit_bench_test.go, -benchtime 3000x -count 3):
// Append went 562-719 ns and 655 B/op to 33-41 ns and 0 B/op for a single
// event, and 309-328 us and 676 kB/op to 15.9-19.1 us and 0 B/op for a
// saturated 1000-event batch.

// clusterAuditGateBatch is the warm batch shape both arms are charged for.
func clusterAuditGateBatch() []AuditEntry { return clusterAuditEvents("gate", 10) }

// saturate drives log past a full window so the measurement charges the steady
// state the CP spends its life in, not the one-time fill.
func saturate(log clusterAuditAppender, maxSize int, batch []AuditEntry) {
	for filled := 0; filled < 2*maxSize; filled += len(batch) {
		log.Append("node-warm", batch)
	}
}

// clusterAuditAllocsPerLap reports allocations per FULL LAP of the window past
// saturation, which is the unit both gates below measure in.
//
// It is per-lap and not per-call for a measurement reason, not a stylistic one.
// testing.AllocsPerRun averages with INTEGER division (`mallocs/runs`), so a
// cost paid in periodic spikes is erased by it: the pre-change shape reallocates
// a few times per thousand appends, which over 200 single-Append runs rounds to
// a reported 0.000 — the same figure an allocation-free ring reports. A
// per-call gate therefore passes against BOTH shapes and guards nothing. Per
// lap the signal survives exactly: the pre-change shape's spare capacity shrinks
// by one entry per append and is at most one growth step wide, so a lap cannot
// complete without reallocating (measured: 1 allocation per lap at maxSize=128,
// 2 at maxSize=512, reproducible across runs), while the
// ring allocates nothing after its one-time buffer (0).
func clusterAuditAllocsPerLap(newLog func() clusterAuditAppender, maxSize int) float64 {
	log := newLog()
	batch := clusterAuditGateBatch()
	saturate(log, maxSize, batch)
	return testing.AllocsPerRun(5, func() {
		for filled := 0; filled < 2*maxSize; filled += len(batch) {
			log.Append("node-a", batch)
		}
	})
}

// TestBenchGate_ClusterAuditAppendIsAllocationFree pins the floor the whole
// fleet's audit aggregation point gets: once the window is saturated, taking
// Data Plane pushes must not touch the heap at all, however many laps they
// drive. Reintroducing any per-append allocation — a growing backing array, a
// per-entry pointer, a formatted string — fails here.
func TestBenchGate_ClusterAuditAppendIsAllocationFree(t *testing.T) {
	for _, maxSize := range []int{128, 512} {
		got := clusterAuditAllocsPerLap(func() clusterAuditAppender {
			return &clusterAuditLog{maxSize: maxSize}
		}, maxSize)
		if got != 0 {
			t.Errorf("maxSize=%d: Append allocated %.1f time(s) per lap of a saturated ring; want 0. "+
				"A growing backing array reallocates and memmoves the entire live window under c.mu, "+
				"on the one mutex every Data Plane's PushAuditEvents RPC funnels through.", maxSize, got)
		}
	}
}

// TestBenchGate_ClusterAuditAppendBeatsLegacy is the before/after contract,
// measured in ONE run against the frozen pre-change implementation so it can
// never become a stale number quoted from a commit message. It asserts the
// SAVING, not an absolute figure. See clusterAuditAllocsPerLap for why the unit
// is a lap.
func TestBenchGate_ClusterAuditAppendBeatsLegacy(t *testing.T) {
	for _, maxSize := range []int{128, 512} {
		now := clusterAuditAllocsPerLap(func() clusterAuditAppender {
			return &clusterAuditLog{maxSize: maxSize}
		}, maxSize)
		legacy := clusterAuditAllocsPerLap(func() clusterAuditAppender {
			return &legacyClusterAuditLog{maxSize: maxSize}
		}, maxSize)
		if now >= legacy {
			t.Errorf("maxSize=%d: current shape allocates %.1f time(s) per lap, frozen pre-change "+
				"shape allocates %.1f — the saving is gone", maxSize, now, legacy)
		}
		if legacy == 0 {
			t.Errorf("maxSize=%d: the frozen pre-change shape measured 0 allocations per lap, so this "+
				"gate is measuring nothing — the oracle or the lap width has drifted", maxSize)
		}
	}
}
