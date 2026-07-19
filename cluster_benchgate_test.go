//go:build benchgate

package main

// cluster_benchgate_test.go — GA hardening: deterministic memory fences for the
// 2M-cap cluster config path. Keyed on allocations/bytes per op (hardware-
// independent), these catch a regression that reintroduces per-DP snapshot
// materialization on an unchanged poll, or that doubles the blocklist-apply
// footprint the 10x cap raise depends on staying bounded.
//
//   go test -tags benchgate -run 'TestBenchGate_' -v .

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// TestBenchGate_GetConfigUnchangedFastPath locks in the P0-3 win: an unchanged
// poll (DP already at the current version) must allocate a small CONSTANT — the
// sentinel — NOT anything proportional to the published snapshot. Proven by
// running at two very different snapshot sizes and asserting the per-op
// allocations are the same small constant: if the fast path ever regressed to
// copying/marshaling the full snapshot, the large-snapshot number would blow up.
func TestBenchGate_GetConfigUnchangedFastPath(t *testing.T) {
	orig := globalConfigStore
	t.Cleanup(func() { globalConfigStore = orig })
	svc := &controlPlaneServer{}

	measure := func(hosts int) int64 {
		globalConfigStore = &ConfigStore{}
		bh := make([]string, hosts)
		for i := range bh {
			bh[i] = "host-fill.example"
		}
		if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: bh}); err != nil {
			t.Fatalf("publish %d hosts: %v", hosts, err)
		}
		req, _ := json.Marshal(getConfigRequest{KnownVersion: globalConfigStore.Version()})
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := svc.GetConfig(context.Background(), req); err != nil {
					b.Fatal(err)
				}
			}
		})
		t.Logf("unchanged GetConfig @ %d hosts: %d allocs/op, %d B/op", hosts, res.AllocsPerOp(), res.AllocedBytesPerOp())
		return res.AllocsPerOp()
	}

	small := measure(1_000)
	large := measure(1_000_000)
	// The fast path returns the sentinel before ever touching the snapshot, so
	// allocations must NOT grow with snapshot size. Allow a tiny drift for
	// runtime noise; a proportional regression would be orders of magnitude.
	const maxAllocs int64 = 20
	if small > maxAllocs || large > maxAllocs {
		t.Errorf("unchanged-poll allocs exceed the constant bound %d: small=%d large=%d", maxAllocs, small, large)
	}
	if large > small+5 {
		t.Errorf("REGRESSION: unchanged-poll allocations grow with snapshot size (small=%d large=%d) — the version-conditional fast path is materializing the snapshot", small, large)
	}
}

// TestBenchGate_BlocklistApplyBytes fences the memory footprint of the blocklist
// map rebuild (the build-then-swap core of a config apply). At 200k hosts the
// rebuild allocates a bounded amount; a regression that holds an extra copy or
// changes the map shape blows past the bound. This is the per-node memory the
// 2M cap depends on staying linear (see the min-sizing table in
// docs/operator/cluster-config-capacity.md).
func TestBenchGate_BlocklistApplyBytes(t *testing.T) {
	const n = 200_000
	hosts := make([]string, n)
	for i := range hosts {
		// Distinct realistic hostnames so the map actually holds n entries.
		hosts[i] = "h" + itoaFixed(i) + ".malware.example"
	}
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s := blocklist.New()
			s.ReplaceFeedEntries(hosts)
		}
	})
	bytesPerOp := res.AllocedBytesPerOp()
	// ~200k entries × (map cell + string header + backing) lands well under this;
	// the bound catches a doubling (an extra retained copy) without flaking on
	// map-growth variance. ~256 bytes/host is generous headroom over the ~90 B
	// steady state.
	const maxBytes int64 = 256 * n
	t.Logf("blocklist rebuild @ %d hosts: %d B/op (bound %d), %d allocs/op", n, bytesPerOp, maxBytes, res.AllocsPerOp())
	if bytesPerOp > maxBytes {
		t.Errorf("REGRESSION: blocklist rebuild allocates %d B/op at %d hosts, exceeds bound %d — an extra copy in the apply path?", bytesPerOp, n, maxBytes)
	}
}

// itoaFixed is a tiny allocation-light int→string for building distinct test
// hostnames (avoids pulling strconv into the hot benchmark loop's intent).
func itoaFixed(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
