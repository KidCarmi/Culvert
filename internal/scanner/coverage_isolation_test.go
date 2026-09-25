package scanner

// Coverage-isolation fixtures (CI-REDESIGN stage 5B, roadmap/CI-REDESIGN.md
// §14.2). Each pins a block that the sharded race run and the unsharded
// reference covered on different runs, so coverage equivalence no longer
// depends on chance or on test order.

import (
	"fmt"
	"sort"
	"testing"
)

// Pins BypassHosts' insertion-sort SWAP. The list is read out of a map, so the
// swap runs only when Go's randomized map iteration yields an unsorted order.
// TestBypassHosts uses two hosts, so whether that happened was a coin flip on
// every run, sharded or not — qualification round 3 (qa-gate run 35839915521)
// saw the reference cover it and the lane not, on identical code.
//
// With 64 hosts, one iteration coming back already sorted is not a practical
// possibility; reading the list repeatedly makes the swap certain to run while
// the assertion stays the function's real contract (sorted, complete, stable).
func TestIsolation_BypassHostsSortsAnUnorderedMap(t *testing.T) {
	s := New(1 << 20)
	var hosts []string
	for i := 0; i < 64; i++ {
		hosts = append(hosts, fmt.Sprintf("h%02d.example", 63-i))
	}
	s.SetBypassHosts(hosts)

	want := append([]string(nil), hosts...)
	sort.Strings(want)
	for round := 0; round < 8; round++ {
		got := s.BypassHosts()
		if len(got) != len(want) {
			t.Fatalf("round %d: %d hosts, want %d", round, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("round %d: BypassHosts not sorted at %d: got %q, want %q", round, i, got[i], want[i])
			}
		}
	}
}
