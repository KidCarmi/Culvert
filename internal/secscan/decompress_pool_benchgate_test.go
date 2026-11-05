//go:build benchgate

package secscan

import "testing"

// Performance-regression gate for the pooled scan-path decompressors
// (secscan.go), in the repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v ./internal/secscan/
//
// The correctness contracts — the differential against the frozen pre-pool
// arms, the retention check and the bomb control — live in
// decompress_pool_test.go and run in the NORMAL suite, where they belong.
//
// The gates here are ALLOCATION gates, never timing ratios. An allocation
// count is exact and machine-independent, so these fail deterministically on
// any runner, with or without -race — unlike a ns/op ratio, which is the shape
// this repository has repeatedly had to abandon because a gate that can flake
// gets muted (see the sanitizeLog, connlimit and histogram notes).

// allocsForExpansion reports allocations per call of one expansion arm. The
// payload is built once, outside the measured closure, so the compression is
// charged to neither arm.
func allocsForExpansion(tb testing.TB, fn func([]byte, string) ([]byte, bool), data []byte, ce string) float64 {
	tb.Helper()
	// One warm-up call so the pooled arm is measured in its steady state: the
	// very first call through an empty sync.Pool legitimately constructs the
	// decoder it will then reuse, and charging that to the average would be
	// measuring the pool's first use rather than the path production runs.
	if _, bomb := fn(data, ce); bomb {
		tb.Fatalf("warm-up expansion refused a well-formed %s body", ce)
	}
	return testing.AllocsPerRun(200, func() {
		if _, bomb := fn(data, ce); bomb {
			tb.Fatalf("expansion refused a well-formed %s body", ce)
		}
	})
}

// TestBenchGate_PooledExpansionBeatsLegacy is the before/after contract,
// measured in ONE run against the frozen pre-pool arms so it can never become
// a stale number quoted from a commit message. It asserts the SAVING, not an
// absolute figure.
//
// The margin is deliberate rather than ">=": the removed state is a fixed
// 32 KiB flate window plus its Huffman tables and gzip's header scratch, which
// is 5-6 allocations where the pooled arm makes 2 (the output buffer and its
// one geometric grow). A change that left only a token saving would have given
// up the thing this costs its complexity for, so the gate requires the pooled
// arm to make strictly FEWER THAN HALF the allocations of the arm it replaced.
func TestBenchGate_PooledExpansionBeatsLegacy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pooled, legacy func([]byte, string) ([]byte, bool)
		ce             string
		data           []byte
	}{
		{"gzip", expandGzipForScan, legacyExpandGzipForScan, "gzip", benchGzipPayload(t, 16<<10)},
		{"deflate", expandDeflateForScan, legacyExpandDeflateForScan, "deflate", benchDeflatePayload(t, 16<<10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := allocsForExpansion(t, tc.pooled, tc.data, tc.ce)
			legacy := allocsForExpansion(t, tc.legacy, tc.data, tc.ce)
			if now*2 >= legacy {
				t.Errorf("%s: pooled arm allocates %.1f/call, frozen pre-pool arm allocates "+
					"%.1f/call — the saving is gone or no longer worth the pool. The usual "+
					"cause is a decoder that is no longer being reused: check that release() "+
					"still returns it and that nothing hands it a reader it must wrap "+
					"(a source that is not a flate.Reader costs a 4 KiB bufio per call).",
					tc.name, now, legacy)
			}
		})
	}
}

// TestBenchGate_PooledExpansionIsFlatInBodySize pins the property the pool
// exists for: the decoder state is reconstructed per RESPONSE, not per byte, so
// growing the body must not grow the arm's own allocation count beyond the
// output buffer's geometric growth. The legacy arm's 5-6 fixed allocations are
// paid on a 1 KiB response exactly as on a 256 KiB one, which is why the
// saving is largest on the small responses that dominate real traffic.
func TestBenchGate_PooledExpansionIsFlatInBodySize(t *testing.T) {
	small := allocsForExpansion(t, expandGzipForScan, benchGzipPayload(t, 1<<10), "gzip")
	large := allocsForExpansion(t, expandGzipForScan, benchGzipPayload(t, 256<<10), "gzip")
	// readCapped starts at a 32 KiB buffer and doubles, so a 256 KiB body
	// legitimately costs a few more allocations than a 1 KiB one. What must not
	// reappear is a per-call decoder: that is a fixed cost, so it would lift
	// BOTH numbers, and the small body is where it would stand out.
	if small > 4 {
		t.Errorf("a 1 KiB gzip response costs %.1f allocations through the pooled arm; "+
			"want at most 4 (the output buffer and its grows). A fixed decoder "+
			"allocation has come back.", small)
	}
	if large <= small {
		t.Logf("note: 256 KiB body costs %.1f allocations vs %.1f for 1 KiB — "+
			"output-buffer growth, not decoder state", large, small)
	}
}

// TestBenchGate_PooledExpansionStillExpands is the CONTROL. Every gate above is
// satisfied most cheaply by an arm that returns the compressed bytes untouched,
// which would silently put ClamAV, YARA and DPI back to scanning gzip frames —
// the signature gap the 1.1 fix closed, and invisible in every counter.
func TestBenchGate_PooledExpansionStillExpands(t *testing.T) {
	body := benchMarkupBody(16 << 10)
	for _, tc := range []struct {
		ce   string
		data []byte
	}{
		{"gzip", benchGzipPayload(t, 16<<10)},
		{"deflate", benchDeflatePayload(t, 16<<10)},
	} {
		out, bomb := DecompressForScan(tc.data, tc.ce)
		if bomb {
			t.Errorf("%s: well-formed body refused as a bomb", tc.ce)
			continue
		}
		if len(out) != len(body) {
			t.Errorf("%s: expanded to %d bytes, want the %d-byte original — the arm is "+
				"returning compressed bytes, so the scanners see no content",
				tc.ce, len(out), len(body))
		}
	}
}
