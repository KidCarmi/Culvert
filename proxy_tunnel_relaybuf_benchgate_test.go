//go:build benchgate

package main

// proxy_tunnel_relaybuf_benchgate_test.go — the hard gates on relay buffer
// RESIDENCY.
//
// Lives with the other benchgate tests because it is a PERFORMANCE contract,
// not a behaviour one, and because it establishes 96+ loopback connections and
// reads runtime.MemStats under two forced collections — work that does not
// belong in the default suite, where the shuffled race job runs everything
// under load.
//
//	go test -tags benchgate -run 'TestBenchGate_RelayBuffer' -count=1 -v .
//
// What these protect. idleCopyCounted holds its buffer for the LIFETIME of a
// tunnel, so a buffer taken for a pair that never reads it is resident memory
// multiplied by the concurrent connection count — the single scalability
// quantity a forward proxy is bought for. Before relayCopyReadsBuffer, every
// production relay direction pinned 128 KB it never touched: ~2.4 GiB at 10k
// concurrent tunnels. allocs/op cannot see this (a warm sync.Pool reports ~0
// either way), so residency is gated directly.
//
// Both gates are measured in ONE process against the frozen pre-change body
// (idleCopyCountedLegacyAlwaysBuffered, proxy_tunnel_relaybuf_bench_test.go),
// so the result is machine-independent: the absolute ceiling catches a
// regression that reintroduces the unconditional buffer, and the comparison
// catches a rewrite that happens to hit the ceiling while losing the saving the
// change was justified by.

import (
	"testing"
)

// relayHeldCeilingPerRelay is the per-direction residency ceiling. The measured
// steady state is ~70 B/relay (the goroutine's heap-escaping bits), against a
// 131,072-byte buffer if one is taken. 4 KB leaves two orders of magnitude of
// room for MemStats noise and for an unrelated small allocation joining the
// measured window, while still being 32x below a single relay buffer — so the
// only way to breach it is to take a buffer again.
const relayHeldCeilingPerRelay = 4096

func TestBenchGate_RelayBufferResidency(t *testing.T) {
	held, teardown := relayHeldBytes(t, relayResidencyRelays, idleCopyCounted)
	defer teardown()

	perRelay := float64(held) / float64(relayResidencyRelays)
	t.Logf("idleCopyCounted: %d relay directions hold %d B total, %.1f B/relay (ceiling %d, one buffer is %d)",
		relayResidencyRelays, held, perRelay, relayHeldCeilingPerRelay, relayBufSize)

	if perRelay > relayHeldCeilingPerRelay {
		t.Errorf("REGRESSION: an open relay direction holds %.0f B, exceeds the ceiling %d — "+
			"idleCopyCounted is checking a %d-byte buffer out of relayBufPool for a pair whose copy "+
			"never reads it (relayCopyReadsBuffer). That memory is held for the whole LIFE of the "+
			"tunnel, so it is multiplied by the concurrent connection count: ~%.1f GB at 10k tunnels "+
			"(two directions each). See proxy_tunnel_relaybuf_bench_test.go.",
			perRelay, relayHeldCeilingPerRelay, relayBufSize,
			perRelay*2*10000/(1024*1024*1024))
	}
}

// TestBenchGate_RelayBufferBeatsLegacy is the before/after relationship,
// measured in one run so it is machine-independent: the shipped shape must hold
// at least a whole relay buffer less, per direction, than the frozen
// always-buffered body. Residency is deterministic to within MemStats noise, so
// this is a hard gate rather than a timing heuristic.
func TestBenchGate_RelayBufferBeatsLegacy(t *testing.T) {
	legacyHeld, legacyDown := relayHeldBytes(t, relayResidencyRelays, idleCopyCountedLegacyAlwaysBuffered)
	legacyDown()
	currentHeld, currentDown := relayHeldBytes(t, relayResidencyRelays, idleCopyCounted)
	currentDown()

	legacyPer := float64(legacyHeld) / float64(relayResidencyRelays)
	currentPer := float64(currentHeld) / float64(relayResidencyRelays)
	t.Logf("held B/relay: legacy %.0f, current %.0f, saving %.0f (one buffer is %d)",
		legacyPer, currentPer, legacyPer-currentPer, relayBufSize)

	// The legacy arm must actually have taken a buffer, or the comparison below
	// is vacuous — a broken harness that measures ~0 for both would otherwise
	// pass this gate while proving nothing.
	if legacyPer < relayBufSize*0.9 {
		t.Fatalf("harness broken: the always-buffered body holds only %.0f B/relay, "+
			"expected ~%d — the measurement is not seeing the pooled buffer, so the "+
			"saving below cannot be read as evidence", legacyPer, relayBufSize)
	}
	// The required saving is one whole buffer LESS the per-relay noise the
	// absolute gate already tolerates. Demanding a full relayBufSize is wrong,
	// not merely strict: both arms carry the same few-hundred-byte MemStats
	// floor, so a run where the current arm's floor lands above the legacy
	// arm's own excess over relayBufSize reports a saving a few hundred bytes
	// short of the buffer while the buffer is in fact entirely gone. Observed
	// savings are 130.7-131.4 KB against a 127 KB bar, and taking the buffer
	// back drops the saving to ~0 — two orders of magnitude below it.
	const minSaving = relayBufSize - relayHeldCeilingPerRelay
	if saving := legacyPer - currentPer; saving < minSaving {
		t.Errorf("REGRESSION: the shipped relay holds only %.0f B/relay less than the frozen "+
			"always-buffered body, under the %d-byte bar (one %d-byte buffer less the "+
			"per-relay measurement floor) — the buffer that the splice path never reads is "+
			"back on the per-tunnel residency bill.",
			saving, minSaving, relayBufSize)
	}
}
