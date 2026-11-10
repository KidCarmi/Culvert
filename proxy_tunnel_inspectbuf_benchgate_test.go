//go:build benchgate

package main

// proxy_tunnel_inspectbuf_benchgate_test.go — the hard ceiling on what an open
// TLS-inspected HTTP/1.1 tunnel's reader pair may hold (inspectLoopReadBufSize,
// proxy_tunnel.go).
//
// Lives with the other benchgate tests because it is a PERFORMANCE contract,
// not a behaviour one, and because it establishes 192 loopback connections and
// reads runtime.MemStats under forced collections — work that does not belong in
// the default suite, where the shuffled determinism job runs everything under
// load. The behaviour contracts on this constant (the chunked-trailer window it
// bounds, and the header shapes that genuinely do not depend on it) are in the
// DEFAULT suite, in proxy_tunnel_inspectbuf_test.go, which is where they belong.
//
//	go test -tags benchgate -run 'TestBenchGate_InspectReadBuf' -count=1 -v .
//
// What this protects, and what it deliberately does NOT. runH1InspectLoop builds
// both readers when the tunnel is established and holds them until it closes, so
// each buffer is resident memory multiplied by the concurrent inspected-tunnel
// count — and on an inspecting gateway that is the dominant concurrent
// connection class. At the shipped 32 KiB per leg that is ~65.7 KB per tunnel,
// ~627 MiB at 10k. That size is NOT free to reduce: it bounds the chunked-trailer
// block the tunnel accepts, which is why there is no "smaller is better" gate
// here and why the per-tunnel figure is pinned as a CEILING only.
//
// The ceiling's job is to make an INCREASE deliberate. Raising either leg — or
// adding a third buffered reader to the loop — pushes the per-tunnel residency
// past the bar and fails here with the multiplier attached, so the decision is
// taken with the memory consequence in hand rather than as a one-character diff.
//
// allocs/op cannot see a cost of this shape at all (one allocation per tunnel
// that never goes away), which is why residency is gated directly.

import (
	"testing"
)

// inspectBufHeldCeilingPerTunnel is the per-tunnel residency ceiling, in
// ABSOLUTE bytes.
//
// Absolute, and deliberately not derived from inspectLoopReadBufSize: a ceiling
// expressed as a multiple of the constant it constrains rises with it, so
// raising the buffer would keep passing its own gate.
//
// The measured steady state is 65,747-65,750 B/tunnel across five runs (two
// 32,768-byte buffers plus a ~211 B MemStats floor). 80 KiB leaves ~22% headroom
// for measurement noise and for an unrelated small allocation joining the
// window, while a rise to 64 KiB per leg (two buffers, ~131 KB) breaches it, and
// so does adding a third 32 KiB reader (~98 KB).
const inspectBufHeldCeilingPerTunnel = 80 * 1024

func TestBenchGate_InspectReadBufResidency(t *testing.T) {
	held, teardown := inspectBufHeldBytes(t, inspectResidencyTunnels, newInspectLoopReaders)
	defer teardown()

	perTunnel := float64(held) / float64(inspectResidencyTunnels)
	t.Logf("newInspectLoopReaders: %d inspected tunnels hold %d B total, %.1f B/tunnel "+
		"(ceiling %d; the shipped pair is 2x%d, so ~%.0f MiB at 10k concurrent inspected tunnels)",
		inspectResidencyTunnels, held, perTunnel, inspectBufHeldCeilingPerTunnel,
		inspectLoopReadBufSize, perTunnel*10000/(1024*1024))

	// Lower bound first. The measurement is a one-sided MemStats delta, so a
	// broken or noise-swamped population reports ~0 and would satisfy the
	// ceiling while proving nothing — the gate would then pass for the one
	// reason that is not a pass. Require the two buffers to actually be visible.
	if minHeld := 2 * inspectLoopReadBufSize * 0.9; perTunnel < minHeld {
		t.Fatalf("harness broken: an open inspected tunnel appears to hold only %.0f B/tunnel, "+
			"expected ~%d (two %d-byte buffers) — the measurement is not seeing the readers, so "+
			"the ceiling below cannot be read as evidence",
			perTunnel, 2*inspectLoopReadBufSize, inspectLoopReadBufSize)
	}

	if perTunnel > inspectBufHeldCeilingPerTunnel {
		t.Errorf("REGRESSION: an open inspected tunnel's reader pair holds %.0f B, over the "+
			"%d-byte ceiling. This memory is held for the whole LIFE of the tunnel, so it is "+
			"multiplied by the concurrent inspected-tunnel count — the dominant connection class "+
			"on an inspecting gateway: ~%.0f MiB at 10k tunnels against ~%.0f MiB at the shipped "+
			"size. If the increase is intended, record WHY per-tunnel memory is being spent and "+
			"raise this ceiling in the same change; note that the size also bounds the "+
			"chunked-trailer window (see inspectLoopReadBufSize), so the two decisions are "+
			"coupled and neither should be made as a side effect of the other.",
			perTunnel, inspectBufHeldCeilingPerTunnel,
			perTunnel*10000/(1024*1024),
			float64(2*inspectLoopReadBufSize)*10000/(1024*1024))
	}
}
