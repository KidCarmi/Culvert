package main

// proxy_tunnel_relaybuf_bench_test.go — evidence for the relay buffer's
// RESIDENCY, which is the quantity that was wrong, and the throughput control
// that shows the fix did not buy it with bandwidth.
//
// Run:
//
//	go test -run '^$' -bench 'Relay' -benchmem -count=6 .
//
// WHY RESIDENCY AND NOT allocs/op. Every other relay benchmark in this
// repository measures a per-call cost. The relay buffer is not a per-call cost:
// idleCopyCounted checks one out before its copy loop and returns it on
// FUNCTION EXIT, so a buffer is held for as long as the tunnel stays open —
// minutes to hours — and allocs/op over a warm sync.Pool reports ~0 for it
// either way. The honest instrument is the live heap a population of OPEN
// relays holds, which is what relayHeldBytes measures: baseline after two GCs
// (which also empties relayBufPool, so a pre-warmed pool cannot flatter the
// legacy arm), relays established and proved running, then the heap re-read
// under a live population.
//
// WHAT WAS WRONG. io.copyBuffer delegates to src.WriteTo(dst) when src is an
// io.WriterTo, and to dst.ReadFrom(src) when dst is an io.ReaderFrom, and in
// BOTH cases never touches the buffer argument. *net.TCPConn implements both,
// so the CONNECT-bypass relay — every HTTPS passthrough tunnel — spliced in the
// kernel and ignored its buffer; *bufio.Reader implements io.WriterTo, so the
// WebSocket relay ignored its buffer too. Both directions of every production
// tunnel therefore pinned 128 KB that nothing read.
//
// Measured on this machine (Go 1.27.3, linux/amd64, 4 vCPU Xeon @ 2.10 GHz,
// 48 idle splice-path relay directions):
//
//	BenchmarkRelayResidency, -count=2      held-B/relay     48 relays
//	  legacy (always pooled)                   131,177       6.005 MB
//	  current (predicate)                           70       0.003 MB
//	                                        -131,107 B      -99.95%
//
//	allocated while establishing 48 relays   6.43 MB  ->  135 KB   (-98%)
//
// Per TUNNEL that is ~256 KiB -> ~140 B, because a tunnel runs two directions.
// At 1k concurrent tunnels the fix removes ~250 MiB of resident heap and at 10k
// ~2.4 GiB, on a product whose connection scalability is a sold property.
//
// The decision also costs less than the pool round trip it replaced, serially
// and under contention (-count=5, medians):
//
//	                                        serial      4x parallel
//	relayCopyReadsBuffer                    2.97 ns        0.81 ns
//	getRelayBuf + relayBufPool.Put         11.45 ns        2.81 ns
//
// (TestBenchGate_RelayBufferResidency reads ~550 B/relay rather than the
// benchmark's ~70 B for the same population: it runs once as a Test rather
// than inside a b.N loop, so the measurement window carries its own setup.
// Both are three orders of magnitude below a 131,072-byte buffer, which is
// the only quantity either number has to distinguish.)
//
// THROUGHPUT IS THE CONTROL. The dispatch io.Copy performs is unchanged — the
// predicate is io.copyBuffer's own condition for reaching its read loop — so
// the splice path must relay at the same rate. BenchmarkRelayThroughput_Splice
// measures bytes/s through the real idleCopyCounted so a future change that
// "saves" the buffer by losing the kernel splice is visible as a bandwidth
// regression rather than as a memory win. Measured (-count=5 -benchtime=4000x,
// 256 KB chunks over loopback, medians): current 2,460 MB/s against legacy
// 2,483 MB/s, with both arms spanning 2,337-2,851 MB/s — one spread, no gap.
// A lost splice would not be a few per cent; it would be a per-byte userspace
// round trip.
//
// TestBenchGate_RelayBufferResidency and TestBenchGate_RelayBufferBeatsLegacy
// (proxy_tunnel_relaybuf_benchgate_test.go) gate both numbers.

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// relayCopyFunc is the shape of the copy step a relay direction runs. The
// current and frozen-legacy bodies differ ONLY in whether they check a pooled
// buffer out, which is what the arms below compare.
type relayCopyFunc func(dst net.Conn, src io.Reader, srcConn net.Conn, shared *atomic.Int64) int64

// idleCopyCountedLegacyAlwaysBuffered is the FROZEN pre-change acquisition: a
// pooled 128 KB buffer for every relay direction, whatever the pair. It is a
// deliberate verbatim copy of the removed lines, kept so the comparison stays
// reproducible in-tree rather than living only in a commit message. It is not
// called by production and must NOT be "kept in sync" with idleCopyCounted —
// its whole value is that it does not move.
func idleCopyCountedLegacyAlwaysBuffered(dst net.Conn, src io.Reader, srcConn net.Conn, shared *atomic.Int64) int64 {
	timeout := tunnelIdleTimeout
	armInterval := timeout / 2
	bp := getRelayBuf()
	defer relayBufPool.Put(bp)
	var total int64
	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(armInterval))
		n, err := io.CopyBuffer(dst, src, *bp)
		total += n
		if n > 0 {
			shared.Store(monoNanos())
		}
		var ne net.Error
		if err != nil && errors.As(err, &ne) && ne.Timeout() {
			if monoSince(shared.Load()) >= timeout {
				_ = dst.Close()
				_ = srcConn.Close()
				return total
			}
			continue
		}
		return total
	}
}

// relayHeldBytes establishes `relays` idle splice-path relay directions through
// copyFn and returns the live heap they hold while open, plus a teardown.
//
// Shape per relay is the production one: *net.TCPConn → *net.TCPConn, which is
// what handleTunnelBypass hands bidiRelayCounted. Every connection is created
// BEFORE the baseline snapshot so the conns themselves are not charged to the
// relay, and each relay is proved to have entered its copy (one byte through,
// end to end) before the heap is re-read — otherwise a goroutine still parked
// at the `go` statement would report zero residency for the legacy arm too.
func relayHeldBytes(tb testing.TB, relays int, copyFn relayCopyFunc) (held uint64, teardown func()) {
	tb.Helper()
	// Deliberately NOT tb.Cleanup: a benchmark calls this once per b.N
	// iteration, and deferring 4 closes per relay to the end of the run would
	// let a long -benchtime exhaust file descriptors and ephemeral ports. Every
	// socket this function opens is closed by the teardown it returns, so the
	// resource high-water mark is one population.
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}

	type leg struct {
		srcW, srcR net.Conn
		dstW, dstR net.Conn
	}
	legs := make([]leg, 0, relays)
	for i := 0; i < relays; i++ {
		sw, sr := relayDialPair(tb, l)
		dw, dr := relayDialPair(tb, l)
		legs = append(legs, leg{sw, sr, dw, dr})
	}

	// Two collections: the second clears sync.Pool's victim cache, so
	// relayBufPool holds nothing and the legacy arm must allocate for real.
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	stop := make(chan struct{}, relays)
	for i := range legs {
		lg := legs[i]
		go func() {
			shared := newTunnelActivityStamp()
			copyFn(lg.dstW, lg.srcR, lg.srcR, shared)
			stop <- struct{}{}
		}()
	}
	// Prove each relay is inside its copy: one byte in, one byte out.
	probe := []byte{0x5a}
	sink := make([]byte, 1)
	for i := range legs {
		if _, err := legs[i].srcW.Write(probe); err != nil {
			tb.Fatalf("relay %d probe write: %v", i, err)
		}
		if _, err := io.ReadFull(legs[i].dstR, sink); err != nil {
			tb.Fatalf("relay %d probe read: %v", i, err)
		}
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc {
		held = after.HeapAlloc - before.HeapAlloc
	}

	return held, func() {
		for i := range legs {
			_ = legs[i].srcW.Close()
			_ = legs[i].srcR.Close()
			_ = legs[i].dstW.Close()
			_ = legs[i].dstR.Close()
		}
		for i := 0; i < relays; i++ {
			<-stop
		}
		_ = l.Close()
	}
}

// relayDialPair is relayTestTCPPair without the tb.Cleanup registration — see
// relayHeldBytes for why a per-iteration harness must own its own closes.
func relayDialPair(tb testing.TB, l net.Listener) (dialed, accepted net.Conn) {
	tb.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := l.Accept()
		ch <- res{c, err}
	}()
	d, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		tb.Fatalf("accept: %v", r.err)
	}
	return d, r.c
}

// relayResidencyRelays is the population size every residency measurement uses.
// 48 directions is 192 file descriptors — comfortably inside a default ulimit —
// and 48 x 128 KB is ~6 MB against a measurement floor of a few hundred KB, so
// the legacy and current arms are separated by more than an order of magnitude.
const relayResidencyRelays = 48

// BenchmarkRelayResidency_Current and _Legacy report held bytes per open relay
// direction. b.N is irrelevant to the quantity (residency is not per-op), so
// each iteration re-measures a fresh population and the custom metric is what
// to read; keep -benchtime small (the default is fine).
func BenchmarkRelayResidency_Current(b *testing.B) {
	benchRelayResidency(b, idleCopyCounted)
}

func BenchmarkRelayResidency_Legacy(b *testing.B) {
	benchRelayResidency(b, idleCopyCountedLegacyAlwaysBuffered)
}

func benchRelayResidency(b *testing.B, copyFn relayCopyFunc) {
	var last uint64
	for i := 0; i < b.N; i++ {
		held, teardown := relayHeldBytes(b, relayResidencyRelays, copyFn)
		last = held
		teardown()
	}
	b.ReportMetric(float64(last)/float64(relayResidencyRelays), "held-B/relay")
	b.ReportMetric(float64(last)/(1024*1024), "held-MB/total")
}

// BenchmarkRelayBufferDecision measures the per-direction cost of the decision
// itself on the production pair — it must be free, since it replaces a pool Get
// that was not.
func BenchmarkRelayBufferDecision(b *testing.B) {
	l := relayTestListener(b)
	dst, src := relayTestTCPPair(b, l)
	b.ReportAllocs()
	b.ResetTimer()
	var reads bool
	for i := 0; i < b.N; i++ {
		reads = relayCopyReadsBuffer(dst, src)
	}
	if reads {
		b.Fatal("a TCPConn pair must not be the buffered shape")
	}
}

// BenchmarkRelayBufferAcquire_Legacy is the cost the decision replaces: one
// pool Get plus the Put, per relay direction, for a buffer the splice path
// never reads.
func BenchmarkRelayBufferAcquire_Legacy(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bp := getRelayBuf()
		relayBufPool.Put(bp)
	}
}

// BenchmarkRelayThroughput_Splice is the CONTROL: bytes/s through the real
// idleCopyCounted on the real production pair. The fix must not move it — the
// kernel splice is what makes a bypass tunnel fast, and "saving" the buffer by
// losing that path would show up here and nowhere else.
func BenchmarkRelayThroughput_Splice(b *testing.B) {
	benchRelayThroughput(b, idleCopyCounted)
}

func benchRelayThroughput(b *testing.B, copyFn relayCopyFunc) {
	const chunk = 256 * 1024
	l := relayTestListener(b)
	srcW, srcR := relayTestTCPPair(b, l)
	dstW, dstR := relayTestTCPPair(b, l)

	shared := newTunnelActivityStamp()
	relayDone := make(chan struct{})
	go func() { defer close(relayDone); copyFn(dstW, srcR, srcR, shared) }()

	payload := make([]byte, chunk)
	sink := make([]byte, chunk)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			if _, err := io.ReadFull(dstR, sink); err != nil {
				return
			}
		}
	}()

	b.SetBytes(chunk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := srcW.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	b.StopTimer()
	// Close the source half so the relay drains and both helpers exit before
	// the next arm runs; t.Cleanup closes the rest.
	_ = srcW.Close()
	_ = srcR.Close()
	<-relayDone
	_ = dstW.Close()
	<-drained
}

// BenchmarkRelayBufferDecisionParallel and BenchmarkRelayBufferAcquireParallel
// are the concurrency arms. Tunnel establishment is the burst-shaped part of a
// gateway's life — a connection storm brings relays up on every core at once —
// and what the decision REPLACED was a sync.Pool Get/Put pair, i.e. a shared
// structure on exactly that path. Two interface assertions on values already in
// registers have nothing to contend on; these two arms are what shows it, and
// what would expose a future buffer scheme that put a contended structure back.
func BenchmarkRelayBufferDecisionParallel(b *testing.B) {
	l := relayTestListener(b)
	dst, src := relayTestTCPPair(b, l)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var reads bool
		for pb.Next() {
			reads = relayCopyReadsBuffer(dst, src)
		}
		if reads {
			b.Error("a TCPConn pair must not be the buffered shape")
		}
	})
}

func BenchmarkRelayBufferAcquireParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bp := getRelayBuf()
			relayBufPool.Put(bp)
		}
	})
}

// BenchmarkRelayThroughput_SpliceLegacy is the same control through the frozen
// always-buffered body. The two must relay at the same rate: the predicate is
// io.copyBuffer's own condition for reaching its read loop, so neither arm's
// dispatch differs and only the buffer the delegated path ignores does. A gap
// here would mean the dispatch moved.
func BenchmarkRelayThroughput_SpliceLegacy(b *testing.B) {
	benchRelayThroughput(b, idleCopyCountedLegacyAlwaysBuffered)
}
