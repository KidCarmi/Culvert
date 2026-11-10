package main

// proxy_tunnel_inspectbuf_bench_test.go — evidence for inspectLoopReadBufSize
// (proxy_tunnel.go).
//
// These benchmarks PRICE the shipped size; they do not justify a change to it.
// The size is load-bearing for the chunked-trailer window an inspected tunnel
// accepts (see the rationale on inspectLoopReadBufSize and
// TestInspectLoopReadBuf_TrailerWindowIsLoadBearing), so what the numbers below
// establish is what that window costs — the input the proxy/inspection owner
// needs, not a saving available on performance grounds.
//
// Two quantities, in this order of importance:
//
//  1. RESIDENCY — the cost. Both of runH1InspectLoop's readers are built at
//     tunnel establishment and live until the tunnel closes, so their buffers
//     are resident heap multiplied by the concurrent inspected-tunnel count —
//     the scalability quantity an inspecting gateway is bought for. allocs/op
//     cannot see it, because it is one allocation per tunnel that simply never
//     goes away, which is why the repository's existing per-request allocation
//     gates say nothing about it. The _Shrunk4K arm is the counterfactual.
//
//  2. THROUGHPUT AND PARSE LATENCY — recorded to CLOSE that question, not to
//     justify anything. The refill rate on these readers is set by the TLS
//     record size, not by the buffer (tls.Conn.Read returns at most one record),
//     so the size is not a throughput knob in either direction. Measured on a
//     REAL handshaked TLS pair over TCP loopback, because an in-memory pipe has
//     no record boundary.
//
// The shipped arm goes through the production constructor
// (newInspectLoopReaders), not through a local bufio.NewReaderSize with the same
// constant: that way a future change to how production builds these readers is
// inside what these benchmarks measure.
//
//	go test -run '^$' -bench 'InspectReadBuf|InspectReadRequest|InspectBodyReadThrough' -benchtime=2s -count=3 .

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

// newInspectLoopReadersShrunk is the HYPOTHETICAL memory-motivated pair: two
// readers at net/http's own default size for these two roles. It is here to
// price the shipped size, not as a candidate — shrinking to it narrows the
// chunked-trailer window an inspected tunnel accepts, which is what
// TestInspectLoopReadBuf_TrailerWindowIsLoadBearing demonstrates.
func newInspectLoopReadersShrunk(clientTLS, upstreamTLS io.Reader) (clientBR, upstreamBR *bufio.Reader) {
	return bufio.NewReaderSize(clientTLS, inspectLoopReadBufShrunkSize),
		bufio.NewReaderSize(upstreamTLS, inspectLoopReadBufShrunkSize)
}

// inspectReaderCtor is the shape both arms share.
type inspectReaderCtor func(clientTLS, upstreamTLS io.Reader) (*bufio.Reader, *bufio.Reader)

// inspectResidencyTunnels is the population every residency measurement uses.
// 48 tunnels is 2 conn pairs each — 192 file descriptors, inside a default
// ulimit — and 48 x 64 KiB is ~3 MB for the legacy arm against a MemStats floor
// of a few hundred bytes per tunnel, so the two arms are separated by more than
// an order of magnitude.
const inspectResidencyTunnels = 48

// inspectBufHeldBytes populates `tunnels` inspected-tunnel reader PAIRS through
// ctor and returns the live heap they hold.
//
// What is measured and what is not. Each tunnel gets two real loopback conns —
// the same two in both arms — and the reader pair the loop would build over
// them. The conns, their kernel buffers and (in production) the two tls.Conns
// are IDENTICAL between the arms, so they cancel in the before/after comparison
// and are deliberately left out of the absolute figure: the quantity this change
// controls is the two bufio buffers, and including per-tunnel cost it does not
// control would only make the ceiling harder to read.
//
// Deliberately NOT tb.Cleanup: a benchmark calls this once per b.N iteration,
// and deferring 2 closes per tunnel to the end of a long -benchtime would
// exhaust file descriptors. Every socket opened here is closed by the returned
// teardown, so the resource high-water mark is one population.
func inspectBufHeldBytes(tb testing.TB, tunnels int, ctor inspectReaderCtor) (held uint64, teardown func()) {
	tb.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}

	type tunnel struct {
		clientW, clientR net.Conn
		upW, upR         net.Conn
	}
	tuns := make([]tunnel, 0, tunnels)
	for i := 0; i < tunnels; i++ {
		cw, cr := relayDialPair(tb, l)
		uw, ur := relayDialPair(tb, l)
		tuns = append(tuns, tunnel{cw, cr, uw, ur})
	}

	// Two collections before the baseline so no deferred sweep work from
	// establishing the conns lands inside the measured window.
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	readers := make([]*bufio.Reader, 0, tunnels*2)
	for i := range tuns {
		cbr, ubr := ctor(tuns[i].clientR, tuns[i].upR)
		readers = append(readers, cbr, ubr)
	}
	// Prove every reader is live and wired to its conn: one byte in, one byte
	// read back THROUGH the reader. A population of readers that were never
	// used would still hold their buffers (bufio allocates eagerly), but it
	// would not be the production object graph.
	for i := range tuns {
		if _, werr := tuns[i].clientW.Write([]byte{0x5a}); werr != nil {
			tb.Fatalf("tunnel %d client probe write: %v", i, werr)
		}
		if _, werr := tuns[i].upW.Write([]byte{0x5a}); werr != nil {
			tb.Fatalf("tunnel %d upstream probe write: %v", i, werr)
		}
	}
	for i, br := range readers {
		if b, rerr := br.ReadByte(); rerr != nil || b != 0x5a {
			tb.Fatalf("reader %d probe read: byte %#x err %v", i, b, rerr)
		}
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc {
		held = after.HeapAlloc - before.HeapAlloc
	}
	runtime.KeepAlive(readers)

	return held, func() {
		for i := range tuns {
			tuns[i].clientW.Close() //nolint:errcheck // teardown
			tuns[i].clientR.Close() //nolint:errcheck // teardown
			tuns[i].upW.Close()     //nolint:errcheck // teardown
			tuns[i].upR.Close()     //nolint:errcheck // teardown
		}
		l.Close() //nolint:errcheck // teardown
	}
}

func benchInspectResidency(b *testing.B, ctor inspectReaderCtor) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		held, teardown := inspectBufHeldBytes(b, inspectResidencyTunnels, ctor)
		b.ReportMetric(float64(held)/float64(inspectResidencyTunnels), "held-B/tunnel")
		teardown()
	}
}

// BenchmarkInspectReadBufResidency_Shipped measures what an open inspected
// tunnel's reader pair holds at the shipped size — the memory price of the
// chunked-trailer window that size buys.
func BenchmarkInspectReadBufResidency_Shipped(b *testing.B) {
	benchInspectResidency(b, newInspectLoopReaders)
}

// BenchmarkInspectReadBufResidency_Shrunk4K is the same measurement at
// net/http's own default size. The gap between the two is what the trailer
// window costs per concurrent inspected tunnel — the number the proxy/inspection
// owner needs in order to decide, not a saving this change takes.
func BenchmarkInspectReadBufResidency_Shrunk4K(b *testing.B) {
	benchInspectResidency(b, newInspectLoopReadersShrunk)
}

// ── throughput / latency controls, on a real TLS pair ────────────────────────

// inspectTLSPair returns a fully handshaked (server, client) *tls.Conn pair over
// TCP loopback, using a forged leaf from the in-memory bench CA — i.e. the same
// kind of conn runH1InspectLoop's readers sit on. A real conn (not net.Pipe) is
// required: TLS record framing over a socket is what sets the refill rate these
// benchmarks exist to compare.
func inspectTLSPair(tb testing.TB, pool *x509.CertPool) (srv, cli *tls.Conn) {
	tb.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	defer l.Close() //nolint:errcheck // the accepted/dialled conns outlive it

	type res struct {
		c   *tls.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		raw, aerr := l.Accept()
		if aerr != nil {
			ch <- res{nil, aerr}
			return
		}
		s := tls.Server(raw, mitmClientTLSConfig)
		if herr := s.HandshakeContext(context.Background()); herr != nil {
			ch <- res{nil, herr}
			return
		}
		ch <- res{s, nil}
	}()

	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	c := tls.Client(raw, &tls.Config{ServerName: "bench.example.com", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if herr := c.HandshakeContext(context.Background()); herr != nil {
		tb.Fatalf("client handshake: %v", herr)
	}
	r := <-ch
	if r.err != nil {
		tb.Fatalf("server handshake: %v", r.err)
	}
	return r.c, c
}

// inspectBenchInnerRequest is a realistic decrypted inner request: a browser's
// header set, ~650 bytes, comfortably inside either buffer size. The point of
// the measurement is not a pathological header block (parity for those is pinned
// by the differential oracle) but the ORDINARY request, which is what a latency
// claim has to be about.
const inspectBenchInnerRequest = "GET /some/path/resource.json HTTP/1.1\r\n" +
	"Host: www.example.com\r\n" +
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
	"Accept-Language: en-US,en;q=0.9\r\n" +
	"Accept-Encoding: gzip, deflate, br\r\n" +
	"Cookie: sid=0123456789abcdef0123456789abcdef; prefs=aaaabbbbccccdddd; tracking=xxxxyyyyzzzz\r\n" +
	"Referer: https://www.example.com/index.html\r\n" +
	"Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Site: same-origin\r\n" +
	"\r\n"

// feedTLS writes payload to cli in a loop until stop closes, so the reader under
// measurement never starves. The writer is the same in both arms.
func feedTLS(cli *tls.Conn, payload []byte, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		if _, err := cli.Write(payload); err != nil {
			return
		}
	}
}

func benchInspectReadRequest(b *testing.B, ctor inspectReaderCtor) {
	pool := installBenchCA(b)
	srv, cli := inspectTLSPair(b, pool)
	defer srv.Close() //nolint:errcheck // bench teardown
	defer cli.Close() //nolint:errcheck // bench teardown

	stop := make(chan struct{})
	go feedTLS(cli, []byte(inspectBenchInnerRequest), stop)

	// The pair's second reader is built too, so both arms carry the same object
	// graph; only the first is read from.
	clientBR, _ := ctor(srv, strings.NewReader(""))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			b.Fatalf("ReadRequest: %v", err)
		}
		runtime.KeepAlive(req)
	}
	b.StopTimer()
	close(stop)
}

// BenchmarkInspectReadRequest_Shipped / _Shrunk4K: the per-inner-request parse
// cost at both sizes. Recorded so the next reader does not re-measure it: the
// size is NOT a throughput decision, so if it is ever changed, it will be for
// the trailer window and the memory, not for these numbers.
func BenchmarkInspectReadRequest_Shipped(b *testing.B) {
	benchInspectReadRequest(b, newInspectLoopReaders)
}

func BenchmarkInspectReadRequest_Shrunk4K(b *testing.B) {
	benchInspectReadRequest(b, newInspectLoopReadersShrunk)
}

// inspectBodyChunk is the read size the consumer asks for. 1 KiB is chosen
// against this change's interest: it is SMALLER than either buffer, so every
// read is served from the buffer and the buffer's size sets the refill
// frequency. A bulk consumer asking for >= the buffer size bypasses the buffer
// entirely at both sizes, which would be a flattering shape to measure.
const inspectBodyChunk = 1024

func benchInspectBodyReadThrough(b *testing.B, ctor inspectReaderCtor) {
	pool := installBenchCA(b)
	srv, cli := inspectTLSPair(b, pool)
	defer srv.Close() //nolint:errcheck // bench teardown
	defer cli.Close() //nolint:errcheck // bench teardown

	payload := make([]byte, 256*1024)
	stop := make(chan struct{})
	go feedTLS(cli, payload, stop)

	clientBR, _ := ctor(srv, strings.NewReader(""))
	dst := make([]byte, inspectBodyChunk)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		read := 0
		for read < len(payload) {
			n, err := clientBR.Read(dst)
			if err != nil {
				b.Fatalf("Read: %v", err)
			}
			read += n
		}
	}
	b.StopTimer()
	close(stop)
}

// BenchmarkInspectBodyReadThrough_Shipped / _Shrunk4K: the bandwidth arm, at a
// consumer read size SMALLER than either buffer, so the buffer is actually used
// rather than bypassed. Also no ordering — see the header comment.
func BenchmarkInspectBodyReadThrough_Shipped(b *testing.B) {
	benchInspectBodyReadThrough(b, newInspectLoopReaders)
}

func BenchmarkInspectBodyReadThrough_Shrunk4K(b *testing.B) {
	benchInspectBodyReadThrough(b, newInspectLoopReadersShrunk)
}
