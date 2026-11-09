package main

// proxy_tunnel_relaybuf_test.go — correctness contract for the relay copy's
// buffer decision (relayCopyReadsBuffer, proxy_tunnel.go).
//
// The optimization it guards is a NEGATIVE one: the relay stops checking a
// 128 KB pooled buffer out of relayBufPool for pairs whose copy never reads it.
// Two things therefore have to be proved, and neither is provable by inspection
// of the predicate alone:
//
//  1. the predicate agrees with what io.CopyBuffer ACTUALLY does — established
//     here by a differential oracle that hands io.CopyBuffer a sentinel-filled
//     buffer and checks whether the bytes moved, rather than by restating the
//     interface assertions the predicate itself makes; and
//  2. a pair that DOES need a buffer still relays every byte.
//
// The oracle is what makes the change safe against a future Go release that
// changes io.copyBuffer's dispatch or adds WriteTo/ReadFrom to another type:
// the predicate and the behaviour are compared, so drift fails here instead of
// silently reintroducing a 32 KB per-call allocation on a relay hot path.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

// relayTestListener returns a loopback TCP listener closed at test end.
func relayTestListener(tb testing.TB) net.Listener {
	tb.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	tb.Cleanup(func() { _ = l.Close() })
	return l
}

// relayTestTCPPair dials l and returns both ends of the accepted connection.
// Both are *net.TCPConn — the concrete type on the CONNECT-bypass relay, and
// the reason the production path never reads a relay buffer.
func relayTestTCPPair(tb testing.TB, l net.Listener) (dialed, accepted net.Conn) {
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
	tb.Cleanup(func() { _ = d.Close(); _ = r.c.Close() })
	return d, r.c
}

// TestRelayCopyReadsBuffer_MirrorsIOCopyDispatch is the differential oracle:
// for every pair shape the relay can see, the predicate's answer must equal
// whether io.CopyBuffer actually TOUCHED the buffer it was handed.
//
// The payload is larger than the sentinel buffer slot being watched so a copy
// that goes through the buffer cannot miss it, and non-zero-filled so a read
// into a zeroed region is still detectable.
func TestRelayCopyReadsBuffer_MirrorsIOCopyDispatch(t *testing.T) {
	l := relayTestListener(t)

	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	cases := []struct {
		name string
		// build returns the dst/src pair plus a func that feeds the payload in
		// and a func that returns what arrived at dst.
		build func(t *testing.T) (dst io.Writer, src io.Reader, feed func(), drain func() []byte)
	}{
		{
			name: "TCPConn<-TCPConn (CONNECT bypass)",
			build: func(t *testing.T) (io.Writer, io.Reader, func(), func() []byte) {
				srcW, srcR := relayTestTCPPair(t, l) // payload written to srcW, read from srcR
				dstW, dstR := relayTestTCPPair(t, l) // relay writes to dstW, test reads dstR
				return dstW, srcR,
					func() { go func() { _, _ = srcW.Write(payload); _ = srcW.(*net.TCPConn).CloseWrite() }() },
					func() []byte { return relayDrain(t, dstR, len(payload)) }
			},
		},
		{
			name: "TCPConn<-bufio.Reader (WebSocket)",
			build: func(t *testing.T) (io.Writer, io.Reader, func(), func() []byte) {
				srcW, srcR := relayTestTCPPair(t, l)
				dstW, dstR := relayTestTCPPair(t, l)
				return dstW, bufio.NewReader(srcR),
					func() { go func() { _, _ = srcW.Write(payload); _ = srcW.(*net.TCPConn).CloseWrite() }() },
					func() []byte { return relayDrain(t, dstR, len(payload)) }
			},
		},
		{
			name: "pipe<-pipe (neither interface)",
			build: func(t *testing.T) (io.Writer, io.Reader, func(), func() []byte) {
				srcW, srcR := net.Pipe()
				dstW, dstR := net.Pipe()
				t.Cleanup(func() { _ = srcW.Close(); _ = srcR.Close(); _ = dstW.Close(); _ = dstR.Close() })
				return dstW, srcR,
					func() { go func() { _, _ = srcW.Write(payload); _ = srcW.Close() }() },
					func() []byte { return relayDrain(t, dstR, len(payload)) }
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst, src, feed, drain := tc.build(t)
			predicted := relayCopyReadsBuffer(dst, src)

			// A sentinel buffer the same size the relay would pool, filled with
			// a byte the payload may also contain — the comparison is against
			// the whole sentinel, so a partial read is still a mismatch.
			buf := bytes.Repeat([]byte{0xA5}, relayBufSize)
			sentinel := bytes.Clone(buf)

			feed()
			var got []byte
			var wg sync.WaitGroup
			wg.Add(1)
			go func() { defer wg.Done(); got = drain() }()
			if _, err := io.CopyBuffer(dst, src, buf); err != nil && err != io.EOF {
				t.Logf("copy returned %v (expected on peer close)", err)
			}
			switch c := dst.(type) {
			case interface{ CloseWrite() error }:
				_ = c.CloseWrite()
			case io.Closer:
				_ = c.Close()
			}
			wg.Wait()

			touched := !bytes.Equal(buf, sentinel)
			if touched != predicted {
				t.Errorf("relayCopyReadsBuffer said %v but io.CopyBuffer %s the buffer — "+
					"the predicate no longer mirrors io.copyBuffer's WriterTo/ReaderFrom dispatch. "+
					"idleCopyCounted decides from this predicate whether to check a %d-byte buffer "+
					"out of relayBufPool, so a false negative means a per-call allocation on a relay "+
					"hot path and a false positive means a pinned buffer nothing reads.",
					predicted, map[bool]string{true: "READ", false: "never touched"}[touched], relayBufSize)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("relayed payload differs: got %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

// relayDrain reads exactly want bytes (or until EOF) from c.
func relayDrain(tb testing.TB, c net.Conn, want int) []byte {
	tb.Helper()
	out := make([]byte, 0, want)
	b := make([]byte, 32*1024)
	for len(out) < want {
		n, err := c.Read(b)
		out = append(out, b[:n]...)
		if err != nil {
			break
		}
	}
	return out
}

// TestRelaySlowPathStillRelaysEveryByte is the negative control for the
// optimization: a pair that needs a buffer must still move the whole payload
// through idleCopyCounted, which is the function that now decides whether to
// take one. net.Pipe implements neither io.WriterTo nor io.ReaderFrom, so it is
// the shape that still reaches io.CopyBuffer's own read loop.
func TestRelaySlowPathStillRelaysEveryByte(t *testing.T) {
	srcW, srcR := net.Pipe()
	dstW, dstR := net.Pipe()
	defer func() { _ = srcW.Close(); _ = srcR.Close(); _ = dstW.Close(); _ = dstR.Close() }()

	if !relayCopyReadsBuffer(dstW, srcR) {
		t.Fatal("test premise broken: a net.Pipe pair must be the buffered shape")
	}

	payload := bytes.Repeat([]byte("culvert-relay-slow-path-"), 4096) // ~96 KB
	go func() { _, _ = srcW.Write(payload); _ = srcW.Close() }()

	var got []byte
	done := make(chan struct{})
	go func() { defer close(done); got = relayDrain(t, dstR, len(payload)) }()

	shared := newTunnelActivityStamp()
	n := idleCopyCounted(dstW, srcR, srcR, shared)
	_ = dstW.Close()
	<-done

	if n != int64(len(payload)) {
		t.Errorf("idleCopyCounted counted %d bytes, want %d", n, len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("slow-path relay corrupted the payload: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestRelayBypassPreservesBothDirections exercises the real bidirectional
// entry point on the real production types, so the buffer decision is proved
// through bidiRelayCounted rather than through idleCopyCounted alone — both
// directions, both byte counts.
func TestRelayBypassPreservesBothDirections(t *testing.T) {
	l := relayTestListener(t)
	clientSide, clientConn := relayTestTCPPair(t, l) // "client" <-> proxy
	destConn, destSide := relayTestTCPPair(t, l)     // proxy <-> "dest"

	up := bytes.Repeat([]byte("up->"), 8192)     // 32 KB client → dest
	down := bytes.Repeat([]byte("<-down"), 8192) // 48 KB dest → client

	var wg sync.WaitGroup
	wg.Add(4)
	var gotUp, gotDown []byte
	go func() { defer wg.Done(); _, _ = clientSide.Write(up); _ = clientSide.(*net.TCPConn).CloseWrite() }()
	go func() { defer wg.Done(); _, _ = destSide.Write(down); _ = destSide.(*net.TCPConn).CloseWrite() }()
	go func() { defer wg.Done(); gotUp = relayDrain(t, destSide, len(up)) }()
	go func() { defer wg.Done(); gotDown = relayDrain(t, clientSide, len(down)) }()

	// Same argument order as handleTunnelBypass: (destConn, clientConn, clientConn, destConn).
	toDest, toClient := bidiRelayCounted(destConn, clientConn, clientConn, destConn)
	wg.Wait()

	if !bytes.Equal(gotUp, up) {
		t.Errorf("client→dest corrupted: got %d bytes, want %d", len(gotUp), len(up))
	}
	if !bytes.Equal(gotDown, down) {
		t.Errorf("dest→client corrupted: got %d bytes, want %d", len(gotDown), len(down))
	}
	if toDest != int64(len(up)) || toClient != int64(len(down)) {
		t.Errorf("byte accounting drifted: toDest=%d (want %d), toClient=%d (want %d) — "+
			"recordTunnelCloseGated bills the operator from these counts",
			toDest, len(up), toClient, len(down))
	}
}
