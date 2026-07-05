package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// installBenchCA installs a fresh in-memory CA into certMgr and returns a pool
// trusting its forged leaves. tb is *testing.T or *testing.B.
func installBenchCA(tb testing.TB) *x509.CertPool {
	tb.Helper()
	prev := certMgr
	cm := ca.New()
	if err := cm.InitCA(); err != nil {
		tb.Fatalf("InitCA: %v", err)
	}
	certMgr = cm
	tb.Cleanup(func() { certMgr = prev })
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cm.CACertPEM()) {
		tb.Fatal("append CA PEM")
	}
	return pool
}

// mitmHandshake runs one client↔proxy(forged-leaf) TLS handshake over an
// in-memory pipe: the proxy side uses serverCfg (the code under test), the
// client trusts the CA pool and uses clientCache for resumption. After the
// handshake it flushes one byte each way so the client consumes the TLS 1.3
// NewSessionTicket (required for the NEXT connection to resume). Returns whether
// the client resumed this handshake.
func mitmHandshake(tb testing.TB, serverCfg *tls.Config, pool *x509.CertPool, clientCache tls.ClientSessionCache) bool {
	cConn, sConn := net.Pipe()
	srv := tls.Server(sConn, serverCfg)
	cli := tls.Client(cConn, &tls.Config{
		ServerName:         "bench.example.com",
		RootCAs:            pool,
		ClientSessionCache: clientCache,
		MinVersion:         tls.VersionTLS12,
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.HandshakeContext(context.Background()); err != nil {
			return
		}
		_, _ = srv.Write([]byte{0}) // flush session ticket(s) to the client
		// Tear down via the RAW pipe conn, not srv.Close(): tls.Conn.Close
		// sends a close_notify alert with a fixed 5s write deadline, and over
		// an unread net.Pipe both peers' alerts deadlock and wait out the full
		// 5s — a pure test artifact that would dwarf the ~1ms handshake.
		_ = sConn.Close()
	}()

	if err := cli.HandshakeContext(context.Background()); err != nil {
		tb.Fatalf("client handshake: %v", err)
	}
	resumed := cli.ConnectionState().DidResume
	buf := make([]byte, 1)
	_, _ = cli.Read(buf) // consume the NewSessionTicket → populates clientCache
	_ = cConn.Close()
	<-done
	return resumed
}

// TestMITMClientResumption proves perf-F2: the SHARED mitmClientTLSConfig lets a
// returning client resume (stable session-ticket keys), while a fresh
// per-connection config — the pre-F2 behavior — cannot (rotated keys), so it
// full-handshakes every time.
func TestMITMClientResumption(t *testing.T) {
	pool := installBenchCA(t)

	// Shared config (the fix): first connection is full, subsequent ones resume.
	t.Run("shared config resumes", func(t *testing.T) {
		cache := tls.NewLRUClientSessionCache(8)
		if mitmHandshake(t, mitmClientTLSConfig, pool, cache) {
			t.Fatal("first handshake must NOT resume (cold cache)")
		}
		if !mitmHandshake(t, mitmClientTLSConfig, pool, cache) {
			t.Fatal("second handshake against the shared config MUST resume — F2 regression")
		}
	})

	// Per-connection config (pre-F2): even with a warm client cache, a fresh
	// server config each time cannot decrypt the client's ticket → never resumes.
	t.Run("per-connection config never resumes", func(t *testing.T) {
		cache := tls.NewLRUClientSessionCache(8)
		perConn := func() *tls.Config {
			return &tls.Config{
				GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return certMgr.GetCert(chi) },
				MinVersion:     tls.VersionTLS12,
				NextProtos:     []string{"http/1.1"},
			}
		}
		_ = mitmHandshake(t, perConn(), pool, cache)
		if mitmHandshake(t, perConn(), pool, cache) {
			t.Fatal("a fresh per-connection config must NOT resume (this is the waste F2 removes)")
		}
	})
}

// TestMITMResumptionEndsOnCAChange proves the CA-epoch fix for the Codex P2:
// once the Root CA changes, an outstanding TLS session ticket can no longer
// resume (ca.CAChangedObserver → rotateMITMTicketKeys flushes the shared
// config's ticket keys), so the client is forced to full-handshake and
// re-present a leaf under the NEW CA. Resumption then re-establishes within the
// new epoch. Without the flush, step 3 would resume under the old-CA session.
func TestMITMResumptionEndsOnCAChange(t *testing.T) {
	pool1 := installBenchCA(t) // certMgr = CA #1; also flushes ticket keys via InitCA
	cache := tls.NewLRUClientSessionCache(8)

	// Epoch 1: prime a resumable session under CA #1.
	if mitmHandshake(t, mitmClientTLSConfig, pool1, cache) {
		t.Fatal("first handshake must NOT resume (cold cache)")
	}
	if !mitmHandshake(t, mitmClientTLSConfig, pool1, cache) {
		t.Fatal("second handshake under CA #1 MUST resume")
	}

	// Rotate the Root CA. InitCA fires ca.CAChangedObserver, which flushes the
	// MITM ticket keys, ending epoch 1. Rebuild the client trust pool for CA #2
	// so the full handshake can still verify (we are isolating resumption, not
	// trust).
	if err := certMgr.InitCA(); err != nil {
		t.Fatalf("rotate InitCA: %v", err)
	}
	pool2 := x509.NewCertPool()
	if !pool2.AppendCertsFromPEM(certMgr.CACertPEM()) {
		t.Fatal("append CA #2 PEM")
	}

	// Epoch 2, first handshake: the client still offers its stale CA #1 ticket,
	// but the flushed ticket keys can't decrypt it → full handshake, no resume.
	if mitmHandshake(t, mitmClientTLSConfig, pool2, cache) {
		t.Fatal("P2 regression: resumed a session across a CA change — ticket keys were not flushed")
	}
	// Resumption works again within epoch 2.
	if !mitmHandshake(t, mitmClientTLSConfig, pool2, cache) {
		t.Fatal("handshake under CA #2 MUST resume once the new epoch is primed")
	}
}

// BenchmarkMITMClientHandshake_Shared measures the steady-state client-facing
// handshake with the shared config: after a warm-up connection, every handshake
// resumes (skips ECDHE + cert send + signature).
func BenchmarkMITMClientHandshake_Shared(b *testing.B) {
	pool := installBenchCA(b)
	cache := tls.NewLRUClientSessionCache(64)
	_ = mitmHandshake(b, mitmClientTLSConfig, pool, cache) // warm the cache
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !mitmHandshake(b, mitmClientTLSConfig, pool, cache) {
			b.Fatal("expected resumption in steady state")
		}
	}
}

// BenchmarkMITMClientHandshake_PerConn measures the pre-F2 behavior: a fresh
// config per connection, so every handshake is full (no resumption). The delta
// vs _Shared is the F2 win.
func BenchmarkMITMClientHandshake_PerConn(b *testing.B) {
	pool := installBenchCA(b)
	cache := tls.NewLRUClientSessionCache(64)
	perConn := func() *tls.Config {
		return &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return certMgr.GetCert(chi) },
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"http/1.1"},
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mitmHandshake(b, perConn(), pool, cache)
	}
}
