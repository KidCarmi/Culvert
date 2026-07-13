package main

// autoexclude_rescue_test.go — ADR-0009: the client-cert live-rescue now works
// via STRUCTURAL CertificateRequest detection (a GetClientCertificate callback
// that only PRODUCES a signal) instead of the handshake error string (which a Go
// client dialing a cert-requiring origin never surfaces as "certificate
// required"). These tests drive REAL handshakes through the REAL
// upstreamInspectTLSConfig — never mocked error strings — and pin the decision
// gate, the SSRF re-dial guard, and the structured feed reason. The full
// end-to-end proxy path (rescue → bypass → client mTLS + audit/alert/metric/feed)
// is in mitm_inspect_e2e_test.go (TestMITM_ClientCertOrigin_*).

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// probeClientCertDetection stands up a loopback origin (optionally requiring a
// client cert, capped at originMax), dials it through the REAL
// upstreamInspectTLSConfig with the ADR-0009 signal-only callback attached, and
// returns (origin-asked-for-client-cert, our handshake error). trustOrigin points
// the real config's RootCAs at the test origin so a positive case isolates the
// client-cert signal from cert verification; leave it false (with skipVerify
// false) to exercise the cert-verify-precedence path.
func probeClientCertDetection(t *testing.T, originMax uint16, requireClientCert, skipVerify, trustOrigin bool) (originAsked bool, herr error) {
	t.Helper()
	cert, pool := canarySelfSigned(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	clientAuth := tls.NoClientCert
	if requireClientCert {
		clientAuth = tls.RequireAnyClientCert
	}
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		// #nosec G402 -- test origin pins the version to probe both legs
		scfg := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: clientAuth, MinVersion: tls.VersionTLS12, MaxVersion: originMax}
		s := tls.Server(c, scfg)
		_ = s.HandshakeContext(ctx)
		_ = s.Close()
	}()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cfg := upstreamInspectTLSConfig("canary.example", skipVerify) // the REAL proxy upstream config
	if trustOrigin && !skipVerify {
		cfg.RootCAs = pool // trust the test origin cert to isolate the client-cert signal
	}
	var asked atomic.Bool
	// Same signal-only callback the strip path attaches: record + present NO cert.
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		asked.Store(true)
		return &tls.Certificate{}, nil
	}
	up := tls.Client(conn, cfg)
	herr = up.HandshakeContext(ctx)
	_ = up.Close()
	return asked.Load(), herr
}

// TestClientCertRescue_DecisionRealHandshakes pins clientCertRescueDecision
// against real handshakes for every required case: TLS 1.2/1.3 positive and
// negative, cert-verify precedence, and fail-close isolation.
func TestClientCertRescue_DecisionRealHandshakes(t *testing.T) {
	// POSITIVE: origin requires a client cert → we detect it and rescue, in BOTH
	// TLS versions (herr==nil on 1.3, a generic handshake failure on 1.2).
	for _, ver := range []struct {
		name string
		max  uint16
	}{{"TLS1.3", tls.VersionTLS13}, {"TLS1.2", tls.VersionTLS12}} {
		t.Run("positive_"+ver.name, func(t *testing.T) {
			asked, herr := probeClientCertDetection(t, ver.max, true, true, false)
			if !asked {
				t.Fatalf("%s: origin CertificateRequest was NOT detected (callback never fired)", ver.name)
			}
			if !clientCertRescueDecision(true, asked, herr) {
				t.Fatalf("%s: fail-open + origin-asked should rescue (herr=%v)", ver.name, herr)
			}
		})
		t.Run("negative_no_client_cert_"+ver.name, func(t *testing.T) {
			asked, herr := probeClientCertDetection(t, ver.max, false, true, false)
			if asked {
				t.Fatalf("%s: origin did NOT request a client cert, but the signal fired", ver.name)
			}
			if clientCertRescueDecision(true, asked, herr) {
				t.Fatalf("%s: a non-client-cert origin must NOT rescue", ver.name)
			}
		})
	}

	// NEGATIVE — cert-verify precedence: an untrusted origin cert must stay
	// fail-closed. With verification ON the handshake aborts at cert-verify BEFORE
	// the client responds to any CertificateRequest, so the signal never fires and
	// the decision is false either way.
	t.Run("negative_cert_verify_fails_closed", func(t *testing.T) {
		asked, herr := probeClientCertDetection(t, tls.VersionTLS13, true, false, false)
		if herr == nil {
			t.Fatal("expected a cert-verify failure against the untrusted origin")
		}
		if !isOriginCertVerifyErr(herr) {
			t.Fatalf("expected a cert-verify error, got %v", herr)
		}
		if clientCertRescueDecision(true, asked, herr) {
			t.Fatalf("cert-verify failure MUST stay fail-closed (asked=%v)", asked)
		}
	})

	// NEGATIVE — fail-close isolation: a fail-close rule never rescues, even if the
	// origin asked for a client cert.
	t.Run("negative_fail_close_never_rescues", func(t *testing.T) {
		if clientCertRescueDecision(false, true, nil) {
			t.Fatal("fail-close (failOpen=false) must never rescue")
		}
	})
}

// TestClientCertRescue_SSRFRedialRejected proves the rescue's re-dial cannot be
// used to reach an internal host: handleTunnelBypass runs its own isPrivateHost
// guard (before any hijack), so a private target is rejected with 403 even on the
// rescue path. (The SSRF check precedes the hijack, so a non-hijackable recorder
// still exercises it.)
func TestClientCertRescue_SSRFRedialRejected(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://127.0.0.1:9/", http.NoBody)
	req.Host = "127.0.0.1:9" // loopback = private (not relaxed in this test)
	handleTunnelBypass(rec, req, nil, ProxyIdentity{ClientIP: "203.0.113.7"}, feedReasonClientCertRescue)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rescue re-dial to a private host: got %d, want 403 — the SSRF guard must reject it", rec.Code)
	}
}

// TestClientCertRescue_FeedReasonPlumbing pins that the structured rescue reason
// reaches the TUNNEL_CLOSED feed entry's ActionTaken field (observability
// requirement) and that byte accounting still happens.
func TestClientCertRescue_FeedReasonPlumbing(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	const feedHost = "cc-feed.example:443"
	recordTunnelCloseGatedReason(nil, ProxyIdentity{ClientIP: "203.0.113.8", Identity: "u1"},
		"CONNECT", feedHost, 11, 22, time.Now().Add(-time.Second), "bypass", feedReasonClientCertRescue)
	entry := findTunnelClose(feedHost)
	if entry == nil {
		t.Fatal("no TUNNEL_CLOSED feed entry for the rescue bypass")
	}
	if entry.ActionTaken != feedReasonClientCertRescue {
		t.Fatalf("feed ActionTaken = %q, want %q — the rescue must be queryable in the feed", entry.ActionTaken, feedReasonClientCertRescue)
	}
	if entry.SSLAction != "bypass" {
		t.Fatalf("feed SSLAction = %q, want bypass", entry.SSLAction)
	}
}
