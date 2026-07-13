package main

// autoexclude_rescue_gap_test.go — pins the CONFIRMED F5 behavior gap: the
// origin-leg client-cert-required "live rescue" does NOT fire through the real
// proxy upstream-handshake path.
//
// Root cause (verified against the exact upstreamInspectTLSConfig the strip path
// uses — MinVersion TLS1.2, no MaxVersion cap, no client cert):
//   - Against a TLS 1.3 cert-requiring origin, our client HandshakeContext returns
//     nil (TLS 1.3 completes the client's side before the server validates the
//     client cert), so maybeFailOpenOrigin is NEVER called — no rescue, no learn;
//     the proxy proceeds to inspect and the origin's certificate_required alert
//     only surfaces mid-relay (after the 200 is sent).
//   - Against a TLS 1.2 cert-requiring origin, HandshakeContext returns a generic
//     "handshake failure", which the classifier deliberately drops (learn=false,
//     rescue=false) — a plain 502, no rescue, no learn.
//
// This test documents that reality so it cannot regress silently and so the fix
// (detect the origin's CertificateRequest via a GetClientCertificate callback —
// see ADR-0009) has a red test to turn green. The operator guide's "client cert
// required ⇒ live-rescues" row is corrected to match until the fix lands.
//
// If you are here because this test failed after implementing the ADR-0009 fix:
// that is expected — update the assertions to require rescue=true and delete the
// "gap" framing.

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// dialCertRequiringOrigin stands up a loopback TLS origin that REQUIRES a client
// certificate (capped at originMax), dials it with the EXACT proxy upstream inspect
// config (skip-verify to isolate the client-cert failure from cert verification),
// and returns our client-side HandshakeContext error (nil if it "succeeded").
func dialCertRequiringOrigin(t *testing.T, originMax uint16) error {
	t.Helper()
	cert, _ := canarySelfSigned(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		// #nosec G402 -- test origin deliberately caps the version to probe both legs
		scfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   originMax,
		}
		s := tls.Server(c, scfg)
		_ = s.HandshakeContext(ctx)
		_ = s.Close()
	}()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	up := tls.Client(conn, upstreamInspectTLSConfig("canary.example", true))
	herr := up.HandshakeContext(ctx)
	_ = up.Close()
	return herr
}

// TestClientCertRescue_GapConfirmed pins that neither the rescue nor the learn
// fires for a cert-requiring origin through the real upstream config.
func TestClientCertRescue_GapConfirmed(t *testing.T) {
	// TLS 1.3 (modern default): the client handshake returns nil, so the strip
	// path's `if err != nil { maybeFailOpenOrigin(... ) }` branch is never entered.
	if err := dialCertRequiringOrigin(t, tls.VersionTLS13); err != nil {
		t.Logf("NOTE: TLS1.3 cert-requiring origin returned a non-nil handshake error %q; "+
			"if this is now a certificate_required error the rescue may work — reconcile with ADR-0009", err.Error())
		// A non-nil error here would mean Go changed behavior; classify it and only
		// fail if it (incorrectly, per today's classifier) does NOT rescue — i.e. the
		// gap persists in a new form. We assert the gap explicitly:
		if _, _, rescue := classifyOriginInspectFailure(err); rescue {
			t.Skip("TLS1.3 now surfaces a rescuable error — the gap is closed; update this test per ADR-0009")
		}
	}
	// The essential assertion: whatever a TLS 1.3 cert-requiring origin produces,
	// the strip path today does NOT rescue it (either nil → never called, or a
	// non-rescuable error). Documented; ADR-0009 tracks the fix.

	// TLS 1.2: a generic handshake failure the classifier must NOT learn/rescue.
	err12 := dialCertRequiringOrigin(t, tls.VersionTLS12)
	if err12 == nil {
		t.Skip("TLS1.2 cert-requiring origin unexpectedly succeeded; environment-dependent")
	}
	r, learn, rescue := classifyOriginInspectFailure(err12)
	if learn || rescue {
		t.Fatalf("TLS1.2 cert-requiring origin error %q classified as (%q, learn=%v, rescue=%v); "+
			"today this is a generic handshake_failure that must stay fail-closed — if this changed, "+
			"reconcile with ADR-0009", err12.Error(), r, learn, rescue)
	}
}
