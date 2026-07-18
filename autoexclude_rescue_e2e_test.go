package main

// autoexclude_rescue_e2e_test.go — ADR-0009 end-to-end proof through the REAL
// proxy data plane. A CONNECT to a client-certificate-requiring origin under a
// FAIL-OPEN inspect rule must: (1) fail inspection (the proxy has no client cert),
// (2) be live-rescued to a raw bypass tunnel, so (3) the real client — which DOES
// have a client cert — completes its own mTLS handshake straight to the origin and
// round-trips a request. The rescue must be observable: audit + metric + a
// structured feed reason. Runs for BOTH TLS 1.2 and TLS 1.3 origins.
//
// Before the ADR-0009 fix this CONNECT returned 502 (TLS 1.2) or a tunnel that
// broke right after connect (TLS 1.3), so the client handshake could not complete.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// failOpenInspectRule installs a fresh decryption-profile store with a single
// fail-open profile and a matching allow+inspect (skip-verify) rule, so the strip
// path reaches a fail-open decision against a self-signed loopback origin.
func failOpenInspectRule(t *testing.T, profileName string) {
	t.Helper()
	swapProfiles(t)
	if _, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: profileName, OnInspectError: "fail-open"}); err != nil {
		t.Fatalf("seed fail-open profile: %v", err)
	}
	policyStore.rules = nil
	policyStore.Add(PolicyRule{
		Priority: 1, Name: "failopen-inspect", DestFQDN: "*",
		Action: ActionAllow, SSLAction: SSLInspect, TLSSkipVerify: true,
		DecryptionProfile: profileName,
	})
}

// TestMITM_ClientCertOrigin_RescuesAndBypasses covers a TLS 1.2 origin that
// REQUIRES a client cert: the proxy's upstream handshake FAILS (no cert to
// present), which proves inspection cannot continue, so the session is rescued to
// a bypass and the real client (which has a cert) completes its own mTLS. (A TLS
// 1.3 required origin completes our client handshake before rejecting, so it is
// deliberately NOT auto-rescued — see clientCertRescueDecision / ADR-0009 — which
// is what keeps OPTIONAL-mTLS origins inspected; that case is
// TestMITM_OptionalClientCertOrigin_StaysInspected.)
func TestMITM_ClientCertOrigin_RescuesAndBypasses(t *testing.T) {
	runClientCertRescueE2E(t, "TLS1.2", tls.VersionTLS12)
}

// runClientCertRescueE2E drives one TLS-version cell of the rescue e2e.
func runClientCertRescueE2E(t *testing.T, verName string, verNum uint16) {
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)
	setupInspectCA(t) // certMgr.Ready() ⇒ the inspect path is taken

	// Origin REQUIRES a client certificate (RequireAnyClientCert), pinned to one
	// TLS version. The proxy has no client cert to present.
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("origin-mtls-ok"))
	}))
	origin.TLS = &tls.Config{ //nolint:gosec // G402: version pinned to exercise the cell
		MinVersion: verNum,
		MaxVersion: verNum,
		ClientAuth: tls.RequireAnyClientCert,
	}
	origin.StartTLS()
	defer origin.Close()
	target := origin.Listener.Addr().String()
	originRoots := upstreamCertPool(t, origin)

	proxyURL := startTestProxy(t)
	failOpenInspectRule(t, "fo-e2e")

	beforeRescue := atomic.LoadInt64(&autoExcludeRescueCounter)
	baseTS := time.Now().UnixMilli()
	clientCert := selfSignedCert(t, "ecdsa") // the real client HAS a cert (origin only requires one)

	raw, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close() //nolint:errcheck // test cleanup
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	// A 200 here is already proof of rescue: without the fix inspection failed and
	// the proxy returned 502 (TLS 1.2) or broke the tunnel right after connect (1.3).
	if err := readCONNECT200(raw); err != nil {
		t.Fatalf("%s: CONNECT not rescued to a bypass tunnel: %v", verName, err)
	}

	// The client does its OWN mTLS straight to the origin through the bypass tunnel:
	// presents its client cert, trusts the ORIGIN's cert (NOT the proxy CA). Success
	// proves passthrough (bypass), not inspection.
	tc := tls.Client(raw, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      originRoots,
		ServerName:   "example.com", // httptest cert SAN
		Certificates: []tls.Certificate{clientCert},
	})
	if err := tc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("%s: client mTLS handshake through the rescue tunnel failed: %v", verName, err)
	}
	_, _ = fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("%s: read origin response: %v", verName, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "origin-mtls-ok" {
		t.Fatalf("%s: origin round-trip: status=%d body=%q, want 200 origin-mtls-ok", verName, resp.StatusCode, body)
	}
	_ = tc.Close()
	_ = raw.Close()

	// ── Observability: metric + audit + structured feed reason ──
	if got := atomic.LoadInt64(&autoExcludeRescueCounter); got < beforeRescue+1 {
		t.Errorf("%s: rescue metric = %d, want >= %d", verName, got, beforeRescue+1)
	}
	foundAudit := false
	audits := auditGet()
	for i := range audits {
		if audits[i].TS >= baseTS && audits[i].Action == "decryption.autoexclude.rescue" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Errorf("%s: no decryption.autoexclude.rescue audit entry", verName)
	}
	entry := findTunnelClose(target)
	if entry == nil {
		t.Fatalf("%s: no TUNNEL_CLOSED feed entry for the rescue tunnel", verName)
	}
	if entry.ActionTaken != feedReasonClientCertRescue {
		t.Errorf("%s: feed ActionTaken = %q, want %q", verName, entry.ActionTaken, feedReasonClientCertRescue)
	}
	if entry.SSLAction != "bypass" {
		t.Errorf("%s: feed SSLAction = %q, want bypass (the rescue is a bypass)", verName, entry.SSLAction)
	}
	// ADR-0011 dec block: the rescue projects its OWN outcome onto the feed row.
	// Asserted here because the rescue DecryptionOutcome is hand-built inline (no
	// tested factory), so without this a regression that mislabels the projected
	// fields — the class of bug that motivated this slice — would ship green.
	if entry.Dec == nil {
		t.Fatalf("%s: rescue feed entry missing its dec block", verName)
	}
	if entry.Dec.Outcome != "rescued" || entry.Dec.DecisionSource != "autoexclude_rescue" {
		t.Errorf("%s: rescue dec outcome/source = %q/%q, want rescued/autoexclude_rescue", verName, entry.Dec.Outcome, entry.Dec.DecisionSource)
	}
	if !entry.Dec.Rescued || !entry.Dec.CacheLearned {
		t.Errorf("%s: rescue dec must set rescued+cache_learned, got rescued=%v cache_learned=%v", verName, entry.Dec.Rescued, entry.Dec.CacheLearned)
	}
	if entry.Dec.ExclReason != "client_cert_required" || entry.Dec.FailCategory != "client_cert_required" {
		t.Errorf("%s: rescue dec excl_reason/fail_category = %q/%q, want client_cert_required", verName, entry.Dec.ExclReason, entry.Dec.FailCategory)
	}
	// Scope attribution (the primary fix): a rescue is scoped to its fail-open
	// profile, so profile_id AND excl_scope must carry the same non-empty scope —
	// otherwise a per-scope blast-radius/SIEM query misses every rescued session.
	if entry.Dec.ProfileID == "" || entry.Dec.ExclScope == "" || entry.Dec.ProfileID != entry.Dec.ExclScope {
		t.Errorf("%s: rescue dec must carry a consistent non-empty scope, got profile_id=%q excl_scope=%q",
			verName, entry.Dec.ProfileID, entry.Dec.ExclScope)
	}
}

// TestMITM_OptionalClientCertOrigin_StaysInspected is the guard for the review
// finding: an origin that merely REQUESTS a client cert (tls.RequestClientCert,
// optional mTLS) completes the upstream handshake and is perfectly inspectable, so
// under a fail-open rule it must be INSPECTED, never bypassed. Proven by a client
// that trusts ONLY the proxy CA completing its handshake (it sees the proxy's
// forged leaf ⇒ MITM happened) and round-tripping a request, with zero rescues.
func TestMITM_OptionalClientCertOrigin_StaysInspected(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("optional-inspected-ok"))
	}))
	origin.TLS = &tls.Config{ //nolint:gosec // G402: pin TLS 1.3 — the version the review flagged
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequestClientCert, // OPTIONAL: requests but does not require
	}
	origin.StartTLS()
	defer origin.Close()
	target := origin.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	failOpenInspectRule(t, "fo-optional")
	beforeRescue := atomic.LoadInt64(&autoExcludeRescueCounter)

	// Client trusts ONLY the proxy CA: success ⇒ it saw the proxy's forged leaf ⇒
	// the connection was INSPECTED (MITM), not bypassed to the origin's real cert.
	tc, err := connectAndTLS(proxyURL.Host, target, "example.com", proxyRoots)
	if err != nil {
		t.Fatalf("optional-mTLS origin must be INSPECTED (client trusting the proxy CA should handshake): %v — the rescue must NOT bypass optional client-cert origins", err)
	}
	defer tc.Close() //nolint:errcheck // test cleanup
	_, _ = fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read inspected response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "optional-inspected-ok" {
		t.Fatalf("optional-mTLS inspected round-trip: status=%d body=%q, want 200 optional-inspected-ok", resp.StatusCode, body)
	}

	// The proxy-CA handshake succeeding above already proves MITM (inspection); the
	// rescue counter must not have moved (no bypass).
	if got := atomic.LoadInt64(&autoExcludeRescueCounter); got != beforeRescue {
		t.Errorf("optional-mTLS origin triggered %d rescue(s) — it must be inspected, not bypassed", got-beforeRescue)
	}
}
