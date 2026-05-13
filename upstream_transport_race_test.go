package main

// upstream_transport_race_test.go — P5.3 / S6 Category A lab tests
// from roadmap/UPSTREAM-TRANSPORT-LAB-PLAN.md.
//
// These tests drive HTTP/S traffic through getUpstreamTransport()
// concurrently with the production mutator paths (applyUpstreamProxy,
// applyHotReload, apiOCSPConfig) and rely on -race to flag any
// unsynchronized write to a published transport.
//
// They are designed to fail under -race on pre-P5.3 main (where the
// in-place mutation races against http.Transport.RoundTrip's reads)
// and pass on this branch (where every mutation is a swap onto a
// freshly-built transport).
//
// Iteration counts follow roadmap/UPSTREAM-TRANSPORT-LAB-PLAN.md §4.2:
//   - Lightweight HTTP / proxy churn: up to 1000 traffic iters.
//   - Heavier HTTPS / TLS-handshake: 100–250 traffic iters.
// All tests are bounded; total wall-clock budget per test under -race
// must stay ≤ ~5 s.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	a1TrafficIters  = 1000
	a1MutationIters = 100
	a2TrafficIters  = 200
	a2MutationIters = 100
	a3TrafficIters  = 1000
	a3MutationIters = 100
	a4TrafficIters  = 200
	a4MutationIters = 100
)

// snapshotForRaceTests captures and restores the package globals
// the lab tests mutate. P5.3 test-side discipline: snapshot via
// Load(), restore via Store(), never mutate fields on a published
// transport. Also snapshots upstreamOpTLSCfg (operator's TLS
// template) which is held under upstreamTransportWriteMu.
func snapshotForRaceTests(t *testing.T) {
	t.Helper()
	origPtr := upstreamTransportPtr.Load()
	origOCSP := globalOCSP.Enabled()
	upstreamTransportWriteMu.Lock()
	origOpTLS := upstreamOpTLSCfg
	// Clear at start so tests don't inherit state from a prior test.
	upstreamOpTLSCfg = nil
	upstreamTransportWriteMu.Unlock()
	t.Cleanup(func() {
		upstreamTransportPtr.Store(origPtr)
		upstreamTransportWriteMu.Lock()
		upstreamOpTLSCfg = origOpTLS
		upstreamTransportWriteMu.Unlock()
		if origOCSP {
			globalOCSP.Enable()
		} else {
			globalOCSP.Disable()
		}
		upstreamPool.Configure(nil, 0, 0)
	})
}

// httptestRootCAs returns a *x509.CertPool that trusts the given
// httptest TLS server's certificate. Used by A2 / A4 so the traffic
// goroutine's HTTPS handshake succeeds against the test server.
func httptestRootCAs(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	if srv.Certificate() == nil {
		t.Fatal("httptest server has no certificate; expected NewTLSServer")
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// installTLSConfigForTesting seeds the operator's TLS template with
// the given RootCAs and rebuilds the transport via a swap. Used by
// A2/A4 to seed the test transport so HTTPS handshakes against the
// httptest TLS server succeed. P5.3: writes go to the operator
// template; the swap auto-attaches a Clone to the new transport.
func installTLSConfigForTesting(t *testing.T, rootCAs *x509.CertPool) {
	t.Helper()
	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		upstreamOpTLSCfg = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		}
		return cloneTransport(old)
	})
}

// errgroupLite is a minimal WaitGroup-based barrier so the test
// reaches a clean teardown point even if one of the goroutines hit a
// timed-out request. Using sync.WaitGroup directly + a context for
// deadline.
type errgroupLite struct {
	wg sync.WaitGroup
}

func (g *errgroupLite) Go(fn func()) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		fn()
	}()
}

func (g *errgroupLite) Wait() {
	g.wg.Wait()
}

// ────────────────────────────────────────────────────────────────────
// A1 — Proxy mutation under HTTP traffic
// ────────────────────────────────────────────────────────────────────

// TestUpstreamTransport_ProxyMutationUnderTraffic drives HTTP GETs
// through getUpstreamTransport() while a mutator goroutine swaps the
// pool / Proxy via applyUpstreamProxy. Race-detector clean = R-1
// fixed.
func TestUpstreamTransport_ProxyMutationUnderTraffic(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	// Two synthetic parent proxies. Each just returns 200 to any
	// request (handler ignores absolute-form URL when the client
	// uses Proxy=parent.URL — the race surface is in the Transport,
	// not the response correctness).
	pp1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(pp1.Close)
	pp2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(pp2.Close)

	// Bootstrap a clean transport with no Proxy installed yet, then
	// configure the pool to pp1 and install Proxy.
	upstreamTransportPtr.Store(newBaseUpstreamTransport())
	upstreamPool.Configure([]UpstreamEntry{{URL: pp1.URL}}, 5, time.Minute)
	applyUpstreamProxy()

	dstURL := pp1.URL + "/" // any URL; the proxy short-circuits

	var g errgroupLite
	var trafficOK atomic.Int64

	// Traffic goroutine — A1's lightweight HTTP path.
	g.Go(func() {
		for i := 0; i < a1TrafficIters; i++ {
			client := &http.Client{
				Transport: getUpstreamTransport(),
				Timeout:   2 * time.Second,
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, dstURL, nil)
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				trafficOK.Add(1)
			}
		}
	})

	// Mutator goroutine — alternates pool config + applyUpstreamProxy.
	g.Go(func() {
		urls := [2]string{pp1.URL, pp2.URL}
		for i := 0; i < a1MutationIters; i++ {
			upstreamPool.Configure(
				[]UpstreamEntry{{URL: urls[i%2]}},
				5,
				time.Minute,
			)
			applyUpstreamProxy()
		}
	})

	g.Wait()

	if trafficOK.Load() == 0 {
		t.Errorf("zero successful HTTP requests across %d iterations; the test fixture is broken", a1TrafficIters)
	}
}

// ────────────────────────────────────────────────────────────────────
// A2 — OCSP mutation under TLS traffic
// ────────────────────────────────────────────────────────────────────

// TestUpstreamTransport_OCSPMutationUnderTLSTraffic drives HTTPS GETs
// while a mutator goroutine swaps the transport to install OCSP
// verify callbacks. Race-detector clean = R-2 + R-4 fixed.
func TestUpstreamTransport_OCSPMutationUnderTLSTraffic(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	dst := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(dst.Close)

	// Bootstrap a transport with RootCAs pointing at dst so the
	// handshake succeeds. Proxy is intentionally unset for this test
	// (direct HTTPS to dst).
	upstreamTransportPtr.Store(newBaseUpstreamTransport())
	installTLSConfigForTesting(t, httptestRootCAs(t, dst))

	var g errgroupLite
	var trafficOK atomic.Int64
	var handshakeFailures atomic.Int64

	g.Go(func() {
		for i := 0; i < a2TrafficIters; i++ {
			client := &http.Client{
				Transport: getUpstreamTransport(),
				Timeout:   3 * time.Second,
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, dst.URL, nil)
			resp, err := client.Do(req)
			if err != nil {
				// During OCSP swap-in, the VerifyConnection / VerifyPeerCertificate
				// callbacks may run against the test cert and reject it (the test
				// cert is not OCSP-stapled). That's expected; we only care that
				// the race detector stays quiet.
				if errors.Is(err, x509.UnknownAuthorityError{}) {
					handshakeFailures.Add(1)
				}
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			trafficOK.Add(1)
		}
	})

	g.Go(func() {
		for i := 0; i < a2MutationIters; i++ {
			// Install OCSP onto a freshly-cloned tls.Config; mirrors
			// the apiOCSPConfig swap path.
			swapUpstreamTransport(func(old *http.Transport) *http.Transport {
				newT := cloneTransport(old)
				tlsCfg := cloneTLSConfig(newT.TLSClientConfig)
				if tlsCfg.MinVersion == 0 {
					tlsCfg.MinVersion = tls.VersionTLS12
				}
				ConfigureTLSConfigOCSP(tlsCfg)
				newT.TLSClientConfig = tlsCfg
				return newT
			})
			// Counterpart "disable" swap — clears the OCSP callbacks
			// by installing a fresh TLS config preserving RootCAs.
			swapUpstreamTransport(func(old *http.Transport) *http.Transport {
				newT := cloneTransport(old)
				// Clone current config, drop the verifiers.
				tlsCfg := cloneTLSConfig(newT.TLSClientConfig)
				tlsCfg.VerifyPeerCertificate = nil
				tlsCfg.VerifyConnection = nil
				newT.TLSClientConfig = tlsCfg
				return newT
			})
		}
	})

	g.Wait()

	// Success criterion: completes without a race detector report.
	// We do NOT require trafficOK > 0 because the OCSP verify
	// callback can reject the test cert (it's not OCSP-stapled);
	// the race-detector cleanliness is the actual contract. The
	// counters are exercised via Add() inside the goroutines, which
	// satisfies Go's "must be used" rule without copying the lock.
}

// ────────────────────────────────────────────────────────────────────
// A3 — Hot-reload proxy churn under HTTP traffic
// ────────────────────────────────────────────────────────────────────

// TestUpstreamTransport_HotReloadProxyChurnUnderTraffic drives the
// SIGHUP-specific applyHotReload code path so P5.3 covers BOTH the
// admin-API mutator (A1) and the SIGHUP mutator with the same race
// surface.
func TestUpstreamTransport_HotReloadProxyChurnUnderTraffic(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	pp1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(pp1.Close)
	pp2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(pp2.Close)

	upstreamTransportPtr.Store(newBaseUpstreamTransport())
	upstreamPool.Configure([]UpstreamEntry{{URL: pp1.URL}}, 5, time.Minute)
	applyUpstreamProxy()

	dstURL := pp1.URL + "/"

	var g errgroupLite
	var trafficOK atomic.Int64

	g.Go(func() {
		for i := 0; i < a3TrafficIters; i++ {
			client := &http.Client{
				Transport: getUpstreamTransport(),
				Timeout:   2 * time.Second,
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, dstURL, nil)
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				trafficOK.Add(1)
			}
		}
	})

	g.Go(func() {
		urls := [2]string{pp1.URL, pp2.URL}
		for i := 0; i < a3MutationIters; i++ {
			fc := &FileConfig{}
			fc.Upstream.Proxies = []UpstreamEntry{{URL: urls[i%2]}}
			// applyHotReload's other branches (rl, ipf, bl, rewrite)
			// are guarded by len/value checks; an fc with only the
			// Upstream block set exercises only the upstream branch.
			applyHotReload(fc)
		}
	})

	g.Wait()

	if trafficOK.Load() == 0 {
		t.Errorf("zero successful HTTP requests across %d iterations; the test fixture is broken", a3TrafficIters)
	}
}

// ────────────────────────────────────────────────────────────────────
// A4 — OCSP toggle via admin API under TLS traffic
// ────────────────────────────────────────────────────────────────────

// TestUpstreamTransport_OCSPToggleViaAdminAPIUnderTraffic drives the
// actual apiOCSPConfig handler (not just its helper) concurrently
// with HTTPS traffic. Catches regressions where P5.3's swap covers
// the helper but not the admin-API handler.
func TestUpstreamTransport_OCSPToggleViaAdminAPIUnderTraffic(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	snapshotForRaceTests(t)

	dst := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(dst.Close)

	upstreamTransportPtr.Store(newBaseUpstreamTransport())
	installTLSConfigForTesting(t, httptestRootCAs(t, dst))

	var g errgroupLite

	g.Go(func() {
		for i := 0; i < a4TrafficIters; i++ {
			client := &http.Client{
				Transport: getUpstreamTransport(),
				Timeout:   3 * time.Second,
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, dst.URL, nil)
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
	})

	g.Go(func() {
		for i := 0; i < a4MutationIters; i++ {
			// Toggle OCSP on, then off, via the real admin handler.
			body, _ := json.Marshal(map[string]any{"enabled": true})
			rOn := httptest.NewRequest(http.MethodPost, "/api/ocsp", bytes.NewReader(body))
			rOn.Header.Set("Content-Type", "application/json")
			rOn = rOn.WithContext(context.WithValue(rOn.Context(), uiRoleKey{}, RoleAdmin))
			wOn := httptest.NewRecorder()
			apiOCSPConfig(wOn, rOn)

			body, _ = json.Marshal(map[string]any{"enabled": false})
			rOff := httptest.NewRequest(http.MethodPost, "/api/ocsp", bytes.NewReader(body))
			rOff.Header.Set("Content-Type", "application/json")
			rOff = rOff.WithContext(context.WithValue(rOff.Context(), uiRoleKey{}, RoleAdmin))
			wOff := httptest.NewRecorder()
			apiOCSPConfig(wOff, rOff)
		}
	})

	g.Wait()
}

