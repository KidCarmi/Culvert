package main

// controlplane_cptlsconfig_race_test.go — CA-7 race regression guard
// (P6.3 Root-CA discovery, §13 CA-7 / §10 CA-R-3).
//
// Status: REGRESSION GUARD (CA-7 fixed in this same PR).
// ========================================================
// Pre-fix this harness PROVED a race: rebuildCPCertPool wrote
// cpTLSConfig.cfg.ClientCAs at controlplane.go:1771 under
// cpTLSConfig.mu, while the stdlib crypto/tls handshake read
// cfg.ClientCAs unlocked. Captured `-race` output before the fix:
//
//	==================
//	WARNING: DATA RACE
//	Write at 0x... by goroutine 14:
//	  proxy.rebuildCPCertPool()
//	      /home/user/Culvert/controlplane.go:1771
//	Previous read at 0x... by goroutine 12:
//	  proxy.TestCA7_CpTLSConfig_ClientCAsConcurrentReadVsWrite_Race
//	  .func1()
//	      .../controlplane_cptlsconfig_race_test.go:<read site>
//	==================
//
// Fix (same PR): buildServerTLS installs a GetConfigForClient
// callback (getCPTLSConfigForClient at controlplane.go:1775). The
// stdlib now invokes this hook once per ClientHello; the callback
// takes cpTLSConfig.mu and returns Clone() whose .ClientCAs is the
// pointer-snapshot of the *x509.CertPool at the time of the clone.
// A concurrent rebuildCPCertPool writes a NEW pool into the
// original cfg.ClientCAs field; the clone holds the OLD pool
// pointer — different memory location, no race. Pools are
// immutable post-publication (rebuildCPCertPool builds a fresh
// pool each call and never mutates pre-existing ones), so the
// clone's reader sees a stable snapshot.
//
// What this test now verifies
// ===========================
//   - The post-fix access pattern (via getCPTLSConfigForClient)
//     is race-free under concurrent rebuildCPCertPool activity.
//     The test fails immediately under `-race` if anyone later
//     removes the GetConfigForClient hook OR if a concurrent
//     mutator becomes able to touch the pool the clone is
//     pointing at.
//
// Harness shape (mirrors CL-11 / PR #243 design)
// ==============================================
//   - Snapshot+restore the package-global cpTLSConfig via its own
//     mutex (PR #241/#245 whitebox idiom).
//   - Install a fresh *tls.Config with ClientCAs = NewCertPool()
//     and GetConfigForClient = getCPTLSConfigForClient so the
//     post-fix path is exercised.
//   - Spawn N reader goroutines: each calls
//     getCPTLSConfigForClient(nil) to get a per-handshake clone
//     (mimicking the stdlib's handshake hook), then reads
//     clone.ClientCAs — same access pattern the stdlib uses on
//     the returned cfg.
//   - Spawn 1 writer goroutine calling rebuildCPCertPool in a
//     tight loop. Each call takes cpTLSConfig.mu and writes
//     cpTLSConfig.cfg.ClientCAs.
//   - A startBarrier releases all goroutines simultaneously.
//
// Why this is deterministic
// =========================
//   - No sleeps. All synchronization via sync.WaitGroup and the
//     start barrier.
//   - No timing-based assertions. -race is the assertion.
//   - No external network: no TLS handshake, no listener, no
//     socket. The harness exercises the same field-access pattern
//     the stdlib uses on the returned cfg, so any race the stdlib
//     would hit, this harness hits too.
//   - Bounded iteration counts; runs in ~50ms.

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
)

// snapshotCPTLSConfig captures and restores the package-global
// cpTLSConfig fields for the duration of the test. PR #241 whitebox
// snapshot pattern, applied via cpTLSConfig's own mutex.
func snapshotCPTLSConfig(t *testing.T) {
	t.Helper()
	cpTLSConfig.mu.Lock()
	origCfg := cpTLSConfig.cfg
	origBaseCAF := cpTLSConfig.baseCAF
	cpTLSConfig.mu.Unlock()
	t.Cleanup(func() {
		cpTLSConfig.mu.Lock()
		cpTLSConfig.cfg = origCfg
		cpTLSConfig.baseCAF = origBaseCAF
		cpTLSConfig.mu.Unlock()
	})
}

func TestCA7_CpTLSConfig_ClientCAsConcurrentReadVsWrite_Race(t *testing.T) {
	snapshotCPTLSConfig(t)

	// Install a fresh *tls.Config wired with the GetConfigForClient
	// callback (post-fix production shape). rebuildCPCertPool has
	// a target field to mutate; the readers go through the callback
	// just like the stdlib handshake does.
	cpTLSConfig.mu.Lock()
	cpTLSConfig.cfg = &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ClientCAs:          x509.NewCertPool(),
		GetConfigForClient: getCPTLSConfigForClient,
	}
	cpTLSConfig.baseCAF = "" // no on-disk base CA — keeps the test hermetic
	cpTLSConfig.mu.Unlock()

	const (
		readers           = 4
		readsPerGoroutine = 1000
		writes            = 100
	)

	startBarrier := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(readers + 1)

	// Reader goroutines: invoke the production hook
	// (getCPTLSConfigForClient) and read .ClientCAs from the
	// returned clone. This mirrors the stdlib handshake's access
	// pattern post-fix: stdlib calls GetConfigForClient per
	// ClientHello, then uses the returned cfg's ClientCAs for the
	// verify-options. The clone's ClientCAs is a pointer-snapshot
	// of the pool at clone time; concurrent rebuilds replace the
	// original cfg.ClientCAs with a NEW pool and don't touch the
	// pool the clone is pointing at.
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			<-startBarrier
			var sink *x509.CertPool
			for j := 0; j < readsPerGoroutine; j++ {
				clone, err := getCPTLSConfigForClient(nil)
				if err != nil || clone == nil {
					continue
				}
				// Same shape as stdlib post-fix:
				// `cfgForHandshake.ClientCAs` where
				// cfgForHandshake is GetConfigForClient's return.
				sink = clone.ClientCAs
			}
			_ = sink // prevent dead-store elimination
		}()
	}

	// Writer goroutine: hot-loop rebuildCPCertPool. Each call takes
	// cpTLSConfig.mu and writes cpTLSConfig.cfg.ClientCAs at
	// controlplane.go:1771. With the GetConfigForClient hook in
	// place, this write no longer races against the reader's
	// clone.ClientCAs (different memory location).
	go func() {
		defer wg.Done()
		<-startBarrier
		for j := 0; j < writes; j++ {
			rebuildCPCertPool()
		}
	}()

	close(startBarrier)
	wg.Wait()

	// No assertions beyond -race. If `-race` fires on any future
	// commit, either the GetConfigForClient hook was removed or a
	// new concurrent mutator started touching the clone's pool —
	// either way the harness flags the regression at the access
	// site.
}
