package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCAMetrics_CacheHitMissAndSize verifies CA-2 PR1: GetCert increments the
// leaf-cert cache hit/miss counters and /metrics renders all three families
// with the expected values. Drives a fresh CertManager to a distinct state
// (1 hit, 2 misses, 2 entries) so assertions can't accidentally match another
// metric, then scrapes /metrics. Fails if a render line or an increment is
// removed. Local crypto only — no network, no sleeps.
func TestCAMetrics_CacheHitMissAndSize(t *testing.T) {
	oldTok := metricsToken
	oldMgr := certMgr
	t.Cleanup(func() {
		metricsToken = oldTok
		certMgr = oldMgr
	})
	metricsToken = ""

	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	certMgr = cm

	get := func(host string) {
		if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host}); err != nil {
			t.Fatalf("GetCert(%q): %v", host, err)
		}
	}
	get("a.test") // miss 1, size 1
	get("a.test") // hit 1  (cached)
	get("b.test") // miss 2, size 2

	hits, misses, size := cm.CacheStats()
	if hits != 1 || misses != 2 || size != 2 {
		t.Fatalf("CacheStats() = (%d,%d,%d), want (1,2,2)", hits, misses, size)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_cert_cache_hits_total counter",
		fmt.Sprintf("culvert_cert_cache_hits_total %d", hits),
		"# TYPE culvert_cert_cache_misses_total counter",
		fmt.Sprintf("culvert_cert_cache_misses_total %d", misses),
		"# TYPE culvert_cert_cache_size gauge",
		fmt.Sprintf("culvert_cert_cache_size %d", size),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}
