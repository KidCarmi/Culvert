package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// TestCertSignHistogram_RequestHistogramUnchanged proves the generalization
// kept the request-latency metric byte-for-byte: a fresh newLatencyHistogram()
// must still render the exact HELP/TYPE lines for culvert_request_duration_seconds.
func TestCertSignHistogram_RequestHistogramUnchanged(t *testing.T) {
	h := newLatencyHistogram()
	h.Observe(0.1)
	var buf strings.Builder
	h.WritePrometheus(&buf)
	out := buf.String()
	for _, want := range []string{
		"# HELP culvert_request_duration_seconds Request latency histogram\n",
		"# TYPE culvert_request_duration_seconds histogram\n",
		"culvert_request_duration_seconds_bucket{le=\"0.005\"}",
		"culvert_request_duration_seconds_bucket{le=\"+Inf\"}",
		"culvert_request_duration_seconds_sum ",
		"culvert_request_duration_seconds_count ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("request histogram output missing %q\n--- out ---\n%s", want, out)
		}
	}
}

// TestCertSignHistogram_ObservesSignOnly verifies CA-2 PR2: a GetCert cache
// miss (which signs) records exactly one signing observation, a cache hit
// records none, and /metrics exposes the bucket/sum/count families. Uses count
// deltas on the package-singleton histogram for shuffle-safety. Local crypto
// only — no network, no sleeps. Fails if the Observe call is removed.
func TestCertSignHistogram_ObservesSignOnly(t *testing.T) {
	oldTok := metricsToken
	oldMgr := certMgr
	t.Cleanup(func() {
		metricsToken = oldTok
		certMgr = oldMgr
	})
	metricsToken = ""

	cm := ca.New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	certMgr = cm

	get := func(host string) {
		if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host}); err != nil {
			t.Fatalf("GetCert(%q): %v", host, err)
		}
	}

	before := certSignHist.Count()

	get("sign.test") // miss → signs → +1 observation
	afterMiss := certSignHist.Count()
	if afterMiss != before+1 {
		t.Fatalf("sign histogram count after miss = %d, want %d (one observation per sign)", afterMiss, before+1)
	}

	get("sign.test") // cache hit → must NOT observe a sign
	afterHit := certSignHist.Count()
	if afterHit != afterMiss {
		t.Fatalf("sign histogram count after cache hit = %d, want %d (hit must not record a sign)", afterHit, afterMiss)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_cert_sign_duration_seconds histogram",
		"culvert_cert_sign_duration_seconds_bucket{le=\"0.0001\"}",
		"culvert_cert_sign_duration_seconds_bucket{le=\"+Inf\"}",
		"culvert_cert_sign_duration_seconds_sum ",
		"culvert_cert_sign_duration_seconds_count ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}
