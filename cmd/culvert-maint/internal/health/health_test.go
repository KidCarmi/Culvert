package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse url %q: %v", s, err)
	}
	return u
}

func TestProbe_Validate(t *testing.T) {
	cases := []struct {
		name string
		p    Probe
		ok   bool
	}{
		{"nil base", Probe{HealthPath: "/h", ReadyPath: "/r"}, false},
		{"missing host", Probe{BaseURL: &url.URL{Scheme: "http"}, HealthPath: "/h", ReadyPath: "/r"}, false},
		{"bad scheme", Probe{BaseURL: mustParseURL(t, "ftp://x"), HealthPath: "/h", ReadyPath: "/r"}, false},
		{"missing leading slash on health", Probe{BaseURL: mustParseURL(t, "http://x"), HealthPath: "h", ReadyPath: "/r"}, false},
		{"missing leading slash on ready", Probe{BaseURL: mustParseURL(t, "http://x"), HealthPath: "/h", ReadyPath: "r"}, false},
		{"ok", Probe{BaseURL: mustParseURL(t, "http://x"), HealthPath: "/h", ReadyPath: "/r"}, true},
	}
	for _, c := range cases {
		err := c.p.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: want ok, got %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: want error, got nil", c.name)
		}
	}
}

func TestProbe_ReadyOKHealthOK_FirstTry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	p := Probe{
		BaseURL:        mustParseURL(t, srv.URL),
		HealthPath:     "/health",
		ReadyPath:      "/ready",
		Budget:         5 * time.Second,
		PollInterval:   100 * time.Millisecond,
		RequestTimeout: 1 * time.Second,
	}
	res, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.ReadyOK || !res.HealthOK {
		t.Errorf("both should pass: %+v", res)
	}
	if res.Failed() {
		t.Errorf("Failed() must be false on success")
	}
}

// /ready returns 503 a few times, then 200. /health 200. Probe must
// poll, succeed, then check /health.
func TestProbe_ReadyEventuallyOK_HealthOK(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ready" {
			n := attempts.Add(1)
			if n < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	p := Probe{
		BaseURL:        mustParseURL(t, srv.URL),
		HealthPath:     "/health",
		ReadyPath:      "/ready",
		Budget:         5 * time.Second,
		PollInterval:   50 * time.Millisecond,
		RequestTimeout: 1 * time.Second,
	}
	res, _ := p.Run(context.Background())
	if !res.ReadyOK {
		t.Errorf("ReadyOK must be true after retries: %+v", res)
	}
	if !strings.Contains(res.ReadyDetail, "attempt") {
		t.Errorf("detail should mention attempt count: %q", res.ReadyDetail)
	}
}

func TestProbe_ReadyTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := Probe{
		BaseURL:        mustParseURL(t, srv.URL),
		HealthPath:     "/health",
		ReadyPath:      "/ready",
		Budget:         200 * time.Millisecond,
		PollInterval:   50 * time.Millisecond,
		RequestTimeout: 100 * time.Millisecond,
	}
	res, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ReadyOK {
		t.Errorf("/ready should not have succeeded")
	}
	if !strings.Contains(res.ReadyDetail, "ready_timeout") {
		t.Errorf("detail should say ready_timeout: %q", res.ReadyDetail)
	}
	if !res.Failed() {
		t.Errorf("Failed() must be true on /ready timeout")
	}
}

func TestProbe_HealthFailsButReadyOK_OverallSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	p := Probe{
		BaseURL:        mustParseURL(t, srv.URL),
		HealthPath:     "/health",
		ReadyPath:      "/ready",
		Budget:         2 * time.Second,
		PollInterval:   50 * time.Millisecond,
		RequestTimeout: 500 * time.Millisecond,
	}
	res, _ := p.Run(context.Background())
	if !res.ReadyOK {
		t.Errorf("ReadyOK must be true")
	}
	if res.HealthOK {
		t.Errorf("HealthOK must be false")
	}
	// /ready is the gate; /health failure is informational only.
	if res.Failed() {
		t.Errorf("Failed() must be false when /ready passes even if /health fails")
	}
}

func TestProbe_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := Probe{
		BaseURL:        mustParseURL(t, srv.URL),
		HealthPath:     "/health",
		ReadyPath:      "/ready",
		Budget:         5 * time.Second,
		PollInterval:   1 * time.Second,
		RequestTimeout: 100 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	res, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ReadyOK {
		t.Errorf("ReadyOK should be false after context cancel")
	}
	if !strings.Contains(res.ReadyDetail, "ready_") {
		t.Errorf("detail should mention ready: %q", res.ReadyDetail)
	}
}
