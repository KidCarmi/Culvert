package main

// upstream_pool_startup_test.go — per-slice tests for the upstream-pool
// startup slice (resolver normalisation rules). The loader's collaborators
// (UpstreamPool.Configure, applyUpstreamProxy, the health loop) are owned and
// tested by upstream.go / proxy.go suites.

import (
	"testing"
	"time"
)

func TestResolveUpstreamPoolStartupConfig_Defaults(t *testing.T) {
	got := resolveUpstreamPoolStartupConfig(&FileConfig{})
	if got.CBTimeout != upstreamPoolDefaultCBTimeout {
		t.Errorf("CBTimeout = %v, want default %v", got.CBTimeout, upstreamPoolDefaultCBTimeout)
	}
	if got.HealthInterval != 0 {
		t.Errorf("HealthInterval = %v, want 0 (health loop off)", got.HealthInterval)
	}
	if len(got.Proxies) != 0 || got.CBThreshold != 0 {
		t.Errorf("unexpected non-zero pool config: %+v", got)
	}
}

func TestResolveUpstreamPoolStartupConfig_ParsesAndNormalises(t *testing.T) {
	fc := &FileConfig{}
	fc.Upstream.Proxies = []UpstreamEntry{{URL: "http://parent:3128"}}
	fc.Upstream.CircuitBreaker.Threshold = 5
	fc.Upstream.CircuitBreaker.Timeout = "90s"
	fc.Upstream.HealthInterval = "30s"

	got := resolveUpstreamPoolStartupConfig(fc)
	if got.CBTimeout != 90*time.Second {
		t.Errorf("CBTimeout = %v, want 90s", got.CBTimeout)
	}
	if got.HealthInterval != 30*time.Second {
		t.Errorf("HealthInterval = %v, want 30s", got.HealthInterval)
	}
	if got.CBThreshold != 5 || len(got.Proxies) != 1 {
		t.Errorf("pool config = %+v", got)
	}
}

func TestResolveUpstreamPoolStartupConfig_BadDurationsCollapse(t *testing.T) {
	fc := &FileConfig{}
	fc.Upstream.CircuitBreaker.Timeout = "not-a-duration"
	fc.Upstream.HealthInterval = "-5s" // non-positive → off

	got := resolveUpstreamPoolStartupConfig(fc)
	if got.CBTimeout != upstreamPoolDefaultCBTimeout {
		t.Errorf("bad CB timeout must collapse to default, got %v", got.CBTimeout)
	}
	if got.HealthInterval != 0 {
		t.Errorf("non-positive health interval must collapse to 0 (off), got %v", got.HealthInterval)
	}
}
