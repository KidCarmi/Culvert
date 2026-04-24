package main

// metrics_token_startup_test.go — PR3 expansion Batch 1 coverage.

import (
	"log"
	"os"
	"sync"
	"testing"
)

var metricsTokenLoggerMu sync.Mutex

func ensureMetricsTokenTestLogger(t *testing.T) {
	t.Helper()
	metricsTokenLoggerMu.Lock()
	defer metricsTokenLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// resetMetricsTokenGlobal snapshots/restores the metricsToken package
// global for test isolation under -shuffle.
func resetMetricsTokenGlobal(t *testing.T) {
	t.Helper()
	orig := metricsToken
	t.Cleanup(func() { metricsToken = orig })
}

func TestResolveMetricsTokenStartupConfig_CLIWinsOverFileConfig(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.MetricsToken = "from-config"
	got := resolveMetricsTokenStartupConfig(fc, "from-cli")
	if got.Token != "from-cli" {
		t.Errorf("CLI override should win; got %q", got.Token)
	}
}

func TestResolveMetricsTokenStartupConfig_FallbackToFileConfig(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.MetricsToken = "from-config"
	got := resolveMetricsTokenStartupConfig(fc, "")
	if got.Token != "from-config" {
		t.Errorf("expected FileConfig value; got %q", got.Token)
	}
}

func TestResolveMetricsTokenStartupConfig_Empty(t *testing.T) {
	got := resolveMetricsTokenStartupConfig(&FileConfig{}, "")
	if got.Token != "" {
		t.Errorf("expected empty token; got %q", got.Token)
	}
}

func TestLoadMetricsToken_SetsGlobal(t *testing.T) {
	resetMetricsTokenGlobal(t)
	ensureMetricsTokenTestLogger(t)
	loadMetricsToken(metricsTokenStartupConfig{Token: "abc123"})
	if metricsToken != "abc123" {
		t.Errorf("metricsToken not set; got %q", metricsToken)
	}
}

func TestLoadMetricsToken_EmptyClearsGlobal(t *testing.T) {
	resetMetricsTokenGlobal(t)
	ensureMetricsTokenTestLogger(t)
	metricsToken = "stale-value"
	loadMetricsToken(metricsTokenStartupConfig{Token: ""})
	if metricsToken != "" {
		t.Errorf("metricsToken should be cleared; got %q", metricsToken)
	}
}
