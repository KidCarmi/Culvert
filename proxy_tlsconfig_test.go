package main

// Tests for upstreamInspectTLSConfig / upstreamVerifyRoots — the upstream-leg
// TLS configuration of SSL-inspected tunnels. The performance contract (the
// system root pool is loaded ONCE and shared, never re-cloned per tunnel) is
// pinned here by pointer identity and in bench_regression_test.go by
// allocs/op; the security contract (TLS 1.2 floor, fail-secure verification,
// per-rule skip-verify) is pinned field by field.

import (
	"crypto/tls"
	"testing"
)

func TestUpstreamInspectTLSConfig_VerifyDefaults(t *testing.T) {
	cfg := upstreamInspectTLSConfig("origin.example.com", false)
	if cfg.ServerName != "origin.example.com" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "origin.example.com")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = 0x%04x, want TLS 1.2 (0x%04x)", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true on the default (verifying) path")
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs = nil on the verifying path; want the shared system pool (fail-secure)")
	}
}

func TestUpstreamInspectTLSConfig_SkipVerify(t *testing.T) {
	cfg := upstreamInspectTLSConfig("selfsigned.internal", true)
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false; want true for a tlsSkipVerify rule")
	}
	if cfg.ServerName != "selfsigned.internal" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "selfsigned.internal")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = 0x%04x, want TLS 1.2 (0x%04x)", cfg.MinVersion, tls.VersionTLS12)
	}
}

// TestUpstreamInspectTLSConfig_SharedRootPool pins the optimization contract:
// every verifying config must reference the SAME CertPool instance. If a
// refactor reintroduces a per-tunnel x509.SystemCertPool() call (which clones
// ~150 roots per invocation), pointer identity breaks and this fails.
func TestUpstreamInspectTLSConfig_SharedRootPool(t *testing.T) {
	a := upstreamInspectTLSConfig("a.example.com", false)
	b := upstreamInspectTLSConfig("b.example.com", false)
	if a.RootCAs == nil || b.RootCAs == nil {
		t.Fatal("RootCAs = nil; want the shared system pool")
	}
	if a.RootCAs != b.RootCAs {
		t.Error("RootCAs differ between calls — the system root pool is being re-cloned per tunnel")
	}
	if got := upstreamVerifyRoots(); got != a.RootCAs {
		t.Error("upstreamVerifyRoots() returned a different pool than the one wired into configs")
	}
	// Distinct configs must still get distinct per-tunnel ServerNames.
	if a.ServerName == b.ServerName {
		t.Error("configs unexpectedly share ServerName")
	}
}
