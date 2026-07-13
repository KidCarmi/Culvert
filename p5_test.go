package main

import (
	"os"
	"strings"
	"testing"
)

// ── Config Validation Tests ─────────────────────────────────────────────────

func TestConfigValidate_Valid(t *testing.T) {
	fc := &FileConfig{}
	fc.DefaultAction = "allow"
	fc.Security.IPFilterMode = "block"
	fc.LogFormat = "json"
	fc.SessionTimeoutHours = 24
	fc.Proxy.Port = 8080
	if err := fc.validate(); err != nil {
		t.Errorf("expected valid config, got: %v", err)
	}
}

func TestConfigValidate_InvalidDefaultAction(t *testing.T) {
	fc := &FileConfig{}
	fc.DefaultAction = "permit"
	err := fc.validate()
	if err == nil || !strings.Contains(err.Error(), "default_action") {
		t.Errorf("expected default_action error, got: %v", err)
	}
}

func TestConfigValidate_InvalidIPFilterMode(t *testing.T) {
	fc := &FileConfig{}
	fc.Security.IPFilterMode = "whitelist"
	err := fc.validate()
	if err == nil || !strings.Contains(err.Error(), "ip_filter_mode") {
		t.Errorf("expected ip_filter_mode error, got: %v", err)
	}
}

func TestConfigValidate_InvalidLogFormat(t *testing.T) {
	fc := &FileConfig{}
	fc.LogFormat = "xml"
	err := fc.validate()
	if err == nil || !strings.Contains(err.Error(), "log_format") {
		t.Errorf("expected log_format error, got: %v", err)
	}
}

func TestConfigValidate_InvalidSessionTimeout(t *testing.T) {
	fc := &FileConfig{}
	fc.SessionTimeoutHours = 200
	err := fc.validate()
	if err == nil || !strings.Contains(err.Error(), "session_timeout_hours") {
		t.Errorf("expected session_timeout_hours error, got: %v", err)
	}
}

func TestConfigValidate_InvalidPort(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.Port = 99999
	err := fc.validate()
	if err == nil || !strings.Contains(err.Error(), "proxy.port") {
		t.Errorf("expected proxy.port error, got: %v", err)
	}
}

// TestConfigValidate_PortCollision_ProxyAndUIPort proves that a config file
// setting proxy.port and proxy.ui_port to the SAME value is rejected at
// config-load time with a clear, actionable error — rather than passing
// validate() silently and only failing much later, at the very end of
// startup (after policy/threat-feed/GeoIP/etc. have already initialized),
// with a bare OS-level "listen tcp :N: bind: address already in use" that
// never names which two config keys collided. Confirmed against the real
// binary: `culvert -port 8080 -ui-port 8080` runs the full init sequence
// and only then logger.Fatalf's on the raw bind error.
func TestConfigValidate_PortCollision_ProxyAndUIPort(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.Port = 8080
	fc.Proxy.UIPort = 8080
	err := fc.validate()
	if err == nil {
		t.Fatal("expected an error when proxy.port and proxy.ui_port collide, got nil")
	}
	if !strings.Contains(err.Error(), "proxy.port") || !strings.Contains(err.Error(), "proxy.ui_port") {
		t.Errorf("expected an error naming both proxy.port and proxy.ui_port, got: %v", err)
	}
}

// TestConfigValidate_PortCollision_ProxyAndSOCKS5Port covers the same class
// of collision for the (optional) SOCKS5 listener.
func TestConfigValidate_PortCollision_ProxyAndSOCKS5Port(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.Port = 8080
	fc.Proxy.SOCKS5Port = 8080
	err := fc.validate()
	if err == nil {
		t.Fatal("expected an error when proxy.port and proxy.socks5_port collide, got nil")
	}
	if !strings.Contains(err.Error(), "proxy.port") || !strings.Contains(err.Error(), "proxy.socks5_port") {
		t.Errorf("expected an error naming both proxy.port and proxy.socks5_port, got: %v", err)
	}
}

// TestConfigValidate_PortCollision_UIAndSOCKS5Port covers ui_port vs the
// SOCKS5 listener.
func TestConfigValidate_PortCollision_UIAndSOCKS5Port(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.UIPort = 9090
	fc.Proxy.SOCKS5Port = 9090
	err := fc.validate()
	if err == nil {
		t.Fatal("expected an error when proxy.ui_port and proxy.socks5_port collide, got nil")
	}
	if !strings.Contains(err.Error(), "proxy.ui_port") || !strings.Contains(err.Error(), "proxy.socks5_port") {
		t.Errorf("expected an error naming both proxy.ui_port and proxy.socks5_port, got: %v", err)
	}
}

// TestConfigValidate_PortCollision_DisabledSOCKS5Ignored proves that
// SOCKS5Port==0 (its documented "disabled" sentinel) is never treated as a
// collision, even though proxy.port/proxy.ui_port might also be unset (0)
// in a minimal/partial config during this table-only unit test.
func TestConfigValidate_PortCollision_DisabledSOCKS5Ignored(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.Port = 8080
	fc.Proxy.UIPort = 9090
	fc.Proxy.SOCKS5Port = 0
	if err := fc.validate(); err != nil {
		t.Errorf("expected no error with SOCKS5Port disabled (0), got: %v", err)
	}
}

func TestConfigValidate_NegativeRateLimit(t *testing.T) {
	fc := &FileConfig{}
	fc.Security.RateLimit = -1
	err := fc.validate()
	if err == nil || !strings.Contains(err.Error(), "rate_limit") {
		t.Errorf("expected rate_limit error, got: %v", err)
	}
}

func TestConfigValidate_MultipleErrors(t *testing.T) {
	fc := &FileConfig{}
	fc.DefaultAction = "nope"
	fc.LogFormat = "xml"
	err := fc.validate()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "default_action") || !strings.Contains(err.Error(), "log_format") {
		t.Errorf("expected both errors, got: %v", err)
	}
}

func TestLoadFileConfig_UnknownField(t *testing.T) {
	// Write a config with an unknown field.
	tmp, err := os.CreateTemp("", "culvert-cfg-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, _ = tmp.WriteString("proxy:\n  port: 8080\nunknown_field: true\n")
	_ = tmp.Close()

	_, err = loadFileConfig(tmp.Name())
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !strings.Contains(err.Error(), "unknown_field") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected unknown field error, got: %v", err)
	}
}

func TestLoadFileConfig_InvalidValue(t *testing.T) {
	tmp, err := os.CreateTemp("", "culvert-cfg-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, _ = tmp.WriteString("default_action: \"nope\"\n")
	_ = tmp.Close()

	_, err = loadFileConfig(tmp.Name())
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "default_action") {
		t.Errorf("expected default_action validation error, got: %v", err)
	}
}

// API Rate Limiter tests moved to internal/lockout (ADR-0002) — they require
// whitebox access to the now-internal APIRateLimiter.entries field.

// ── Structured JSON Logger Tests ────────────────────────────────────────────

func TestJSONLogWriter_StructuredFields(t *testing.T) {
	var buf strings.Builder
	w := &jsonLogWriter{dst: &buf}

	_, _ = w.Write([]byte("BLOCKED 10.0.0.1 {req_id=abc123 action=block}\n"))
	out := buf.String()
	if !strings.Contains(out, `"req_id":"abc123"`) {
		t.Errorf("expected req_id field, got: %s", out)
	}
	if !strings.Contains(out, `"action":"block"`) {
		t.Errorf("expected action field, got: %s", out)
	}
	if !strings.Contains(out, `"msg":"BLOCKED 10.0.0.1"`) {
		t.Errorf("expected msg without fields, got: %s", out)
	}
}

func TestJSONLogWriter_PlainMessage(t *testing.T) {
	var buf strings.Builder
	w := &jsonLogWriter{dst: &buf}

	_, _ = w.Write([]byte("plain log message\n"))
	out := buf.String()
	if !strings.Contains(out, `"msg":"plain log message"`) {
		t.Errorf("expected plain message, got: %s", out)
	}
	// Should not have req_id or action fields.
	if strings.Contains(out, "req_id") {
		t.Errorf("unexpected req_id in plain message")
	}
}
