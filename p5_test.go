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
	defer os.Remove(tmp.Name())
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
	defer os.Remove(tmp.Name())
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

// ── API Rate Limiter Tests ──────────────────────────────────────────────────

func TestAPIRateLimiter_Allow(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	for i := 0; i < apiRateBurst; i++ {
		if !lim.Allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	// Next should be rejected.
	if lim.Allow("10.0.0.1") {
		t.Error("should be rate limited after burst")
	}
}

func TestAPIRateLimiter_DifferentIPs(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	for i := 0; i < apiRateBurst; i++ {
		lim.Allow("10.0.0.1")
	}
	// Different IP should still be allowed.
	if !lim.Allow("10.0.0.2") {
		t.Error("different IP should not be rate limited")
	}
}

func TestAPIRateLimiter_Cleanup(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	lim.Allow("10.0.0.1")
	if len(lim.entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	// Manually expire the entry.
	lim.entries["10.0.0.1"].windowStart = lim.entries["10.0.0.1"].windowStart.Add(-2 * apiRateWindow)
	lim.Cleanup()
	if len(lim.entries) != 0 {
		t.Error("expected cleanup to remove expired entry")
	}
}

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
