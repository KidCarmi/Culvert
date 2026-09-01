package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseFlags_LogRotationFlags_DefaultToUnsetSentinel proves that
// -log-max-mb and -request-log-max-mb, like every other CLI flag combined
// via firstNonZero (port, ui-port, rate-limit, socks5-port, session-timeout,
// keep-last, cdr-timeout-sec, cdr-max-file-size-mb — all declared with a
// zero flag.Int default so an unset flag can never outrank config.yaml),
// must default to 0 so an operator's config.yaml value is not silently
// discarded when the flag isn't passed on the command line.
//
// Before the fix, flag.Int("log-max-mb", 50, ...) and
// flag.Int("request-log-max-mb", 100, ...) baked their fallback default
// straight into the flag, so *s.logMaxMB / *s.requestLogMaxMB were never 0
// even when the operator never passed the flag — permanently outranking
// proxy.log_max_mb / request_log_max_mb in every firstNonZero(cli, fc, ...)
// call, in every deployment that configures log rotation size only via
// config.yaml (e.g. the shipped docker-compose.yml, which does not pass
// either flag).
func TestParseFlags_LogRotationFlags_DefaultToUnsetSentinel(t *testing.T) {
	origArgs := os.Args
	origCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = origArgs
		flag.CommandLine = origCommandLine
	})

	// Fresh FlagSet + argv with no flags at all, simulating an operator who
	// configures everything via config.yaml and never touches these two
	// CLI flags.
	flag.CommandLine = flag.NewFlagSet("culvert", flag.ContinueOnError)
	os.Args = []string{"culvert"}

	s := &startupState{}
	parseFlags(s)

	if s.logMaxMB == nil || *s.logMaxMB != 0 {
		t.Errorf("-log-max-mb default = %v, want 0 (unset sentinel) so config.yaml's proxy.log_max_mb is honored", derefInt(s.logMaxMB))
	}
	if s.requestLogMaxMB == nil || *s.requestLogMaxMB != 0 {
		t.Errorf("-request-log-max-mb default = %v, want 0 (unset sentinel) so config.yaml's request_log_max_mb is honored", derefInt(s.requestLogMaxMB))
	}
}

func derefInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// TestLoadFileConfigAndFlags_LogMaxMB_YAMLHonoredWhenFlagUnset reproduces
// the real end-to-end deployment shape: an operator sets proxy.log_max_mb
// in config.yaml and never passes -log-max-mb. The resolved s.lMaxMB must
// come from config.yaml, not from a hardcoded CLI default the operator
// never asked for.
func TestLoadFileConfigAndFlags_LogMaxMB_YAMLHonoredWhenFlagUnset(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yamlBody := "proxy:\n  log_max_mb: 5\n"
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	zero := 0
	empty := ""
	s := &startupState{
		configPath:   &cfgPath,
		proxyPort:    &zero,
		uiPortFlag:   &zero,
		socks5Port:   &zero,
		logFilePath:  &empty,
		blockFile:    &empty,
		logMaxMB:     &zero, // flag not passed on the CLI -> unset sentinel
		user:         &empty,
		pass:         &empty,
		tlsCert:      &empty,
		tlsKey:       &empty,
		rateLimitRPM: &zero,
		ipMode:       &empty,
	}

	loadFileConfigAndFlags(s)

	if s.lMaxMB != 5 {
		t.Errorf("s.lMaxMB = %d, want 5 (from config.yaml proxy.log_max_mb); the CLI flag's built-in default must not outrank an explicit config.yaml value", s.lMaxMB)
	}
}

// ── Port-collision validation (validatePortCollisions) ──────────────────────
//
// validatePortCollisions runs on the RESOLVED listener ports — after CLI
// overrides and firstNonZero defaults are applied in loadFileConfigAndFlags —
// not on the raw config.yaml fields. An earlier version of this check lived
// in FileConfig.validate() (config.go) and compared the raw fields directly;
// PR review (#729) correctly flagged that as the wrong layer: it would
// reject a config.yaml collision a CLI override later resolves, AND miss a
// collision created when an omitted field silently takes its default value.
// These tests cover both of those cases directly at the resolved-value
// layer, plus the pure collision-detection logic in isolation.

func TestValidatePortCollisions_AllDistinct(t *testing.T) {
	if err := validatePortCollisions(8080, 9090, 1080); err != nil {
		t.Errorf("expected no error for distinct ports, got: %v", err)
	}
}

func TestValidatePortCollisions_ProxyAndUICollide(t *testing.T) {
	err := validatePortCollisions(8080, 8080, 0)
	if err == nil {
		t.Fatal("expected an error when the proxy and UI ports collide, got nil")
	}
	if !strings.Contains(err.Error(), "proxy port") || !strings.Contains(err.Error(), "UI port") {
		t.Errorf("expected an error naming both the proxy port and UI port, got: %v", err)
	}
}

func TestValidatePortCollisions_ProxyAndSOCKS5Collide(t *testing.T) {
	err := validatePortCollisions(8080, 9090, 8080)
	if err == nil {
		t.Fatal("expected an error when the proxy and SOCKS5 ports collide, got nil")
	}
	if !strings.Contains(err.Error(), "proxy port") || !strings.Contains(err.Error(), "SOCKS5 port") {
		t.Errorf("expected an error naming both the proxy port and SOCKS5 port, got: %v", err)
	}
}

func TestValidatePortCollisions_UIAndSOCKS5Collide(t *testing.T) {
	err := validatePortCollisions(8080, 9090, 9090)
	if err == nil {
		t.Fatal("expected an error when the UI and SOCKS5 ports collide, got nil")
	}
	if !strings.Contains(err.Error(), "UI port") || !strings.Contains(err.Error(), "SOCKS5 port") {
		t.Errorf("expected an error naming both the UI port and SOCKS5 port, got: %v", err)
	}
}

// TestValidatePortCollisions_DisabledSOCKS5Ignored proves SOCKS5's
// documented "disabled" sentinel (0) is never treated as a collision, even
// when the proxy/UI ports are also 0 (both unset in this direct call).
func TestValidatePortCollisions_DisabledSOCKS5Ignored(t *testing.T) {
	if err := validatePortCollisions(8080, 9090, 0); err != nil {
		t.Errorf("expected no error with SOCKS5 port disabled (0), got: %v", err)
	}
}

// ── Port-range validation (validatePortRanges) ───────────────────────────────
//
// config.yaml's proxy.port/ui_port/socks5_port are range-checked by
// FileConfig.validateLimits (config.go) — but that check runs on the raw
// YAML fields BEFORE CLI-flag overrides are merged in loadFileConfigAndFlags
// (main.go), and a value that reaches loadFileConfigAndFlags only via a CLI
// flag (e.g. -port on a hand-edited docker-compose.yml `command:` override,
// or a systemd ExecStart line) never passes through validateLimits at all.
// The resolved value then flows straight to
// http.Server{Addr: fmt.Sprintf(":%d", s.pPort)} with no gate in between, so
// an out-of-range CLI port (e.g. -port 99999 or -port -1) was previously
// caught only much later, inside ListenAndServe's own error return — after
// the admin UI server has already started (startAdminUI runs before
// buildAndStartProxyServer in main's boot sequence) — with a bare
// OS-level "listen tcp: address :-1: invalid port" instead of a clear,
// immediate startup error naming the bad flag. validatePortRanges closes
// that gap the same way validatePortCollisions closes the collision gap:
// it runs on the RESOLVED values in loadFileConfigAndFlags, so both the
// YAML and CLI paths are checked identically regardless of which one
// supplied the value.

func TestValidatePortRanges_AllValid(t *testing.T) {
	if err := validatePortRanges(8080, 9090, 1080); err != nil {
		t.Errorf("expected no error for in-range ports, got: %v", err)
	}
}

func TestValidatePortRanges_Boundaries(t *testing.T) {
	if err := validatePortRanges(1, 65535, 0); err != nil {
		t.Errorf("expected no error at the valid boundaries 1 and 65535, got: %v", err)
	}
}

func TestValidatePortRanges_ProxyPortNegative(t *testing.T) {
	err := validatePortRanges(-1, 9090, 0)
	if err == nil {
		t.Fatal("expected an error for a negative proxy port, got nil")
	}
	if !strings.Contains(err.Error(), "proxy port") {
		t.Errorf("expected the error to name the proxy port, got: %v", err)
	}
}

func TestValidatePortRanges_UIPortTooLarge(t *testing.T) {
	err := validatePortRanges(8080, 65536, 0)
	if err == nil {
		t.Fatal("expected an error for a UI port above 65535, got nil")
	}
	if !strings.Contains(err.Error(), "UI port") {
		t.Errorf("expected the error to name the UI port, got: %v", err)
	}
}

func TestValidatePortRanges_SOCKS5PortOutOfRange(t *testing.T) {
	err := validatePortRanges(8080, 9090, 99999)
	if err == nil {
		t.Fatal("expected an error for a SOCKS5 port above 65535, got nil")
	}
	if !strings.Contains(err.Error(), "SOCKS5 port") {
		t.Errorf("expected the error to name the SOCKS5 port, got: %v", err)
	}
}

// TestValidatePortRanges_DisabledSOCKS5Ignored proves SOCKS5's documented
// "disabled" sentinel (0) is never treated as out-of-range, matching
// validatePortCollisions's handling of the same sentinel.
func TestValidatePortRanges_DisabledSOCKS5Ignored(t *testing.T) {
	if err := validatePortRanges(8080, 9090, 0); err != nil {
		t.Errorf("expected no error with SOCKS5 port disabled (0), got: %v", err)
	}
}

// TestLoadFileConfigAndFlags_PortCollision_ResolvedByCLIOverride proves the
// false-positive the raw-field check would have produced: config.yaml sets
// proxy.port and proxy.ui_port to the SAME value, but a CLI -ui-port flag
// overrides the UI port to something distinct before the collision check
// runs. Because validatePortCollisions checks the RESOLVED values, this
// must succeed (no fatal exit) with the CLI override's value winning.
func TestLoadFileConfigAndFlags_PortCollision_ResolvedByCLIOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yamlBody := "proxy:\n  port: 8080\n  ui_port: 8080\n"
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	zero := 0
	empty := ""
	overriddenUIPort := 9090
	s := &startupState{
		configPath:   &cfgPath,
		proxyPort:    &zero,
		uiPortFlag:   &overriddenUIPort, // -ui-port 9090 on the CLI
		socks5Port:   &zero,
		logFilePath:  &empty,
		blockFile:    &empty,
		logMaxMB:     &zero,
		user:         &empty,
		pass:         &empty,
		tlsCert:      &empty,
		tlsKey:       &empty,
		rateLimitRPM: &zero,
		ipMode:       &empty,
	}

	// Must not call log.Fatalf (would os.Exit the test binary) — the
	// resolved ports (8080, 9090) do not collide.
	loadFileConfigAndFlags(s)

	if s.pPort != 8080 || s.uPort != 9090 {
		t.Errorf("s.pPort=%d s.uPort=%d, want 8080/9090 (CLI -ui-port override resolving the config.yaml collision)", s.pPort, s.uPort)
	}
}

// ── CDR fail_mode CLI/YAML validation parity (validCDRFailMode) ─────────────
//
// config.yaml's cdr.fail_mode is validated by FileConfig.validateCDR: an
// unrecognized value (e.g. a typo like "clsoed") fails the whole config load
// with a clear error, so the operator sees the mistake immediately.
//
// The CLI flag -cdr-fail-mode reaches the SAME field (merged in
// cdr_startup_config.go's resolveCDRStartupConfig, CLI wins over config.yaml)
// but had no equivalent gate: an invalid CLI value was stored verbatim into
// CDRConfig.FailMode with no error. CDRFailOpen() (config.go) treats ANY
// value other than the exact string "closed" as fail-OPEN — the LESS safe
// posture — so a typo in an operator's attempt to harden CDR to fail-closed
// (e.g. "-cdr-fail-mode clsoed") would silently run fail-OPEN instead, with
// no startup warning, error, or log line pointing at the mistake. The same
// typo in config.yaml refuses to start.
//
// validCDRFailMode is the shared predicate: used by validateCDR (config.go)
// for the YAML path and by initCDR (main.go) for the CLI path, so both
// channels reject the same invalid values instead of only one of them.
func TestValidCDRFailMode(t *testing.T) {
	tests := []struct {
		fm   string
		want bool
	}{
		{"", true},        // unset — default (open)
		{"open", true},    // explicit open
		{"closed", true},  // explicit closed
		{"clsoed", false}, // typo — must be rejected, not silently treated as open
		{"OPEN", false},   // config.yaml's validateCDR is case-sensitive; CLI must match
		{"Closed", false},
		{"bogus", false},
	}
	for _, tt := range tests {
		if got := validCDRFailMode(tt.fm); got != tt.want {
			t.Errorf("validCDRFailMode(%q) = %v, want %v", tt.fm, got, tt.want)
		}
	}
}

// ── CDR server_fingerprint hex validation (validateCDR) ─────────────────────
//
// validateCDR's server_fingerprint check enforced only LENGTH (64 chars after
// stripping the optional "sha256:"/"SHA256:" prefix and colons) but never
// checked that those characters were actually hex digits — even though its
// own error message promises "expected 64 hex chars (SHA-256)". A config.yaml
// with a 64-character but non-hex server_fingerprint (e.g. a fat-fingered
// paste, or 'g'/'z'/'q' substituted for valid hex digits) sailed through
// startup validation. The mistake then only surfaces later as a NON-FATAL
// "CDR: initial client dial failed ... invalid hex" log line from
// buildCDRTLSConfig (cdr.go, loadCDR path) — CDR silently never comes up
// instead of a clear, immediate startup error naming the bad field.
func TestValidateCDR_RejectsNonHexServerFingerprint(t *testing.T) {
	tests := []struct {
		name string
		fp   string
		want bool // true = validate() should accept
	}{
		{"empty (unset)", "", true},
		{"valid 64-char hex", strings.Repeat("ab", 32), true},
		{"valid with sha256: prefix", "sha256:" + strings.Repeat("cd", 32), true},
		{"valid with colons", strings.Repeat("ab:", 31) + "ab", true},
		{"right length, non-hex chars", strings.Repeat("zq", 32), false},
		{"right length, one bad char", strings.Repeat("a", 63) + "z", false},
		{"too short", strings.Repeat("a", 63), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FileConfig{}
			fc.CDR.Enabled = true
			fc.CDR.Endpoint = "sluice:8443"
			fc.CDR.ServerFingerprint = tt.fp
			err := fc.validate()
			if tt.want && err != nil {
				t.Errorf("validate() rejected a valid server_fingerprint %q: %v", tt.fp, err)
			}
			if !tt.want && err == nil {
				t.Errorf("validate() accepted an invalid server_fingerprint %q, want a rejection", tt.fp)
			}
		})
	}
}
