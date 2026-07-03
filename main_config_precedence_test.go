package main

import (
	"flag"
	"os"
	"path/filepath"
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
