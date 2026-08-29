package main

import "github.com/KidCarmi/Culvert/internal/yara"

// The pure-Go YARA engine moved to internal/yara (ADR-0002, second scan engine).
// package main keeps the process-wide rule set, the unqualified type name, and
// thin aliases for the runtime config getters/setters so the many consumers —
// admin_settings.go, diagnostics.go, security_scan.go, ui_security.go, main.go —
// stay unchanged. The package renamed the config funcs to Get*/Set* and the
// validator to ValidateSource (revive: yara.ValidateYARASource is repetitive).
type YARARuleSet = yara.RuleSet

var globalYARA = yara.NewRuleSet()

var (
	yaraGetEnabled       = yara.GetEnabled
	yaraGetMaxInflight   = yara.GetMaxInflight
	yaraGetTimeoutSecs   = yara.GetTimeoutSecs
	yaraGetAlertDegraded = yara.GetAlertDegraded
	yaraGetOnTimeout     = yara.GetOnTimeout
	yaraGetOnSaturation  = yara.GetOnSaturation

	yaraSetEnabled       = yara.SetEnabled
	yaraSetMaxInflight   = yara.SetMaxInflight
	yaraSetTimeoutSecs   = yara.SetTimeoutSecs
	yaraSetOnTimeout     = yara.SetOnTimeout
	yaraSetOnSaturation  = yara.SetOnSaturation
	yaraSetAlertDegraded = yara.SetAlertDegraded

	// ValidateYARASource validates rule source for the admin UI's "validate"
	// feature without loading it into the global set.
	ValidateYARASource = yara.ValidateSource
)

// yaraInflightLoad reports the in-flight regex-match goroutine count for the
// security-scan stats map (the counter is package-internal to internal/yara).
func yaraInflightLoad() int64 { return yara.Inflight() }

// yaraMatchPanicsLoad reports how many regex-match rounds panicked (a
// runtime crash, NOT a timeout — those are a separate, uncounted code path)
// and were contained by the CHAOS-25 per-match guard (see yara.MatchPanics's
// doc comment). Non-zero means a scan verdict was decided by the configured
// on-timeout posture rather than by the rule itself, so it belongs in the
// same admin-visible stats map as the other YARA runtime-health counters.
func yaraMatchPanicsLoad() int64 { return yara.MatchPanics() }

// Posture strings for on_timeout / on_saturation, re-exposed unqualified for
// diagnostics.go and ui_security.go.
const (
	yaraFailClosed        = yara.FailClosed
	yaraFailOpenWithAlert = yara.FailOpenWithAlert
)
