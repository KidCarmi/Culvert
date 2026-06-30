package main

// yaraRule builds YARA rule source with the opening brace on its own line
// (required by the parser). The engine tests moved to internal/yara with their
// own copy; this package-main copy serves the remaining cross-subsystem tests
// (tier3_coverage, final_coverage, rewrite_scanner_policy, ui_security_coverage,
// yara_settings) that build a rule set via the exported RuleSet.LoadSource /
// WriteRule API.
//
//nolint:unparam // cond is general by design (mirrors internal/yara's helper); current main callers happen to pass "any of them"
func yaraRule(name, strings_, cond string) string {
	s := "rule " + name + "\n{\n"
	if strings_ != "" {
		s += "    strings:\n" + strings_ + "\n"
	}
	s += "    condition:\n        " + cond + "\n}\n"
	return s
}
