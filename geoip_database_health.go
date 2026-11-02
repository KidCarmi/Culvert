package main

import (
	"fmt"
	"strings"

	"github.com/KidCarmi/Culvert/internal/geoip"
)

// geoip_database_health.go — operator-contract row for "country rules exist but
// no GeoIP database is loaded".
//
// Without a loaded database a destCountry rule can never match (it fails closed
// to "no match"), so an enabled country BLOCK rule silently stops blocking.
// Until this row existed that fact lived only in the startup log line
// ("GeoIP: disabled …" / "failed to open …") and, for a failed load, in
// GET /api/geoip; the Diagnostics panel instead said "no GeoIP database loaded,
// or no destination-country rules in use" (geo_resolution), which cannot tell
// the operator which of the two applies. Report-only: no rule, matcher or
// loader behaviour changes.

const geoDatabaseMaxNamedRules = 5

// checkGeoDatabaseForRules returns a single WARN row when at least one enabled
// rule carries a destCountry condition and no GeoIP database is loaded. It
// contributes nothing otherwise (database loaded, or no such rule).
func checkGeoDatabaseForRules(rules []PolicyRule) []OperatorContractCheck {
	if geoip.Enabled() {
		return nil
	}
	var names []string
	total := 0
	for i := range rules {
		if len(rules[i].DestCountry) == 0 || !ruleIsEnabled(&rules[i]) {
			continue
		}
		total++
		if len(names) < geoDatabaseMaxNamedRules {
			names = append(names, fmt.Sprintf("%q", rules[i].Name))
		}
	}
	if total == 0 {
		return nil
	}
	listed := strings.Join(names, ", ")
	if total > len(names) {
		listed += fmt.Sprintf(" and %d more", total-len(names))
	}
	reason := "no GeoIP database is configured"
	action := "Configure a MaxMind GeoLite2-Country database (-geoip-db / the GeoIP setting) and restart, or remove the country condition from these rules. Until then they never match."
	if msg, _, ok := geoip.LoadError(); ok {
		reason = "the configured GeoIP database failed to load (" + sanitizeLog(msg) + ")"
		action = "Fix the database path or replace the corrupt/expired .mmdb file shown under the GeoIP settings, then restart. Until then these rules never match."
	}
	return []OperatorContractCheck{{
		Code:   "geoip_database_for_rules",
		Status: diagWarn,
		Message: fmt.Sprintf("%d enabled rule(s) use a destination-country condition but %s, so they do not match any traffic: %s",
			total, reason, listed),
		OperatorAction: action,
	}}
}
