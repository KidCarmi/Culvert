package dlp

import (
	"regexp"
	"strings"
)

// This file is the deterministic, bounded PII/financial V1 corpus. It makes NO
// claim of universal PII detection. Each detector is a PRECISE, developer-authored
// RE2 pattern (linear, non-backtracking) plus a Go skip predicate, NOT a broad
// entropy or dictionary heuristic — so ordinary MCP data (SHAs, UUIDs, ULIDs,
// prose) is not destroyed. Documented residual limits per detector are in the
// package tests (positive fixtures, near-miss negatives, Unicode/format-rune cases).
//
// All patterns are fixed at package init; there is no user-supplied regex.

type piiDetector struct {
	id    string
	class Classification
	sev   Severity
	re    *regexp.Regexp
	// skip returns true when a syntactic match is NOT the sensitive datum (e.g. a
	// PAN that fails the Luhn check, an SSN with a forbidden area group).
	skip func(match string) bool
}

var piiDetectors = []piiDetector{
	{
		id: "pii.email", class: ClassPII, sev: SevMedium,
		// Conservative: a single '@', dotted domain, no spaces.
		re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}`),
	},
	{
		id: "pii.us_ssn", class: ClassPII, sev: SevHigh,
		re:   regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`),
		skip: skipInvalidSSN,
	},
	{
		id: "pii.e164_phone", class: ClassPII, sev: SevLow,
		// E.164-ish: leading + and 8–15 digits. Precision-first (requires the +).
		re: regexp.MustCompile(`\+[1-9][0-9]{7,14}\b`),
	},
	{
		id: "financial.pan", class: ClassFinancial, sev: SevHigh,
		// 13–19 digit run, optionally space/dash grouped. Luhn-gated to avoid
		// flagging ordinary long digit strings (ids, counters).
		re:   regexp.MustCompile(`\b(?:[0-9][ \-]?){13,19}\b`),
		skip: skipNonLuhn,
	},
}

// scanPII applies the PII/financial corpus to one string leaf under the op budget.
func (st *scanState) scanPII(s, path string) error {
	for i := range piiDetectors {
		st.ops++
		if st.ops > st.lim.MaxValidationOps() {
			st.rep.Truncated = true
			return dlpLimit("scan operations")
		}
		d := &piiDetectors[i]
		locs := d.re.FindAllString(s, st.lim.MaxFindings()+1)
		count := 0
		for _, m := range locs {
			if d.skip != nil && d.skip(m) {
				continue
			}
			count++
		}
		if count > 0 {
			st.add(Finding{Class: d.class, Severity: d.sev, Path: path, DetectorID: d.id, Count: count})
		}
	}
	return nil
}

// skipInvalidSSN drops obviously-invalid SSN shapes (area 000/666/9xx, group 00,
// serial 0000) so a random ###-##-#### id is less likely to be a false positive.
func skipInvalidSSN(m string) bool {
	parts := strings.Split(m, "-")
	if len(parts) != 3 {
		return true
	}
	area, group, serial := parts[0], parts[1], parts[2]
	if area == "000" || area == "666" || area[0] == '9' {
		return true
	}
	if group == "00" || serial == "0000" {
		return true
	}
	return false
}

// skipNonLuhn drops digit runs that fail the Luhn checksum (so ordinary long
// numeric ids are not classified as payment cards). Bounded: single pass.
func skipNonLuhn(m string) bool {
	var digits []int
	for _, r := range m {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return true
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 != 0
}
