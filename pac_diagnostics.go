package main

import (
	"fmt"
	"sort"
	"strings"
)

// pacDiagMaxProfiles bounds how many degraded profile IDs the row names, so a
// fleet-wide breakage cannot bloat the report.
const pacDiagMaxProfiles = 5

// checkPACDegraded rolls the last-served PAC compile-warning state (already
// tracked in pacDegraded and shown as a badge on the PAC page) up into the
// operator contract. A degraded compile can drop a rule, lose a pool
// reference or flip a profile's clients to fail-closed, yet every other
// health surface stays green; without this row the operator only finds out by
// opening the PAC page or reading the server log. Report-only: it reads the
// existing snapshot and contributes nothing when no profile is degraded.
// Warning messages are deliberately left out (they can quote pool/rule
// names); the row names profile IDs and the stable issue codes.
func checkPACDegraded() []OperatorContractCheck {
	snap := pacDegradedSnapshot()
	if len(snap) == 0 {
		return nil
	}
	ids := make([]string, 0, len(snap))
	for id := range snap {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	codes := map[string]struct{}{}
	for _, p := range snap {
		for _, w := range p.Warnings {
			codes[w.Code] = struct{}{}
		}
	}
	codeList := make([]string, 0, len(codes))
	for c := range codes {
		codeList = append(codeList, c)
	}
	sort.Strings(codeList)

	shown := ids
	more := ""
	if len(shown) > pacDiagMaxProfiles {
		more = fmt.Sprintf(" (+%d more)", len(shown)-pacDiagMaxProfiles)
		shown = shown[:pacDiagMaxProfiles]
	}
	return []OperatorContractCheck{{
		Code:   "pac_profile_degraded",
		Status: diagWarn,
		Message: fmt.Sprintf("%d PAC profile(s) were last served with compile warnings: %s%s (issue codes: %s)",
			len(ids), strings.Join(shown, ", "), more, strings.Join(codeList, ", ")),
		OperatorAction: "Open the PAC File page, review the degraded badge and warning detail on each listed profile, and fix the referenced rule or pool; the row clears when the profile next serves cleanly.",
	}}
}
