package main

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
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
// pacLegacyNewerAtBoot records the startup finding that a legacy CWD
// pac_config.json is newer than the active store (loadPAC): edits made by a
// downgraded binary are being ignored. Boot-time fact, cleared only by a
// restart after the operator reconciles the files, so the row reads an atomic
// and does no disk I/O at request time.
var pacLegacyNewerAtBoot atomic.Bool

// checkPACLegacyNewer surfaces that startup finding in the operator contract.
// Previously it was a single startup log line, so an operator whose PAC edits
// "did not take" after a downgrade/re-upgrade had to SSH in and grep logs.
// Report-only: contributes nothing unless the condition was found at boot, and
// the message names no file paths.
func checkPACLegacyNewer() []OperatorContractCheck {
	if !pacLegacyNewerAtBoot.Load() {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "pac_legacy_config_newer",
		Status: diagWarn,
		Message: "a legacy pac_config.json is newer than the active PAC store — PAC edits made while a downgraded build ran are being ignored, " +
			"so clients may be steered by older settings than the operator last saved",
		OperatorAction: "Compare the PAC File page with the intended steering. Re-apply the missing edits there, or copy the legacy pac_config.json over the active store (see the startup log for both paths), then restart the proxy; the row clears at the next start.",
	}}
}

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
