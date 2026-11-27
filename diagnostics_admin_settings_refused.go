package main

// diagnostics_admin_settings_refused.go — operator-contract row for GUI-saved
// admin settings that were REFUSED at startup.
//
// LoadAdminSettings validates two persisted slices before applying them: the
// adaptive decryption auto-exclusion tunables and the support-bundle retention
// caps. An out-of-range value (a hand-edited or restored admin_settings.json,
// or a file written under different bounds) is refused fail-closed and the
// compiled defaults run instead. That is the right enforcement outcome, but the
// only trace was one log line: the GUI then shows the defaults, and the operator
// who saved other values has no on-appliance signal that their saved values are
// not in effect. The decompression-ratio slice already reports this shape
// (scan_decompress_ratio); this row covers the two remaining refusing slices.
//
// Report-only: a latch set by the load-time refusal and cleared by the next
// successful save of that slice. No change to validation, defaults or apply.
// Names the setting only, never the refused values (viewer-readable).

import (
	"strings"
	"sync/atomic"
)

var (
	autoExcludeTunablesRefusedAtLoad atomic.Bool
	supportRetentionRefusedAtLoad    atomic.Bool
)

// checkAdminSettingsRefusedAtLoad returns zero or one row naming every saved
// admin-settings slice that startup refused and replaced with its defaults.
func checkAdminSettingsRefusedAtLoad() []OperatorContractCheck {
	return adminSettingsRefusedRows(autoExcludeTunablesRefusedAtLoad.Load(), supportRetentionRefusedAtLoad.Load())
}

func adminSettingsRefusedRows(autoExclude, retention bool) []OperatorContractCheck {
	var names, fixes []string
	if autoExclude {
		names = append(names, "adaptive decryption auto-exclusion tunables")
		fixes = append(fixes, "Decryption Exclusions → Cache Tuning")
	}
	if retention {
		names = append(names, "support-bundle retention caps")
		fixes = append(fixes, "Support → Retention tuning")
	}
	if len(names) == 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "admin_settings_refused",
		Status: diagWarn,
		Message: "The saved " + strings.Join(names, " and ") +
			" were outside the allowed range and were REFUSED at startup — the shipped defaults are in effect instead (fail-closed; your saved values are not applied)",
		OperatorAction: "Review the values shown under " + strings.Join(fixes, " and ") +
			" and save the values you want (or keep the defaults); a successful save clears this warning.",
	}}
}
