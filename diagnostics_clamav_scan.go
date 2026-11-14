package main

// diagnostics_clamav_scan.go — operator-contract row for an unreachable ClamAV
// daemon.
//
// With antivirus scanning configured, a ClamAV daemon that cannot be reached is
// a fail-open condition: the ClamAV leg of every body scan errors and the
// content is forwarded without an antivirus verdict (internal/secscan ScanBody,
// "forwarding UNSCANNED (fail-open)"). That state is reported on /ready, on
// /health, on /metrics, by the scan_clam_error alert and on the Security
// Scanning panel. The one-page diagnostics report, where an operator checks "is
// this node protected the way I configured it", did not carry it: the verdict
// read healthy while malware scanning was dark, and /ready's own failing row
// could only send the operator to a different panel.
//
// Report-only: the same ClamAVStatus read /health and /ready already make — a
// memory read while the cached observation is fresh, otherwise one coalesced
// probe the caller waits on for a bounded time — and no change to scanning,
// readiness or fail-open behaviour. Contributes nothing when ClamAV is not
// configured, scanning is off, the daemon answers, the first observation has
// not landed yet, or body scanning is delegated to the remote scan service
// (whose reachability the Security Scanning panel reports separately). The row
// is readable by the viewer role, so the message is a fixed string: the probe
// error names the daemon's internal address and stays on the role-gated
// Security Scanning status.

import (
	"fmt"
	"strings"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// clamAVScanCode is the diagnostics code of the unreachable-ClamAV row.
const clamAVScanCode = "clamav_scan"

// checkClamAVScan returns zero or one row for an unreachable ClamAV daemon.
func checkClamAVScan() []OperatorContractCheck {
	if globalSecScanner == nil || !globalSecScanner.Enabled() {
		return nil
	}
	if globalRemoteScanner != nil && globalRemoteScanner.Enabled() {
		return nil
	}
	if !strings.HasPrefix(globalSecScanner.ClamAVStatus(), "unreachable") {
		return nil
	}
	msg := "ClamAV antivirus daemon is unreachable — scanned content is being forwarded WITHOUT an antivirus verdict (fail-open); YARA rules and threat feeds still apply"
	if n := secscan.Counters().ClamScanError; n > 0 {
		msg += fmt.Sprintf(" (%d antivirus scan errors since start)", n)
	}
	return []OperatorContractCheck{{
		Code:           clamAVScanCode,
		Status:         diagWarn,
		Message:        msg,
		OperatorAction: "The Security Scanning panel shows the live ClamAV status and the connection error. Restore the ClamAV daemon (service running, address reachable from this node); the row clears within about 30 seconds of the daemon answering, with no restart.",
	}}
}
