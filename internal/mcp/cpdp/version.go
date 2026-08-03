package cpdp

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// CompatVersion is a MONOTONIC MCP-snapshot compatibility integer, NOT a display
// version. A snapshot's minimum_dp_version is a CompatVersion; a DP build
// declares its own DPCompatVersion. The comparison is a numeric ordering, never
// a lexicographic string compare (MCP-CPDP-003): a DP applies a snapshot only
// when its own compatibility version is greater than or equal to the snapshot's
// minimum. Each increment maps to a concrete DP-build capability change; the
// mapping is recorded next to DPCompatVersion below.
type CompatVersion uint32

// DPCompatVersion is THIS build's MCP snapshot compatibility version. It is the
// value a running Data Plane compares against a snapshot's minimum_dp_version.
// It increments (by a deliberate edit here) whenever a DP build gains the ability
// to interpret a security-relevant snapshot semantic that an older DP must not
// partially apply.
//
//	1 — PR-10 baseline: signed envelope, epoch fencing, revision tuple,
//	    minimum-version gate, acknowledgements, atomic activation, rollback.
const DPCompatVersion CompatVersion = 1

// maxCompatVersion bounds a declared minimum_dp_version so a malformed/absurd
// value is rejected rather than silently fencing every DP out forever.
const maxCompatVersion CompatVersion = 1 << 20

// ValidMinVersion reports whether v is a well-formed minimum_dp_version for a
// PR-10 MCP snapshot. An ABSENT minimum (0) is rejected — a PR-10 snapshot MUST
// declare a positive minimum so an older DP can never ignore the gate — as is a
// value above the hard cap.
func (v CompatVersion) ValidMinVersion() bool {
	return v >= 1 && v <= maxCompatVersion
}

// CheckMinVersion evaluates the minimum-DP-version gate for a snapshot declaring
// min as its minimum_dp_version, running on a DP whose own compatibility version
// is dp. It returns:
//
//   - ReasonSnapshotMinVersionMalformed if min is absent/out of range;
//   - ReasonSnapshotMinVersionUnmet if the DP is below the required minimum
//     (the DP MUST NOT apply and keeps its prior valid snapshot);
//   - nil if the DP is at or above the minimum and may continue validation.
func CheckMinVersion(min, dp CompatVersion) error {
	if !min.ValidMinVersion() {
		return mcperr.New(mcperr.ReasonSnapshotMinVersionMalformed, "cpdp.version",
			"minimum_dp_version absent or out of range")
	}
	if dp < min {
		return mcperr.New(mcperr.ReasonSnapshotMinVersionUnmet, "cpdp.version",
			"data-plane compatibility version below snapshot minimum")
	}
	return nil
}
