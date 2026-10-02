package main

import "os"

// release_transition_policy.go — the supported-upgrade-transition floor that CI
// stamps into every published catalog manifest (min_upgrade_from) and that the
// dispatch planner enforces (checkTransition, release_dispatch.go).
//
// Why a constant in the tree and not a CI input: the planner's behaviour and
// the catalog's claim must come from ONE reviewed source. A floor raised here
// is a statement that releases older than it are no longer qualified
// predecessors — move it only together with evidence in
// docs/appliance/upgrade-transition-matrix.md (the Docker-driven real-
// predecessor transition test in release_transition_test.go is the gate that
// qualifies a floor; raising the floor past a qualified predecessor is a
// product decision, lowering it below one is unsupported by evidence).
//
// Semantics (checkTransition):
//   - running >= floor      ⇒ dispatch proceeds
//   - running <  floor      ⇒ refused (unsupported_transition), no acknowledgement
//   - running unknown       ⇒ refused (unknown_current) unless acknowledged
//   - target < running      ⇒ refused (downgrade) unless allow_downgrade
//
// The floor applies to releases published AFTER this policy shipped; catalogs
// published before it carry no min_upgrade_from and constrain nothing, so an
// existing installation keeps its behaviour until it is on a release that
// declares a floor.
const releaseMinUpgradeFrom = "1.0.250"

// resolveSpecMinUpgradeFrom returns the floor CI stamps into the manifest. The
// env override exists for the re-sign path and for lab catalogs only; CI's
// release job does not set it, so the constant is the production value.
func resolveSpecMinUpgradeFrom() string {
	if v, ok := os.LookupEnv("CULVERT_RELEASE_SPEC_MIN_UPGRADE_FROM"); ok {
		return v // explicit "" ⇒ unconstrained (lab)
	}
	return releaseMinUpgradeFrom
}
