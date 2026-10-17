package releaseproof

import (
	"errors"
	"regexp"

	"golang.org/x/mod/semver"
)

var versionCoreRE = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[-+].+)?$`)

// ValidVersion accepts complete, unprefixed SemVer 2.0 versions, including
// prereleases and build metadata. Abbreviated Go module versions are refused.
func ValidVersion(version string) bool {
	return versionCoreRE.MatchString(version) && semver.IsValid("v"+version)
}

// CheckUpgradeFrom enforces this target's signed minimum against a separately
// verified observed baseline. An empty floor preserves legacy unconstrained
// catalogs. Neither caller labels nor catalog replay epochs identify versions.
func (a Authorization) CheckUpgradeFrom(prior Authorization) error {
	if a.MinUpgradeFrom == "" {
		return nil
	}
	if !ValidVersion(a.MinUpgradeFrom) || !ValidVersion(a.VersionID) {
		return errors.New("release proof: malformed signed upgrade floor or target version")
	}
	if !ValidVersion(prior.VersionID) {
		return errors.New("release proof: signed baseline version cannot satisfy upgrade floor")
	}
	if semver.Compare("v"+prior.VersionID, "v"+a.MinUpgradeFrom) < 0 {
		return errors.New("release proof: observed signed baseline is below target min_upgrade_from")
	}
	return nil
}
