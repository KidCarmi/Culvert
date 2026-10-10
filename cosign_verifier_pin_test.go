package main

import (
	"regexp"
	"testing"
)

// The verifier is itself executable supply-chain input. Every default must
// select the same immutable multi-platform image, including offline OVA builds.
func TestCosignVerifierDefaultsUseSameImmutableDigest(t *testing.T) {
	re := regexp.MustCompile(`(?m)^(?:MAINT_)?COSIGN_IMAGE=.*?(ghcr\.io/sigstore/cosign/cosign:v3\.0\.6@sha256:[0-9a-f]{64})`)
	var selected string
	for _, path := range []string{"scripts/install.sh", "packaging/culvert-maint/install.sh", "appliance/build/manifest.env"} {
		matches := re.FindAllStringSubmatch(readContractFile(t, path), -1)
		if len(matches) != 1 {
			t.Fatalf("%s must select one immutable verifier default", path)
		}
		if selected != "" && matches[0][1] != selected {
			t.Fatalf("%s uses a different verifier digest", path)
		}
		selected = matches[0][1]
	}
}
