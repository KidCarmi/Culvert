package main

// Machine-enforced SemVer consistency (API-architecture review finding): the
// contract's info.version must be >= every operation's x-culvert-introduced-version,
// so a MINOR addition of new operations cannot be shipped without bumping the
// declared contract version. Guards the exact 1.0.0-vs-1.1.0 drift the reviewer
// caught.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/apicontract"
)

func parseSemver(t *testing.T, s string) [3]int {
	t.Helper()
	var v [3]int
	parts := strings.SplitN(strings.TrimSpace(s), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("not a semver: %q", s)
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			t.Fatalf("not a semver: %q (%v)", s, err)
		}
		v[i] = n
	}
	return v
}

func semverLess(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func TestOpenAPI_InfoVersionCoversIntroduced(t *testing.T) {
	spec := loadContract(t)
	if spec.Doc.Info == nil || spec.Doc.Info.Version == "" {
		t.Fatal("contract has no info.version")
	}
	infoV := parseSemver(t, spec.Doc.Info.Version)

	for _, op := range spec.Ops {
		iv := apicontract.Ext(op.Op, "x-culvert-introduced-version")
		if iv == "" {
			continue // presence is enforced by StyleLint; this test is about the value
		}
		introduced := parseSemver(t, iv)
		if semverLess(infoV, introduced) {
			t.Errorf("%s %s: x-culvert-introduced-version %s exceeds contract info.version %s — bump info.version",
				op.Method, op.Path, iv, spec.Doc.Info.Version)
		}
	}
}
