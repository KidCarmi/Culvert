package server

import (
	"regexp"
	"testing"

	"culvert-maint/internal/journal"
)

// allowlist mirrors the shape the apply handler uses: the pinned repo by digest.
var testAllowlist = regexp.MustCompile(`^ghcr\.io/kidcarmi/culvert@sha256:[a-f0-9]{64}$`)

func recWith(targetRef, targetDig, priorRef, priorDig string) *journal.Record {
	return &journal.Record{
		OpID: testOpULID, Kind: "upgrades.apply", Phase: journal.PhaseRestarting,
		TargetRef: targetRef, TargetDigest: targetDig, PriorRef: priorRef, PriorDigest: priorDig,
	}
}

func TestValidateReconcileRefs_Valid(t *testing.T) {
	rec := recWith(repo+"@sha256:"+digNew, digNew, repo+"@sha256:"+digOld, digOld)
	ok, why := validateReconcileRefs(rec, repo, testAllowlist)
	if !ok {
		t.Errorf("valid refs rejected: %s", why)
	}
}

func TestValidateReconcileRefs_OnlyTarget(t *testing.T) {
	// A record with just a target (no prior) is still actionable.
	rec := recWith(repo+"@sha256:"+digNew, digNew, "", "")
	if ok, why := validateReconcileRefs(rec, repo, testAllowlist); !ok {
		t.Errorf("target-only record rejected: %s", why)
	}
}

func TestValidateReconcileRefs_Rejections(t *testing.T) {
	foreignDig := "abababababababababababababababababababababababababababababababab"
	tests := []struct {
		name string
		rec  *journal.Record
	}{
		{"foreign repo", recWith("evil.io/malware@sha256:"+digNew, digNew, "", "")},
		{"tag not digest", recWith("ghcr.io/kidcarmi/culvert:latest", digNew, "", "")},
		{"not in allowlist", recWith("ghcr.io/other/img@sha256:"+digNew, digNew, "", "")},
		{"ref digest != record digest", recWith(repo+"@sha256:"+digNew, foreignDig, "", "")},
		{"no actionable ref", recWith("", "", "", "")},
		{"digest present but ref empty", recWith("", digNew, "", "")},
		{"prior foreign while target valid", recWith(repo+"@sha256:"+digNew, digNew, "evil.io/x@sha256:"+digOld, digOld)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := validateReconcileRefs(tc.rec, repo, testAllowlist)
			if ok {
				t.Errorf("expected rejection for %s, got accepted", tc.name)
			}
			if why == "" {
				t.Errorf("rejection must carry a reason for %s", tc.name)
			}
		})
	}
}

// TestValidateReconcileRefs_CustomProxyRepo proves the proxyRepo parameter is
// load-bearing: a ref bound to a non-default repo validates only when proxyRepo
// (and the allowlist) match it — an air-gapped/mirror deployment's case.
func TestValidateReconcileRefs_CustomProxyRepo(t *testing.T) {
	const customRepo = "registry.internal.example/culvert/proxy"
	customAllow := regexp.MustCompile(`^registry\.internal\.example/culvert/proxy@sha256:[a-f0-9]{64}$`)
	rec := recWith(customRepo+"@sha256:"+digNew, digNew, "", "")

	if ok, why := validateReconcileRefs(rec, customRepo, customAllow); !ok {
		t.Errorf("custom-repo ref rejected under matching proxyRepo: %s", why)
	}
	// The same ref must be rejected under the DEFAULT proxyRepo (repo binding).
	if ok, _ := validateReconcileRefs(rec, repo, customAllow); ok {
		t.Error("custom-repo ref must be rejected when proxyRepo is the default")
	}
}

func TestValidateReconcileRefs_NilAllowlistRejects(t *testing.T) {
	// A missing allowlist must fail closed, never accept.
	rec := recWith(repo+"@sha256:"+digNew, digNew, "", "")
	if ok, _ := validateReconcileRefs(rec, repo, nil); ok {
		t.Error("nil allowlist must reject (fail closed)")
	}
}
