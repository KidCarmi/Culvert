package server

import (
	"testing"

	"culvert-maint/internal/journal"
)

func recWith(targetRef, targetDig, priorRef, priorDig string) *journal.Record {
	return &journal.Record{
		OpID: testOpULID, Kind: "upgrades.apply", Phase: journal.PhaseRestarting,
		TargetRef: targetRef, TargetDigest: targetDig, PriorRef: priorRef, PriorDigest: priorDig,
	}
}

func TestValidateReconcileRefs_Valid(t *testing.T) {
	rec := recWith(repo+"@sha256:"+digNew, digNew, repo+"@sha256:"+digOld, digOld)
	ok, why := validateReconcileRefs(rec, repo)
	if !ok {
		t.Errorf("valid refs rejected: %s", why)
	}
}

func TestValidateReconcileRefs_OnlyTarget(t *testing.T) {
	// A record with just a target (no prior) is still actionable.
	rec := recWith(repo+"@sha256:"+digNew, digNew, "", "")
	if ok, why := validateReconcileRefs(rec, repo); !ok {
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
		{"ref digest != record digest", recWith(repo+"@sha256:"+digNew, foreignDig, "", "")},
		{"no actionable ref", recWith("", "", "", "")},
		{"digest present but ref empty", recWith("", digNew, "", "")},
		{"prior foreign while target valid", recWith(repo+"@sha256:"+digNew, digNew, "evil.io/x@sha256:"+digOld, digOld)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := validateReconcileRefs(tc.rec, repo)
			if ok {
				t.Errorf("expected rejection for %s, got accepted", tc.name)
			}
			if why == "" {
				t.Errorf("rejection must carry a reason for %s", tc.name)
			}
		})
	}
}

// TestValidateReconcileRefs_TagScopedAllowlistUnaffected is the Codex P2
// regression: a digest ref must validate regardless of any operator
// image_allowlist shape (the allowlist is admission-time and deliberately not
// re-checked here) — a policy-admitted tag upgrade whose journal stores the
// resolved digest ref must NOT be loud-stopped by reconcile.
func TestValidateReconcileRefs_TagScopedAllowlistUnaffected(t *testing.T) {
	// The record carries only the resolved digest ref (as apply stores it).
	rec := recWith(repo+"@sha256:"+digNew, digNew, "", "")
	if ok, why := validateReconcileRefs(rec, repo); !ok {
		t.Errorf("resolved digest ref must validate irrespective of allowlist shape: %s", why)
	}
}

// TestValidateReconcileRefs_CustomProxyRepo proves the proxyRepo parameter is
// load-bearing: a ref bound to a non-default repo validates only when proxyRepo
// matches it — an air-gapped/mirror deployment's case.
func TestValidateReconcileRefs_CustomProxyRepo(t *testing.T) {
	const customRepo = "registry.internal.example/culvert/proxy"
	rec := recWith(customRepo+"@sha256:"+digNew, digNew, "", "")

	if ok, why := validateReconcileRefs(rec, customRepo); !ok {
		t.Errorf("custom-repo ref rejected under matching proxyRepo: %s", why)
	}
	// The same ref must be rejected under the DEFAULT proxyRepo (repo binding).
	if ok, _ := validateReconcileRefs(rec, repo); ok {
		t.Error("custom-repo ref must be rejected when proxyRepo is the default")
	}
}
