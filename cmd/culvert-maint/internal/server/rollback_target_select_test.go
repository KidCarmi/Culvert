// Unit test for rollback-target selection (deriveRollbackTarget). Kept apart
// from the flow-level tests in pinned_tag_consistency_test.go.
package server

import (
	"regexp"
	"testing"

	"culvert-maint/internal/config"
)

// The strict gate is unchanged: when NO RepoDigest passes it, there is still no
// rollback target (never a guess).
func TestDeriveRollbackTarget_SelectsFirstRefPassingTheGate(t *testing.T) {
	s := &Server{opts: Options{Cfg: &config.Config{
		ImageAllowlist: regexp.MustCompile(`^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`),
	}}}

	cases := []struct {
		name       string
		refs       []string
		wantRef    string
		wantReason string
	}{
		{"registry only", []string{repo + "@sha256:" + digOld}, repo + "@sha256:" + digOld, ""},
		{"local tag entry first", []string{"culvert/proxy@sha256:" + digOld, repo + "@sha256:" + digOld}, repo + "@sha256:" + digOld, ""},
		{"only the local tag entry", []string{"culvert/proxy@sha256:" + digOld}, "", "no_prior_digest"},
		{"none", nil, "", "no_prior_digest"},
		{"two distinct digests", []string{repo + "@sha256:" + digOld, repo + "@sha256:" + digNew}, "", "ambiguous_prior_digest"},
	}
	for _, tc := range cases {
		acc := &upgradeApplyAccumulator{priorDigests: bareDigests(tc.refs)}
		s.deriveRollbackTarget(acc, tc.refs)
		if acc.priorRef != tc.wantRef || acc.priorCaptureReason != tc.wantReason {
			t.Errorf("%s: priorRef=%q reason=%q, want %q / %q", tc.name, acc.priorRef, acc.priorCaptureReason, tc.wantRef, tc.wantReason)
		}
	}
}
