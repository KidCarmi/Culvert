package server

import (
	"regexp"
	"strings"
	"testing"

	"culvert-maint/internal/config"
	"culvert-maint/internal/runner"
)

func TestRollbackBaselineUsesHostRepository(t *testing.T) {
	const mirror = "127.0.0.1:5055/culvert"
	local := mirror + "@sha256:" + strings.Repeat("e", 64)
	other := mirror + "@sha256:" + strings.Repeat("f", 64)
	s := &Server{opts: Options{Cfg: &config.Config{ProxyRepo: mirror, ImageAllowlist: regexp.MustCompile(`^127\.0\.0\.1:5055/culvert@sha256:[a-f0-9]{64}$`)}}}
	for _, tc := range []struct {
		name         string
		refs         []string
		want, reason string
	}{
		{"mirror baseline", []string{priorRef, local}, local, ""},
		{"missing mirror refuses upstream fallback", []string{priorRef}, "", "no_prior_digest"},
		{"conflicting mirror refuses first match", []string{local, other, priorRef}, "", "ambiguous_prior_digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acc := &upgradeApplyAccumulator{priorDigests: bareDigests(tc.refs)}
			s.deriveRollbackTarget(acc, &runner.RunningProxyImage{RepoDigests: tc.refs})
			if acc.priorRef != tc.want || acc.priorCaptureReason != tc.reason {
				t.Fatalf("baseline=(%q,%q), want(%q,%q)", acc.priorRef, acc.priorCaptureReason, tc.want, tc.reason)
			}
		})
	}
}
