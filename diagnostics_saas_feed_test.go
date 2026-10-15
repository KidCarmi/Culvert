package main

import (
	"strings"
	"testing"
	"time"
)

// swapSaaSFeedStatusForTest installs s as the process-wide status holder and
// restores the previous one on cleanup.
func swapSaaSFeedStatusForTest(t *testing.T, s *saasFeedStatus) {
	t.Helper()
	prev := globalSaaSFeedStatus
	globalSaaSFeedStatus = s
	t.Cleanup(func() { globalSaaSFeedStatus = prev })
}

func TestSaaSFeedDiagnostics(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	enabled := feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}}
	fresh := func(s *saasFeedStatus) {
		s.noteConfig(enabled)
		s.noteActivation(viewFor(sourceDownloaded, 5, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"), saasFeedActivationDelta{})
	}
	cases := []struct {
		name   string
		setup  func(s *saasFeedStatus)
		status string // "" ⇒ no row
		want   string
	}{
		{"disabled", func(s *saasFeedStatus) {
			s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Enabled: false}})
		}, "", ""},
		{"embedded", func(s *saasFeedStatus) { s.noteConfig(enabled) }, "", ""},
		{"fresh", fresh, "", ""},
		{"waiting", func(s *saasFeedStatus) {
			s.noteConfig(feedAuthorityResolution{Authority: authorityManagedDP, WaitingForAuthority: true})
		}, diagWarn, "waiting for a valid authoritative"},
		{"stale", func(s *saasFeedStatus) {
			s.noteConfig(enabled)
			v := viewFor(sourceCached, 5, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")
			v.Stale = true
			s.noteActivation(v, saasFeedActivationDelta{})
		}, diagWarn, "expired last-known-good"},
		{"degraded", func(s *saasFeedStatus) {
			fresh(s)
			s.noteAttemptFailure(saasFeedErrFetch, 0, false, "dial tcp 10.0.0.1:443: raw detail")
		}, diagWarn, "last error class: fetch"},
		{"critical", func(s *saasFeedStatus) {
			s.noteConfig(enabled)
			s.noteRecovery(recoveryResult{Class: recoveryEquivocation, Critical: true, Detail: "equivocation"})
		}, diagFail, "critical state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := statusWithClock(base)
			tc.setup(s)
			swapSaaSFeedStatusForTest(t, s)
			checks := checkSaaSFeed()
			if tc.status == "" {
				if len(checks) != 0 {
					t.Fatalf("expected no row, got %+v", checks)
				}
				return
			}
			if len(checks) != 1 {
				t.Fatalf("expected one row, got %+v", checks)
			}
			c := checks[0]
			if c.Code != "saas_feed" || c.Status != tc.status || !strings.Contains(c.Message, tc.want) {
				t.Errorf("row = %+v, want status %s containing %q", c, tc.status, tc.want)
			}
			if c.OperatorAction == "" {
				t.Error("warn/fail row must carry an operator action")
			}
			if strings.Contains(c.Message, "10.0.0.1") || strings.Contains(c.Message, "raw detail") {
				t.Errorf("message leaked raw error detail: %q", c.Message)
			}
		})
	}
}
