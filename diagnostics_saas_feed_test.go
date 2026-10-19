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
		}, diagWarn, "past its signed expiry"},
		{"stale_served_recovery_is_stale_not_critical", func(s *saasFeedStatus) {
			s.noteConfig(enabled)
			v := viewFor(sourceCached, 5, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")
			v.Stale = true
			s.noteRecovery(recoveryResult{Class: recoveryStaleServed, ActiveVersion: 5, Stale: true, Critical: true, View: v})
		}, diagWarn, "signed generation 5 (cached) is serving as the last-known-good"},
		{"stale_generation_kept_by_fail_closed_recovery_stays_critical", func(s *saasFeedStatus) {
			s.noteConfig(enabled)
			v := viewFor(sourceCached, 5, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")
			v.Stale = true
			s.noteRecovery(recoveryResult{Class: recoveryEquivocation, ActiveVersion: 5, Stale: true, Critical: true, View: v})
		}, diagFail, "critical state (corruption, equivocation or lost authority: equivocation) — signed generation 5 (cached) is serving"},
		{"waiting_with_cached_generation", func(s *saasFeedStatus) {
			s.noteConfig(enabled)
			s.noteRecovery(recoveryResult{Class: recoveryActiveServed, ActiveVersion: 5,
				View: viewFor(sourceCached, 5, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z")})
			s.noteWaitingForAuthority("authority mirror missing")
		}, diagWarn, "signed generation 5 (cached) is serving"},
		{"embedded_never_activated_failing", func(s *saasFeedStatus) {
			s.noteConfig(enabled)
			s.noteAttemptFailure(saasFeedErrFetch, 0, false, "dial tcp 10.0.0.1:443: raw detail")
		}, diagWarn, "has not activated a signed generation and refresh is failing (1 consecutive failures) — the embedded baseline is serving"},
		{"degraded", func(s *saasFeedStatus) {
			fresh(s)
			s.noteAttemptFailure(saasFeedErrFetch, 0, false, "dial tcp 10.0.0.1:443: raw detail")
		}, diagWarn, "last error class: fetch"},
		{"critical", func(s *saasFeedStatus) {
			s.noteConfig(enabled)
			s.noteRecovery(recoveryResult{Class: recoveryEquivocation, Critical: true, Detail: "equivocation"})
		}, diagFail, "critical state (corruption, equivocation or lost authority: equivocation) — the embedded baseline is serving"},
		{"critical_with_signed_view", func(s *saasFeedStatus) {
			s.noteConfig(enabled)
			s.noteRecovery(recoveryResult{Class: recoveryEquivocation, ActiveVersion: 5, Critical: true,
				View: viewFor(sourceCached, 5, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z")})
		}, diagFail, "signed generation 5 (cached) is serving"},
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
			if strings.Count(c.Message, " is serving") != 1 {
				t.Errorf("message must name exactly one serving source: %q", c.Message)
			}
			if strings.Contains(c.Message, "10.0.0.1") || strings.Contains(c.Message, "raw detail") {
				t.Errorf("message leaked raw error detail: %q", c.Message)
			}
		})
	}
}

// TestSaaSFeedDiagAction_ByErrorClass pins that only fetch/http failures are
// told to wait for the network: persist, verify, parse, freshness, floor and
// config failures persist after the origin recovers.
func TestSaaSFeedDiagAction_ByErrorClass(t *testing.T) {
	network := "once the origin or network path is reachable"
	if a := saasFeedDiagAction(saasFeedStatusSnapshot{LastErrorClass: saasFeedErrFetch}); !strings.Contains(a, network) {
		t.Errorf("fetch: want network guidance, got %q", a)
	}
	// An http failure proves the origin answered: point at the URL/publisher
	// and name the bounded status code.
	if a := saasFeedDiagAction(saasFeedStatusSnapshot{LastErrorClass: saasFeedErrHTTP, LastHTTPStatus: 404}); strings.Contains(a, network) ||
		!strings.Contains(a, "origin was reached but answered HTTP 404") {
		t.Errorf("http: want reached-origin guidance naming the status, got %q", a)
	}
	want := map[string]string{
		saasFeedErrNone:      "use Refresh to fetch a current generation",
		saasFeedErrPersist:   "write access",
		saasFeedErrVerify:    "feed is rejected",
		saasFeedErrParse:     "feed is rejected",
		saasFeedErrFreshness: "node clock",
		saasFeedErrFloor:     "rollback",
		saasFeedErrConfig:    "control-plane authority",
		saasFeedErrInternal:  "correct the reported failure class",
	}
	for class, frag := range want {
		a := saasFeedDiagAction(saasFeedStatusSnapshot{LastErrorClass: class})
		if strings.Contains(a, network) || !strings.Contains(a, frag) || !strings.Contains(a, "Signed SaaS Feed tab") {
			t.Errorf("class %q: want %q without network-only guidance, got %q", class, frag, a)
		}
	}
}
