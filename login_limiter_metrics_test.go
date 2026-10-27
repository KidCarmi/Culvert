package main

import (
	"fmt"
	"strings"
	"testing"
)

// TestLoginLimiterEntries_IsOnTheMetricsSurface pins culvert_login_limiter_entries
// (AU-17b): the lockout maps are keyed by usernames an unauthenticated caller
// chooses over the public GET /api/auth/status, and this gauge is the operator's
// only view of how large they have grown.
func TestLoginLimiterEntries_IsOnTheMetricsSurface(t *testing.T) {
	snapshotLoginLimiter(t) // starts from an empty limiter, restored afterwards

	expose := func() string {
		var buf strings.Builder
		liveFeedWritePrometheus(&buf)
		return buf.String()
	}
	out := expose()
	if !strings.Contains(out, "# TYPE culvert_login_limiter_entries gauge") {
		t.Fatal("culvert_login_limiter_entries is missing its TYPE gauge line")
	}
	if !strings.Contains(out, "\nculvert_login_limiter_entries 0\n") {
		t.Fatalf("empty limiter not exposed as 0; exposition:\n%s", out)
	}

	loginLimiter.RecordFailure("198.51.100.40", "au17b-metric-a")
	loginLimiter.RecordFailure("198.51.100.40", "au17b-metric-b")
	want := loginLimiter.EntryCount()
	if want != 4 {
		t.Fatalf("precondition: EntryCount = %d after two (IP, user) failures, want 4", want)
	}
	if out := expose(); !strings.Contains(out, fmt.Sprintf("\nculvert_login_limiter_entries %d\n", want)) {
		t.Fatalf("gauge does not report the live entry count %d; exposition:\n%s", want, out)
	}
}
