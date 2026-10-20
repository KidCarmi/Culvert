package main

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// A persisted/restored admin_settings.json is not subject to the API's 1–168
// range check. An oversized session_timeout_hours must clamp to the 168h
// ceiling (as the -session-timeout path does), not wrap time.Duration to a
// negative number and collapse every admin session to the 15-minute floor.
func TestApplyAdminServices_HugeSessionTimeoutHoursClampsToCeiling(t *testing.T) {
	origTTL := session.TTL()
	t.Cleanup(func() { session.SetTTL(origTTL) })

	applyAdminServices(&AdminSettings{SessionTimeoutHours: 3_000_000})

	if got, want := session.TTL(), 168*time.Hour; got != want {
		t.Fatalf("TTL = %v; want %v (Duration overflow collapsed to the floor)", got, want)
	}
}
