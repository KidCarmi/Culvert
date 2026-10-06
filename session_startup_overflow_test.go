package main

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// An oversized -session-timeout (CLI values never pass FileConfig.validate)
// must clamp to the 168h ceiling, like any other too-large value — not wrap
// time.Duration to a negative number and collapse to the 15-minute floor.
func TestLoadSession_HugeTimeoutHoursClampsToCeiling(t *testing.T) {
	origTTL := session.TTL()
	t.Cleanup(func() { session.SetTTL(origTTL) })

	if err := loadSession(sessionStartupConfig{TimeoutHours: 3_000_000}); err != nil {
		t.Fatalf("loadSession: %v", err)
	}
	if got, want := session.TTL(), 168*time.Hour; got != want {
		t.Fatalf("TTL = %v; want %v (Duration overflow collapsed to the floor)", got, want)
	}
}
