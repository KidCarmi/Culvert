//go:build linux

package main

import (
	"context"
	"testing"
	"time"
)

func TestStorageProbeRejectsMalformedAndOverflowingCounters(t *testing.T) {
	for _, raw := range []string{"", "1 2 3 4", "1 2 3 4 5 6", "-1 2 4096 4 5", "1 2 0 4 5", "1 nope 4096 4 5", "18446744073709551615 18446744073709551615 4096 4 5", "1 18446744073709551616 1 4 5", "3 2 4096 4 5"} {
		got := parseStoragePrerequisite("/", raw)
		if got.State != "unknown" || got.ID != "storage:/" {
			t.Fatalf("%q: %+v", raw, got)
		}
	}
	if got := parseStoragePrerequisite("/", "1048576 5242880 4096 50 100\n"); got.State != "ok" {
		t.Fatal(got)
	}
}

func TestPrerequisitesRespectCancellationWithoutInventingSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	checks := collectPrerequisites(ctx)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancelled prerequisites took %s", elapsed)
	}
	if len(checks) != 7 {
		t.Fatal(checks)
	}
	for _, check := range checks {
		if check.ID == "" || check.State != "unknown" {
			t.Fatalf("cancelled prerequisite invented evidence: %+v", check)
		}
	}
}
