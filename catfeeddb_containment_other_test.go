//go:build !linux

package main

import (
	"runtime"
	"strings"
	"testing"
)

// Off Linux, CHAOS-74 runtime fault containment is unavailable by design. The
// diagnostics row for a serving store must say so instead of implying the
// Layer-1 fallback exists on this build; severity is unchanged.
func TestCheckCategoryFeedDB_ReportsContainmentUnavailableOffLinux(t *testing.T) {
	swapCommunityDBGlobals(t)
	noteCatFeedDBState(catFeedDBHealth{Configured: true, Available: true})

	row := checkCategoryFeedDB()
	if row.Status != diagOK {
		t.Fatalf("a healthy store must stay ok, got %q: %s", row.Status, row.Message)
	}
	want := "runtime fault containment: unavailable on " + runtime.GOOS
	if !strings.Contains(row.Message, want) {
		t.Fatalf("row does not report %q: %s", want, row.Message)
	}
}
