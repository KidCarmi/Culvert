package main

import (
	"strings"
	"testing"
)

// The access_cidr_lists row (main) describes a rejected UI allowlist from "the
// previous list still in force". On the appliance line a rejected UI allowlist
// is FAIL-CLOSED (refuseLoadedUIAccessPolicy): no list is in force and the
// admin UI is refused to everyone. Merged without this branch, the row read
// "the admin UI accepts every client IP" for a UI that was locked shut.
func TestAccessCIDRListsCheck_FailClosedUIAllowlistIsDescribedAsRefused(t *testing.T) {
	// loadUIAccessPolicy writes the allowlist, the refusal latch, the IdP
	// registry and the access-list rejection record; restore all of them.
	resetUIAccessPolicyGlobals(t)
	publishUIAllowedCIDRs(nil)

	// The real startup path, with an entry that cannot parse.
	if err := loadUIAccessPolicy(uiAccessPolicyStartupConfig{AllowList: []string{"10.0.0.0/33"}}); err != nil {
		t.Fatalf("loadUIAccessPolicy: %v", err)
	}
	if !uiAccessPolicyRefused() {
		t.Fatal("precondition: an invalid UI allowlist must refuse the admin UI")
	}
	got := checkAccessCIDRLists()
	if got.Status != diagWarn {
		t.Fatalf("status = %q, want warn", got.Status)
	}
	if !strings.Contains(got.Message, "refused to every client") {
		t.Fatalf("the row must say the admin UI is refused: %q", got.Message)
	}
	if strings.Contains(got.Message, "accepts every client") {
		t.Fatalf("the row must not claim the admin UI is open while it is refused: %q", got.Message)
	}
}
