package main

import (
	"errors"
	"testing"
)

func TestAccessCIDRListsCheck(t *testing.T) {
	t.Cleanup(func() {
		noteAccessCIDRResult(accessCIDRUIAllow, nil)
		noteAccessCIDRResult(accessCIDRTrustedProxy, nil)
	})
	noteAccessCIDRResult(accessCIDRUIAllow, nil)
	noteAccessCIDRResult(accessCIDRTrustedProxy, nil)
	if got := checkAccessCIDRLists(); got.Status != diagOK {
		t.Fatalf("clean state status = %q, want ok", got.Status)
	}
	noteAccessCIDRResult(accessCIDRUIAllow, errors.New("invalid IP/CIDR: 10.0.0.0/33"))
	got := checkAccessCIDRLists()
	if got.Status != diagWarn || got.OperatorAction == "" {
		t.Fatalf("rejected allowlist = %+v, want warn with action", got)
	}
	noteAccessCIDRResult(accessCIDRUIAllow, nil)
	if got := checkAccessCIDRLists(); got.Status != diagOK {
		t.Fatalf("after valid save status = %q, want ok", got.Status)
	}
	noteAccessCIDRResult(accessCIDRTrustedProxy, errors.New("invalid IP/CIDR: x"))
	if got := checkAccessCIDRLists(); got.Status != diagWarn {
		t.Fatalf("rejected trusted proxy status = %q, want warn", got.Status)
	}
}
