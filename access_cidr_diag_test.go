package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// snapshotAccessCIDRRejects restores the access-list rejection state after the
// test. The state is process-global and startup/settings loaders record into
// it, so a test that feeds them an invalid list must not leak the warning into
// a later test under -shuffle.
func snapshotAccessCIDRRejects(t *testing.T) {
	t.Helper()
	accessCIDRRejectMu.Lock()
	orig := make(map[string]string, len(accessCIDRRejects))
	for k, v := range accessCIDRRejects {
		orig[k] = v
	}
	accessCIDRRejectMu.Unlock()
	t.Cleanup(func() {
		accessCIDRRejectMu.Lock()
		accessCIDRRejects = orig
		accessCIDRRejectMu.Unlock()
	})
}

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

// TestAccessCIDRListsCheck_DescribesRetainedSet pins that a rejected update is
// described from the list still in force: an invalid admin-settings list does
// not replace a valid YAML/CLI seed, so the row must not claim the set is empty.
func TestAccessCIDRListsCheck_DescribesRetainedSet(t *testing.T) {
	prevTP, prevUI := ListTrustedProxyCIDRs(), ListUIAllowedCIDRs()
	t.Cleanup(func() {
		_ = SetTrustedProxyCIDRs(prevTP)
		_ = SetUIAllowedCIDRs(prevUI)
		noteAccessCIDRResult(accessCIDRUIAllow, nil)
		noteAccessCIDRResult(accessCIDRTrustedProxy, nil)
	})

	if err := SetTrustedProxyCIDRs([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	noteAccessCIDRResult(accessCIDRTrustedProxy, SetTrustedProxyCIDRs([]string{"10.0.0.0/33"}))
	got := checkAccessCIDRLists()
	if got.Status != diagWarn || !strings.Contains(got.Message, "previous list stays in force (1 entry)") ||
		strings.Contains(got.Message, "X-Forwarded-For is not trusted") {
		t.Fatalf("retained seed must be reported as in force, got %q", got.Message)
	}

	_ = SetTrustedProxyCIDRs(nil)
	if got := checkAccessCIDRLists(); !strings.Contains(got.Message, "which is empty, so X-Forwarded-For is not trusted") {
		t.Fatalf("empty retained set must say XFF is not trusted, got %q", got.Message)
	}
}

// TestAPINetworkSettings_ValidSaveClearsTrustedProxyRejection pins the stated
// recovery action: a valid POST /api/settings/network clears the warning.
func TestAPINetworkSettings_ValidSaveClearsTrustedProxyRejection(t *testing.T) {
	snapshotNetworkSettings(t)
	snapshotAdminSettingsPath(t)
	snapshotAccessCIDRRejects(t)
	prevTP := ListTrustedProxyCIDRs()
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(prevTP) })
	// Only the trusted-proxy rejection is under test; start with no admin
	// allowlist rejection so the row's overall status reflects this save.
	noteAccessCIDRResult(accessCIDRUIAllow, nil)
	noteAccessCIDRResult(accessCIDRTrustedProxy, errors.New("invalid IP/CIDR: x"))

	body := strings.NewReader(`{"trusted_proxy_cidrs":["192.0.2.0/24"]}`)
	r := adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/settings/network", body))
	w := httptest.NewRecorder()
	apiNetworkSettings(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", w.Code, w.Body.String())
	}
	if got := checkAccessCIDRLists(); got.Status != diagOK {
		t.Fatalf("valid network save must clear the trusted-proxy warning, got %+v", got)
	}
}
