package main

// ui_access_recovery_e2e_test.go — the documented local recovery of a corrupt
// admin_settings.json (docs/appliance/management-access-hardening.md), driven
// end to end through the real LoadAdminSettings / uiIPGuardMiddleware /
// SaveAdminSettings path rather than through the policy helpers alone:
//
//	corrupt file → load → management refused (503), omnibus save refused,
//	corrupt bytes quarantined → operator repairs admin_settings.json with an
//	explicit UI policy → restart (load) → the permitted peer is served, every
//	other peer is still denied, and the quarantined copy is never erased.

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// uiRecoveryEnv isolates every process global a full LoadAdminSettings of a
// minimal document touches, so the test is safe under -shuffle.
func uiRecoveryEnv(t *testing.T) string {
	t.Helper()
	uiPolicyFixture(t)
	captureStartupAlerts(t)
	isolateStateCorruption(t)
	isolateRewriterForTest(t)
	swapDecRedact(t, decRedactHosts())
	prevRC := requireCommitEnabled()
	prevSaaS := getSaaSFeedDurable()
	t.Cleanup(func() {
		setRequireCommit(prevRC)
		setSaaSFeedDurable(prevSaaS)
	})
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	setUISettingsTestPath(t, path)
	return path
}

// uiRecoveryRestart models a fresh process: boot-default (open, non-explicit)
// management policy, then the settings load that establishes authority.
func uiRecoveryRestart(t *testing.T, path string) {
	t.Helper()
	if err := SetUIAllowedCIDRs(nil); err != nil {
		t.Fatal(err)
	}
	uiAllowedNetsMu.Lock()
	uiAccessExplicit = false
	uiAllowedNetsMu.Unlock()
	resetStateCorruption()
	LoadAdminSettings(path)
}

func uiRecoveryWantRefused(t *testing.T, stage string) {
	t.Helper()
	for _, peer := range []string{"192.0.2.10:1000", "198.51.100.7:1000", "[2001:db8::1]:1000"} {
		got := uiPolicyResponse(t, peer)
		if got.Code != 503 || !strings.Contains(got.Body.String(), "ui_access_policy_unavailable") {
			t.Fatalf("%s: peer %s got %d %s, want 503 ui_access_policy_unavailable", stage, peer, got.Code, got.Body.String())
		}
	}
	checks := map[string]*readinessCheck{}
	appendUIAccessReadinessCheck(checks)
	if checks["ui_access_policy"] == nil || checks["ui_access_policy"].Status != "fail" {
		t.Fatalf("%s: /ready lacks the ui_access_policy fail row", stage)
	}
}

func uiRecoverySave(t *testing.T) error {
	t.Helper()
	err := SaveAdminSettings()
	if err != nil && runtime.GOOS == "windows" && errors.Is(err, fileutil.ErrReplacedNotSynced) {
		return nil // landed; Windows cannot fsync the directory handle
	}
	return err
}

type uiRecoveryCase struct {
	name     string
	repaired string
	allowed  []string // peers the repaired policy must admit
	denied   []string // peers it must still refuse
}

func TestUIAccessCorruptSettingsDocumentedRecovery(t *testing.T) {
	for _, tc := range []uiRecoveryCase{
		{
			name:     "restricted list",
			repaired: `{"ui_allow_ips":["192.0.2.0/24","2001:db8::/32"]}`,
			allowed:  []string{"192.0.2.10:1000", "[2001:db8::1]:1000"},
			denied:   []string{"198.51.100.7:1000", "[2001:db9::1]:1000"},
		},
		{
			name:     "deliberately open (explicit empty)",
			repaired: `{"ui_allow_ips":[],"ui_allow_ips_saved":true}`,
			allowed:  []string{"192.0.2.10:1000", "198.51.100.7:1000"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) { runUIRecoveryCase(t, tc) })
	}
}

func runUIRecoveryCase(t *testing.T, tc uiRecoveryCase) {
	corrupt := []byte(`{"ui_allow_ips":["192.0.2.0/24"],"rate_limit_rpm":`) // torn write
	path := uiRecoveryEnv(t)
	writeRepair(t, path, string(corrupt))

	// 1. Boot on the corrupt file: fail closed, evidence preserved.
	uiRecoveryRestart(t, path)
	uiRecoveryWantRefused(t, "corrupt load")
	if err := uiRecoverySave(t); err == nil {
		t.Fatal("omnibus save accepted while the management policy is unknown")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a refused save wrote a replacement settings file")
	}
	q := quarantinedFiles(t, path)
	if len(q) != 1 {
		t.Fatalf("want one quarantined copy, got %v", q)
	}
	assertQuarantineIntact(t, q[0], corrupt)

	// 2. Replacement documents WITHOUT an explicit UI policy do not silently
	// reopen management while the quarantine is present.
	for _, partial := range []string{`{}`, `{"ui_allow_ips":[]}`} {
		writeRepair(t, path, partial)
		uiRecoveryRestart(t, path)
		uiRecoveryWantRefused(t, "repair without explicit policy "+partial)
	}

	// 3. The documented repair: an explicit policy, then a restart.
	writeRepair(t, path, tc.repaired)
	uiRecoveryRestart(t, path)
	uiRecoveryWantPeers(t, "after repair", tc)
	checks := map[string]*readinessCheck{}
	appendUIAccessReadinessCheck(checks)
	if checks["ui_access_policy"] != nil {
		t.Fatal("/ready still reports the policy unavailable after repair")
	}
	if err := uiRecoverySave(t); err != nil {
		t.Fatalf("omnibus save still refused after repair: %v", err)
	}

	// 4. Trust history is not erased: the quarantined copy survives the
	// repair, the restart and a subsequent save, byte for byte.
	if got := quarantinedFiles(t, path); len(got) != 1 || got[0] != q[0] {
		t.Fatalf("quarantined copy changed: %v", got)
	}
	assertQuarantineIntact(t, q[0], corrupt)

	// 5. The repaired policy is durable across a further restart.
	uiRecoveryRestart(t, path)
	uiRecoveryWantPeers(t, "after second restart", tc)
}

func uiRecoveryWantPeers(t *testing.T, stage string, tc uiRecoveryCase) {
	t.Helper()
	for _, peer := range tc.allowed {
		if got := uiPolicyResponse(t, peer).Code; got != 204 {
			t.Fatalf("%s: permitted peer %s got %d", stage, peer, got)
		}
	}
	for _, peer := range tc.denied {
		if got := uiPolicyResponse(t, peer).Code; got != 403 {
			t.Fatalf("%s: non-permitted peer %s got %d, want 403", stage, peer, got)
		}
	}
}

func writeRepair(t *testing.T, path, doc string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertQuarantineIntact(t *testing.T, q string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(q) //nolint:gosec // test-owned temp path
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("quarantined copy %s altered or lost: %v", q, err)
	}
}

// The test peers must sit where the cases claim: a fixture typo would turn a
// "still denied" assertion into one that passes for the wrong reason.
func TestUIAccessRecoveryFixturePeers(t *testing.T) {
	_, v4, _ := net.ParseCIDR("192.0.2.0/24")
	_, v6, _ := net.ParseCIDR("2001:db8::/32")
	if !v4.Contains(net.ParseIP("192.0.2.10")) || !v6.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("allowed fixture peers are outside the repaired policy")
	}
	if v4.Contains(net.ParseIP("198.51.100.7")) || v6.Contains(net.ParseIP("2001:db9::1")) {
		t.Fatal("denied fixture peers are inside the repaired policy")
	}
}
