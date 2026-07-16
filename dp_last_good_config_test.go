package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
)

func withDPLastGoodConfigTestGlobals(t *testing.T) {
	t.Helper()
	origDataDir := dataDir
	origState, _ := dpLastGoodConfigSnapshotState.Load().(dpLastGoodConfigSnapshotStatus)
	dataDir = t.TempDir()
	dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{})
	t.Cleanup(func() {
		dataDir = origDataDir
		dpLastGoodConfigSnapshotState.Store(origState)
	})
}

func TestDPLastGoodConfigSnapshot_RoundTripPreservesIdPProfiles(t *testing.T) {
	withDPLastGoodConfigTestGlobals(t)
	snap := ConfigSnapshot{
		Version:               42,
		ProxyBaseURL:          "https://proxy.example.com",
		TrustForwardedHeaders: true,
		IdPProfiles: []*IdPProfile{{
			ID:      "oidc",
			Name:    "OIDC",
			Type:    IdPTypeOIDC,
			Enabled: false,
			OIDC: &OIDCProfileConfig{
				Issuer:       "https://idp.example",
				ClientID:     "culvert",
				ClientSecret: "secret",
			},
		}},
	}

	persistDPLastGoodConfigSnapshot(snap)
	path := filepath.Join(dataDir, dpLastGoodConfigSnapshotFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted snapshot: %v", err)
	}
	var onDisk ConfigSnapshot
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("unmarshal persisted snapshot: %v", err)
	}
	if len(onDisk.IdPProfiles) != 1 || onDisk.IdPProfiles[0].OIDC.ClientSecret != "secret" {
		t.Fatalf("persisted IdP profile lost write-only fields: %+v", onDisk.IdPProfiles)
	}

	loaded, err := loadDPLastGoodConfigSnapshot()
	if err != nil {
		t.Fatalf("load last-good snapshot: %v", err)
	}
	if loaded.Version != 42 || loaded.ProxyBaseURL != snap.ProxyBaseURL {
		t.Fatalf("loaded snapshot = %+v, want version/base URL from persisted snapshot", loaded)
	}
}

func TestDPConfigPolicySaveFailureDoesNotAdvanceVersionOrLastGood(t *testing.T) {
	setupProxyTest(t)
	withDPLastGoodConfigTestGlobals(t)
	snapshotPolicyStoreForTest(t)
	restoreEpoch := resetDPLastSeenEpochForTest()
	t.Cleanup(restoreEpoch)
	origPollFailing := dpControlPlanePollFailing.Load()
	dpControlPlanePollFailing.Store(false)
	t.Cleanup(func() { dpControlPlanePollFailing.Store(origPollFailing) })

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policyStore.path = policyPath
	if err := os.Mkdir(policyPath+".meta", 0o700); err != nil {
		t.Fatal(err)
	}
	snap := ConfigSnapshot{
		Version: 2,
		PolicyRules: []PolicyRule{{
			Priority: 1,
			Name:     "not-durable",
			Action:   ActionAllow,
		}},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	client := &DataPlaneClient{
		lastVersion: 1,
		callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			return raw, nil
		},
	}

	client.fetchAndApply(t.Context())

	if client.lastVersion != 1 {
		t.Fatalf("lastVersion = %d, want 1 after failed policy save", client.lastVersion)
	}
	if !dpControlPlanePollFailing.Load() {
		t.Fatal("failed policy save reported the control-plane poll healthy")
	}
	if _, err := os.Stat(dpLastGoodConfigSnapshotPath()); !os.IsNotExist(err) {
		t.Fatalf("failed policy save persisted a last-known-good snapshot: %v", err)
	}
}

func TestApplyDPLastGoodPolicySaveFailureReturnsError(t *testing.T) {
	setupProxyTest(t)
	withDPLastGoodConfigTestGlobals(t)
	snapshotPolicyStoreForTest(t)
	restoreEpoch := resetDPLastSeenEpochForTest()
	t.Cleanup(restoreEpoch)

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policyStore.path = policyPath
	if err := os.Mkdir(policyPath+".meta", 0o700); err != nil {
		t.Fatal(err)
	}
	persistDPLastGoodConfigSnapshot(ConfigSnapshot{
		Version: 3,
		PolicyRules: []PolicyRule{{
			Priority: 1,
			Name:     "not-durable-lkg",
			Action:   ActionAllow,
		}},
	})

	if _, err := applyDPLastGoodConfigSnapshot(); err == nil {
		t.Fatal("last-known-good apply succeeded despite failed policy persistence")
	}
}

func TestDPLastGoodConfig_MergeCPAddressesSeedsFailoverPeers(t *testing.T) {
	got := mergeCPAddresses("cp1:50051", []string{"cp2:50051", "cp1:50051", "  cp3:50051  ", ""})
	if got != "cp1:50051,cp2:50051,cp3:50051" {
		t.Fatalf("mergeCPAddresses = %q, want configured address followed by cached peers", got)
	}
}

func TestDPLastGoodConfigDiagnostics_CPDownRequiresLocalSnapshot(t *testing.T) {
	origDP := audit.DPMode()
	origClient := activeDPClient.Load()
	origPollFailing := dpControlPlanePollFailing.Load()
	origState, _ := dpLastGoodConfigSnapshotState.Load().(dpLastGoodConfigSnapshotStatus)
	audit.SetDPMode(true)
	activeDPClient.Store(&DataPlaneClient{})
	dpControlPlanePollFailing.Store(true)
	dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{})
	t.Cleanup(func() {
		audit.SetDPMode(origDP)
		activeDPClient.Store(origClient)
		dpControlPlanePollFailing.Store(origPollFailing)
		dpLastGoodConfigSnapshotState.Store(origState)
	})

	if got := checkDPLastGoodConfigSnapshot(); got.Status != diagFail {
		t.Fatalf("status without local snapshot = %q, want fail", got.Status)
	}
	dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{Loaded: true, SavedVersion: 7})
	if got := checkDPLastGoodConfigSnapshot(); got.Status != diagWarn {
		t.Fatalf("status with local snapshot while CP down = %q, want warn", got.Status)
	}
	dpControlPlanePollFailing.Store(false)
	if got := checkDPLastGoodConfigSnapshot(); got.Status != diagOK {
		t.Fatalf("status with healthy CP polling = %q, want ok", got.Status)
	}
}
