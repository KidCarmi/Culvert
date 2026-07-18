package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/filetxn"
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
	beforeConfig := globalConfigStore.Get()
	beforeBaseURL := cfg.ProxyBaseURL()
	beforeTrust := trustForwardedHeaders
	t.Cleanup(func() {
		SetProxyBaseURL(beforeBaseURL)
		trustForwardedHeaders = beforeTrust
	})
	SetProxyBaseURL("https://old-proxy.example")
	trustForwardedHeaders = false
	bl.Add("old-state.example")
	snap := ConfigSnapshot{
		Version:      2,
		ProxyBaseURL: "https://must-not-apply.example",
		BlockedHosts: []string{"must-not-apply.example"},
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
	if got := globalConfigStore.Get(); got.ProxyBaseURL != beforeConfig.ProxyBaseURL {
		t.Fatalf("failed policy save partially applied config store: %q", got.ProxyBaseURL)
	}
	if !bl.IsBlocked("old-state.example") || bl.IsBlocked("must-not-apply.example") {
		t.Fatal("policy persistence failure partially applied blocklist state")
	}
	if got := cfg.ProxyBaseURL(); got != "https://old-proxy.example" || trustForwardedHeaders {
		t.Fatalf("policy persistence failure partially applied external auth: base=%q trust=%v", got, trustForwardedHeaders)
	}
}

func TestDPLastGoodPersistFailureDoesNotAdvanceVersionOrHealth(t *testing.T) {
	setupProxyTest(t)
	withDPLastGoodConfigTestGlobals(t)
	snapshotPolicyStoreForTest(t)
	restoreEpoch := resetDPLastSeenEpochForTest()
	defer restoreEpoch()
	origPollFailing := dpControlPlanePollFailing.Load()
	dpControlPlanePollFailing.Store(false)
	defer dpControlPlanePollFailing.Store(origPollFailing)

	policyStore.path = filepath.Join(dataDir, "policy.json")
	if err := policyStore.ReplaceAllAndSave([]PolicyRule{{Priority: 1, Name: "old-policy", Action: ActionAllow}}); err != nil {
		t.Fatal(err)
	}
	oldBegin := beginCrossStoreTxn
	beginCrossStoreTxn = func(journalPath, kind string, writes []filetxn.Write, opts ...filetxn.Option) (*filetxn.Txn, error) {
		lastGoodWrite := -1
		for i := range writes {
			if writes[i].Path == dpLastGoodConfigSnapshotPath() {
				lastGoodWrite = i
				break
			}
		}
		if lastGoodWrite < 0 {
			return nil, errors.New("test seam: last-known-good write missing from transaction")
		}
		failurePoint := fmt.Sprintf("before-write-%d", lastGoodWrite)
		opts = append(opts, filetxn.WithBoundaryHook(func(point string) error {
			if point == failurePoint {
				return errors.New("injected last-known-good write failure")
			}
			return nil
		}))
		return filetxn.Begin(journalPath, kind, writes, opts...)
	}
	t.Cleanup(func() { beginCrossStoreTxn = oldBegin })

	snap := ConfigSnapshot{
		Version:      2,
		BlockedHosts: []string{"must-not-apply.example"},
		PolicyRules:  []PolicyRule{{Priority: 1, Name: "new-policy", Action: ActionDrop}},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	client := &DataPlaneClient{lastVersion: 1, callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return raw, nil
	}}
	client.fetchAndApply(t.Context())
	if client.lastVersion != 1 {
		t.Fatalf("lastVersion=%d, want retryable version 1", client.lastVersion)
	}
	if !dpControlPlanePollFailing.Load() {
		t.Fatal("last-good persistence failure reported healthy polling")
	}
	if got := policyStore.List()[0].Name; got != "old-policy" {
		t.Fatalf("last-good failure published policy memory %q", got)
	}
	fresh := &PolicyStore{}
	if err := fresh.Load(policyStore.path); err != nil {
		t.Fatal(err)
	}
	if got := fresh.List()[0].Name; got != "old-policy" {
		t.Fatalf("last-good failure left policy disk at %q", got)
	}
	if _, err := os.Stat(dpLastGoodConfigSnapshotPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed last-good write persisted snapshot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "dp_config_apply.txn")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed transaction journal was not cleaned up: %v", err)
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
