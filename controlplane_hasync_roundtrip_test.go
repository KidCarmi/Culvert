package main

// controlplane_hasync_roundtrip_test.go — GA hardening: real-wire coverage for
// HASync, the SECOND snapshot-carrying RPC. HASync moves a full ConfigSnapshot
// AND the AES-wrapped CA key through the exact registerConfigService + rawCodec
// + 128 MiB outbound frame that this program proved was 100% broken for
// GetConfig until it was fixed — yet HASync had been exercised only through the
// callForTest mock. This drives it end-to-end over bufconn so the registration,
// codec, frame, token auth, and the ServableConfig guard are all proven on the
// wire the way GetConfig now is.

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCPGRPC_HASyncRoundTrip(t *testing.T) {
	// Set a known HA token for the duration of the test.
	origToken := globalHA.token
	t.Cleanup(func() { globalHA.token = origToken })
	globalHA.token = "ha-roundtrip-token"

	// Publish a config so the leader has a valid, servable snapshot to replicate.
	wantVer := publishLargeSnapshot(50_000)

	dial := startBufconnCP(t)
	conn := dial(t, clusterClientCallOptions()...)

	// Valid token → a state bundle carrying the published config + version.
	reqBytes, _ := json.Marshal(map[string]string{
		"token":        "ha-roundtrip-token",
		"standby_addr": "127.0.0.1:50051",
	})
	var raw json.RawMessage
	if err := conn.Invoke(context.Background(), methodHASync, json.RawMessage(reqBytes), &raw); err != nil {
		t.Fatalf("HASync with valid token failed on the wire: %v", err)
	}
	var bundle HAStateBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("decode HA state bundle: %v", err)
	}
	if bundle.Version != wantVer || bundle.Config.Version != wantVer {
		t.Errorf("bundle version mismatch: bundle=%d config=%d, want %d", bundle.Version, bundle.Config.Version, wantVer)
	}
	if len(bundle.Config.BlockedHosts) != 50_000 {
		t.Errorf("bundle carried %d blocked hosts, want 50000", len(bundle.Config.BlockedHosts))
	}
	// The bundle must carry cluster state (even if empty JSON) — proves the
	// full HAStateBundle round-tripped through the raw codec, not just Config.
	if len(bundle.ClusterState) == 0 {
		t.Error("bundle ClusterState is empty — full-bundle encode/decode did not round-trip")
	}

	// Invalid token → PermissionDenied (auth enforced on the real wire).
	badReq, _ := json.Marshal(map[string]string{"token": "wrong-token", "standby_addr": "127.0.0.1:50051"})
	var bad json.RawMessage
	err := conn.Invoke(context.Background(), methodHASync, json.RawMessage(badReq), &bad)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("HASync with a bad token: got %v (code %s), want PermissionDenied", err, status.Code(err))
	}
}

// TestCPGRPC_HASyncRefusesWhenNoValidConfig proves the ServableConfig guard on
// the HASync path: a leader whose initial publish was rejected must NOT ship an
// empty config to a standby (which would apply the zero state). It returns
// Unavailable instead, so the standby keeps its last-good.
func TestCPGRPC_HASyncRefusesWhenNoValidConfig(t *testing.T) {
	origToken := globalHA.token
	origStore := globalConfigStore
	t.Cleanup(func() {
		globalHA.token = origToken
		globalConfigStore = origStore
	})
	globalHA.token = "ha-guard-token"
	// Fresh store whose only publish attempt is rejected → never published.
	globalConfigStore = &ConfigStore{}
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: make([]string, maxSnapBlockedHosts+1)}); err == nil {
		t.Fatal("over-cap publish should have been rejected")
	}

	dial := startBufconnCP(t)
	conn := dial(t, clusterClientCallOptions()...)
	reqBytes, _ := json.Marshal(map[string]string{"token": "ha-guard-token", "standby_addr": "127.0.0.1:50051"})
	var raw json.RawMessage
	err := conn.Invoke(context.Background(), methodHASync, json.RawMessage(reqBytes), &raw)
	if status.Code(err) != codes.Unavailable {
		t.Errorf("HASync with no valid config: got %v (code %s), want Unavailable (must not ship empty config)", err, status.Code(err))
	}
}
