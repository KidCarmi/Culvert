package apply

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
)

// TestMixedVersionMatrix consolidates the mixed-version CP/DP behavior matrix
// against the DP apply engine: a compatible DP applies; a below-minimum DP rejects
// and keeps its last good; a newer/unknown snapshot schema is rejected; an
// older-CP absence (nil envelope, exercised at the transport layer) never wipes
// state. Each row asserts the active snapshot after the attempt.
func TestMixedVersionMatrix(t *testing.T) {
	s, ts := mkSigner(t, "k1")

	t.Run("compatible DP applies", func(t *testing.T) {
		a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
		if _, err := a.Apply(gwEnv(t, s, 5, 2)); err != nil {
			t.Fatalf("compatible apply: %v", err)
		}
		if a.Active() == nil {
			t.Fatal("compatible DP did not apply")
		}
	})

	t.Run("below-minimum DP rejects and keeps last good", func(t *testing.T) {
		a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
		good := gwEnv(t, s, 5, 2)
		a.Apply(good)
		// A snapshot requiring a newer DP than this build.
		m := good.Manifest
		m.Epoch = 6
		m.Revisions.Config = 3
		m.MinDPVersion = cpdp.DPCompatVersion + 10
		hi := signManifest(t, s, m)
		if _, err := a.Apply(hi); err == nil {
			t.Fatal("below-minimum snapshot must be rejected")
		}
		if a.Active().ContentHash != good.ContentHash {
			t.Fatal("below-minimum rejection lost the last good snapshot")
		}
	})

	t.Run("unknown schema rejected", func(t *testing.T) {
		a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
		good := gwEnv(t, s, 5, 2)
		a.Apply(good)
		m := good.Manifest
		m.Epoch = 6
		m.Revisions.Config = 3
		m.SchemaVersion = 99
		bad := signManifest(t, s, m)
		if _, err := a.Apply(bad); err == nil {
			t.Fatal("unknown schema must be rejected")
		}
		if a.Active().ContentHash != good.ContentHash {
			t.Fatal("unknown-schema rejection lost the last good snapshot")
		}
	})

	t.Run("fail-static: Active reads local with no CP dependency", func(t *testing.T) {
		a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
		good := gwEnv(t, s, 5, 2)
		a.Apply(good)
		// No CP is reachable in this test — Active() must still serve the last valid
		// snapshot without any CP round trip.
		if a.Active() == nil || a.Active().ContentHash != good.ContentHash {
			t.Fatal("fail-static did not serve the last valid snapshot")
		}
	})
}

// signManifest signs a gateway envelope with an explicit manifest + the standard
// valid gateway payload.
func signManifest(t *testing.T, s cpdp.Signer, m cpdp.Manifest) *cpdp.Envelope {
	t.Helper()
	p := cpdp.Payload{Gateway: &cpdp.GatewayPayload{
		Servers: []cpdp.ServerRecord{{ID: "s1", Endpoint: "https://s1", PinnedIdentity: "x", Verified: true, Enabled: true}},
		Tools:   []cpdp.ToolRecord{{Server: "s1", Name: "read", Fingerprint: "fp"}}, PolicySource: gwPolicyDoc,
	}}
	env, err := cpdp.Sign(m, p, s, cpdp.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return env
}
