package apply

import (
	"encoding/json"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
)

// rawStore feeds arbitrary bytes as the persisted state for the recovery fuzzer.
type rawStore struct{ raw []byte }

func (r *rawStore) Persist(*PersistedState) error { return nil }
func (r *rawStore) Load() (*PersistedState, error) {
	if len(r.raw) == 0 {
		return nil, nil
	}
	var st PersistedState
	if err := json.Unmarshal(r.raw, &st); err != nil {
		return nil, err // corrupt → fail closed (mirrors the file store)
	}
	return &st, nil
}

var fidc atomic.Int64

// FuzzRecover proves that recovery over arbitrary persisted bytes never panics and
// never activates a snapshot that fails signature/hash/min-version verification.
func FuzzRecover(f *testing.F) {
	s, err := cpdp.GenerateLocalSigner("k1")
	if err != nil {
		f.Fatal(err)
	}
	ts, err := cpdp.NewTrustStore([]cpdp.TrustRoot{{KeyID: "k1", Alg: cpdp.SigAlgEd25519, Public: s.Public()}})
	if err != nil {
		f.Fatal(err)
	}
	// A genuine persisted state as a seed.
	env := signGW(f, s, 5, 2)
	good, _ := json.Marshal(&PersistedState{Version: persistStateVersion, Capability: cpdp.CapabilityGateway, Current: env, Epoch: 5, Revisions: env.Manifest.Revisions})
	f.Add(good)
	f.Add([]byte(`{"version":1,"capability":"gateway"}`))
	f.Add([]byte(`garbage`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		a, err := New(Config{
			Capability: cpdp.CapabilityGateway, Trust: ts, DPVersion: cpdp.DPCompatVersion,
			Limits: cpdp.DefaultLimits(), NodeID: "n", Store: &rawStore{raw: raw},
			Clock: func() int64 { return 1 }, IDGen: func() string { return "a" + strconv.FormatInt(fidc.Add(1), 10) },
		})
		if err != nil {
			t.Fatal(err)
		}
		rerr := a.Recover()
		if rerr != nil {
			// On any recovery error the applier must have NO active snapshot.
			if a.Active() != nil {
				t.Fatalf("recovery error but active is set")
			}
			return
		}
		// If recovery succeeded with an active snapshot, it MUST verify.
		if act := a.Active(); act != nil {
			if verr := cpdp.VerifySignature(act, ts, cpdp.DefaultLimits()); verr != nil {
				t.Fatalf("recovered an unverifiable active snapshot")
			}
		}
	})
}

func signGW(f *testing.F, s cpdp.Signer, epoch int64, rev uint64) *cpdp.Envelope {
	f.Helper()
	m := cpdp.Manifest{
		SchemaVersion: cpdp.SchemaVersion, Capability: cpdp.CapabilityGateway, Epoch: epoch,
		Revisions: cpdp.Revisions{Config: rev, Policy: rev, Catalog: 1, Credential: 1}, MinDPVersion: 1,
		PayloadType: "gateway", PayloadVersion: 1, CreatedUnixNano: 1, Source: cpdp.SourceMeta{Kind: "publish"},
	}
	p := cpdp.Payload{Gateway: &cpdp.GatewayPayload{PolicySource: gwPolicyDoc}}
	env, err := cpdp.Sign(m, p, s, cpdp.DefaultLimits())
	if err != nil {
		f.Fatal(err)
	}
	return env
}
