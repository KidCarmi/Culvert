package apply

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ---- helpers ------------------------------------------------------------------

const gwPolicyDoc = `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`

func mkSigner(t *testing.T, keyID string) (cpdp.Signer, *cpdp.TrustStore) {
	t.Helper()
	s, err := cpdp.GenerateLocalSigner(keyID)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := cpdp.NewTrustStore([]cpdp.TrustRoot{{KeyID: keyID, Alg: cpdp.SigAlgEd25519, Public: s.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	return s, ts
}

func gwEnv(t *testing.T, s cpdp.Signer, epoch int64, cfgRev uint64) *cpdp.Envelope {
	t.Helper()
	m := cpdp.Manifest{
		SchemaVersion: cpdp.SchemaVersion, Capability: cpdp.CapabilityGateway,
		Epoch: epoch, Revisions: cpdp.Revisions{Config: cfgRev, Policy: cfgRev, Catalog: 1, Credential: 1},
		MinDPVersion: 1, PayloadType: "gateway", PayloadVersion: 1, CreatedUnixNano: 1000,
		Source: cpdp.SourceMeta{Kind: "publish"},
	}
	p := cpdp.Payload{Gateway: &cpdp.GatewayPayload{
		Listener:     cpdp.GatewayListener{Enabled: true, BindAddress: "127.0.0.1", Port: 8091, PolicyDefaultAction: "deny"},
		Servers:      []cpdp.ServerRecord{{ID: "s1", Endpoint: "https://s1", PinnedIdentity: "sha256:aa", Verified: true, Enabled: true}},
		Tools:        []cpdp.ToolRecord{{Server: "s1", Name: "read", Fingerprint: "fp"}},
		PolicySource: gwPolicyDoc,
	}}
	env, err := cpdp.Sign(m, p, s, cpdp.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// memStore is an in-memory SnapStore with a fail switch and an onPersist hook used
// to prove persist-before-swap ordering.
type memStore struct {
	mu        sync.Mutex
	st        *PersistedState
	failNext  atomic.Bool
	persists  atomic.Int64
	onPersist func(*PersistedState)
}

func (m *memStore) Persist(st *PersistedState) error {
	if m.failNext.Load() {
		return mcperr.New(mcperr.ReasonSnapshotPersistFailed, "test", "injected persist failure")
	}
	if m.onPersist != nil {
		m.onPersist(st)
	}
	m.mu.Lock()
	m.st = st
	m.mu.Unlock()
	m.persists.Add(1)
	return nil
}

func (m *memStore) Load() (*PersistedState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st, nil
}

var idc atomic.Int64

func newApplier(t *testing.T, capab cpdp.Capability, ts *cpdp.TrustStore, store SnapStore) *Applier {
	t.Helper()
	a, err := New(Config{
		Capability: capab, Trust: ts, DPVersion: cpdp.DPCompatVersion, Limits: cpdp.DefaultLimits(),
		NodeID: "node-1", Store: store,
		Clock: func() int64 { return 42 },
		IDGen: func() string { return "ack-" + strconv.FormatInt(idc.Add(1), 10) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ---- blocking tests -----------------------------------------------------------

func TestApply_ValidActivatesAndPersistsBeforeSwap(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	env := gwEnv(t, s, 5, 2)

	// Prove persist happens BEFORE the active swap: at persist time the applier's
	// active pointer must still be the OLD value (nil here).
	store.onPersist = func(*PersistedState) {
		if a.store.Active() != nil {
			t.Errorf("active swapped before persist completed")
		}
	}
	ack, err := a.Apply(env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if ack.State != cpdp.AckApplied || ack.ContentHash != env.ContentHash {
		t.Fatalf("ack not applied/bound: %+v", ack)
	}
	if a.Active().ContentHash != env.ContentHash {
		t.Fatal("active not the applied env")
	}
	if store.persists.Load() != 1 {
		t.Fatalf("persists = %d, want 1", store.persists.Load())
	}
	if a.TrustedEpoch() != 5 {
		t.Fatalf("epoch = %d, want 5", a.TrustedEpoch())
	}
}

func TestApply_ValidationFailureLeavesActiveUnchanged(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	// Establish a valid active snapshot.
	env1 := gwEnv(t, s, 5, 2)
	if _, err := a.Apply(env1); err != nil {
		t.Fatal(err)
	}
	before := a.Active().ContentHash

	// Tamper a new envelope's payload after signing → hash mismatch on validation.
	env2 := gwEnv(t, s, 6, 3)
	env2.Payload.Gateway.Tools[0].Name = "tampered"
	ack, err := a.Apply(env2)
	reasonMust(t, err, mcperr.ReasonSnapshotHashMismatch)
	if ack.State != cpdp.AckRejected {
		t.Fatalf("ack state = %v, want rejected", ack.State)
	}
	if a.Active().ContentHash != before {
		t.Fatal("active changed after validation failure")
	}
	if a.TrustedEpoch() != 5 {
		t.Fatal("epoch advanced on validation failure")
	}
}

func TestApply_PreparationFailureLeavesActiveUnchanged(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	env1 := gwEnv(t, s, 5, 2)
	a.Apply(env1)
	before := a.Active().ContentHash

	// A syntactically-signed envelope whose policy source will fail to compile.
	m := env1.Manifest
	m.Epoch = 6
	m.Revisions.Config = 3
	p := cpdp.Payload{Gateway: &cpdp.GatewayPayload{PolicySource: "{not valid policy}"}}
	bad, _ := cpdp.Sign(m, p, s, cpdp.DefaultLimits())
	_, err := a.Apply(bad)
	if err == nil {
		t.Fatal("expected preparation failure")
	}
	if a.Active().ContentHash != before {
		t.Fatal("active changed after preparation failure")
	}
	if store.persists.Load() != 1 {
		t.Fatalf("prepare failure must not persist; persists=%d", store.persists.Load())
	}
}

func TestApply_PersistFailureLeavesActiveUnchanged(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	env1 := gwEnv(t, s, 5, 2)
	a.Apply(env1)
	before := a.Active().ContentHash
	beforeEpoch := a.TrustedEpoch()

	store.failNext.Store(true)
	env2 := gwEnv(t, s, 6, 3)
	ack, err := a.Apply(env2)
	reasonMust(t, err, mcperr.ReasonSnapshotPersistFailed)
	if ack.State != cpdp.AckRejected {
		t.Fatalf("ack = %v", ack.State)
	}
	if a.Active().ContentHash != before {
		t.Fatal("active changed after persist failure")
	}
	if a.TrustedEpoch() != beforeEpoch {
		t.Fatal("epoch advanced after persist failure (must not ratchet before persist)")
	}
}

// TestApply_SameRevDiffHashNotPersisted proves a same-epoch+same-config-revision
// candidate with a DIFFERENT content hash is rejected BEFORE persistence, so a
// subsequent restart never recovers the rejected candidate (rejection atomicity).
func TestApply_SameRevDiffHashNotPersisted(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	e1 := gwEnv(t, s, 5, 2)
	a.Apply(e1)
	if store.persists.Load() != 1 {
		t.Fatalf("first apply persists = %d", store.persists.Load())
	}
	// Same manifest (epoch 5, config 2) but a different payload ⇒ different hash.
	p2 := gwEnv(t, s, 5, 2)
	p2.Payload.Gateway.Tools[0].Name = "different"
	dup, _ := cpdp.Sign(p2.Manifest, p2.Payload, s, cpdp.DefaultLimits())
	if _, err := a.Apply(dup); err == nil {
		t.Fatal("same-revision different-content must be rejected")
	}
	if store.persists.Load() != 1 {
		t.Fatalf("rejected candidate was persisted: persists=%d", store.persists.Load())
	}
	// Restart restores e1, NOT the rejected candidate.
	a2 := newApplier(t, cpdp.CapabilityGateway, ts, store)
	if err := a2.Recover(); err != nil {
		t.Fatal(err)
	}
	if a2.Active().ContentHash != e1.ContentHash {
		t.Fatal("restart recovered a rejected candidate")
	}
}

func TestApply_InvalidHighEpochDoesNotRatchet(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
	a.Apply(gwEnv(t, s, 5, 2))
	// A very high epoch but a tampered signature.
	env := gwEnv(t, s, 100, 3)
	env.Signature = env.Signature[:len(env.Signature)-4] + "AAAA"
	_, err := a.Apply(env)
	if err == nil {
		t.Fatal("expected signature failure")
	}
	if a.TrustedEpoch() == 100 {
		t.Fatal("invalid high epoch ratcheted the trusted epoch")
	}
}

func TestApply_CurrentBecomesPreviousAndRestartRestores(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	e1 := gwEnv(t, s, 5, 2)
	e2 := gwEnv(t, s, 5, 3)
	a.Apply(e1)
	a.Apply(e2)
	if a.Active().ContentHash != e2.ContentHash || a.PreviousHash() != e1.ContentHash {
		t.Fatal("current/previous not advanced")
	}
	// Restart: a fresh applier over the same store restores exact hashes + revisions.
	a2 := newApplier(t, cpdp.CapabilityGateway, ts, store)
	if err := a2.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if a2.Active().ContentHash != e2.ContentHash || a2.PreviousHash() != e1.ContentHash {
		t.Fatal("restart did not restore exact hashes")
	}
	if a2.Active().Manifest.Revisions != e2.Manifest.Revisions {
		t.Fatal("restart did not restore exact revisions")
	}
	if a2.TrustedEpoch() != 5 {
		t.Fatalf("restart epoch = %d, want 5", a2.TrustedEpoch())
	}
}

func TestRecover_CorruptStateFailsClosed(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	a.Apply(gwEnv(t, s, 5, 2))
	// Corrupt the persisted current signature.
	store.st.Current.Signature = "AAAA"
	a2 := newApplier(t, cpdp.CapabilityGateway, ts, store)
	if err := a2.Recover(); err == nil {
		t.Fatal("recover must fail closed on corrupt state")
	}
	if a2.Active() != nil {
		t.Fatal("corrupt recovery must not activate a permissive empty state")
	}
}

func TestApply_AckDeliveryFailureDoesNotUndoActivation(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
	env := gwEnv(t, s, 5, 2)
	a.Apply(env)
	// Simulate a delivery failure: do NOT call ClearPendingAck. The activation and
	// pending ack both survive.
	if a.PendingAck() == nil || a.PendingAck().State != cpdp.AckApplied {
		t.Fatal("pending applied ack missing")
	}
	if a.Active().ContentHash != env.ContentHash {
		t.Fatal("activation undone by ack non-delivery")
	}
}

func TestApply_GatewayAndManagementIndependent(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	gwA := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
	mgA := newApplier(t, cpdp.CapabilityManagement, ts, &memStore{})
	if _, err := gwA.Apply(gwEnv(t, s, 5, 2)); err != nil {
		t.Fatal(err)
	}
	// A gateway envelope must not activate the management applier.
	if _, err := mgA.Apply(gwEnv(t, s, 5, 2)); err == nil {
		t.Fatal("management applier accepted a gateway snapshot")
	}
	if mgA.Active() != nil {
		t.Fatal("management active changed from a gateway snapshot")
	}
	// The gateway applier is unaffected.
	if gwA.Active() == nil {
		t.Fatal("gateway active lost")
	}
}

func TestApply_ReadersSeeOldOrNewNeverPartial(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
	e1 := gwEnv(t, s, 5, 2)
	a.Apply(e1)
	e2 := gwEnv(t, s, 5, 3)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					act := a.Active()
					if act == nil {
						t.Error("reader saw nil during apply")
						return
					}
					h := act.ContentHash
					if h != e1.ContentHash && h != e2.ContentHash {
						t.Errorf("reader saw a partial/unknown hash %q", h)
						return
					}
				}
			}
		}()
	}
	a.Apply(e2)
	close(stop)
	wg.Wait()
	if a.Active().ContentHash != e2.ContentHash {
		t.Fatal("final active not e2")
	}
}

// TestApply_RollbackRevertsToPreviousPersistBeforeSwap covers the DP-side rollback:
// a signed directive reverts to the retained previous snapshot, persisting before
// the swap, without moving the trusted epoch backwards.
func TestApply_RollbackRevertsToPreviousPersistBeforeSwap(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	e1 := gwEnv(t, s, 5, 2)
	e2 := gwEnv(t, s, 5, 3)
	a.Apply(e1)
	a.Apply(e2)
	epochBefore := a.TrustedEpoch()

	d, err := cpdp.SignRollback(cpdp.RollbackDirective{
		Capability: cpdp.CapabilityGateway, Epoch: 5,
		CurrentActiveHash: e2.ContentHash, TargetHash: e1.ContentHash, CommandID: "cmd1", MinDPVersion: 1,
	}, s)
	if err != nil {
		t.Fatal(err)
	}
	// persist-before-swap for rollback: at persist time active must still be e2.
	store.onPersist = func(*PersistedState) {
		if a.store.Active().ContentHash != e2.ContentHash {
			t.Errorf("rollback swapped before persist")
		}
	}
	ack, err := a.Rollback(d)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if ack.State != cpdp.AckRolledBack || ack.ContentHash != e1.ContentHash {
		t.Fatalf("rollback ack = %+v", ack)
	}
	if a.Active().ContentHash != e1.ContentHash {
		t.Fatal("rollback did not activate e1")
	}
	if a.TrustedEpoch() != epochBefore {
		t.Fatal("rollback moved the trusted epoch")
	}
}

// TestApply_RollbackTargetMissingLeavesActive proves a directive whose target is
// not retained leaves the current snapshot active.
func TestApply_RollbackTargetMissingLeavesActive(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
	e1 := gwEnv(t, s, 5, 2)
	a.Apply(e1)
	d, _ := cpdp.SignRollback(cpdp.RollbackDirective{
		Capability: cpdp.CapabilityGateway, CurrentActiveHash: e1.ContentHash,
		TargetHash: "notretained", CommandID: "c", MinDPVersion: 1,
	}, s)
	if _, err := a.Rollback(d); err == nil {
		t.Fatal("expected rollback failure")
	}
	if a.Active().ContentHash != e1.ContentHash {
		t.Fatal("active changed after failed rollback")
	}
}

func reasonMust(t *testing.T, err error, want mcperr.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %v, got nil", want)
	}
	if got := mcperr.ReasonOf(err); got != want {
		t.Fatalf("reason = %v, want %v (%v)", got, want, err)
	}
}

// ---- AbortApplied / RejectAck (transaction compensation) -----------------------

// TestAbortApplied_RevertsToPreviousPersistBeforeSwap proves AbortApplied undoes the
// last Apply: the active pointer returns to the prior snapshot, a Rejected ack
// replaces the pending Applied one, the revert is durably persisted (so a restart
// recovers the prior snapshot, never the aborted one), and persist happens before
// the in-memory swap.
func TestAbortApplied_RevertsToPreviousPersistBeforeSwap(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	e1 := gwEnv(t, s, 5, 2)
	e2 := gwEnv(t, s, 5, 3)
	if _, err := a.Apply(e1); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(e2); err != nil {
		t.Fatal(err)
	}
	// At persist time of the abort, the active pointer must still be the aborted e2.
	store.onPersist = func(st *PersistedState) {
		if a.store.Active() == nil || a.store.Active().ContentHash != e2.ContentHash {
			t.Errorf("active swapped before abort persist completed")
		}
		if st.Current == nil || st.Current.ContentHash != e1.ContentHash {
			t.Errorf("abort did not persist the prior snapshot as current")
		}
	}
	ack, err := a.AbortApplied(mcperr.New(mcperr.ReasonSnapshotPersistFailed, "test", "rollout persist failed"))
	if err != nil {
		t.Fatalf("abort: %v", err)
	}
	if ack.State != cpdp.AckRejected || ack.ContentHash != e2.ContentHash {
		t.Fatalf("abort ack not a rejection bound to the aborted env: %+v", ack)
	}
	if a.Active() == nil || a.Active().ContentHash != e1.ContentHash {
		t.Fatalf("abort did not revert active to the prior snapshot")
	}
	if a.PendingAck() == nil || a.PendingAck().State != cpdp.AckRejected {
		t.Fatal("pending ack must be the rejection after abort (no AckApplied may survive)")
	}
	// Restart recovers the prior snapshot, never the aborted one.
	a2 := newApplier(t, cpdp.CapabilityGateway, ts, store)
	if err := a2.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if a2.Active() == nil || a2.Active().ContentHash != e1.ContentHash {
		t.Fatal("restart after abort did not recover the prior snapshot")
	}
}

// TestAbortApplied_FirstApplyRevertsToNoActive proves aborting the FIRST apply (no
// prior snapshot) reverts to no-active (fail-closed / disabled), and a restart
// recovers no active snapshot.
func TestAbortApplied_FirstApplyRevertsToNoActive(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	e1 := gwEnv(t, s, 5, 2)
	if _, err := a.Apply(e1); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AbortApplied(mcperr.New(mcperr.ReasonSnapshotPersistFailed, "test", "x")); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if a.Active() != nil {
		t.Fatal("abort of the first apply must leave no active snapshot")
	}
	a2 := newApplier(t, cpdp.CapabilityGateway, ts, store)
	if err := a2.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if a2.Active() != nil {
		t.Fatal("restart after aborting the first apply must recover no active snapshot")
	}
}

// TestAbortApplied_PersistFailureLeavesAbortedActiveAndErrors proves that when the
// compensating write itself fails (a still-degraded disk), AbortApplied returns the
// error with the active pointer left on the aborted envelope — never a silent
// half-abort — so the caller/recovery can converge it.
func TestAbortApplied_PersistFailureLeavesAbortedActiveAndErrors(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	store := &memStore{}
	a := newApplier(t, cpdp.CapabilityGateway, ts, store)
	e1 := gwEnv(t, s, 5, 2)
	e2 := gwEnv(t, s, 5, 3)
	if _, err := a.Apply(e1); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(e2); err != nil {
		t.Fatal(err)
	}
	store.failNext.Store(true)
	ack, err := a.AbortApplied(mcperr.New(mcperr.ReasonSnapshotPersistFailed, "test", "x"))
	if err == nil {
		t.Fatal("abort must surface a compensating-write failure")
	}
	if ack == nil || ack.State != cpdp.AckRejected {
		t.Fatal("abort must still return a rejection ack")
	}
	if a.Active() == nil || a.Active().ContentHash != e2.ContentHash {
		t.Fatal("a failed abort must leave the active pointer on the aborted env (no silent half-abort)")
	}
}

// TestRejectAck_NoMutation proves RejectAck builds a bound rejection without touching
// active state or the pending ack.
func TestRejectAck_NoMutation(t *testing.T) {
	s, ts := mkSigner(t, "k1")
	a := newApplier(t, cpdp.CapabilityGateway, ts, &memStore{})
	e1 := gwEnv(t, s, 5, 2)
	if _, err := a.Apply(e1); err != nil {
		t.Fatal(err)
	}
	e2 := gwEnv(t, s, 5, 3)
	ack := a.RejectAck(e2, mcperr.New(mcperr.ReasonSnapshotPersistFailed, "test", "rollout precondition"))
	if ack.State != cpdp.AckRejected || ack.ContentHash != e2.ContentHash {
		t.Fatalf("reject ack not bound to e2: %+v", ack)
	}
	if a.Active() == nil || a.Active().ContentHash != e1.ContentHash {
		t.Fatal("RejectAck must not change active state")
	}
	if a.PendingAck() == nil || a.PendingAck().State != cpdp.AckApplied {
		t.Fatal("RejectAck must not disturb the existing pending Applied ack")
	}
}
