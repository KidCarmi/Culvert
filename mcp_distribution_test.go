package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	cpdpapply "github.com/KidCarmi/Culvert/internal/mcp/cpdp/apply"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp/publication"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/secret"
)

const mcpTestPolicyDoc = `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`

func mcpTestSigner(t *testing.T) (cpdp.Signer, *cpdp.TrustStore) {
	t.Helper()
	s, err := cpdp.GenerateLocalSigner("mcp-k1")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := cpdp.NewTrustStore([]cpdp.TrustRoot{{KeyID: "mcp-k1", Alg: cpdp.SigAlgEd25519, Public: s.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	return s, ts
}

func mcpTestGWEnv(t *testing.T, s cpdp.Signer) *cpdp.Envelope {
	t.Helper()
	m := cpdp.Manifest{
		SchemaVersion: cpdp.SchemaVersion, Capability: cpdp.CapabilityGateway, Epoch: 0,
		Revisions: cpdp.Revisions{Config: 2, Policy: 2, Catalog: 1, Credential: 1}, MinDPVersion: 1,
		PayloadType: "gateway", PayloadVersion: 1, CreatedUnixNano: 1000, Source: cpdp.SourceMeta{Kind: "publish"},
	}
	p := cpdp.Payload{Gateway: &cpdp.GatewayPayload{
		Listener: cpdp.GatewayListener{Enabled: true, BindAddress: "127.0.0.1", Port: 8091, PolicyDefaultAction: "deny"},
		Servers:  []cpdp.ServerRecord{{ID: "s1", Endpoint: "https://s1", PinnedIdentity: "sha256:aa", Verified: true, Enabled: true}},
		Tools:    []cpdp.ToolRecord{{Server: "s1", Name: "read", Fingerprint: "fp"}}, PolicySource: mcpTestPolicyDoc,
	}}
	env, err := cpdp.Sign(m, p, s, cpdp.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestMCP_SWGByteCompatWhenDisabled proves a ConfigSnapshot with MCP distribution
// disabled (the default) carries NO mcp_* fields on the wire — byte-compatible with
// the pre-PR-10 SWG snapshot.
func TestMCP_SWGByteCompatWhenDisabled(t *testing.T) {
	if globalMCPDistribution.enabled.Load() {
		t.Skip("MCP distribution unexpectedly enabled")
	}
	snap := ConfigSnapshot{Version: 1}
	snap.MCPGatewaySnapshot = mcpCapturedGateway()
	snap.MCPManagementSnapshot = mcpCapturedManagement()
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "mcp_gateway_snapshot") || strings.Contains(string(raw), "mcp_management_snapshot") {
		t.Fatalf("disabled MCP leaked fields onto the wire: %s", raw)
	}
}

// TestMCP_ApplySnapshotDisabledNoOp proves applySnapshotMCP is a no-op when no DP
// applier is wired (keep-local; absence is not deletion).
func TestMCP_ApplySnapshotDisabledNoOp(t *testing.T) {
	s, _ := mcpTestSigner(t)
	snap := ConfigSnapshot{Version: 1, MCPGatewaySnapshot: mcpTestGWEnv(t, s)}
	applySnapshotMCP(snap) // must not panic and must not require a DP applier
}

// TestMCP_ApplySnapshotValidAndMalformed proves a wired DP applier activates a
// valid envelope and rejects a malformed one WHOLE without affecting SWG state.
func TestMCP_ApplySnapshotValidAndMalformed(t *testing.T) {
	s, ts := mcpTestSigner(t)
	dir := t.TempDir()
	ap, err := cpdpapply.New(cpdpapply.Config{
		Capability: cpdp.CapabilityGateway, Trust: ts, DPVersion: cpdp.DPCompatVersion, Limits: cpdp.DefaultLimits(),
		NodeID: "dp-1", Store: cpdpapply.NewFileStore(dir, cpdp.CapabilityGateway),
		Clock: func() int64 { return 1 }, IDGen: func() string { return "ack" },
	})
	if err != nil {
		t.Fatal(err)
	}
	globalMCPDistribution.setDPApplier(cpdp.CapabilityGateway, ap)
	defer globalMCPDistribution.setDPApplier(cpdp.CapabilityGateway, nil)

	valid := mcpTestGWEnv(t, s)
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: valid})
	if ap.Active() == nil || ap.Active().ContentHash != valid.ContentHash {
		t.Fatal("valid MCP envelope did not activate")
	}
	// A tampered envelope must be rejected whole; the prior active is retained.
	bad := mcpTestGWEnv(t, s)
	bad.Payload.Gateway.Tools[0].Name = "tampered"
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: bad})
	if ap.Active().ContentHash != valid.ContentHash {
		t.Fatal("malformed MCP envelope corrupted the active snapshot")
	}
}

// ---- real PR-8 path re-run ----------------------------------------------------

// failBackend wraps the OS spool backend and fails AppendSync when armed, to prove
// a post-admission durable-commit failure aborts publication with no side effects.
type failBackend struct {
	inner spool.Backend
	fail  bool
}

func (f *failBackend) MkdirAll(d string, p os.FileMode) error { return f.inner.MkdirAll(d, p) }
func (f *failBackend) AppendSync(path string, frame []byte, perm os.FileMode) error {
	if f.fail {
		return os.ErrInvalid // simulated ENOSPC/fsync failure
	}
	return f.inner.AppendSync(path, frame, perm)
}
func (f *failBackend) AtomicReplace(path string, d []byte, p os.FileMode) error {
	return f.inner.AtomicReplace(path, d, p)
}
func (f *failBackend) ReadFile(path string) ([]byte, error) { return f.inner.ReadFile(path) }
func (f *failBackend) ReadAt(path string, o int64, b []byte) (int, error) {
	return f.inner.ReadAt(path, o, b)
}
func (f *failBackend) Truncate(path string, s int64) error { return f.inner.Truncate(path, s) }
func (f *failBackend) Remove(path string) error            { return f.inner.Remove(path) }
func (f *failBackend) Size(path string) (int64, error)     { return f.inner.Size(path) }
func (f *failBackend) List(dir string) ([]string, error)   { return f.inner.List(dir) }

func mcpTestKEK() *secret.Provider {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 7)
	}
	return secret.MemoryProvider(k)
}

func newRealCoord(t *testing.T, be spool.Backend) (*publication.Coordinator, *events.Manager) {
	t.Helper()
	mgr, err := events.NewManager(events.ManagerConfig{
		NodeID: "cp-1", DataDir: t.TempDir(), KEK: mcpTestKEK(),
		GatewayLimits: limits.DefaultGatewayEvent(), ManagementLimits: limits.DefaultManagementEvent(),
		Backend: be, Clock: func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := mcpTestSigner(t)
	coord, err := publication.New(publication.Config{
		Capability: cpdp.CapabilityGateway, Signer: s, Limits: cpdp.DefaultLimits(), DPVersion: cpdp.DPCompatVersion,
		Auth: mcpHAWriteAuthority{}, Committer: newMCPEventsCommitter(mgr, "test"),
		Dist: mcpPullDistributor{}, Clock: func() int64 { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return coord, mgr
}

func mcpPubInput(rev uint64) publication.PublishInput {
	return publication.PublishInput{
		Payload: cpdp.Payload{Gateway: &cpdp.GatewayPayload{
			Servers: []cpdp.ServerRecord{{ID: "s1", Endpoint: "https://s1", PinnedIdentity: "x", Verified: true, Enabled: true}},
			Tools:   []cpdp.ToolRecord{{Server: "s1", Name: "read", Fingerprint: "fp"}}, PolicySource: mcpTestPolicyDoc,
		}},
		Revisions: cpdp.Revisions{Config: rev, Policy: rev, Catalog: 1, Credential: 1}, MinDPVersion: 1, PayloadType: "gateway",
		CandidateHash: "c", VerifyApproval: func() bool { return true }, VerifyBase: func() bool { return true },
	}
}

// TestMCP_RealPR8_ForwardHappyPath proves a publish against the REAL event manager
// commits durably and installs the signed envelope.
func TestMCP_RealPR8_ForwardHappyPath(t *testing.T) {
	coord, _ := newRealCoord(t, &failBackend{inner: spool.NewOSBackend()})
	if _, err := coord.Publish(mcpPubInput(2)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if coord.CurrentHash() == "" {
		t.Fatal("healthy real-path publish did not install a snapshot")
	}
}

// TestMCP_RealPR8_ForwardPostAdmissionCommitFailure_NoSideEffects: a confirmed
// spool-commit failure (AppendSync error) aborts publication — nothing signed,
// installed or pushed.
func TestMCP_RealPR8_ForwardPostAdmissionCommitFailure_NoSideEffects(t *testing.T) {
	be := &failBackend{inner: spool.NewOSBackend(), fail: true}
	coord, _ := newRealCoord(t, be)
	if _, err := coord.Publish(mcpPubInput(2)); err == nil {
		t.Fatal("expected a durability failure")
	}
	if coord.CurrentHash() != "" {
		t.Fatal("a snapshot was installed despite a post-admission commit failure")
	}
}

// TestMCP_RealPR8_ForwardAdmissionRejection_NoSideEffects: once the critical
// durability domain is degraded, a new critical publish is rejected at admission
// (before the spool) — no side effects.
func TestMCP_RealPR8_ForwardAdmissionRejection_NoSideEffects(t *testing.T) {
	be := &failBackend{inner: spool.NewOSBackend(), fail: true}
	coord, mgr := newRealCoord(t, be)
	// First publish fails post-admission → domain becomes critical-durability-degraded.
	_, _ = coord.Publish(mcpPubInput(2))
	if mgr.WriteAllowedCritical(mcpModelCapability(cpdp.CapabilityGateway)) {
		t.Fatal("domain should be degraded after a critical commit failure")
	}
	// Even with the backend now healthy, the degraded domain rejects at admission.
	be.fail = false
	if _, err := coord.Publish(mcpPubInput(3)); err == nil {
		t.Fatal("expected admission rejection in a degraded domain")
	}
	if coord.CurrentHash() != "" {
		t.Fatal("a snapshot was installed despite admission rejection")
	}
}

// TestMCP_RealPR8_RollbackPostAdmissionCommitFailure_NoSwap: a rollback whose PR-8
// event cannot durably commit performs NO swap — the current snapshot stays active.
func TestMCP_RealPR8_RollbackPostAdmissionCommitFailure_NoSwap(t *testing.T) {
	be := &failBackend{inner: spool.NewOSBackend()}
	coord, _ := newRealCoord(t, be)
	if _, err := coord.Publish(mcpPubInput(2)); err != nil {
		t.Fatal(err)
	}
	e1 := coord.CurrentHash()
	if _, err := coord.Publish(mcpPubInput(3)); err != nil {
		t.Fatal(err)
	}
	cur := coord.CurrentHash()
	be.fail = true // the rollback event will fail to commit
	_, err := coord.Rollback(publication.RollbackInput{TargetHash: e1, CommandID: "cmd", VerifyApproval: func() bool { return true }})
	if err == nil {
		t.Fatal("expected rollback durability failure")
	}
	if coord.CurrentHash() != cur {
		t.Fatal("CURRENT POINTER CHANGED despite a rollback commit failure (no swap allowed)")
	}
}

// TestMCP_AckAuthBinding proves an acknowledgement is bound to the authenticated
// enrolled-node identity: a mismatched node id is rejected.
func TestMCP_AckAuthBinding(t *testing.T) {
	coord, _ := newRealCoord(t, &failBackend{inner: spool.NewOSBackend()})
	if _, err := coord.Publish(mcpPubInput(2)); err != nil {
		t.Fatal(err)
	}
	hash := coord.CurrentHash()
	ack := cpdp.Acknowledgement{
		AckID: "a", NodeID: "node-A", Capability: cpdp.CapabilityGateway, ContentHash: hash,
		State: cpdp.AckApplied, Health: "ok",
	}
	// Authenticated as a DIFFERENT node ⇒ rejected.
	if err := mcpIngestAck(coord, "node-B", ack); err == nil {
		t.Fatal("ack accepted with a mismatched authenticated node identity")
	}
	// Unauthenticated ⇒ rejected.
	if err := mcpIngestAck(coord, "", ack); err == nil {
		t.Fatal("ack accepted over an unauthenticated context")
	}
	// Correctly authenticated ⇒ accepted.
	if err := mcpIngestAck(coord, "node-A", ack); err != nil {
		t.Fatalf("valid authenticated ack rejected: %v", err)
	}
}
