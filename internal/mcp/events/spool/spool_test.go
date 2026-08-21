package spool

import (
	"bytes"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/secret"
)

func testKEK() *secret.Provider {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return secret.MemoryProvider(key)
}

func testLimits(t *testing.T) limits.EventLimits {
	t.Helper()
	return limits.DefaultGatewayEvent()
}

func newTestSpool(t *testing.T, root string) *Spool {
	t.Helper()
	s, err := New(Config{
		Root: root, Capability: model.CapGateway, NodeID: "dp-test",
		Limits: testLimits(t), KEK: testKEK(),
		Clock: func() time.Time { return time.Unix(0, 1000) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Recover(); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	return s
}

func criticalEvent(id string, canary string) *model.Event {
	e := &model.Event{
		SchemaVersion: model.SchemaVersion, EventID: "evt_" + id, Phase: model.PhaseDecision,
		Criticality: model.CritCritical, Partition: model.PartCrit, Capability: model.CapGateway,
		ActionClass: model.ActionClassWrite, NodeID: "dp-test", DomainID: "d",
		TimeUnixNano: 1000, ReplayID: "rpl_" + id, CorrelationID: "cor_" + id,
		Identity: model.IdentityEvidence{Tenant: "acme", PrincipalID: canary, PrincipalType: "human"},
		Decision: model.DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 7, CatalogRevision: 3},
	}
	_, _ = e.ComputeDigest()
	return e
}

func TestNilKEKFailsClosed(t *testing.T) {
	_, err := New(Config{Root: t.TempDir(), Capability: model.CapGateway, NodeID: "n", Limits: testLimits(t), KEK: nil})
	if err == nil {
		t.Fatal("nil KEK must fail closed (no plaintext fallback)")
	}
	if mcperr.ReasonOf(err) != mcperr.ReasonEventEncryptionUnavailable {
		t.Fatalf("reason = %v, want encryption_unavailable", mcperr.ReasonOf(err))
	}
}

func TestCommitReturnsBoundReceipt(t *testing.T) {
	s := newTestSpool(t, t.TempDir())
	e := criticalEvent("0001", "user-xyz")
	r, err := s.Commit(e)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !r.Valid() {
		t.Fatal("receipt invalid")
	}
	if !r.Matches(e.EventDigest, "acme", model.CapGateway, model.ActionClassWrite) {
		t.Fatal("receipt does not match its decision identity")
	}
	// A receipt for another tenant/action must not match.
	if r.Matches(e.EventDigest, "other", model.CapGateway, model.ActionClassWrite) {
		t.Fatal("receipt matched a different tenant")
	}
	if r.Matches(e.EventDigest, "acme", model.CapGateway, model.ActionClassDestructive) {
		t.Fatal("receipt matched a different action class")
	}
	if r.Partition() != model.PartCrit || r.PolicyRevision() != 7 {
		t.Fatalf("receipt binding wrong: %+v", r)
	}
	// The zero receipt is unforgeable-invalid.
	var zero CommitReceipt
	if zero.Valid() || zero.Matches(e.EventDigest, "acme", model.CapGateway, model.ActionClassWrite) {
		t.Fatal("zero receipt must be invalid")
	}
}

func TestEnqueueIsNotCommit_PersistsAcrossReopen(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	e := criticalEvent("0001", "user-xyz")
	if _, err := s.Commit(e); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Reopen: the committed event must be recovered (durable across restart).
	s2 := newTestSpool(t, root)
	rep, err := s2.Recover()
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rep.Corrupt {
		t.Fatalf("recovery reported corruption: %s", rep.CorruptReason)
	}
	if rep.Records[model.PartCrit] != 1 {
		t.Fatalf("recovered %d P-CRIT records, want 1", rep.Records[model.PartCrit])
	}
}

func TestReplayDedupIdempotentAndConflict(t *testing.T) {
	s := newTestSpool(t, t.TempDir())
	e := criticalEvent("0001", "user-xyz")
	r1, err := s.Commit(e)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Exact-idempotent replay: same replay id + same event → same receipt, no new record.
	r2, err := s.Commit(e)
	if err != nil {
		t.Fatalf("idempotent Commit: %v", err)
	}
	if r2.Sequence() != r1.Sequence() {
		t.Fatal("idempotent replay produced a new sequence")
	}
	// A DIFFERENT event under the same replay id is a conflict.
	e2 := criticalEvent("0001", "user-different")
	if _, err := s.Commit(e2); mcperr.ReasonOf(err) != mcperr.ReasonEventReplayConflict {
		t.Fatalf("want replay conflict, got %v", err)
	}
}

func TestEncryptedAtRest_NoCanaryInSpoolBytes(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	canary := "SUPER-SECRET-CANARY-9f2c"
	e := criticalEvent("0001", canary)
	if _, err := s.Commit(e); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Scan every file under the spool root for the canary; it must not appear in
	// any plaintext-at-rest byte.
	be := osBackend{}
	dir := root + "/" + model.PartCrit.String()
	names, _ := be.List(dir)
	found := false
	for _, n := range names {
		b, _ := be.ReadFile(dir + "/" + n)
		if bytes.Contains(b, []byte(canary)) {
			found = true
		}
	}
	if found {
		t.Fatal("canary appeared in spool plaintext at rest")
	}
	if len(names) == 0 {
		t.Fatal("no segment written")
	}
}

func TestWrongKeyCannotRecover(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	if _, err := s.Commit(criticalEvent("0001", "x")); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Open with a different KEK: the sealed DEK cannot be opened → fail closed.
	otherKey := make([]byte, 32) // all zeros, different from testKEK
	_, err := New(Config{Root: root, Capability: model.CapGateway, NodeID: "dp-test", Limits: testLimits(t), KEK: secret.MemoryProvider(otherKey)})
	if err == nil {
		t.Fatal("wrong KEK must fail to open the spool")
	}
}
