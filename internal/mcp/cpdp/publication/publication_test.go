package publication

import (
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ---- fakes --------------------------------------------------------------------

type fakeAuth struct {
	allowed bool
	epoch   int64
}

func (f *fakeAuth) WriteAllowed() bool  { return f.allowed }
func (f *fakeAuth) CurrentEpoch() int64 { return f.epoch }

type committerMode int

const (
	commitOK committerMode = iota
	commitFailAdmission
	commitFailPostAdmission
)

type fakeCommitter struct {
	mode    committerMode
	actRuns int
}

func (f *fakeCommitter) CommitThenAct(_ PublicationFact, act func() error) error {
	switch f.mode {
	case commitFailAdmission:
		// Queue admission rejected: act NEVER runs.
		return mcperr.New(mcperr.ReasonEventQueueSaturated, "test", "admission saturated")
	case commitFailPostAdmission:
		// Admitted but the durable spool commit failed (ENOSPC/fsync/enc): act NEVER runs.
		return mcperr.New(mcperr.ReasonEventCommitFailed, "test", "post-admission spool commit failure")
	default:
		f.actRuns++
		return act()
	}
}

type fakeDist struct {
	nodes         []string
	rejectNode    map[string]bool // node returns a rejected ack
	unavailable   map[string]bool // node is unreachable
	pushCount     int
	rollbackCount int
	nodeID        string // authenticated identity passed to Record is the node id
}

func (f *fakeDist) Nodes() []string { return f.nodes }

func (f *fakeDist) Push(node string, env *cpdp.Envelope) (*cpdp.Acknowledgement, error) {
	f.pushCount++
	if f.unavailable[node] {
		return nil, errors.New("unreachable")
	}
	st := cpdp.AckApplied
	reason := ""
	if f.rejectNode[node] {
		st = cpdp.AckRejected
		reason = mcperr.ReasonSnapshotMinVersionUnmet.Code()
	}
	return &cpdp.Acknowledgement{
		AckID: "ack-" + node, NodeID: node, Capability: env.Manifest.Capability,
		ContentHash: env.ContentHash, Epoch: env.Manifest.Epoch, Revisions: env.Manifest.Revisions,
		State: st, ActiveHash: env.ContentHash, DPVersion: cpdp.DPCompatVersion, Health: "ok", RejectReason: reason,
	}, nil
}

func (f *fakeDist) PushRollback(node string, d *cpdp.RollbackDirective) (*cpdp.Acknowledgement, error) {
	f.rollbackCount++
	if f.unavailable[node] {
		return nil, errors.New("unreachable")
	}
	return &cpdp.Acknowledgement{
		AckID: "rb-" + node, NodeID: node, Capability: d.Capability, ContentHash: d.TargetHash,
		State: cpdp.AckRolledBack, ActiveHash: d.TargetHash, DPVersion: cpdp.DPCompatVersion, Health: "ok",
	}, nil
}

const gwPolicyDoc = `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`

func gwPayload() cpdp.Payload {
	return cpdp.Payload{Gateway: &cpdp.GatewayPayload{
		Listener:     cpdp.GatewayListener{Enabled: true, BindAddress: "127.0.0.1", Port: 8091, PolicyDefaultAction: "deny"},
		Servers:      []cpdp.ServerRecord{{ID: "s1", Endpoint: "https://s1", PinnedIdentity: "sha256:aa", Verified: true, Enabled: true}},
		Tools:        []cpdp.ToolRecord{{Server: "s1", Name: "read", Fingerprint: "fp"}},
		PolicySource: gwPolicyDoc,
	}}
}

func mkCoord(t *testing.T, auth *fakeAuth, com *fakeCommitter, dist *fakeDist) *Coordinator {
	t.Helper()
	s, err := cpdp.GenerateLocalSigner("k1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		Capability: cpdp.CapabilityGateway, Signer: s, Limits: cpdp.DefaultLimits(),
		DPVersion: cpdp.DPCompatVersion, Auth: auth, Committer: com, Dist: dist,
		Clock: func() int64 { return 100 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pubInput(rev uint64) PublishInput {
	return PublishInput{
		Payload: gwPayload(), Revisions: cpdp.Revisions{Config: rev, Policy: rev, Catalog: 1, Credential: 1},
		MinDPVersion: 1, PayloadType: "gateway", CandidateHash: "cand",
		VerifyApproval: func() bool { return true }, VerifyBase: func() bool { return true },
	}
}

// ---- forward publication ------------------------------------------------------

func TestPublish_HappyPathPartialTruthful(t *testing.T) {
	auth := &fakeAuth{allowed: true, epoch: 5}
	com := &fakeCommitter{mode: commitOK}
	dist := &fakeDist{nodes: []string{"n1", "n2", "n3"}, rejectNode: map[string]bool{"n2": true}, unavailable: map[string]bool{"n3": true}}
	c := mkCoord(t, auth, com, dist)

	res, err := c.Publish(pubInput(2))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if com.actRuns != 1 {
		t.Fatalf("act runs = %d", com.actRuns)
	}
	if res.Counts.Intended != 3 || res.Counts.Applied != 1 || res.Counts.Rejected != 1 || res.Counts.Incompatible != 1 || res.Counts.Unavailable != 1 {
		t.Fatalf("counts = %+v", res.Counts)
	}
	// applied=1 of 3 with an unavailable node → degraded, NOT fully_acknowledged.
	if res.State != StateDistributionDegraded {
		t.Fatalf("state = %q, want degraded", res.State)
	}
	if c.CurrentHash() != res.ContentHash {
		t.Fatal("CP store not installed")
	}
}

func TestPublish_FullyAcknowledged(t *testing.T) {
	c := mkCoord(t, &fakeAuth{allowed: true, epoch: 5}, &fakeCommitter{mode: commitOK}, &fakeDist{nodes: []string{"n1", "n2"}})
	res, err := c.Publish(pubInput(2))
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateFullyAcknowledged {
		t.Fatalf("state = %q, want fully_acknowledged", res.State)
	}
}

func TestPublish_PR8AdmissionSaturation_NoSideEffects(t *testing.T) {
	com := &fakeCommitter{mode: commitFailAdmission}
	dist := &fakeDist{nodes: []string{"n1", "n2"}}
	c := mkCoord(t, &fakeAuth{allowed: true, epoch: 5}, com, dist)
	_, err := c.Publish(pubInput(2))
	reasonMust(t, err, mcperr.ReasonPublicationDurabilityRequired)
	if com.actRuns != 0 {
		t.Fatal("act ran despite admission failure")
	}
	if c.CurrentHash() != "" {
		t.Fatal("a snapshot was installed despite no durable commit")
	}
	if dist.pushCount != 0 {
		t.Fatal("a snapshot was pushed despite no durable commit")
	}
}

func TestPublish_PR8PostAdmissionCommitFailure_NoSideEffects(t *testing.T) {
	com := &fakeCommitter{mode: commitFailPostAdmission}
	dist := &fakeDist{nodes: []string{"n1", "n2"}}
	c := mkCoord(t, &fakeAuth{allowed: true, epoch: 5}, com, dist)
	_, err := c.Publish(pubInput(2))
	reasonMust(t, err, mcperr.ReasonPublicationDurabilityRequired)
	if com.actRuns != 0 || c.CurrentHash() != "" || dist.pushCount != 0 {
		t.Fatalf("post-admission commit failure produced side effects: act=%d hash=%q push=%d", com.actRuns, c.CurrentHash(), dist.pushCount)
	}
}

func TestPublish_LostLeaseRejected(t *testing.T) {
	com := &fakeCommitter{mode: commitOK}
	c := mkCoord(t, &fakeAuth{allowed: false, epoch: 5}, com, &fakeDist{nodes: []string{"n1"}})
	_, err := c.Publish(pubInput(2))
	reasonMust(t, err, mcperr.ReasonDistributionWriteAuthority)
	if com.actRuns != 0 {
		t.Fatal("committed despite no write authority")
	}
}

func TestPublish_StaleBaseAndBadApprovalRejected(t *testing.T) {
	c := mkCoord(t, &fakeAuth{allowed: true, epoch: 5}, &fakeCommitter{mode: commitOK}, &fakeDist{nodes: []string{"n1"}})
	in := pubInput(2)
	in.VerifyBase = func() bool { return false }
	if _, err := c.Publish(in); err == nil {
		t.Fatal("stale base must be rejected")
	}
	in2 := pubInput(2)
	in2.VerifyApproval = func() bool { return false }
	if _, err := c.Publish(in2); err == nil {
		t.Fatal("bad approval must be rejected")
	}
}

// ---- acknowledgement tracking -------------------------------------------------

func TestAckTracker_Rules(t *testing.T) {
	tr := NewAckTracker(cpdp.CapabilityGateway, cpdp.DefaultLimits())
	tr.MarkKnown("h1")
	base := cpdp.Acknowledgement{AckID: "a", NodeID: "n1", Capability: cpdp.CapabilityGateway, ContentHash: "h1", State: cpdp.AckApplied, Health: "ok"}

	// unauthenticated rejected.
	reasonMust(t, tr.Record("", base), mcperr.ReasonAckUnauthenticated)
	// node id mismatch with authenticated identity rejected.
	reasonMust(t, tr.Record("other", base), mcperr.ReasonAckInvalid)
	// unknown hash rejected.
	bad := base
	bad.ContentHash = "h2"
	reasonMust(t, tr.Record("n1", bad), mcperr.ReasonAckInvalid)
	// wrong capability rejected.
	wc := base
	wc.Capability = cpdp.CapabilityManagement
	reasonMust(t, tr.Record("n1", wc), mcperr.ReasonAckInvalid)
	// valid applied recorded; duplicate idempotent.
	if err := tr.Record("n1", base); err != nil {
		t.Fatal(err)
	}
	if err := tr.Record("n1", base); err != nil {
		t.Fatal(err)
	}
	// a stale (received) state cannot regress the applied state.
	stale := base
	stale.State = cpdp.AckReceived
	if err := tr.Record("n1", stale); err != nil {
		t.Fatal(err)
	}
	c := tr.Counts("h1", []string{"n1"})
	if c.Applied != 1 {
		t.Fatalf("stale ack regressed applied: %+v", c)
	}
}

// ---- rollback -----------------------------------------------------------------

func setupPublished(t *testing.T) (*Coordinator, *fakeCommitter, *fakeDist, string) {
	auth := &fakeAuth{allowed: true, epoch: 5}
	com := &fakeCommitter{mode: commitOK}
	dist := &fakeDist{nodes: []string{"n1"}}
	c := mkCoord(t, auth, com, dist)
	if _, err := c.Publish(pubInput(2)); err != nil {
		t.Fatal(err)
	}
	e1 := c.CurrentHash()
	if _, err := c.Publish(pubInput(3)); err != nil {
		t.Fatal(err)
	}
	return c, com, dist, e1
}

func TestRollback_HappyPath(t *testing.T) {
	c, com, dist, e1 := setupPublished(t)
	com.actRuns = 0
	dist.rollbackCount = 0
	res, err := c.Rollback(RollbackInput{TargetHash: e1, CommandID: "cmd", VerifyApproval: func() bool { return true }})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if c.CurrentHash() != e1 {
		t.Fatal("CP store not reverted to target")
	}
	if res.TargetHash != e1 || dist.rollbackCount != 1 {
		t.Fatalf("rollback result/push wrong: %+v push=%d", res, dist.rollbackCount)
	}
}

func TestRollback_PR8AdmissionSaturation_NoSwap(t *testing.T) {
	c, com, dist, e1 := setupPublished(t)
	cur := c.CurrentHash()
	com.mode = commitFailAdmission
	dist.rollbackCount = 0
	_, err := c.Rollback(RollbackInput{TargetHash: e1, CommandID: "cmd", VerifyApproval: func() bool { return true }})
	if err == nil {
		t.Fatal("expected rollback durability failure")
	}
	if c.CurrentHash() != cur {
		t.Fatal("CURRENT POINTER CHANGED despite no durable rollback commit")
	}
	if dist.rollbackCount != 0 {
		t.Fatal("a rollback directive was pushed despite no durable commit")
	}
}

func TestRollback_PR8PostAdmissionCommitFailure_NoSwap(t *testing.T) {
	c, com, dist, e1 := setupPublished(t)
	cur := c.CurrentHash()
	com.mode = commitFailPostAdmission
	dist.rollbackCount = 0
	_, err := c.Rollback(RollbackInput{TargetHash: e1, CommandID: "cmd", VerifyApproval: func() bool { return true }})
	if err == nil {
		t.Fatal("expected rollback durability failure")
	}
	if c.CurrentHash() != cur {
		t.Fatal("CURRENT POINTER CHANGED despite post-admission commit failure")
	}
	if dist.rollbackCount != 0 {
		t.Fatal("directive pushed despite post-admission commit failure")
	}
}

func TestRollback_TargetNotRetained(t *testing.T) {
	c, _, _, _ := setupPublished(t)
	cur := c.CurrentHash()
	if _, err := c.Rollback(RollbackInput{TargetHash: "ghost", CommandID: "c", VerifyApproval: func() bool { return true }}); err == nil {
		t.Fatal("expected target-missing")
	}
	if c.CurrentHash() != cur {
		t.Fatal("active changed after failed rollback")
	}
}

func reasonMust(t *testing.T, err error, want mcperr.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %v, got nil", want)
	}
	if got := mcperr.ReasonOf(err); got != want {
		t.Fatalf("reason = %v, want %v (%v)", got, want, err)
	}
}
