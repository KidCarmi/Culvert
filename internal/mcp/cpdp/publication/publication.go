package publication

import (
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// WriteAuthority is the injected HA lease/write-authority gate (adapter over
// globalHA in package main). The coordinator consults it immediately before the
// irreversible publication boundary.
type WriteAuthority interface {
	// WriteAllowed reports whether this CP currently holds write authority.
	WriteAllowed() bool
	// CurrentEpoch returns the CP's fencing epoch to stamp onto the snapshot.
	CurrentEpoch() int64
}

// Fact is the durable P-CRIT event fact for a config-publication or rollback
// decision. The adapter maps it to the PR-8 events.Manager with
// ActionClassConfigPublication + CritCritical.
type Fact struct {
	Capability  cpdp.Capability
	ContentHash string
	Revision    uint64
	Rollback    bool
	TargetHash  string
}

// DurableCommitter is the injected PR-8 durable-commit seam. CommitThenAct MUST
// durably commit the fact to the encrypted P-CRIT spool and run act ONLY on a
// confirmed commit; on any commit failure (queue saturation OR post-admission
// spool-commit failure) it MUST return an error and NOT run act. This mirrors
// events.Manager.CommitThenAct.
type DurableCommitter interface {
	CommitThenAct(fact Fact, act func() error) error
}

// Distributor is the injected CP→DP transport. Nodes returns the intended DP node
// ids; Push/PushRollback deliver a signed artifact to a node and return its
// acknowledgement (or an error if the node is unreachable).
type Distributor interface {
	Nodes() []string
	Push(node string, env *cpdp.Envelope) (*cpdp.Acknowledgement, error)
	// PushRollback delivers the signed rollback directive AND the reverted (target)
	// envelope to a node, so a pull-based transport can install the reverted snapshot
	// on the wire while the directive remains the audited command.
	PushRollback(node string, d *cpdp.RollbackDirective, reverted *cpdp.Envelope) (*cpdp.Acknowledgement, error)
}

// Config wires a capability-local Coordinator.
type Config struct {
	Capability cpdp.Capability
	Signer     cpdp.Signer
	Limits     cpdp.Limits
	DPVersion  cpdp.CompatVersion // minimum DP version to stamp (>= this build)
	Auth       WriteAuthority
	Committer  DurableCommitter
	Dist       Distributor
	Clock      func() int64
}

// Coordinator is the capability-local CP publication + rollback coordinator.
type Coordinator struct {
	cfg     Config
	tracker *AckTracker

	mu         sync.Mutex // serializes publish/rollback
	cpCurrent  *cpdp.Envelope
	cpPrevious *cpdp.Envelope
	lastState  DistributionState
}

// New returns a capability-local Coordinator.
func New(cfg Config) (*Coordinator, error) {
	if !cfg.Capability.Valid() {
		return nil, mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.pub", "invalid capability")
	}
	if cfg.Signer == nil || cfg.Auth == nil || cfg.Committer == nil || cfg.Dist == nil || cfg.Clock == nil {
		return nil, mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.pub", "incomplete coordinator config")
	}
	return &Coordinator{cfg: cfg, tracker: NewAckTracker(cfg.Capability, cfg.Limits), lastState: StateLocalOnly}, nil
}

// PublishInput is the approved candidate to publish. The approval binding
// callbacks re-verify the four-eyes receipt and the live base revision at publish
// time (TOCTOU guards) — the coordinator refuses to publish if either fails.
type PublishInput struct {
	Payload       cpdp.Payload
	Revisions     cpdp.Revisions
	MinDPVersion  cpdp.CompatVersion
	PayloadType   string
	CandidateHash string // the exact approved candidate hash (PR-9)
	// VerifyApproval re-checks the four-eyes receipt binds to THIS exact candidate.
	// It receives the candidate hash the coordinator recomputed from the payload it
	// is about to sign, so the receipt cannot be satisfied by a different payload.
	VerifyApproval func(candidateHash string) bool
	// VerifyBase re-checks the live base revision still matches (optimistic concurrency).
	VerifyBase func() bool
}

// PublishResult is the truthful outcome of a publication.
type PublishResult struct {
	State       DistributionState  `json:"distribution_state"`
	ContentHash string             `json:"content_hash"`
	Revision    uint64             `json:"revision"`
	Epoch       int64              `json:"epoch"`
	KeyID       string             `json:"signing_key_id"`
	Counts      DistributionCounts `json:"counts"`
}

// Publish runs the forward publication in the mandatory order. NOTHING is signed,
// no revision is committed, no CP-store swap, no push, and no DP change occurs
// before the PR-8 P-CRIT event is durably committed. All of those side effects run
// INSIDE the durable-commit callback, so a commit failure (saturation or
// post-admission) leaves every DP on its prior snapshot and the CP store unchanged.
func (c *Coordinator) Publish(in PublishInput) (PublishResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1-2: resolve + re-verify the EXACT approved candidate + live base. The
	// candidate hash is recomputed from the payload about to be signed and must match
	// the approved candidate; the four-eyes receipt is then checked against that same
	// hash, so a caller cannot approve one candidate and sign a different payload.
	candHash, err := cpdp.CandidateHash(c.cfg.Capability, in.Payload, c.cfg.Limits.CanonicalBounds())
	if err != nil {
		return PublishResult{}, err
	}
	if in.CandidateHash != "" && in.CandidateHash != candHash {
		return PublishResult{}, mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.pub", "payload does not match the approved candidate hash")
	}
	if in.VerifyApproval == nil || !in.VerifyApproval(candHash) {
		return PublishResult{}, mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.pub", "approval receipt does not bind the candidate")
	}
	if in.VerifyBase == nil || !in.VerifyBase() {
		return PublishResult{}, mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.pub", "stale base revision")
	}
	// 3: build the complete capability snapshot off-path (manifest from the CP epoch).
	epoch := c.cfg.Auth.CurrentEpoch()
	m := cpdp.Manifest{
		SchemaVersion: cpdp.SchemaVersion, Capability: c.cfg.Capability, Epoch: epoch,
		Revisions: in.Revisions, MinDPVersion: in.MinDPVersion, PayloadType: in.PayloadType,
		PayloadVersion: 1, CreatedUnixNano: c.cfg.Clock(), Source: cpdp.SourceMeta{Kind: "publish"},
	}
	// 4: validate the UNSIGNED candidate completely.
	if err := cpdp.ValidateCandidate(m, in.Payload, cpdp.ValidateInput{
		ExpectCapability: c.cfg.Capability, DPVersion: c.cfg.DPVersion, Trust: nil, Limits: c.cfg.Limits,
	}); err != nil {
		return PublishResult{}, err
	}
	// Deterministically compute the content hash BEFORE signing (no private key
	// needed) so the PR-8 event can carry it.
	contentHash, err := cpdp.ContentHash(m, in.Payload, c.cfg.Signer.Algorithm(), c.cfg.Signer.KeyID(), c.cfg.Limits.CanonicalBounds())
	if err != nil {
		return PublishResult{}, err
	}
	// 5: check CP lease/write authority immediately before the irreversible boundary.
	if !c.cfg.Auth.WriteAllowed() {
		return PublishResult{}, mcperr.New(mcperr.ReasonDistributionWriteAuthority, "cpdp.pub", "not write-authoritative")
	}
	// 6-8: durably commit the PR-8 config-publication event FIRST; sign/install/push
	// happen ONLY inside act, i.e. only after a confirmed commit.
	var result PublishResult
	commitErr := c.cfg.Committer.CommitThenAct(
		Fact{Capability: c.cfg.Capability, ContentHash: contentHash, Revision: in.Revisions.Config},
		func() error {
			env, serr := cpdp.Sign(m, in.Payload, c.cfg.Signer, c.cfg.Limits)
			if serr != nil {
				return serr
			}
			if env.ContentHash != contentHash {
				return mcperr.New(mcperr.ReasonSnapshotHashMismatch, "cpdp.pub", "signed hash differs from committed hash")
			}
			// Atomically install in the CP publication store (previous <- current).
			c.cpPrevious = c.cpCurrent
			c.cpCurrent = env
			c.tracker.MarkKnown(env.ContentHash)
			// 9: push to intended DPs + collect acknowledgements.
			c.pushAll(env)
			result = c.buildResult(env)
			return nil
		},
	)
	if commitErr != nil {
		// Fail closed: no revision committed, nothing signed/installed/pushed, every
		// DP remains on its prior snapshot/epoch.
		return PublishResult{}, mcperr.Wrap(mcperr.ReasonPublicationDurabilityRequired, "cpdp.pub", "publication event not durable", commitErr)
	}
	c.lastState = result.State
	return result, nil
}

// pushAll delivers the signed envelope to every intended DP and records each
// acknowledgement. A node that is unreachable is left as unavailable (no ack).
func (c *Coordinator) pushAll(env *cpdp.Envelope) {
	for _, node := range c.cfg.Dist.Nodes() {
		ack, err := c.cfg.Dist.Push(node, env)
		if err != nil || ack == nil {
			continue // unavailable — counted as such in the tally
		}
		_ = c.tracker.Record(node, *ack) // node id is the authenticated transport identity
	}
}

func (c *Coordinator) buildResult(env *cpdp.Envelope) PublishResult {
	counts := c.tracker.Counts(env.ContentHash, c.cfg.Dist.Nodes())
	return PublishResult{
		State: deriveState(counts), ContentHash: env.ContentHash,
		Revision: env.Manifest.Revisions.Config, Epoch: env.Manifest.Epoch,
		KeyID: env.KeyID, Counts: counts,
	}
}

// CurrentHash returns the CP publication store's current content hash, or "".
func (c *Coordinator) CurrentHash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cpCurrent == nil {
		return ""
	}
	return c.cpCurrent.ContentHash
}

// PreviousHash returns the CP publication store's previous content hash, or "".
func (c *Coordinator) PreviousHash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cpPrevious == nil {
		return ""
	}
	return c.cpPrevious.ContentHash
}

// RecordAck ingests a DP acknowledgement over the authenticated transport.
func (c *Coordinator) RecordAck(authNodeID string, a cpdp.Acknowledgement) error {
	return c.tracker.Record(authNodeID, a)
}

// State returns the last derived distribution state.
func (c *Coordinator) State() DistributionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastState
}
