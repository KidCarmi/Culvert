package publication

import (
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// RollbackInput is an operator-approved rollback to the retained previous snapshot.
type RollbackInput struct {
	// TargetHash is the exact retained signed snapshot hash to revert to. It must
	// equal the CP publication store's previous hash.
	TargetHash string
	CommandID  string
	// ExpiryUnixNano bounds the directive's validity.
	ExpiryUnixNano int64
	// VerifyApproval re-checks the four-eyes rollback approval binds this command.
	VerifyApproval func() bool
}

// RollbackResult is the truthful outcome of a rollback.
type RollbackResult struct {
	State      DistributionState  `json:"distribution_state"`
	TargetHash string             `json:"target_hash"`
	Epoch      int64              `json:"epoch"`
	Counts     DistributionCounts `json:"counts"`
}

// Rollback runs the operator-controlled rollback in the mandatory order. NOTHING
// is signed or pushed and NO CP or DP pointer swaps before the PR-8 rollback event
// is durably committed — a commit failure leaves the current snapshot active
// everywhere. The rollback side effect is a SWAP, so the failure path is asserted
// on the active pointer, not on revision creation.
func (c *Coordinator) Rollback(in RollbackInput) (RollbackResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1: validate target + current hash.
	if c.cpCurrent == nil {
		return RollbackResult{}, mcperr.New(mcperr.ReasonRollbackTargetMissing, "cpdp.pub.rollback", "no current snapshot")
	}
	if c.cpPrevious == nil || c.cpPrevious.ContentHash != in.TargetHash {
		return RollbackResult{}, mcperr.New(mcperr.ReasonRollbackTargetMissing, "cpdp.pub.rollback", "target is not the retained previous snapshot")
	}
	// 2: four-eyes approval + expiry.
	if in.VerifyApproval == nil || !in.VerifyApproval() {
		return RollbackResult{}, mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.pub.rollback", "rollback approval does not bind the command")
	}
	if in.ExpiryUnixNano != 0 && c.cfg.Clock() > in.ExpiryUnixNano {
		return RollbackResult{}, mcperr.New(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.pub.rollback", "rollback request expired")
	}
	// 3: CP lease/write authority.
	if !c.cfg.Auth.WriteAllowed() {
		return RollbackResult{}, mcperr.New(mcperr.ReasonDistributionWriteAuthority, "cpdp.pub.rollback", "not write-authoritative")
	}
	curHash := c.cpCurrent.ContentHash
	epoch := c.cfg.Auth.CurrentEpoch()

	// 4-6: durably commit the PR-8 rollback event FIRST; sign/push/swap ONLY inside act.
	var result RollbackResult
	commitErr := c.cfg.Committer.CommitThenAct(
		PublicationFact{Capability: c.cfg.Capability, ContentHash: curHash, Rollback: true, TargetHash: in.TargetHash},
		func() error {
			d, serr := cpdp.SignRollback(cpdp.RollbackDirective{
				Capability: c.cfg.Capability, Epoch: epoch, CurrentActiveHash: curHash,
				TargetHash: in.TargetHash, CommandID: in.CommandID, MinDPVersion: c.cfg.DPVersion,
				ExpiryUnixNano: in.ExpiryUnixNano,
			}, c.cfg.Signer)
			if serr != nil {
				return serr
			}
			// Atomically swap the CP store: current <- previous target, previous <- old current.
			old := c.cpCurrent
			c.cpCurrent = c.cpPrevious
			c.cpPrevious = old
			// Push the directive + collect rolled_back acknowledgements.
			for _, node := range c.cfg.Dist.Nodes() {
				ack, err := c.cfg.Dist.PushRollback(node, d)
				if err != nil || ack == nil {
					continue
				}
				_ = c.tracker.Record(node, *ack)
			}
			counts := c.tracker.Counts(in.TargetHash, c.cfg.Dist.Nodes())
			state := StateRollbackPending
			if counts.Intended > 0 && counts.Applied == counts.Intended {
				state = StateRolledBack
			}
			result = RollbackResult{State: state, TargetHash: in.TargetHash, Epoch: epoch, Counts: counts}
			return nil
		},
	)
	if commitErr != nil {
		// Fail closed: no directive signed, no push, no CP or DP swap; current active.
		return RollbackResult{}, mcperr.Wrap(mcperr.ReasonPublicationDurabilityRequired, "cpdp.pub.rollback", "rollback event not durable", commitErr)
	}
	c.lastState = result.State
	return result, nil
}
