package adminapi

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/approval"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// PublicationCommitter durably records the PR-8 P-CRIT configuration-publication
// decision event and returns safe evidence, or a classified error on which the
// publication fails closed (nothing is published, the active policy is retained).
// package main backs this with events.Manager.CommitDecision; tests fake it.
type PublicationCommitter interface {
	CommitPublication(capability, tenant, candidateHash string, base, proposed uint64) (evidenceDigest string, err error)
}

// pendingPublication holds a compiled candidate awaiting four-eyes approval and
// local publication. It is bounded by the approval store's own caps.
type pendingPublication struct {
	capability string
	tenant     string
	snap       *policy.Snapshot
	base       uint64
	proposed   uint64
	hash       string
}

// PublishResult is the safe outcome of a local publication. DistributionState is
// always local_only in PR-9 — signed CP→DP distribution is PR-10.
type PublishResult struct {
	Capability        string `json:"capability"`
	Revision          uint64 `json:"revision"`
	CandidateHash     string `json:"candidate_hash"`
	DistributionState string `json:"distribution_state"`
	EvidenceDigest    string `json:"evidence_digest"`
}

// PublicationService owns the local policy-publication workflow: create (compile
// + bind an approval), approve/reject (four-eyes via the approval store), and
// publish (commit the P-CRIT event, THEN publish into the local PR-6 store).
type PublicationService struct {
	policySvc *PolicyService
	stores    PolicyStores
	approvals *approval.Store
	commit    PublicationCommitter
	idgen     func() approval.ID
	clock     func() time.Time

	mu      sync.Mutex
	pending map[approval.ID]*pendingPublication
}

// NewPublicationService builds the workflow. idgen must return unpredictable,
// unique IDs (package main uses crypto/rand).
func NewPublicationService(ps *PolicyService, stores PolicyStores, approvals *approval.Store, commit PublicationCommitter, idgen func() approval.ID, clock func() time.Time) *PublicationService {
	if clock == nil {
		clock = time.Now
	}
	return &PublicationService{
		policySvc: ps, stores: stores, approvals: approvals, commit: commit,
		idgen: idgen, clock: clock, pending: make(map[approval.ID]*pendingPublication),
	}
}

// Create compiles+validates the candidate, checks the expected base revision,
// and records a pending four-eyes publication request. It publishes nothing.
func (s *PublicationService) Create(capability, tenant string, requester approval.PrincipalID, raw []byte, expectedBase uint64) (approval.ID, error) {
	snap, err := s.policySvc.compile(capability, raw)
	if err != nil {
		return "", err
	}
	store, ok := s.stores.Store(capability)
	if !ok {
		return "", mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.publish", "no policy store for capability")
	}
	base := uint64(store.CurrentRevision())
	if base != expectedBase {
		return "", mcperr.New(mcperr.ReasonPublicationStaleBase, "adminapi.publish", "expected base revision does not match active")
	}
	hash := candidateHash(raw)
	proposed := base + 1
	if uint64(snap.Revision()) != proposed {
		return "", mcperr.New(mcperr.ReasonPublicationValidationFailed, "adminapi.publish", "candidate policy_revision must equal base+1")
	}
	id := s.idgen()
	b := approval.Binding{
		Tenant: tenant, Capability: capability,
		CandidateHash: hash, BaseRevision: base, ProposedRevision: proposed,
		Revisions: approval.Revisions{Policy: base},
	}
	if _, err := s.approvals.Create(id, approval.KindPublication, requester, b); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.pending[id] = &pendingPublication{capability: capability, tenant: tenant, snap: snap, base: base, proposed: proposed, hash: hash}
	s.mu.Unlock()
	return id, nil
}

// Approve grants a pending publication request (four-eyes). The live base
// revision is resolved from the capability store at decide time (TOCTOU guard).
func (s *PublicationService) Approve(id approval.ID, approver approval.PrincipalID, appCommit approval.Committer) (approval.Receipt, error) {
	pp, err := s.lookup(id)
	if err != nil {
		return approval.Receipt{}, err
	}
	store, ok := s.stores.Store(pp.capability)
	if !ok {
		return approval.Receipt{}, mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.publish", "no policy store")
	}
	live := approval.Revisions{Policy: uint64(store.CurrentRevision())}
	return s.approvals.Approve(id, approver, live, appCommit)
}

// Reject denies a pending publication request.
func (s *PublicationService) Reject(id approval.ID, approver approval.PrincipalID, reason string, appCommit approval.Committer) error {
	if _, err := s.lookup(id); err != nil {
		return err
	}
	return s.approvals.Reject(id, approver, reason, appCommit)
}

// Publish performs the final local publication: it verifies the approval is
// granted and the receipt is bound to this exact candidate, commits the P-CRIT
// configuration-publication event, and ONLY on a confirmed receipt publishes
// into the local PR-6 store. Any failure publishes nothing and retains the
// active policy.
func (s *PublicationService) Publish(id approval.ID, tenant string, rc approval.Receipt) (PublishResult, error) {
	pp, err := s.lookup(id)
	if err != nil {
		return PublishResult{}, err
	}
	// Approval must be granted for this tenant.
	req, err := s.approvals.Get(id, tenant)
	if err != nil {
		return PublishResult{}, err
	}
	if req.State() != approval.StateApproved {
		return PublishResult{}, mcperr.New(mcperr.ReasonPublicationNotApproved, "adminapi.publish", "request is not approved")
	}
	if !rc.Matches(pp.tenant, pp.capability, pp.hash, pp.proposed) {
		return PublishResult{}, mcperr.New(mcperr.ReasonApprovalBindingMismatch, "adminapi.publish", "receipt does not match candidate")
	}
	// Durably commit the configuration-publication event BEFORE touching the store.
	digest, err := s.commit.CommitPublication(pp.capability, pp.tenant, pp.hash, pp.base, pp.proposed)
	if err != nil {
		return PublishResult{}, mcperr.Wrap(mcperr.ReasonPublicationDurabilityRequired, "adminapi.publish", "publication event did not commit", err)
	}
	store, ok := s.stores.Store(pp.capability)
	if !ok {
		return PublishResult{}, mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.publish", "no policy store")
	}
	if err := store.Publish(policy.Revision(pp.base), pp.snap); err != nil {
		// The active policy is unchanged; surface as a stale-base publication failure.
		return PublishResult{}, mcperr.Wrap(mcperr.ReasonPublicationStaleBase, "adminapi.publish", "store publish rejected", err)
	}
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
	return PublishResult{
		Capability: pp.capability, Revision: pp.proposed, CandidateHash: pp.hash,
		DistributionState: "local_only", EvidenceDigest: digest,
	}, nil
}

func (s *PublicationService) lookup(id approval.ID) (*pendingPublication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pp, ok := s.pending[id]
	if !ok {
		return nil, mcperr.New(mcperr.ReasonApprovalNotFound, "adminapi.publish", "not found")
	}
	return pp, nil
}
