package main

import (
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp/publication"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// mcpModelCapability maps a cpdp capability onto the PR-8 event-model capability so
// a config-publication decision event is durability-domain-scoped to the right
// capability (Gateway vs Management degrade independently).
func mcpModelCapability(c cpdp.Capability) model.Capability {
	if c == cpdp.CapabilityManagement {
		return model.CapManagement
	}
	return model.CapGateway
}

// mcpHAWriteAuthority adapts the process-wide HA fencing lease to the publication
// coordinator's WriteAuthority contract. It reuses the SINGLE existing fencing
// mechanism (globalHA) — no second leader election.
type mcpHAWriteAuthority struct{}

func (mcpHAWriteAuthority) WriteAllowed() bool  { return globalHA.WriteAllowed() }
func (mcpHAWriteAuthority) CurrentEpoch() int64 { return globalHA.CurrentEpoch() }

var _ publication.WriteAuthority = mcpHAWriteAuthority{}

// mcpEventsCommitter adapts the PR-8 durable event manager to the publication
// coordinator's DurableCommitter contract. It commits the config-publication /
// rollback decision event to the encrypted P-CRIT partition and runs the
// irreversible action (sign/install/push/swap) ONLY on a confirmed durable commit
// — queue admission is never treated as a commit.
type mcpEventsCommitter struct {
	mgr   *events.Manager
	actor string
}

func newMCPEventsCommitter(mgr *events.Manager, actor string) *mcpEventsCommitter {
	if actor == "" {
		actor = "mcp-cp"
	}
	return &mcpEventsCommitter{mgr: mgr, actor: actor}
}

func (e *mcpEventsCommitter) CommitThenAct(fact publication.PublicationFact, act func() error) error {
	if e.mgr == nil {
		// No durable event manager wired ⇒ fail closed: nothing is published.
		return mcperr.New(mcperr.ReasonPublicationDurabilityRequired, "mcp.commit", "event manager not wired")
	}
	reason := "MCP.CONFIG.PUBLISH"
	if fact.Rollback {
		reason = "MCP.CONFIG.ROLLBACK"
	}
	facts := events.DecisionFacts{
		Capability:  mcpModelCapability(fact.Capability),
		Criticality: model.CritCritical,
		ActionClass: model.ActionClassConfigPublication,
		Identity:    model.IdentityEvidence{Tenant: "system", PrincipalID: e.actor, PrincipalType: "admin"},
		Decision: model.DecisionEvidence{
			Action: "ALLOW", ReasonCode: reason, ExecutionState: "not_implemented",
			PolicyRevision: fact.Revision,
		},
		SnapshotHash: fact.ContentHash,
	}
	return e.mgr.CommitThenAct(facts, func(spool.CommitReceipt) error { return act() })
}

var _ publication.DurableCommitter = (*mcpEventsCommitter)(nil)

// mcpPullDistributor adapts the existing PULL-based CP/DP transport (DPs poll the
// signed ConfigSnapshot which carries the MCP envelope) to the coordinator's
// Distributor contract. On a forward publish it installs the signed envelope into
// the CP publication seam so the next captured ConfigSnapshot carries it to every
// DP; acknowledgements return ASYNCHRONOUSLY via mcpIngestAck (bound to the
// authenticated enrolled-node identity), so Push returns a nil ack (pending). It
// therefore never fabricates a fleet-applied state — a freshly published snapshot
// is pending_distribution until real DP acknowledgements arrive.
type mcpPullDistributor struct{}

func (mcpPullDistributor) Nodes() []string { return mcpEnrolledNodeIDs() }

func (mcpPullDistributor) Push(_ string, env *cpdp.Envelope) (*cpdp.Acknowledgement, error) {
	globalMCPDistribution.setCPPublished(env) // rides the next ConfigSnapshot pull
	return nil, nil                           // async ack model — no synchronous ack
}

func (mcpPullDistributor) PushRollback(_ string, _ *cpdp.RollbackDirective) (*cpdp.Acknowledgement, error) {
	// A rollback's DP-visible effect rides the same pull channel: the coordinator
	// re-installs the reverted (previous) envelope as the CP-published current via
	// setCPPublished after the swap. The signed directive is the audited command;
	// its DP delivery is the reverted ConfigSnapshot. Async ack.
	return nil, nil
}

var _ publication.Distributor = mcpPullDistributor{}

// mcpEnrolledNodeIDs returns the intended MCP DP node ids — the enrolled cluster
// nodes. Bounded by the cluster store.
func mcpEnrolledNodeIDs() []string {
	nodes := globalClusterStore.ListNodes()
	ids := make([]string, 0, len(nodes))
	for i := range nodes {
		ids = append(ids, nodes[i].NodeID)
	}
	return ids
}

// mcpIngestAck records a DP acknowledgement into a capability's coordinator, BOUND
// to the authenticated enrolled-node identity (authNodeID, resolved from the mTLS
// peer certificate by the caller). An acknowledgement whose node id does not match
// the authenticated identity, or that arrives without an authenticated identity, is
// rejected by the coordinator's tracker.
func mcpIngestAck(coord *publication.Coordinator, authNodeID string, ack cpdp.Acknowledgement) error {
	if coord == nil {
		return mcperr.New(mcperr.ReasonAckInvalid, "mcp.ack", "no coordinator")
	}
	return coord.RecordAck(authNodeID, ack)
}
