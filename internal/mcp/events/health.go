package events

import (
	"github.com/KidCarmi/Culvert/internal/mcp/events/denial"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/events/state"
)

// Health is a safe, typed snapshot of the whole manager. It carries no tenant,
// subject, token, session, argument or URL — only bounded counts, bytes, ids and
// state names — so it is safe to surface on a health endpoint.
type Health struct {
	NodeID  string
	Domains map[model.Capability]DomainHealth
}

// DomainHealth is one capability domain's safe snapshot.
type DomainHealth struct {
	Capability        model.Capability
	CriticalState     string
	DenialState       string
	Severity          string
	CriticalLoss      uint64
	DenialLoss        uint64
	OrdinaryLoss      uint64
	CommitOK          uint64
	CommitFail        uint64
	DenialAggregates  uint64
	RecoveryAttempts  uint64
	RecoverySuccesses uint64
	Spool             spool.Stats
	Denial            denial.Stats
}

// Health returns a safe snapshot across both capability domains.
func (m *Manager) Health() Health {
	h := Health{NodeID: m.nodeID, Domains: map[model.Capability]DomainHealth{}}
	for capNS, d := range m.domains {
		snap := d.state.Snapshot()
		h.Domains[capNS] = DomainHealth{
			Capability:        capNS,
			CriticalState:     snap.Critical.String(),
			DenialState:       snap.Denial.String(),
			Severity:          severityString(snap.Severity),
			CriticalLoss:      snap.CriticalLoss,
			DenialLoss:        snap.DenialLoss,
			OrdinaryLoss:      d.ordinaryLoss.Load(),
			CommitOK:          d.commitOK.Load(),
			CommitFail:        d.commitFail.Load(),
			DenialAggregates:  d.denialAgg.Load(),
			RecoveryAttempts:  d.recoveryTries.Load(),
			RecoverySuccesses: d.recoveryOK.Load(),
			Spool:             d.spool.Stats(),
			Denial:            d.agg.Stats(),
		}
	}
	return h
}

func severityString(s state.Severity) string {
	switch s {
	case state.SevCritical:
		return "critical"
	case state.SevWarning:
		return "warning"
	default:
		return "none"
	}
}
