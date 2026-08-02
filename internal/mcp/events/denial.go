package events

import (
	"github.com/KidCarmi/Culvert/internal/mcp/events/denial"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/state"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// DenialInput is one authentication-failure or authorization-denial observation.
// Tenant and Principal are set ONLY when verified identity exists (the
// authenticated-but-unauthorized case); for a pre-authentication failure they are
// empty and no tenant is ever invented.
type DenialInput struct {
	Capability model.Capability
	Listener   string
	Source     string
	Reason     string
	Tenant     string
	Principal  string
}

// ObserveDenial feeds one denial into the isolated denial lane BEFORE it can
// occupy any shared queue. It is O(1), never blocks, and NEVER touches the
// critical track or the P-CRIT reserve. A dropped observation (cardinality bound)
// still leaves the triggering request denied by the caller — admission to the
// aggregate is not admission of the request.
func (m *Manager) ObserveDenial(in DenialInput) {
	d, err := m.domainFor(in.Capability)
	if err != nil {
		return
	}
	d.agg.Observe(denial.Observation{
		Now: m.clock(), Listener: in.Listener, Source: in.Source,
		Reason: in.Reason, Tenant: in.Tenant, Principal: in.Principal,
	})
}

// FlushDenials commits the denial aggregates whose window has closed into P-DEN.
// A failed aggregate commit (or a P-DEN quota rejection) enters
// denial-lane-degraded, increments the DISTINCT denial-loss counter, and the
// request stays denied — it NEVER blocks authenticated critical work and NEVER
// enters critical-durability-degraded. It returns the number of aggregates
// committed and the number lost.
func (m *Manager) FlushDenials(capNS model.Capability) (committed, lost int) {
	d, err := m.domainFor(capNS)
	if err != nil {
		return 0, 0
	}
	return m.flushDomainDenials(d, false)
}

func (m *Manager) flushDomainDenials(d *domain, force bool) (committed, lost int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	events := d.agg.Flush(m.clock(), force)
	anyLost := false
	for i := range events {
		e := events[i]
		if _, err := d.spool.Commit(e); err != nil {
			lost++
			anyLost = true
			continue
		}
		committed++
		d.denialAgg.Add(1)
	}
	if anyLost {
		_ = d.state.OnDenialLaneFailure(mcperr.ReasonEventDenialLaneDegraded.Code())
	} else if committed > 0 && d.state.DenialState() != state.StateNormal {
		// Denial commits are succeeding again; clear the denial track if it was
		// degraded and P-DEN is below its low watermark.
		if st := d.spool.Stats(); st.Partitions[model.PartDen].Bytes < int64(d.lim.LowWatermarkBytes()) {
			_ = d.state.OnDenialLaneRecovered()
		}
	}
	return committed, lost
}
