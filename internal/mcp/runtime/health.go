package runtime

import "sync/atomic"

// Phase is a listener's lifecycle phase (typed, low-cardinality).
type Phase uint32

const (
	// PhaseDisabled — the listener is off (no socket, no goroutine).
	PhaseDisabled Phase = iota
	// PhaseStarting — validating/binding.
	PhaseStarting
	// PhaseReady — accepting requests.
	PhaseReady
	// PhaseDegraded — running but shedding load (saturation).
	PhaseDegraded
	// PhaseDraining — graceful shutdown in progress.
	PhaseDraining
	// PhaseStopped — fully stopped.
	PhaseStopped
)

// String returns the phase label.
func (p Phase) String() string {
	switch p {
	case PhaseStarting:
		return "starting"
	case PhaseReady:
		return "ready"
	case PhaseDegraded:
		return "degraded"
	case PhaseDraining:
		return "draining"
	case PhaseStopped:
		return "stopped"
	default:
		return "disabled"
	}
}

// counters holds a listener's safe, low-cardinality metric counters. No
// high-cardinality raw tenant/subject/token/session/tool value is ever a label —
// these are plain totals.
type counters struct {
	phase              atomic.Uint32
	acceptedConns      atomic.Int64
	rejectedConns      atomic.Int64
	requestsTotal      atomic.Int64
	requestsRejected   atomic.Int64
	kernelTerminal     atomic.Int64
	observeOnly        atomic.Int64
	activeSessions     atomic.Int64
	queued             atomic.Int64
	inFlight           atomic.Int64
	timeouts           atomic.Int64
	authFailures       atomic.Int64
	hostOriginFailures atomic.Int64
	admissionRejected  atomic.Int64
	shutdownCancels    atomic.Int64
	observeDrops       atomic.Int64
}

func (c *counters) setPhase(p Phase) { c.phase.Store(uint32(p)) }
func (c *counters) getPhase() Phase  { return Phase(c.phase.Load()) }

// HealthSnapshot is an immutable, listener-independent typed health/metrics view.
type HealthSnapshot struct {
	Capability         string
	ListenerID         string
	Phase              Phase
	AcceptedConns      int64
	RejectedConns      int64
	RequestsTotal      int64
	RequestsRejected   int64
	KernelTerminal     int64
	ObserveOnly        int64
	ActiveSessions     int64
	Queued             int64
	InFlight           int64
	Timeouts           int64
	AuthFailures       int64
	HostOriginFailures int64
	AdmissionRejected  int64
	ShutdownCancels    int64
	ObserveDrops       int64
}

func (c *counters) snapshot(capability, listenerID string) HealthSnapshot {
	return HealthSnapshot{
		Capability: capability, ListenerID: listenerID, Phase: c.getPhase(),
		AcceptedConns: c.acceptedConns.Load(), RejectedConns: c.rejectedConns.Load(),
		RequestsTotal: c.requestsTotal.Load(), RequestsRejected: c.requestsRejected.Load(),
		KernelTerminal: c.kernelTerminal.Load(), ObserveOnly: c.observeOnly.Load(),
		ActiveSessions: c.activeSessions.Load(), Queued: c.queued.Load(), InFlight: c.inFlight.Load(),
		Timeouts: c.timeouts.Load(), AuthFailures: c.authFailures.Load(),
		HostOriginFailures: c.hostOriginFailures.Load(), AdmissionRejected: c.admissionRejected.Load(),
		ShutdownCancels: c.shutdownCancels.Load(), ObserveDrops: c.observeDrops.Load(),
	}
}
