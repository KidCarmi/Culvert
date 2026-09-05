package canary

// health.go — the First-Canary health detectors: elevated error rate and latency pathology.
//
// These are the two whole-Canary breach classes that cannot be decided from a single request. Every
// other AbortCanary code in the taxonomy is a one-occurrence proof (a scope escape either happened
// or did not); these two are judgements over a POPULATION, which is why they need explicit machine
// values rather than prose.
//
// THE CORPUS IS THREE. MaxTotalExecutions for a first Canary is 3, so a detector with a sample floor
// of 5 or 10 is not a conservative detector — it is a detector that can never fire, and a breach
// class that can never fire does not close a blocker. Every threshold here is chosen to be reachable
// inside three executions. They are FIRST-CANARY SAFETY thresholds, not product SLOs: the question
// is not "is this service healthy enough to ship" but "has this bounded experiment already shown
// enough evidence of trouble to stop changing reality".

import (
	"sync"
	"time"
)

const (
	// HealthSampleFloor is the minimum number of settled post-admission attempts before a RATE
	// judgement is made. Two, because the corpus is three: at one sample "100% failure" is one
	// unlucky request, at two it is a pattern, and at three a floor of 2 still leaves the detector
	// able to fire before the budget is spent.
	HealthSampleFloor = 2

	// Error rate trips at >= 50%, evaluated as 2*failures >= samples so the comparison is exact
	// integer arithmetic with no float rounding at the boundary. At the floor that means 1 of 2.
	healthErrorRateNumerator   = 2
	healthErrorRateDenominator = 1

	// HealthLatencyHardLimit is a per-attempt ceiling: ONE attempt at or above it is a pathology on
	// its own, with no floor, because a single 15s tool call in a 3-call experiment is already the
	// experiment misbehaving. It sits at half the 30s hard upstream request timeout, so it fires
	// while the request is still the client's problem rather than after the transport gave up.
	HealthLatencyHardLimit = 15 * time.Second

	// HealthLatencyMeanLimit is the population judgement: a mean at or above it, once the floor is
	// met, is a sustained pathology even when no single attempt reached the hard limit.
	HealthLatencyMeanLimit = 10 * time.Second
)

// HealthSnapshot is the restart-durable, generation-bound detector state. Scalars only — never a
// tenant, subject, host or payload. It is persisted for the same reason the budget is: a detector
// that resets on restart is one a crash can silently disarm, and "restart clears the evidence" is
// exactly the shape this program keeps finding.
type HealthSnapshot struct {
	Generation    uint64 `json:"generation"`
	Samples       int    `json:"samples"`
	Failures      int    `json:"failures"`
	LatencySumNs  int64  `json:"latency_sum_ns"`
	HardLatencies int    `json:"hard_latencies,omitempty"`
}

// HealthMonitor accumulates settled post-admission attempt outcomes for ONE activation generation
// and reports the whole-Canary breach code, if any, that the population now proves. Safe for
// concurrent use.
//
// It is deliberately NOT a general metrics sink. It is fed only by attempts that were ADMITTED and
// then settled — the population whose behaviour the Canary is actually testing. Request-scoped
// denials (a policy deny, a scope refusal, an allowance already consumed) are excluded by the
// caller: counting them would let a healthy Canary abort itself for correctly refusing requests,
// and conditions that carry their own immediate whole-Canary classification are excluded because
// they already trip directly and must not also be laundered through a rate.
type HealthMonitor struct {
	generation uint64

	mu            sync.Mutex
	samples       int
	failures      int
	latencySumNs  int64
	hardLatencies int
}

// NewHealthMonitor arms a fresh monitor for activation generation gen (0 is the "no activation"
// sentinel and yields nil).
func NewHealthMonitor(generation uint64) *HealthMonitor {
	if generation == 0 {
		return nil
	}
	return &HealthMonitor{generation: generation}
}

// Observe records one SETTLED post-admission attempt and returns the whole-Canary breach code the
// population now proves, or "" for none. failed is the caller's classification of an ordinary
// execution failure; latency is the observed attempt duration.
//
// Evaluation order is fixed and documented because two rules can fire on the same observation and a
// nondeterministic winner would make the durable first-cause nondeterministic: the per-attempt hard
// latency limit first (it needs no floor and describes THIS attempt), then error rate, then mean
// latency. A generation mismatch records nothing and returns "" — the observation belongs to a
// different activation.
func (h *HealthMonitor) Observe(gen uint64, failed bool, latency time.Duration) string {
	if h == nil || gen != h.generation {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	h.samples++
	if failed {
		h.failures++
	}
	if latency > 0 {
		h.latencySumNs += int64(latency)
	}
	if latency >= HealthLatencyHardLimit {
		h.hardLatencies++
		return "latency_pathology"
	}
	if h.samples >= HealthSampleFloor && healthErrorRateNumerator*h.failures >= healthErrorRateDenominator*h.samples {
		return "elevated_error_rate"
	}
	if h.samples >= HealthSampleFloor && h.latencySumNs/int64(h.samples) >= int64(HealthLatencyMeanLimit) {
		return "latency_pathology"
	}
	return ""
}

// Stats returns the current counters (samples, failures, mean latency) for the status surface.
func (h *HealthMonitor) Stats() (samples, failures int, mean time.Duration) {
	if h == nil {
		return 0, 0, 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.samples > 0 {
		mean = time.Duration(h.latencySumNs / int64(h.samples))
	}
	return h.samples, h.failures, mean
}

// Snapshot returns the durable detector state so the composition layer can persist it.
func (h *HealthMonitor) Snapshot() HealthSnapshot {
	if h == nil {
		return HealthSnapshot{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return HealthSnapshot{
		Generation:    h.generation,
		Samples:       h.samples,
		Failures:      h.failures,
		LatencySumNs:  h.latencySumNs,
		HardLatencies: h.hardLatencies,
	}
}

// RestoreHealthMonitor rebuilds a monitor for activation generation gen from a durable snapshot. It
// is generation-strict in the same direction as RestoreAbortController: a snapshot for a DIFFERENT
// generation does not transfer (one activation's failures never count against another), so a
// mismatch yields a FRESH monitor. A matching snapshot restores the counters exactly, so a restart
// cannot wipe accumulated failure evidence and hand the Canary a clean slate.
func RestoreHealthMonitor(gen uint64, snap HealthSnapshot) *HealthMonitor {
	if gen == 0 {
		return nil
	}
	if snap.Generation != gen {
		return &HealthMonitor{generation: gen}
	}
	return &HealthMonitor{
		generation:    gen,
		samples:       snap.Samples,
		failures:      snap.Failures,
		latencySumNs:  snap.LatencySumNs,
		hardLatencies: snap.HardLatencies,
	}
}
