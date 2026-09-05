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

// Valid reports whether the snapshot is SEMANTICALLY consistent — not merely well-formed JSON.
//
// A strict decode proves the bytes parse; it cannot prove the numbers mean anything. A record with
// more failures than samples, a negative counter, or latency accumulated against zero samples is
// damaged, and a damaged detector is worse than an absent one: it restores an activation that looks
// measured and is not. Every counter is monotonically accumulated from zero, so these are the exact
// invariants the writer maintains and the reader must therefore be able to assume.
func (s HealthSnapshot) Valid() bool {
	switch {
	case s.Samples < 0, s.Failures < 0, s.LatencySumNs < 0, s.HardLatencies < 0:
		return false
	case s.Failures > s.Samples, s.HardLatencies > s.Samples:
		return false
	case s.Samples == 0 && (s.LatencySumNs != 0 || s.Failures != 0 || s.HardLatencies != 0):
		return false
	// The hard-latency COUNTER and the latency SUM constrain each other, and getting this wrong is
	// the one damaged shape that erases a breach the live path had already proven. {Samples:1,
	// LatencySumNs:15s, HardLatencies:0} is arithmetically tidy and IMPOSSIBLE for this writer:
	// Observe increments HardLatencies for that very sample. Restored, Verdict sees no hard latency
	// and skips the mean check below the floor — so an activation whose single attempt already
	// tripped latency_pathology comes back holding execution authority (Codex round 3 P1).
	//
	// Two bounds follow from the definition of the counter, and together they pin the one-sample
	// case exactly:
	//   - each hard sample contributed at least the limit, so the sum is at least that many limits;
	//   - if NO sample was hard, every sample was strictly under the limit, so the sum is strictly
	//     under Samples limits.
	case s.LatencySumNs < int64(s.HardLatencies)*int64(HealthLatencyHardLimit):
		return false
	// Samples > 0 guards the bound: at zero samples the sum is zero and "0 >= 0" would reject the
	// ordinary empty snapshot every fresh activation persists.
	case s.Samples > 0 && s.HardLatencies == 0 && s.LatencySumNs >= int64(s.Samples)*int64(HealthLatencyHardLimit):
		return false
	}
	return true
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

// Verdict re-derives the whole-Canary breach the CURRENT population proves, WITHOUT recording an
// observation. It returns "" when the population is within threshold.
//
// It exists because Observe's return value is the only place the thresholds were evaluated, and
// that value is transient: the counters are persisted, but the LATCH is a separate durable write.
// A crash between those two writes leaves a record whose numbers already prove a breach and whose
// abort controller says the activation is healthy — so restore must re-ask the question rather than
// trust that the last process got as far as latching. The evaluation ORDER matches Observe's so a
// re-derived first cause names the same code the live path would have.
func (h *HealthMonitor) Verdict() string {
	if h == nil {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hardLatencies > 0 {
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

// RestoreHealthMonitor rebuilds a monitor for activation generation gen from a durable snapshot.
// ok is false when the snapshot cannot be trusted to describe THIS activation, and the caller must
// then refuse to restore the activation at all rather than continue with a cleared detector.
//
// Three refusals, and none of them is "be careful": each is a way an activation could come back
// holding execution authority while its detector says nothing happened.
//
//   - A snapshot for a DIFFERENT generation. The budget, abort and health snapshots are written
//     together in one atomic record, so they cannot legitimately disagree about which activation
//     they describe; a disagreement is a damaged or hand-edited record.
//   - A ZERO snapshot against a non-zero generation. This is the shape a record written before the
//     detectors existed has, and an activation that cannot prove it is within threshold must not
//     resume — "no evidence" is not "no failures".
//   - A semantically invalid snapshot (see Valid).
//
// A matching, valid snapshot restores the counters exactly, so a restart cannot wipe accumulated
// failure evidence and hand the Canary a clean slate.
func RestoreHealthMonitor(gen uint64, snap HealthSnapshot) (h *HealthMonitor, ok bool) {
	if gen == 0 {
		return nil, true // no activation to restore; not a failure
	}
	if snap.Generation != gen || !snap.Valid() {
		return nil, false
	}
	return &HealthMonitor{
		generation:    gen,
		samples:       snap.Samples,
		failures:      snap.Failures,
		latencySumNs:  snap.LatencySumNs,
		hardLatencies: snap.HardLatencies,
	}, true
}
