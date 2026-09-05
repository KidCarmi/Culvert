package canary

import (
	"testing"
	"time"
)

// The First-Canary corpus is THREE executions. Every threshold here must be reachable inside that
// corpus, because a detector that cannot fire within the authorized experiment does not close
// blocker #7 — it only looks like it does. These gates pin reachability as hard as they pin the
// thresholds themselves.

func TestHealth_ErrorRateReachableWithinThreeExecutions(t *testing.T) {
	h := NewHealthMonitor(1)
	// One failure alone is below the sample floor: a single unlucky request is not a rate.
	if code := h.Observe(1, true, time.Second); code != "" {
		t.Fatalf("below the sample floor nothing may trip, got %q", code)
	}
	// Second observation reaches the floor at 1/2 = 50% — the threshold is >= 50%, so it trips.
	if code := h.Observe(1, false, time.Second); code != "elevated_error_rate" {
		t.Fatalf("1 failure in 2 samples is 50%% and must trip elevated_error_rate, got %q", code)
	}
}

// The control: a detector that fires on ANY failure would also "pass" the gate above. This proves
// the floor is real, so a single failure in a healthy experiment does not stop it.
func TestHealth_SingleFailureBelowFloorDoesNotTrip(t *testing.T) {
	h := NewHealthMonitor(1)
	if code := h.Observe(1, true, time.Second); code != "" {
		t.Fatalf("one failure must not trip on its own (floor=%d), got %q", HealthSampleFloor, code)
	}
}

// And the other control: a healthy population must not trip however long it runs.
func TestHealth_HealthyPopulationNeverTrips(t *testing.T) {
	h := NewHealthMonitor(1)
	for i := 0; i < 3; i++ {
		if code := h.Observe(1, false, time.Second); code != "" {
			t.Fatalf("a clean attempt must not trip anything, got %q at i=%d", code, i)
		}
	}
}

func TestHealth_HardLatencyTripsOnOneAttemptWithNoFloor(t *testing.T) {
	h := NewHealthMonitor(1)
	// No floor: one attempt at the hard limit is a pathology by itself.
	if code := h.Observe(1, false, HealthLatencyHardLimit); code != "latency_pathology" {
		t.Fatalf("a single attempt at the hard limit must trip latency_pathology, got %q", code)
	}
}

func TestHealth_MeanLatencyTripsWithinTheCorpus(t *testing.T) {
	h := NewHealthMonitor(1)
	// Each attempt is below the hard limit, so only the MEAN rule can fire — and only at the floor.
	if code := h.Observe(1, false, 11*time.Second); code != "" {
		t.Fatalf("below the floor the mean rule must not fire, got %q", code)
	}
	if code := h.Observe(1, false, 11*time.Second); code != "latency_pathology" {
		t.Fatalf("mean 11s over 2 samples must trip latency_pathology, got %q", code)
	}
}

// A fast population must not be dragged over the mean limit by the floor arithmetic.
func TestHealth_FastPopulationDoesNotTripMean(t *testing.T) {
	h := NewHealthMonitor(1)
	for i := 0; i < 3; i++ {
		if code := h.Observe(1, false, time.Second); code != "" {
			t.Fatalf("a 1s mean must not trip the %s mean limit, got %q", HealthLatencyMeanLimit, code)
		}
	}
}

// Thresholds must stay inside the corpus. This is the anti-drift gate: raising the floor above the
// authorized execution count would silently retire both detectors.
func TestHealth_SampleFloorFitsTheFirstCanaryCorpus(t *testing.T) {
	const firstCanaryMaxExecutions = 3
	if HealthSampleFloor > firstCanaryMaxExecutions {
		t.Fatalf("sample floor %d exceeds the %d-execution First-Canary corpus: the detector could never fire",
			HealthSampleFloor, firstCanaryMaxExecutions)
	}
	if HealthLatencyHardLimit >= 30*time.Second {
		t.Fatalf("the hard latency limit (%s) must fire BEFORE the 30s upstream request timeout gives up",
			HealthLatencyHardLimit)
	}
	if HealthLatencyMeanLimit > HealthLatencyHardLimit {
		t.Fatalf("the mean limit (%s) above the per-attempt hard limit (%s) would be unreachable",
			HealthLatencyMeanLimit, HealthLatencyHardLimit)
	}
}

// A monitor is generation-bound in the same direction as the abort controller: one activation's
// failures never count against another's.
func TestHealth_GenerationStrict(t *testing.T) {
	h := NewHealthMonitor(7)
	if code := h.Observe(8, true, time.Second); code != "" {
		t.Fatalf("an observation for a different generation must record nothing, got %q", code)
	}
	if s, f, _ := h.Stats(); s != 0 || f != 0 {
		t.Fatalf("a foreign-generation observation must not be recorded, samples=%d failures=%d", s, f)
	}
}

// Restart must not hand a misbehaving Canary a clean slate.
func TestHealth_RestartPreservesFailureEvidence(t *testing.T) {
	h := NewHealthMonitor(3)
	h.Observe(3, true, time.Second) // one failure banked, below the floor
	restored, ok := RestoreHealthMonitor(3, h.Snapshot())
	if !ok {
		t.Fatal("a matching, valid snapshot must restore")
	}
	if s, f, _ := restored.Stats(); s != 1 || f != 1 {
		t.Fatalf("restore must carry the counters forward, samples=%d failures=%d", s, f)
	}
	// The SECOND observation after the restart reaches the floor and trips — the pre-restart
	// failure still counts.
	if code := restored.Observe(3, false, time.Second); code != "elevated_error_rate" {
		t.Fatalf("a restart must not wipe failure evidence; expected the floor to be reached, got %q", code)
	}
}

// A snapshot from a DIFFERENT generation must not transfer — and must not quietly become a fresh,
// empty monitor either. A cleared detector on a restored activation is execution authority with the
// evidence wiped, so the caller is told to refuse the restore outright.
func TestHealth_RestoreIsGenerationStrict(t *testing.T) {
	h := NewHealthMonitor(3)
	h.Observe(3, true, time.Second)
	if _, ok := RestoreHealthMonitor(4, h.Snapshot()); ok {
		t.Fatal("SECURITY: a foreign-generation snapshot must REFUSE the restore, not clear the detector")
	}
}

// An ABSENT snapshot against a live generation is the shape a record written before the detectors
// existed has. "No evidence" is not "no failures": it must refuse too.
func TestHealth_RestoreRefusesAnAbsentSnapshot(t *testing.T) {
	if _, ok := RestoreHealthMonitor(3, HealthSnapshot{}); ok {
		t.Fatal("SECURITY: a missing health snapshot must refuse the restore")
	}
	if _, ok := RestoreHealthMonitor(0, HealthSnapshot{}); !ok {
		t.Fatal("no activation (generation 0) is not a restore failure")
	}
}

// A semantically damaged snapshot must refuse, whatever the JSON said. Each case is an invariant
// the writer maintains and a reader therefore must be able to assume.
func TestHealth_RestoreRefusesDamagedCounters(t *testing.T) {
	for name, snap := range map[string]HealthSnapshot{
		"negative samples":      {Generation: 3, Samples: -1},
		"negative failures":     {Generation: 3, Samples: 2, Failures: -1},
		"negative latency":      {Generation: 3, Samples: 2, LatencySumNs: -1},
		"more failures":         {Generation: 3, Samples: 1, Failures: 2},
		"more hard latencies":   {Generation: 3, Samples: 1, HardLatencies: 2},
		"latency without work":  {Generation: 3, Samples: 0, LatencySumNs: 5},
		"failures without work": {Generation: 3, Samples: 0, Failures: 1},
	} {
		if _, ok := RestoreHealthMonitor(3, snap); ok {
			t.Fatalf("SECURITY: %s must refuse the restore", name)
		}
	}
}

// Verdict re-derives what the population proves WITHOUT observing, and agrees with Observe. It is
// what closes the crash window between persisting the counters and latching the abort.
func TestHealth_VerdictReDerivesTheBreachWithoutObserving(t *testing.T) {
	h := NewHealthMonitor(3)
	if v := h.Verdict(); v != "" {
		t.Fatalf("an empty population proves nothing, got %q", v)
	}
	h.Observe(3, true, time.Second)
	if v := h.Verdict(); v != "" {
		t.Fatalf("one failure is below the floor, got %q", v)
	}
	h.Observe(3, false, time.Second) // 1 of 2 = 50%
	if v := h.Verdict(); v != "elevated_error_rate" {
		t.Fatalf("Verdict must re-derive the breach Observe reported, got %q", v)
	}
	if s, f, _ := h.Stats(); s != 2 || f != 1 {
		t.Fatalf("Verdict must not record an observation, samples=%d failures=%d", s, f)
	}
	// And it survives the restore, which is the whole point: the counters are durable, the latch is
	// a separate write, and a crash between them must not lose the verdict.
	restored, ok := RestoreHealthMonitor(3, h.Snapshot())
	if !ok {
		t.Fatal("a valid snapshot must restore")
	}
	if v := restored.Verdict(); v != "elevated_error_rate" {
		t.Fatalf("a restored population must prove the same breach, got %q", v)
	}
}

// A hard-latency attempt is proven by its own counter, so Verdict finds it after a restart even
// though the mean is nowhere near the limit.
func TestHealth_VerdictRemembersAHardLatency(t *testing.T) {
	h := NewHealthMonitor(3)
	h.Observe(3, false, HealthLatencyHardLimit)
	restored, ok := RestoreHealthMonitor(3, h.Snapshot())
	if !ok {
		t.Fatal("a valid snapshot must restore")
	}
	if v := restored.Verdict(); v != "latency_pathology" {
		t.Fatalf("a banked hard latency must survive the restart, got %q", v)
	}
}

// A snapshot that ERASES a hard-latency observation must be refused. {Samples:1, LatencySumNs:15s,
// HardLatencies:0} is arithmetically tidy and impossible for this writer — Observe increments
// HardLatencies for exactly that sample — and restored it would hide a breach the live path already
// proved: Verdict finds no hard latency and skips the mean check below the floor.
func TestHealth_RestoreRefusesAnErasedHardLatency(t *testing.T) {
	erased := HealthSnapshot{Generation: 3, Samples: 1, LatencySumNs: int64(HealthLatencyHardLimit)}
	if erased.Valid() {
		t.Fatal("SECURITY: a sample at the hard limit with a zero hard-latency counter is impossible and must not validate")
	}
	if _, ok := RestoreHealthMonitor(3, erased); ok {
		t.Fatal("SECURITY: such a snapshot must refuse the restore")
	}
	// The honest form of the same observation restores AND still proves the breach.
	honest := HealthSnapshot{Generation: 3, Samples: 1, LatencySumNs: int64(HealthLatencyHardLimit), HardLatencies: 1}
	h, ok := RestoreHealthMonitor(3, honest)
	if !ok {
		t.Fatal("the honest form of the same observation must restore")
	}
	if v := h.Verdict(); v != "latency_pathology" {
		t.Fatalf("the restored hard latency must still prove the breach, got %q", v)
	}
}

// The two bounds relating the hard-latency counter to the sum, and the controls that keep them from
// being satisfiable by refusing everything.
func TestHealth_HardLatencyCounterBoundsAreConsistent(t *testing.T) {
	lim := int64(HealthLatencyHardLimit)
	for name, snap := range map[string]HealthSnapshot{
		"sum below one hard latency":   {Generation: 1, Samples: 2, LatencySumNs: lim - 1, HardLatencies: 1},
		"two hard, sum of one":         {Generation: 1, Samples: 2, LatencySumNs: lim, HardLatencies: 2},
		"none hard but sum reaches it": {Generation: 1, Samples: 2, LatencySumNs: 2 * lim},
	} {
		if snap.Valid() {
			t.Fatalf("SECURITY: %s must not validate", name)
		}
	}
	for name, snap := range map[string]HealthSnapshot{
		"empty":                {Generation: 1},
		"fast samples":         {Generation: 1, Samples: 3, LatencySumNs: int64(3 * time.Second)},
		"one hard, one fast":   {Generation: 1, Samples: 2, LatencySumNs: lim + int64(time.Second), HardLatencies: 1},
		"every sample is hard": {Generation: 1, Samples: 2, LatencySumNs: 2 * lim, HardLatencies: 2},
	} {
		if !snap.Valid() {
			t.Fatalf("an honest snapshot (%s) must validate — refusing it would disarm a healthy experiment", name)
		}
	}
}
