package main

// decryption_trend.go — ADR-0011 §3 "inspection-coverage trend" backend. A bounded,
// volatile in-memory time-series of the decryption COVERAGE ratio, sampled at a fixed
// interval by a background loop. It answers the auditor's question "is my coverage
// eroding?" as a chart, which the point-in-time /api/decryption/health snapshot cannot.
//
// Each sample stores the DELTA over its interval (not the cumulative total): the coverage
// counter is monotonic, so a cumulative ratio flattens and hides recent change — the
// per-interval delta ratio is a true trend. Volatile like the metrics themselves (resets
// on restart; never persisted or CP→DP synced). Interval/window are constants (recorded
// deferral, matching the other ADR-0011 thresholds).

import (
	"context"
	"sync"
	"time"
)

const (
	// decTrendInterval is the sampling cadence. decTrendCap points at this cadence sets
	// the visible window (60s × 360 = 6h).
	decTrendInterval = time.Minute
	decTrendCap      = 360
)

// decTrendSample is one interval's coverage delta. Inspected/Bypassed/Failed are the
// counts that accrued DURING this interval; Ratio is inspected ÷ (inspected + bypassed)
// for the interval (failures excluded, per §3), or 0 when nothing was decisioned.
type decTrendSample struct {
	TS        int64   `json:"ts"` // unix millis at sample time
	Inspected int64   `json:"inspected"`
	Bypassed  int64   `json:"bypassed"`
	Failed    int64   `json:"failed"`
	Ratio     float64 `json:"ratio"`
}

// decCoverageTrend is the bounded coverage-ratio ring. totals is the cumulative-counter
// source (coverageTotals in production; injectable in tests); now is the clock.
type decCoverageTrend struct {
	mu                  sync.RWMutex
	samples             []decTrendSample
	lastI, lastB, lastF int64 // last observed cumulative totals (the delta baseline)
	seeded              bool
	now                 func() time.Time
	totals              func() (inspected, bypassed, failed int64)
}

var decTrend = &decCoverageTrend{now: time.Now, totals: coverageTotals}

// coverageTotals folds the monotonic session counter into the three coverage buckets
// (inspected / all bypass-or-exclusion / failed), matching the /api/decryption/health
// partition.
func coverageTotals() (inspected, bypassed, failed int64) {
	for _, s := range decSessions.snapshot() {
		switch s.Outcome {
		case "inspected":
			inspected += s.Count
		case "failed":
			failed += s.Count
		default: // bypass_manual / bypass_learned / rescued / not_decrypted
			bypassed += s.Count
		}
	}
	return inspected, bypassed, failed
}

// seedBaseline records the current cumulative totals WITHOUT emitting a sample, so the
// first real sample's delta reflects only traffic after the sampler started (not the
// pre-existing lifetime totals). Idempotent.
func (t *decCoverageTrend) seedBaseline() {
	i, b, f := t.totals()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastI, t.lastB, t.lastF, t.seeded = i, b, f, true
}

// sample appends one interval-delta sample and trims the ring to decTrendCap.
func (t *decCoverageTrend) sample() {
	i, b, f := t.totals()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.seeded { // defensive: sample() before seedBaseline() seeds instead of emitting a jump
		t.lastI, t.lastB, t.lastF, t.seeded = i, b, f, true
		return
	}
	di, db, df := i-t.lastI, b-t.lastB, f-t.lastF
	t.lastI, t.lastB, t.lastF = i, b, f
	t.samples = append(t.samples, decTrendSample{
		TS:        t.now().UnixMilli(),
		Inspected: di,
		Bypassed:  db,
		Failed:    df,
		Ratio:     inspectionCoverageRatio(di, db),
	})
	if len(t.samples) > decTrendCap {
		t.samples = t.samples[len(t.samples)-decTrendCap:]
	}
}

// snapshot returns a copy of the ring (oldest-first) for the API.
func (t *decCoverageTrend) snapshot() []decTrendSample {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]decTrendSample, len(t.samples))
	copy(out, t.samples)
	return out
}

// startDecCoverageSampler runs the sampling loop until ctx is cancelled. Parented to the
// lifecycle context (loadBackgroundServices), so it exits on shutdown.
func startDecCoverageSampler(ctx context.Context) {
	decTrend.seedBaseline()
	tick := time.NewTicker(decTrendInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			decTrend.sample()
		}
	}
}
