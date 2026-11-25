//go:build benchgate

package main

// Allocation-regression gate for the decryption COVERAGE counter's write path —
// decSessionCounter.record, which runs once per CONNECT tunnel that carries a
// decryption decision and therefore once per HTTPS connection on a gateway.
//
//	go test -tags benchgate -run 'TestBenchGate_DecSessionCounter' -v .
//
// GATE DESIGN, following TestBenchGate_DecryptionProjectionAllocs.
//
// (1) It measures the PRODUCTION method on a production-shaped counter, not a
// replica, so it can actually fail for the regression it names.
//
// (2) It is keyed on ALLOCATIONS PER OP, and the bound is ZERO rather than
// padded. record has no legitimate reason to touch the heap in the steady
// state: the key is a stack struct over strings that already exist inside the
// enum values, the index is read through an atomic pointer, and the increment
// is an atomic add on a counter allocated once per series. The shape this
// replaced allocated exactly one 48-byte key string per call, which is the
// regression a future "just concatenate the labels" edit would reintroduce —
// and a one-allocation regression on a per-connection path is invisible in any
// ns/op threshold on a shared runner, which is why the bound is structural.
//
// ns/op is deliberately NOT gated. The scaling win this path was changed for
// (see the table in decryption_metrics_bench_test.go) is a RATIO between two
// arms measured in one invocation; a wall-clock threshold on a shared CI vCPU
// would be noise, and the reader lock it removed cannot come back without the
// allocation coming back with it.

import "testing"

func TestBenchGate_DecSessionCounterAllocs(t *testing.T) {
	outcomes, sources, vers := decBenchSeries()

	cases := []struct {
		name      string
		maxAllocs int64
		run       func()
	}{
		{
			// The dominant steady-state shape: one live series, re-counted.
			name:      "one_series",
			maxAllocs: 0,
			run:       func() {},
		},
		{
			// The realistic fleet shape: the adds land on different series, so
			// this also proves the bound is not an artifact of one hot map slot.
			name:      "every_series",
			maxAllocs: 0,
			run:       func() {},
		},
	}

	// Each case gets its OWN warmed counter: a shared one would let the first
	// case pay every insert and leave the second measuring nothing new.
	one := warmDecSessions()
	cases[0].run = func() { one.record(decBenchOutcome, decBenchSource, decBenchTLS) }

	all := warmDecSessions()
	i := 0
	cases[1].run = func() {
		o := outcomes[i%len(outcomes)]
		s := sources[(i/len(outcomes))%len(sources)]
		v := vers[(i/(len(outcomes)*len(sources)))%len(vers)]
		i++
		all.record(o, s, v)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A warm-up outside the measurement: the first call into a freshly
			// warmed counter can still fault in the published map's buckets.
			tc.run()
			got := int64(testing.AllocsPerRun(2000, tc.run))
			if got > tc.maxAllocs {
				t.Fatalf("decSessionCounter.record allocates %d/op, bound %d/op "+
					"(the pre-change shape built a label key string per call; see "+
					"decryption_metrics_bench_test.go)", got, tc.maxAllocs)
			}
		})
	}
}
