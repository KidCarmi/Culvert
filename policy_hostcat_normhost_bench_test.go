package main

import (
	"fmt"
	"strings"
	"testing"
)

// Policy-scan benchmarks for the normalized-host hoist.
//
// The _Legacy arms call matchesCategory's VERBATIM pre-hoist body
// (nhLegacyMatchesCategory, defined in policy_hostcat_normhost_test.go) through
// the same rule-scan shape, so the before/after comparison is timed in ONE
// process on ONE machine and the clock cancels. A cross-run pair of numbers is
// not evidence on this hardware: the box drifts by half again between rounds
// (the standing rule recorded for categoryKey, where a cross-run reading of the
// same question was wrong by an order of magnitude).
//
//	go test -run '^$' -bench 'CategoryScanNormHost' -benchmem -cpu 1,2,4 .
//
// Read the RATIO between the paired arms at each rule count, not the absolutes.

// The destination every arm resolves is UNCATEGORIZED: clean traffic to a host no
// tier covers cannot short-circuit, so every probe runs to completion, which is
// what an ALLOWED request pays.
//
// There are TWO host shapes and reporting both is the honest presentation,
// because the saving has two axes and each shape shows only one of them:
//
//   - CANONICAL ("uncategorized.example.net"): hostutil.NormalizeHost finds
//     nothing to change, so it is a byte scan and allocates NOTHING. The hoist
//     saves CPU only. This is the common shape — most clients send a
//     lowercase authority — so it is the CONSERVATIVE headline.
//   - NON-CANONICAL ("UNCATEGORIZED.EXAMPLE.NET."): strings.ToLower must build a
//     new string, so EVERY per-rule normalization was also a heap allocation.
//     The hoist turns O(rules) allocations into one per request. A trailing dot
//     is legal and an uppercase authority is legal, so this shape is a minority
//     but entirely real — and it is the only one that shows the GC-pressure axis.
//
// Quoting only one of them would misreport the change: the canonical shape hides
// the allocation finding entirely (which is why the pre-existing
// BenchmarkPolicyEvaluate_CategoryRules, whose host is lowercase, reports
// 0 allocs/op on BOTH sides of this change and understates it), and the
// non-canonical shape overstates the CPU saving for typical traffic. This is the
// representation-sampling rule recorded on CHAOS-69, applied to a benchmark
// fixture instead of a bound.
const (
	benchCategoryScanHostCanonical = "uncategorized.example.net"
	benchCategoryScanHost          = "UNCATEGORIZED.EXAMPLE.NET."
)

// benchScanCats returns n category names to probe, modelling n category-scoped
// rules in one scan.
func benchScanCats(n int) []URLCategory {
	cats := make([]URLCategory, n)
	for i := range cats {
		cats[i] = URLCategory(fmt.Sprintf("Category %d", i))
	}
	return cats
}

// benchArmView installs (or clears) the signed-feed effective view for an arm.
// The ARMED posture is the one that matters most: it runs TWO membership probes
// per rule, so before the hoist it normalized one request host twice per rule.
func benchArmView(tb testing.TB, armed bool) {
	tb.Helper()
	prev := saasEffectiveView.Current()
	tb.Cleanup(func() { saasEffectiveView.Swap(prev) })
	if !armed {
		saasEffectiveView.Swap(nil)
		return
	}
	entries := map[string]string{}
	for i := 0; i < 12; i++ {
		entries[fmt.Sprintf("view-host-%d.example.com", i)] = fmt.Sprintf("Category %d", i)
	}
	saasEffectiveView.Swap(newEffectiveView(entries, effectiveCategoryView{Source: sourceDownloaded}))
}

// runCategoryScanOn drives one scan against one host: one scratch, n category
// probes — exactly the shape Evaluate uses (newHostCatScratch once per request,
// matchesCategory once per category-scoped rule). runCategoryScanLegacyOn is the
// same shape over the verbatim pre-hoist body.
//
// Both take the host EXPLICITLY. Single-host convenience wrappers existed here
// and were removed: once the arms were parameterized over both host
// representations the legacy wrapper had no callers (staticcheck U1000, which
// failed this PR's Deep gate), and a wrapper carrying a default host is exactly
// how a later arm drifts onto the shape that hides the allocation axis.
func runCategoryScanOn(host string, cats []URLCategory) bool {
	sc := newHostCatScratch(host)
	hit := false
	for _, c := range cats {
		if sc.matchesCategory(c) {
			hit = true
		}
	}
	return hit
}

func runCategoryScanLegacyOn(host string, cats []URLCategory) bool {
	sc := newHostCatScratch(host)
	hit := false
	for _, c := range cats {
		if nhLegacyMatchesCategory(&sc, c) {
			hit = true
		}
	}
	return hit
}

func benchCategoryScan(b *testing.B, host string, armed, legacy bool) {
	seedCategoryTaxonomy(b, 12, 40)
	benchArmView(b, armed)
	for _, n := range []int{10, 50, 200} {
		cats := benchScanCats(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var hit bool
				if legacy {
					hit = runCategoryScanLegacyOn(host, cats)
				} else {
					hit = runCategoryScanOn(host, cats)
				}
				if hit {
					b.Fatal("unexpected match")
				}
			}
		})
	}
}

// The CANONICAL-host arms isolate the CPU axis (0 allocations on both sides).
func BenchmarkCategoryScanNormHost_CanonicalUnarmed(b *testing.B) {
	benchCategoryScan(b, benchCategoryScanHostCanonical, false, false)
}

func BenchmarkCategoryScanNormHost_CanonicalUnarmedLegacy(b *testing.B) {
	benchCategoryScan(b, benchCategoryScanHostCanonical, false, true)
}

func BenchmarkCategoryScanNormHost_CanonicalArmed(b *testing.B) {
	benchCategoryScan(b, benchCategoryScanHostCanonical, true, false)
}

func BenchmarkCategoryScanNormHost_CanonicalArmedLegacy(b *testing.B) {
	benchCategoryScan(b, benchCategoryScanHostCanonical, true, true)
}

// The NON-CANONICAL arms additionally show the allocation axis: the legacy arms
// allocate once per normalization (once per rule unarmed, twice per rule armed),
// the hoisted arms once per request.
func BenchmarkCategoryScanNormHost_Unarmed(b *testing.B) {
	benchCategoryScan(b, benchCategoryScanHost, false, false)
}

func BenchmarkCategoryScanNormHost_UnarmedLegacy(b *testing.B) {
	benchCategoryScan(b, benchCategoryScanHost, false, true)
}

func BenchmarkCategoryScanNormHost_Armed(b *testing.B) {
	benchCategoryScan(b, benchCategoryScanHost, true, false)
}

func BenchmarkCategoryScanNormHost_ArmedLegacy(b *testing.B) {
	benchCategoryScan(b, benchCategoryScanHost, true, true)
}

// BenchmarkCategoryScanNormHost_Parallel is the concurrency arm: the saving is a
// removed per-rule computation, so it should hold as cores are added rather than
// being masked by a contended lock. Both probes still take catStore's RLock once
// per call — the residual this change deliberately does not touch.
func BenchmarkCategoryScanNormHost_Parallel(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	benchArmView(b, true)
	cats := benchScanCats(50)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Per-worker sink: a shared one makes false sharing the thing measured.
		var sink bool
		for pb.Next() {
			sink = runCategoryScanOn(benchCategoryScanHost, cats)
		}
		_ = sink
	})
}

// TestBenchGate_CategoryScanAllocationsAreFlatInRuleCount is the ALLOCATION
// gate, and it asserts the contract rather than a number: whatever the rule
// count, a scan must allocate the same amount.
//
// That is the honest statement of what the hoist bought on the allocation axis.
// A non-canonical authority (uppercase, or a trailing dot — both legal) forces
// strings.ToLower inside hostutil.NormalizeHost to build a new string, so BEFORE
// the hoist every per-rule normalization was also a heap allocation: one per rule
// unarmed, TWO per rule on the signed-feed-armed branch. Measured here at 200
// rules armed, that was 400 allocations and 12.8 KB per request, in the request
// goroutine, on a gateway whose GC mark cost is per object.
//
// A fixed bound of 0 would be WRONG and was the first draft: the hoisted path
// legitimately allocates ONCE per request (the lowered host string the memo
// holds), so a 0 bound fails against correct code. A fixed bound of 1 would pass
// a future change that reintroduced per-rule allocation at a lower constant.
// FLATNESS is the property that actually distinguishes them, and it is
// machine-independent — a count, not a duration.
//
// The second half compares against the verbatim pre-hoist body in the same run,
// so the gate also fails if the saving disappears without per-rule growth.
func TestBenchGate_CategoryScanAllocationsAreFlatInRuleCount(t *testing.T) {
	seedCategoryTaxonomy(t, 12, 40)

	for _, armed := range []bool{false, true} {
		for _, host := range []string{benchCategoryScanHostCanonical, benchCategoryScanHost} {
			armed, host := armed, host
			name := fmt.Sprintf("armed=%v/canonical=%v", armed, host == benchCategoryScanHostCanonical)
			t.Run(name, func(t *testing.T) {
				benchArmView(t, armed)

				// The category slices are built OUTSIDE the measured closures:
				// benchScanCats allocates, so building one inside would measure the
				// FIXTURE and report ~200 allocations for correct code (it did, in
				// the first draft of this gate).
				fewCats := benchScanCats(10)
				manyCats := benchScanCats(200)

				few := testing.AllocsPerRun(100, func() { runCategoryScanOn(host, fewCats) })
				many := testing.AllocsPerRun(100, func() { runCategoryScanOn(host, manyCats) })
				if many != few {
					t.Errorf("allocations grow with the rule count: %v at 10 rules, %v at 200 "+
						"(want equal). A per-rule normalization is back — check that every "+
						"matcher call in matchesCategory passes sc.normHost().", few, many)
				}

				// Same-run comparison against the pre-hoist body. Only meaningful
				// where the legacy path allocated at all, i.e. a host whose
				// normalized form differs from its input.
				legacyMany := testing.AllocsPerRun(100, func() {
					runCategoryScanLegacyOn(host, manyCats)
				})
				if host == benchCategoryScanHost {
					if legacyMany <= many {
						t.Fatalf("pre-hoist body allocated %v at 200 rules and the hoisted path %v: "+
							"the gate cannot observe the saving it exists to protect", legacyMany, many)
					}
					t.Logf("200 rules: pre-hoist %v allocs/op, hoisted %v allocs/op", legacyMany, many)
				} else if many != 0 {
					// A canonical host needs no new string, so neither path should
					// allocate; a non-zero count here means something else started to.
					t.Errorf("canonical host allocates %v/op; expected 0 (NormalizeHost has nothing to build)", many)
				}
			})
		}
	}
}

// TestBenchGate_ScanHostExercisesNormalization keeps the benchmark fixture
// honest: if benchCategoryScanHost were already canonical, NormalizeHost would
// hit its no-change path and every arm above would understate the saving — the
// representation-sampling trap recorded on CHAOS-69.
func TestBenchGate_ScanHostExercisesNormalization(t *testing.T) {
	norm := normalizeHost(benchCategoryScanHost)
	if norm == benchCategoryScanHost {
		t.Fatalf("benchCategoryScanHost %q is already canonical: the cost arms would understate "+
			"the hoist", benchCategoryScanHost)
	}
	if !strings.EqualFold(strings.TrimSuffix(benchCategoryScanHost, "."), norm) {
		t.Fatalf("fixture normalizes to an unrelated host: %q -> %q", benchCategoryScanHost, norm)
	}
}
