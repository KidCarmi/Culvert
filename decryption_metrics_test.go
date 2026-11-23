package main

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decryption_metrics_test.go — ADR-0011 Phase 2 (Metrics). Pins the coverage counter's
// exposition, exact counts, the bounded-by-construction cardinality invariant, and the
// decEnumOr coercion that keeps every metric label in-vocabulary.

// decSessionLineRE parses one culvert_decrypt_sessions_total series line.
var decSessionLineRE = regexp.MustCompile(
	`culvert_decrypt_sessions_total\{outcome="([^"]*)",decision_source="([^"]*)",tls_version="([^"]*)"\} (\d+)`)

// scrapeDecSessions parses the counter exposition into label-tuple → count.
func scrapeDecSessions(t *testing.T, c *decSessionCounter) map[[3]string]int64 {
	t.Helper()
	var sb strings.Builder
	c.writePrometheus(&sb)
	out := map[[3]string]int64{}
	for _, m := range decSessionLineRE.FindAllStringSubmatch(sb.String(), -1) {
		n, err := strconv.ParseInt(m[4], 10, 64)
		if err != nil {
			t.Fatalf("bad count %q: %v", m[4], err)
		}
		out[[3]string{m[1], m[2], m[3]}] = n
	}
	return out
}

// boundedLabelSets returns the closed membership sets for each label, for the cardinality
// invariant: no metric label may ever carry a value outside these.
func boundedLabelSets() (outcomes, sources, tlsVers map[string]bool) {
	outcomes = map[string]bool{}
	for _, o := range decryptobs.AllOutcomes {
		outcomes[o.String()] = true
	}
	sources = map[string]bool{}
	for _, d := range decryptobs.AllDecisionSources {
		sources[d.String()] = true
	}
	tlsVers = map[string]bool{}
	for _, v := range decryptobs.AllTLSVersions {
		tlsVers[v.String()] = true
	}
	return outcomes, sources, tlsVers
}

// TestDecSessionCounter_RecordAndExposition pins exact counts and the text-exposition
// shape on an isolated instance (the global singleton accumulates across the suite).
func TestDecSessionCounter_RecordAndExposition(t *testing.T) {
	c := &decSessionCounter{}

	// Empty ⇒ no output at all (no zero-value noise).
	var empty strings.Builder
	c.writePrometheus(&empty)
	if empty.Len() != 0 {
		t.Fatalf("empty counter must emit nothing, got %q", empty.String())
	}

	for i := 0; i < 3; i++ {
		c.record("inspected", "policy_inspect", "1.3")
	}
	c.record("bypass_manual", "manual_ssl_bypass", "unknown")

	got := scrapeDecSessions(t, c)
	if got[[3]string{"inspected", "policy_inspect", "1.3"}] != 3 {
		t.Fatalf("inspected/policy_inspect/1.3 = %d, want 3", got[[3]string{"inspected", "policy_inspect", "1.3"}])
	}
	if got[[3]string{"bypass_manual", "manual_ssl_bypass", "unknown"}] != 1 {
		t.Fatalf("bypass_manual/manual_ssl_bypass/unknown = %d, want 1", got[[3]string{"bypass_manual", "manual_ssl_bypass", "unknown"}])
	}
	if len(got) != 2 {
		t.Fatalf("distinct series = %d, want 2", len(got))
	}
	// Exposition must carry the HELP/TYPE header.
	var sb strings.Builder
	c.writePrometheus(&sb)
	if !strings.Contains(sb.String(), "# TYPE culvert_decrypt_sessions_total counter") {
		t.Fatalf("missing TYPE header:\n%s", sb.String())
	}
}

// TestDecSessionCounter_BoundedByConstruction is the cardinality test: recording every
// enum combination (and repeating them) can never produce a series outside the closed
// label space (6 outcomes × 8 sources × 3 tls = 144), and every label stays in-vocabulary.
func TestDecSessionCounter_BoundedByConstruction(t *testing.T) {
	c := &decSessionCounter{}
	for round := 0; round < 2; round++ { // repeat to prove repeats don't add series
		for _, o := range decryptobs.AllOutcomes {
			for _, d := range decryptobs.AllDecisionSources {
				for _, v := range decryptobs.AllTLSVersions {
					c.record(o.String(), d.String(), v.String())
				}
			}
		}
	}
	want := len(decryptobs.AllOutcomes) * len(decryptobs.AllDecisionSources) * len(decryptobs.AllTLSVersions)
	got := scrapeDecSessions(t, c)
	if len(got) != want {
		t.Fatalf("distinct series = %d, want %d (label space must be bounded by construction)", len(got), want)
	}
	oc, ds, tv := boundedLabelSets()
	for k, n := range got {
		if !oc[k[0]] || !ds[k[1]] || !tv[k[2]] {
			t.Fatalf("out-of-vocabulary label tuple %v", k)
		}
		if n != 2 {
			t.Fatalf("series %v count = %d, want 2 (each combo recorded twice)", k, n)
		}
	}
}

// globalDecSessionCount reads the current count for one label tuple off the global
// counter (0 if the series does not exist yet). Used for delta assertions that tolerate
// concurrent accumulation from the rest of the suite.
func globalDecSessionCount(t *testing.T, outcome, source, tlsVer string) int64 {
	t.Helper()
	var sb strings.Builder
	decSessions.writePrometheus(&sb)
	for _, m := range decSessionLineRE.FindAllStringSubmatch(sb.String(), -1) {
		if m[1] == outcome && m[2] == source && m[3] == tlsVer {
			n, _ := strconv.ParseInt(m[4], 10, 64)
			return n
		}
	}
	return 0
}

// inspectedSessionTotal sums the global coverage counter across all tls_versions for
// outcome=inspected/source=policy_inspect. Used by the native-ALPN e2e to assert (delta)
// that a successfully inspected native tunnel is counted, without depending on the exact
// TLS version the loopback origin negotiates.
func inspectedSessionTotal(t *testing.T) int64 {
	t.Helper()
	var sb strings.Builder
	decSessions.writePrometheus(&sb)
	var total int64
	for _, m := range decSessionLineRE.FindAllStringSubmatch(sb.String(), -1) {
		if m[1] == "inspected" && m[2] == "policy_inspect" {
			n, _ := strconv.ParseInt(m[4], 10, 64)
			total += n
		}
	}
	return total
}

// TestRecordTunnelCloseDec_IncrementsCoverage proves the close seam is a session-counting
// terminal: a non-nil outcome through recordTunnelCloseGatedDec bumps the coverage counter
// exactly once (delta-based, so it is robust under -count/-shuffle accumulation).
func TestRecordTunnelCloseDec_IncrementsCoverage(t *testing.T) {
	const (
		oc = "bypass_learned"
		ds = "autoexclude_cache"
		tv = "unknown"
	)
	before := globalDecSessionCount(t, oc, ds, tv)
	o := &DecryptionOutcome{
		Outcome:        decryptobs.OutcomeBypassLearned,
		DecisionSource: decryptobs.DecisionAutoexcludeCache,
		Host:           "dec-metric-wire.example",
	}
	recordTunnelCloseGatedDec(nil, ProxyIdentity{ClientIP: "203.0.113.77"}, "CONNECT", "dec-metric-wire.example", 5, 6, time.Now(), "bypass", "", o, false)
	if got := globalDecSessionCount(t, oc, ds, tv); got != before+1 {
		t.Fatalf("coverage counter delta = %d, want +1 (seam must count the session once)", got-before)
	}
}

// TestRecordTunnelCloseDec_NilNoCoverage proves the nil-outcome path (WS/SOCKS closes)
// does NOT touch the coverage counter.
func TestRecordTunnelCloseDec_NilNoCoverage(t *testing.T) {
	const (
		oc = "not_decrypted"
		ds = "non_tls_fallback"
		tv = "unknown"
	)
	before := globalDecSessionCount(t, oc, ds, tv)
	recordTunnelCloseGatedReason(nil, ProxyIdentity{ClientIP: "203.0.113.78"}, "WS", "dec-metric-nil.example", 1, 2, time.Now(), "", "")
	if got := globalDecSessionCount(t, oc, ds, tv); got != before {
		t.Fatalf("nil-outcome close moved the coverage counter by %d, want 0", got-before)
	}
}

// decFailureLineRE parses one culvert_decrypt_failures_total series line.
var decFailureLineRE = regexp.MustCompile(
	`culvert_decrypt_failures_total\{fail_category="([^"]*)",fail_stage="([^"]*)"\} (\d+)`)

// TestDecFailureCounter_Exposition pins exact counts + bounded labels on an isolated
// instance (10 categories × 7 stages = 70 max series).
func TestDecFailureCounter_Exposition(t *testing.T) {
	c := &decFailureCounter{counts: map[string]*decFailureLabel{}}
	var empty strings.Builder
	c.writePrometheus(&empty)
	if empty.Len() != 0 {
		t.Fatalf("empty failure counter must emit nothing, got %q", empty.String())
	}
	c.record("certificate", "cert_verify")
	c.record("certificate", "cert_verify")
	c.record("client_pinned", "client_leaf_reject")

	var sb strings.Builder
	c.writePrometheus(&sb)
	got := map[[2]string]int64{}
	for _, m := range decFailureLineRE.FindAllStringSubmatch(sb.String(), -1) {
		n, _ := strconv.ParseInt(m[3], 10, 64)
		got[[2]string{m[1], m[2]}] = n
	}
	if got[[2]string{"certificate", "cert_verify"}] != 2 || got[[2]string{"client_pinned", "client_leaf_reject"}] != 1 {
		t.Fatalf("failure counts wrong: %v", got)
	}
	// Cardinality: every enum combination stays bounded.
	c2 := &decFailureCounter{counts: map[string]*decFailureLabel{}}
	for _, cat := range decryptobs.AllFailCategories {
		for _, st := range decryptobs.AllFailStages {
			c2.record(cat.String(), st.String())
		}
	}
	var sb2 strings.Builder
	c2.writePrometheus(&sb2)
	if n := len(decFailureLineRE.FindAllStringSubmatch(sb2.String(), -1)); n != len(decryptobs.AllFailCategories)*len(decryptobs.AllFailStages) {
		t.Fatalf("failure series = %d, want %d (bounded by construction)", n, len(decryptobs.AllFailCategories)*len(decryptobs.AllFailStages))
	}
}

// TestRecordDecryptFailure_CountsBothMetrics proves a failed session increments BOTH the
// failure taxonomy AND the coverage total (outcome=failed) — the paired-count contract.
func TestRecordDecryptFailure_CountsBothMetrics(t *testing.T) {
	failuresBefore := globalDecFailureCount(t, "cipher", "upstream_handshake")
	coverageBefore := globalDecSessionCount(t, "failed", "no_fail_open_502", "unknown")

	recordDecryptFailure(&DecryptionOutcome{
		Outcome:        decryptobs.OutcomeFailed,
		DecisionSource: decryptobs.DecisionNoFailOpen502,
		FailStage:      decryptobs.FailStageUpstreamHandshake,
		FailCategory:   decryptobs.FailCategoryCipher,
	})

	if got := globalDecFailureCount(t, "cipher", "upstream_handshake"); got != failuresBefore+1 {
		t.Fatalf("failures_total delta = %d, want +1", got-failuresBefore)
	}
	if got := globalDecSessionCount(t, "failed", "no_fail_open_502", "unknown"); got != coverageBefore+1 {
		t.Fatalf("sessions_total{failed} delta = %d, want +1 (failed session must also count in coverage)", got-coverageBefore)
	}
	recordDecryptFailure(nil) // nil is a no-op, must not panic
}

// globalDecFailureCount reads the current count for one failure tuple off the global
// counter (0 if absent). Delta-based, tolerant of suite accumulation.
func globalDecFailureCount(t *testing.T, category, stage string) int64 {
	t.Helper()
	var sb strings.Builder
	decFailures.writePrometheus(&sb)
	for _, m := range decFailureLineRE.FindAllStringSubmatch(sb.String(), -1) {
		if m[1] == category && m[2] == stage {
			n, _ := strconv.ParseInt(m[3], 10, 64)
			return n
		}
	}
	return 0
}

// TestRecordDecryptSession_CoercesAndNilGuard exercises the global entry point: a nil
// outcome is a no-op, and an outcome carrying cast/garbage enums coerces to the sentinels
// (never a raw token) so the metric vocabulary stays closed.
func TestRecordDecryptSession_CoercesAndNilGuard(t *testing.T) {
	recordDecryptSession(nil) // must not panic and must add nothing

	recordDecryptSession(&DecryptionOutcome{
		Outcome:        decryptobs.Outcome("garbage"),
		DecisionSource: decryptobs.DecisionSource("nope"),
		TLSVersion:     decryptobs.TLSVersion("99"),
	})

	var sb strings.Builder
	decSessions.writePrometheus(&sb)
	body := sb.String()

	// No raw/cast token may ever appear as a label.
	for _, bad := range []string{`"garbage"`, `"nope"`, `"99"`} {
		if strings.Contains(body, bad) {
			t.Fatalf("unbounded label leaked to metric: %s\n%s", bad, body)
		}
	}
	// The coerced sentinels must be present (not_decrypted / non_tls_fallback / unknown).
	if !strings.Contains(body, `outcome="not_decrypted",decision_source="non_tls_fallback",tls_version="unknown"`) {
		t.Fatalf("coerced sentinel series missing:\n%s", body)
	}

	// Global invariant: EVERY exposed series has in-vocabulary labels regardless of what
	// the rest of the suite recorded.
	oc, ds, tv := boundedLabelSets()
	for _, m := range decSessionLineRE.FindAllStringSubmatch(body, -1) {
		if !oc[m[1]] || !ds[m[2]] || !tv[m[3]] {
			t.Fatalf("global counter exposed out-of-vocabulary labels: %q/%q/%q", m[1], m[2], m[3])
		}
	}
}

// TestDecSessionCounter_MatchesLegacyShape is the differential oracle for the
// coverage counter's rewrite: the published-index shape must produce the SAME
// series, in the SAME insertion order, with the SAME counts as the frozen
// RWMutex + concatenated-key shape it replaced
// (decSessionCounterLegacy, decryption_metrics_bench_test.go).
//
// Order is load-bearing, not incidental: writePrometheus and snapshot both walk
// c.order, and /api/decryption/health returns snapshot() as a JSON array, so a
// rewrite that silently reordered the series would change an API response.
//
// The sequence deliberately interleaves repeats with first sightings, so it
// exercises the published-read path, the copy-on-write insert, and the
// re-check-after-lock arm rather than only the steady state.
func TestDecSessionCounter_MatchesLegacyShape(t *testing.T) {
	outcomes, sources, vers := decBenchSeries()
	type obs struct{ o, s, v string }
	var seq []obs
	for round := 0; round < 3; round++ {
		for i, o := range outcomes {
			for j, s := range sources {
				for k, v := range vers {
					// Skip a shifting subset each round so series are first seen
					// at different points in the sequence, not all up front.
					if (i+j+k+round)%3 == 0 {
						continue
					}
					seq = append(seq, obs{o, s, v})
				}
			}
		}
	}
	if len(seq) == 0 {
		t.Fatal("empty observation sequence: the enum vocabularies are empty")
	}

	got := &decSessionCounter{}
	want := newDecSessionCounterLegacy()
	for _, e := range seq {
		got.record(e.o, e.s, e.v)
		want.record(e.o, e.s, e.v)
	}

	gs, ws := got.snapshot(), want.snapshot()
	if len(gs) != len(ws) {
		t.Fatalf("series count: got %d, legacy %d", len(gs), len(ws))
	}
	for i := range ws {
		if gs[i] != ws[i] {
			t.Fatalf("series %d: got %+v, legacy %+v", i, gs[i], ws[i])
		}
	}
	// The counts must also be the observation count, not merely equal to each
	// other — two identically broken counters would pass the comparison above.
	var total int64
	for _, s := range gs {
		total += s.Count
	}
	if total != int64(len(seq)) {
		t.Fatalf("total counted: got %d, observations %d", total, len(seq))
	}
}

// TestDecSessionCounter_ConcurrentRecordLosesNothing pins the property the
// copy-on-write publish exists to preserve: a record that loaded the PREVIOUS
// index increments the same *decSessionLabel the new index publishes, so an
// increment racing an insert is never dropped. Run with -race.
func TestDecSessionCounter_ConcurrentRecordLosesNothing(t *testing.T) {
	outcomes, sources, vers := decBenchSeries()
	c := &decSessionCounter{}
	const workers, perWorker = 8, 400
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				c.record(
					outcomes[(w+i)%len(outcomes)],
					sources[(w+i*3)%len(sources)],
					vers[(w+i*7)%len(vers)],
				)
			}
		}(w)
	}
	wg.Wait()
	var total int64
	for _, s := range c.snapshot() {
		total += s.Count
	}
	if total != workers*perWorker {
		t.Fatalf("counted %d of %d concurrent observations", total, workers*perWorker)
	}
}
