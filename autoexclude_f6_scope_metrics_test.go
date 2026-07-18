package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// autoexclude_f6_scope_metrics_test.go — F6: per-scope labels on the auto-exclusion
// hit/active series. Pins the hot-path hit counter's {scope} breakdown (incl. the process
// total staying in sync + the cap fold), and the active{scope} gauge emission.

// TestF6_HitByScope_TracksScopeAndTotal proves recordAutoExcludeHit bumps BOTH the process
// total (autoExcludeHitCounter, read by the health API + qualification test) AND the
// per-scope series, keyed by the scope ID with no cross-scope bleed.
func TestF6_HitByScope_TracksScopeAndTotal(t *testing.T) {
	// Unique scope names so the global counter's accumulation across the suite can't collide.
	const scopeX, scopeY = "f6-hit-scopeX", "f6-hit-scopeY"
	// Global counters accumulate across the suite (and across -count reruns), so every
	// assertion is delta-based.
	beforeTotal := autoExcludeHitCounter
	beforeX := hitScopeCount(t, scopeX)
	beforeY := hitScopeCount(t, scopeY)

	recordAutoExcludeHit(scopeX)
	recordAutoExcludeHit(scopeX)
	recordAutoExcludeHit(scopeY)

	if got := autoExcludeHitCounter - beforeTotal; got != 3 {
		t.Fatalf("process total delta = %d, want 3", got)
	}
	if got := hitScopeCount(t, scopeX) - beforeX; got != 2 {
		t.Fatalf("scopeX delta = %d, want 2", got)
	}
	if got := hitScopeCount(t, scopeY) - beforeY; got != 1 {
		t.Fatalf("scopeY delta = %d, want 1", got)
	}
}

// hitScopeCount reads the current {scope} hit count off the global counter (0 if absent).
func hitScopeCount(t *testing.T, scope string) int64 {
	t.Helper()
	var sb strings.Builder
	autoExcludeHitsByScope.writePrometheus(&sb)
	// culvert_decrypt_autoexclude_hit_total{scope="X"} N
	want := `culvert_decrypt_autoexclude_hit_total{scope="` + scope + `"} `
	for _, ln := range strings.Split(sb.String(), "\n") {
		if strings.HasPrefix(ln, want) {
			n, _ := strconv.ParseInt(strings.TrimPrefix(ln, want), 10, 64)
			return n
		}
	}
	return 0
}

// TestF6_HitByScope_CapFolds proves the {scope} label set is bounded: past
// maxAutoExcludeLabels distinct scopes, overflow folds into the shared _other_ bucket
// rather than growing without limit (attacker can't inflate cardinality via profile churn).
func TestF6_HitByScope_CapFolds(t *testing.T) {
	c := &autoExcludeHitScopeCounter{counts: make(map[string]*int64)}
	for i := 0; i < maxAutoExcludeLabels+50; i++ {
		c.record("scope-" + strconv.Itoa(i))
	}
	// The cap admits maxAutoExcludeLabels distinct real scopes plus the shared _other_
	// overflow bucket (same as autoExcludeLearnCounter), so the series count is bounded at
	// maxAutoExcludeLabels+1 no matter how many distinct scopes churn through.
	if len(c.order) != maxAutoExcludeLabels+1 {
		t.Fatalf("distinct scope series = %d, want %d (cap + _other_)", len(c.order), maxAutoExcludeLabels+1)
	}
	var sb strings.Builder
	c.writePrometheus(&sb)
	if !strings.Contains(sb.String(), `scope="_other_"`) {
		t.Fatalf("overflow scopes not folded into _other_:\n%s", sb.String()[:200])
	}
}

// TestF6_ActiveByScope_Emission proves the active{scope} gauge reflects the live cache and
// emits nothing when empty.
func TestF6_ActiveByScope_Emission(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})

	// Empty cache ⇒ no series.
	var empty strings.Builder
	writeAutoExcludeActiveByScope(&empty)
	if empty.Len() != 0 {
		t.Fatalf("empty cache must emit no active series, got %q", empty.String())
	}

	autoExclude().Observe("f6-act-A", "A", "a.example", autoexclude.ReasonClientCertRequired, "ip:1.1.1.1")
	autoExclude().Observe("f6-act-A", "A", "a2.example", autoexclude.ReasonClientCertRequired, "ip:1.1.1.2")
	autoExclude().Observe("f6-act-B", "B", "b.example", autoexclude.ReasonClientCertRequired, "ip:1.1.1.3")

	var sb strings.Builder
	writeAutoExcludeActiveByScope(&sb)
	body := sb.String()
	if !strings.Contains(body, `culvert_decrypt_autoexclude_active{scope="f6-act-A"} 2`) ||
		!strings.Contains(body, `culvert_decrypt_autoexclude_active{scope="f6-act-B"} 1`) {
		t.Fatalf("active-by-scope emission wrong:\n%s", body)
	}
	if !strings.Contains(body, "# TYPE culvert_decrypt_autoexclude_active gauge") {
		t.Fatalf("missing TYPE header:\n%s", body)
	}
}
