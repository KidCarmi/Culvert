package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// surgeClock is a deterministic clock for the surge detector (no time.Sleep, so
// the tests are shuffle-safe under the determinism gate).
type surgeClock struct{ t time.Time }

func (c *surgeClock) now() time.Time      { return c.t }
func (c *surgeClock) add(d time.Duration) { c.t = c.t.Add(d) }

// swapAutoExcludeSurge isolates the process-wide surge detector for a test and
// restores it on cleanup (the swapAutoExclude fence-pollution discipline).
func swapAutoExcludeSurge(t *testing.T, now func() time.Time) {
	t.Helper()
	prev := autoExcludeSurge
	autoExcludeSurge = newSurgeDetector(now)
	t.Cleanup(func() { autoExcludeSurge = prev })
}

// TestSurgeDetector_FiresOncePerWindowAndRearms pins the latched fixed-window
// contract: no fire below threshold, exactly one fire on the crossing, silence
// for the rest of the window (latch), and re-arm on the next window.
func TestSurgeDetector_FiresOncePerWindowAndRearms(t *testing.T) {
	clk := &surgeClock{t: time.Unix(1_700_000_000, 0)}
	d := newSurgeDetector(clk.now)

	for i := 0; i < surgeThreshold-1; i++ {
		if fire, _ := d.observePromotion(); fire {
			t.Fatalf("surge fired before threshold at promotion %d", i+1)
		}
	}
	if fire, n := d.observePromotion(); !fire || n != surgeThreshold {
		t.Fatalf("threshold crossing must fire once: fire=%v count=%d (want true,%d)", fire, n, surgeThreshold)
	}
	// Latched: further promotions in the SAME window are silent.
	for i := 0; i < 10; i++ {
		if fire, _ := d.observePromotion(); fire {
			t.Fatal("surge fired twice within one window — latch broken (would spam the SOC)")
		}
	}
	// New window re-arms: threshold again is required to fire.
	clk.add(surgeWindow + time.Second)
	for i := 0; i < surgeThreshold-1; i++ {
		if fire, _ := d.observePromotion(); fire {
			t.Fatalf("re-armed window fired before threshold at %d", i+1)
		}
	}
	if fire, _ := d.observePromotion(); !fire {
		t.Fatal("re-armed window did not fire at threshold")
	}
}

// TestSurgeDetector_SpreadOutDoesNotFire pins that a legitimate slow rollout
// (promotions spread across windows) never trips the surge — no false positives.
func TestSurgeDetector_SpreadOutDoesNotFire(t *testing.T) {
	clk := &surgeClock{t: time.Unix(1_700_000_000, 0)}
	d := newSurgeDetector(clk.now)
	for i := 0; i < surgeThreshold*3; i++ {
		if fire, _ := d.observePromotion(); fire {
			t.Fatalf("spread-out promotions must not trip the surge (promotion %d)", i)
		}
		clk.add(surgeWindow) // each promotion lands in its own fresh window
	}
}

// TestRecordAutoExclude_SurgeAlertOnRateSpike pins the wiring: a burst of
// promotions within one window fires exactly one aggregate surge alert
// (counter + audit + /metrics), independent of the per-host learn alerts.
func TestRecordAutoExclude_SurgeAlertOnRateSpike(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	clk := &surgeClock{t: time.Unix(1_700_000_000, 0)}
	swapAutoExcludeSurge(t, clk.now)

	before := atomic.LoadInt64(&autoExcludeSurgeCounter)
	baseline := time.Now().UnixMilli()
	fo, _ := bindFailOpenProfile(t, "fo", "fail-open")

	// Promote surgeThreshold DISTINCT hosts within the (frozen) window.
	for i := 0; i < surgeThreshold; i++ {
		host := fmt.Sprintf("h%d.surge.example", i)
		recordAutoExclude(fo, host, autoExReasonUnsupported, ProxyIdentity{ClientIP: "198.51.100.1", Identity: "u"})
	}

	if got := atomic.LoadInt64(&autoExcludeSurgeCounter); got != before+1 {
		t.Fatalf("surge counter = %d, want %d (exactly one aggregate alert for the window)", got, before+1)
	}
	found := false
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "decryption.autoexclude.surge" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no decryption.autoexclude.surge audit entry after the rate spike")
	}
	rw := httptest.NewRecorder()
	handleMetrics(rw, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	if !strings.Contains(rw.Body.String(), "culvert_decrypt_autoexclude_surge_total") {
		t.Fatal("/metrics missing culvert_decrypt_autoexclude_surge_total")
	}
}
