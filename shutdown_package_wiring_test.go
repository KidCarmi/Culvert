package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/shutdown"
)

// Exercise the production constructor: an engine-only log test cannot prove
// main supplies the logger that must report abandonment before sink close.
func TestShutdownPackage_ProductionDiagnosticSink(t *testing.T) {
	release, finished := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		close(release)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("hook did not exit after release")
		}
	})
	out := captureLogger(t, func() {
		reg := newShutdownRegistry()
		reg.Register("production-sink-probe", 1, func(context.Context) error { defer close(finished); <-release; return nil })
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
		defer cancel()
		if err := reg.RunAll(ctx); !errors.Is(err, shutdown.ErrAbandoned) {
			t.Errorf("expected abandonment, got %v", err)
		}
	})
	if !strings.Contains(out, `Shutdown: hook "production-sink-probe"`) {
		t.Fatalf("main did not wire abandonment diagnostics: %q", out)
	}
}

// The arithmetic test moved with the engine and uses the shipped phase sizes
// as representative budgets. Keep their tie to the real production envelope
// explicit, so a future budget change updates that fixture deliberately.
func TestShutdownPackage_ArithmeticFixtureMatchesProductionEnvelope(t *testing.T) {
	if defaultShutdownBudget.Early != 12*time.Second || defaultShutdownBudget.Flush != 10*time.Second ||
		defaultShutdownBudget.Total-defaultShutdownBudget.Early-defaultShutdownBudget.Flush != 23*time.Second {
		t.Fatal("update the engine arithmetic fixtures when changing the production phase budgets")
	}
	if shutdown.DefaultGrace != 3*time.Second || shutdown.DefaultMinSlice != time.Second {
		t.Fatal("watchdog defaults changed; review the container envelope and arithmetic fixtures")
	}
}
