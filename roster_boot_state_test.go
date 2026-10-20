package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Gates for the admin_roster_durability boot state and for the one probe per
// request (PR #1601; Culvert no longer writes the roster at startup).

// TestRosterDurability_NotYetVerifiedAtBoot: a fresh boot loads an existing
// roster and writes nothing, so persistence is not verified yet. The row is
// warn (never fail: the contract verdict stays below fail, and the viewer
// sees a fixed, non-alarming message), and the first landed save makes it
// ok.
func TestRosterDurability_NotYetVerifiedAtBoot(t *testing.T) {
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	setupRosterLoadedNotWritten(t, c)

	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetNotYetVerified {
		t.Fatalf("row = %+v, want warn %q", row, rosterTargetNotYetVerified)
	}
	if !strings.Contains(row.OperatorAction, "No action is needed now") {
		t.Errorf("action = %q, want the no-action-needed remedy", row.OperatorAction)
	}
	contract, viewer := durabilityRowAt(t, RoleViewer)
	if viewer.Status != diagWarn || viewer.Message != rosterDurabilityViewerNotYetVerified {
		t.Errorf("viewer row = %+v, want the fixed not-yet-verified message", viewer)
	}
	// The verdict also folds in every other row, whose state other tests in
	// the package may leave behind, so assert the roster row's contribution:
	// the verdict is exactly what the other rows give with one warn added.
	others := make([]OperatorContractCheck, 0, len(contract.Checks))
	for i := range contract.Checks {
		if contract.Checks[i].Code != adminRosterDurabilityCode {
			others = append(others, contract.Checks[i])
		}
	}
	want := rollUpVerdict(append(others, OperatorContractCheck{Status: diagWarn}))
	if contract.Verdict != want {
		t.Errorf("contract verdict = %q, want %q: not-verified-yet must only warn, never fail", contract.Verdict, want)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Errorf("after the first landed save: row = %+v, want ok", row)
	}
}

// TestRosterDurability_HardProblemsOutrankNotYetVerified: before any write,
// what the live probe finds wrong is reported instead of the pending state.
// Ranking not-verified-yet first fails this test.
func TestRosterDurability_HardProblemsOutrankNotYetVerified(t *testing.T) {
	cases := map[string]struct {
		setup func(t *testing.T, c *Config)
		want  string
	}{
		"parent not writable": {func(t *testing.T, c *Config) {
			setupRosterLoadedNotWritten(t, c)
			injectParentAccess(t, errEACCES)
		}, rosterParentNotWritable},
		"immutable": {func(t *testing.T, c *Config) {
			setupRosterLoadedNotWritten(t, c)
			injectReplacementBlocked(t, fmt.Errorf("%w: immutable: %w", fileutil.ErrReplacementBlocked, syscall.EPERM))
		}, rosterTargetImmutable},
		"missing file": {setupRosterFirstRun, rosterTargetFirstWritePending},
		"storage not responding": {func(t *testing.T, c *Config) {
			setupRosterLoadedNotWritten(t, c)
			path, _ := c.rosterPersistTarget()
			setRosterProbeTiming(t, 0, 100*time.Millisecond)
			block, entered := make(chan struct{}), make(chan struct{})
			countTargetStats(t, path, block, entered)
			t.Cleanup(func() {
				close(block)
				waitProbeIdle(t)
			})
		}, rosterTargetNotResponding},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := configuredRosterCfg(t, false)
			swapCfgForRosterDurability(t, c)
			tc.setup(t, c)
			if row := checkAdminRosterDurability(); row.Status != diagWarn || row.Message != tc.want {
				t.Errorf("row = %+v, want warn %q", row, tc.want)
			}
		})
	}
}

// TestOperatorContract_OneProbePerRequest is the Codex P2 4320228851 gate:
// with the roster's storage stalled, /api/diagnostics and
// /api/health/explain — as a viewer (the redaction path) and as an admin —
// each return within ONE probe wait plus a margin smaller than a second wait.
// Probing again for the viewer row fails this test.
func TestOperatorContract_OneProbePerRequest(t *testing.T) {
	_, path := savedRosterCfg(t)
	const wait = 500 * time.Millisecond
	setRosterProbeTiming(t, 0, wait)
	block, entered := make(chan struct{}), make(chan struct{})
	countTargetStats(t, path, block, entered)
	var once sync.Once
	release := func() { once.Do(func() { close(block) }) }
	t.Cleanup(func() {
		release()
		waitProbeIdle(t)
	})

	handlers := map[string]http.HandlerFunc{"/api/diagnostics": apiDiagnostics, "/api/health/explain": apiHealthExplain}
	for route, h := range handlers {
		for _, role := range []UIRole{RoleViewer, RoleAdmin} {
			r := roleCtx(httptest.NewRequest(http.MethodGet, route, http.NoBody), role)
			w := httptest.NewRecorder()
			start := time.Now()
			h(w, r)
			took := time.Since(start)
			if w.Code != http.StatusOK {
				t.Fatalf("%s as %s: status %d", route, role, w.Code)
			}
			if took > wait+wait*4/5 {
				t.Errorf("%s as %s took %v on stalled storage, want at most one %v wait", route, role, took, wait)
			}
			row := findDiagnosticCheck(decodeContract(t, w), adminRosterDurabilityCode)
			if row == nil || row.Status != diagWarn {
				t.Errorf("%s as %s: row = %+v, want warn (storage not responding)", route, role, row)
			}
		}
	}
}
