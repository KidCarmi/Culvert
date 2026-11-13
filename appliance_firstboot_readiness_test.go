package main

// Provisioning completion is recorded only on evidence (owner direction after
// QEMU campaign 9, PR #1528). install.sh recreates the proxy late (Release
// Management wiring: `compose up -d` without --wait), and first boot used to
// write complete.done straight after it, so `complete` could be on record
// while the application did not answer yet (campaign 7). The finish step now
// waits, within a bound, until the two conditions the console's status-json
// reports hold: the application answers /health (200) AND management answers
// /api/setup/status (200, boolean needsSetup), twice in a row. These tests
// drive that gate through scripted probe answers (harness readycurl) and
// check that complete.done appears only after the evidence, never on a
// timeout, and never on a single answer from just before a recreate.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setReadiness scripts the probe answers: one line per call, last repeats.
// nil leaves that endpoint answering ready.
func (h *fbHarness) setReadiness(health, setup []string) {
	h.t.Helper()
	for name, seq := range map[string][]string{"health": health, "setup": setup} {
		_ = os.Remove(filepath.Join(h.root, name+".n"))
		p := filepath.Join(h.root, name+".seq")
		if seq == nil {
			_ = os.Remove(p)
			continue
		}
		if err := os.WriteFile(p, []byte(strings.Join(seq, "\n")+"\n"), 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *fbHarness) readyCalls(endpoint string) int {
	b, _ := os.ReadFile(h.calls)
	return strings.Count(string(b), "readycurl "+endpoint+"\n")
}

func (h *fbHarness) readinessFailed() string {
	b, err := os.ReadFile(filepath.Join(h.state, "state", "readiness.failed"))
	if err != nil {
		return ""
	}
	return string(b)
}

const setupPending = `200 {"needsSetup":true}`

// Delayed readiness: neither condition holds at first, then both do. Complete
// is recorded only after both held in two consecutive checks, and the record
// follows the evidence in the log.
func TestFirstBoot_Readiness_DelayedApplicationAndManagement(t *testing.T) {
	h := newFBHarness(t)
	h.setReadiness([]string{"000", "000", "200"}, []string{"000", "503 {}", setupPending})
	out, code := h.run("READY_TIMEOUT_S=30; step_finish")
	if code != 0 {
		t.Fatalf("step_finish failed (%d):\n%s", code, out)
	}
	if !h.exists("appliance/state/complete.done") {
		t.Fatalf("completion was not recorded once both conditions held:\n%s", out)
	}
	// Checks 1-2 fail, 3 and 4 pass: exactly four checks of each endpoint.
	if hc, sc := h.readyCalls("health"), h.readyCalls("setup"); hc != 4 || sc != 4 {
		t.Fatalf("checks: health=%d setup=%d, want 4 and 4 (two failing, then two consecutive passing)\n%s", hc, sc, out)
	}
	ev, rec := strings.Index(out, "readiness: application and management answered in 2 consecutive checks"), strings.Index(out, "step complete: done")
	if ev < 0 || rec < 0 || ev > rec {
		t.Fatalf("completion must be recorded only after the readiness evidence:\n%s", out)
	}
	if h.readinessFailed() != "" {
		t.Fatal("a successful wait must not leave readiness.failed")
	}
}

// Permanent failure: the wait ends at its bound, nothing is recorded complete,
// the reason and diagnostics are kept, cloud-init is not retired, and the step
// fails (so the unit's bounded retry applies). A later run that sees the
// services recovers and clears the failure record.
func TestFirstBoot_Readiness_PermanentFailureNeverRecordsComplete(t *testing.T) {
	h := newFBHarness(t)
	h.stub("docker", `echo "stub-compose $*"`)
	h.setReadiness([]string{"000"}, []string{"000"})
	start := time.Now()
	out, code := h.run("READY_TIMEOUT_S=3; step_finish")
	elapsed := time.Since(start)
	if code == 0 {
		t.Fatalf("step_finish succeeded although the services never answered:\n%s", out)
	}
	if h.exists("appliance/state/complete.done") {
		t.Fatal("complete.done was recorded although readiness never held")
	}
	if h.exists("cloud-init.disabled") {
		t.Fatal("cloud-init must not be retired before completion is recorded")
	}
	if elapsed > 15*time.Second {
		t.Fatalf("the wait is not bounded: %v for a 3 s bound", elapsed)
	}
	rf := h.readinessFailed()
	for _, want := range []string{"application /health: http 000", "management /api/setup/status: http 000", "checks"} {
		if !strings.Contains(rf, want) {
			t.Fatalf("readiness.failed lacks %q: %q", want, rf)
		}
	}
	for _, want := range []string{"provisioning NOT recorded complete", "readiness diagnostics", "stub-compose compose ps", "stub-compose compose logs --no-color --tail 40 proxy"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	// Recovery: the services answer now; the same step records completion.
	h.setReadiness(nil, nil)
	out, code = h.run("READY_TIMEOUT_S=30; step_finish")
	if code != 0 || !h.exists("appliance/state/complete.done") {
		t.Fatalf("a retry with ready services did not record completion (%d):\n%s", code, out)
	}
	if h.readinessFailed() != "" {
		t.Fatal("completion must clear readiness.failed")
	}
}

// Proxy recreation: one answer, then the proxy is recreated (no answer), then
// it answers again. The early answer does not count; completion needs two
// consecutive passing checks after the recreate. The control (one
// confirmation) shows the scenario is the one a single check would accept.
func TestFirstBoot_Readiness_ProxyRecreationDoesNotCountAnEarlyAnswer(t *testing.T) {
	h := newFBHarness(t)
	h.setReadiness([]string{"200", "000", "200"}, nil)
	out, code := h.run("READY_TIMEOUT_S=30; step_finish")
	if code != 0 || !h.exists("appliance/state/complete.done") {
		t.Fatalf("step_finish (%d):\n%s", code, out)
	}
	if hc := h.readyCalls("health"); hc != 4 {
		t.Fatalf("health checks = %d, want 4 (answer, recreate gap, then two consecutive answers)\n%s", hc, out)
	}

	ctl := newFBHarness(t)
	ctl.setReadiness([]string{"200", "000", "200"}, nil)
	out, code = ctl.run("READY_TIMEOUT_S=30; READY_CONFIRM=1; step_finish")
	if code != 0 || ctl.readyCalls("health") != 1 {
		t.Fatalf("control: a single confirmation should accept the first answer (code %d, %d checks):\n%s", code, ctl.readyCalls("health"), out)
	}
}

// Either condition alone is insufficient, and management must report the
// setup state as a JSON boolean (what status-json's management_available
// requires); container or listener presence is not evidence.
func TestFirstBoot_Readiness_BothConditionsAreRequired(t *testing.T) {
	cases := []struct {
		name          string
		health, setup []string
		reason        string
	}{
		{"application only", []string{"200"}, []string{"000"}, "management /api/setup/status: http 000"},
		{"management only", []string{"503"}, []string{setupPending}, "application /health: http 503"},
		{"management 200 without needsSetup", []string{"200"}, []string{"200 {}"}, "http 200 without a boolean needsSetup"},
		{"management needsSetup not a boolean", []string{"200"}, []string{`200 {"needsSetup":"yes"}`}, "without a boolean needsSetup"},
		{"management body not JSON", []string{"200"}, []string{"200 <html>starting</html>"}, "without a boolean needsSetup"},
		{"management 503", []string{"200"}, []string{"503 {}"}, "management /api/setup/status: http 503"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFBHarness(t)
			h.setReadiness(tc.health, tc.setup)
			out, code := h.run("READY_TIMEOUT_S=2; step_finish")
			if code == 0 || h.exists("appliance/state/complete.done") {
				t.Fatalf("completion recorded with only partial readiness (%d):\n%s", code, out)
			}
			if rf := h.readinessFailed(); !strings.Contains(rf, tc.reason) {
				t.Fatalf("readiness.failed = %q, want it to name %q", rf, tc.reason)
			}
		})
	}
	// Administrator already enrolled (needsSetup=false) is also a valid state.
	h := newFBHarness(t)
	h.setReadiness(nil, []string{`200 {"needsSetup":false}`})
	if out, code := h.run("READY_TIMEOUT_S=10; step_finish"); code != 0 || !h.exists("appliance/state/complete.done") {
		t.Fatalf("needsSetup=false must count as management available (%d):\n%s", code, out)
	}
}

// The bound holds even when the clock does not advance: with sleep stubbed
// out, the check-count cap (timeout/interval + confirmations + 1) ends the
// wait.
func TestFirstBoot_Readiness_CheckCountBoundsTheWait(t *testing.T) {
	h := newFBHarness(t)
	h.stub("sleep", ":")
	h.setReadiness([]string{"000"}, nil)
	out, code := h.run("READY_TIMEOUT_S=4; READY_INTERVAL_S=1; READY_CONFIRM=2; step_finish")
	if code == 0 || h.exists("appliance/state/complete.done") {
		t.Fatalf("an unbounded or permissive wait (%d):\n%s", code, out)
	}
	if hc := h.readyCalls("health"); hc != 7 {
		t.Fatalf("health checks = %d, want the cap 4/1+2+1 = 7\n%s", hc, out)
	}
}

// complete.done has exactly one writer, and it sits behind the gate.
func TestFirstBoot_Readiness_CompleteHasOneGatedWriter(t *testing.T) {
	b, err := os.ReadFile(fbScript)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if n := strings.Count(src, "done_step complete"); n != 1 {
		t.Fatalf("done_step complete appears %d times, want exactly once", n)
	}
	_, fin, ok := strings.Cut(src, "step_finish() {")
	if ok {
		fin, _, ok = strings.Cut(fin, "\n}\n")
	}
	if !ok {
		t.Fatal("step_finish() not found")
	}
	gate, rec := strings.Index(fin, "wait_for_readiness || return 1"), strings.Index(fin, "done_step complete")
	if gate < 0 || rec < 0 || gate > rec {
		t.Fatal("step_finish must run the readiness gate before recording completion")
	}
}

// culvert-status names the recorded readiness failure until completion.
func TestApplianceStatus_ReportsReadinessFailure(t *testing.T) {
	h := newFBHarness(t)
	rf := filepath.Join(h.state, "state", "readiness.failed")
	if err := os.WriteFile(rf, []byte("2026-11-14T00:00:00Z application /health: http 000; management /api/setup/status: http 000; waited 300s, 152 checks\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := func(args ...string) string {
		abs, _ := filepath.Abs(statusScript)
		// #nosec G204 -- program is the literal "bash"; abs is the checked-in script's path.
		c := exec.CommandContext(t.Context(), "bash", append([]string{abs}, args...)...)
		c.Env = h.env()
		out, _ := c.CombinedOutput()
		return string(out)
	}
	want := "services not ready at the last first-boot check: application /health: http 000; management /api/setup/status: http 000"
	if s := status(); !strings.Contains(s, want) {
		t.Fatalf("status lacks the readiness failure:\n%s", s)
	}
	if s := status("--json"); !strings.Contains(s, want) {
		t.Fatalf("--json lacks the readiness failure:\n%s", s)
	}
	if err := os.WriteFile(filepath.Join(h.state, "state", "complete.done"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if s := status(); strings.Contains(s, "services not ready at the last first-boot check") {
		t.Fatalf("a stale readiness record must not show once completion is recorded:\n%s", s)
	}
}
