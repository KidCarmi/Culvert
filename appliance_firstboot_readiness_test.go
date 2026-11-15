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
	"encoding/json"
	"fmt"
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

// readinessRecord is one line of the gate's per-attempt record.
type readinessRecord struct {
	Phase     string  `json:"phase"`
	Run       string  `json:"run"`
	Check     int     `json:"check"`
	Endpoint  string  `json:"endpoint"`
	StartedMS int64   `json:"started_ms"`
	EndedMS   int64   `json:"ended_ms"`
	TimeoutS  float64 `json:"timeout_s"`
	// Whether the request was launched after the start record, when, and
	// how long the start-record write took (R10-T1).
	Launched     *bool   `json:"launched"`
	LaunchMS     *int64  `json:"launch_ms"`
	LaunchWaitMS *int64  `json:"launch_wait_ms"`
	RC           int     `json:"rc"`
	HTTPCode     string  `json:"http_code"`
	Outcome      string  `json:"outcome"`
	Killed       bool    `json:"killed"`
	Body         *string `json:"body"`
	Stderr       *string `json:"stderr"`
	// The body check's own outcome (management only; null when not run).
	ParseRC        *int     `json:"parse_rc"`
	ParseKilled    bool     `json:"parse_killed"`
	ParseOutcome   string   `json:"parse_outcome"`
	ParseElapsedMS *int64   `json:"parse_elapsed_ms"`
	ParseTimeoutS  *float64 `json:"parse_timeout_s"`
}

// readinessRecords returns the phase=ended records (one per finished check).
func (h *fbHarness) readinessRecords() []readinessRecord {
	h.t.Helper()
	all := h.readinessAll()
	var ended []readinessRecord
	for i := range all {
		if all[i].Phase == "ended" {
			ended = append(ended, all[i])
		}
	}
	return ended
}

// reasonOnRecord reports whether the failure reason, or any finished check's
// "<endpoint label>: <outcome>", names want. The reason names each endpoint's
// LAST started check, which under load can be one cut short by the deadline
// (correctly refused); the records keep every check's own outcome.
func (h *fbHarness) reasonOnRecord(want string) bool {
	h.t.Helper()
	if strings.Contains(h.readinessFailed(), want) {
		return true
	}
	label := map[string]string{"application": "application /health: ", "management": "management /api/setup/status: "}
	ended := h.readinessRecords()
	for i := range ended {
		if strings.Contains(label[ended[i].Endpoint]+ended[i].Outcome, want) {
			return true
		}
	}
	return false
}

// readinessPhase counts records of one phase, optionally for one endpoint.
func (h *fbHarness) readinessPhase(phase, endpoint string) int {
	n := 0
	all := h.readinessAll()
	for i := range all {
		if all[i].Phase == phase && (endpoint == "" || all[i].Endpoint == endpoint) {
			n++
		}
	}
	return n
}

func (h *fbHarness) readinessAll() []readinessRecord {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, "readiness-attempts.jsonl"))
	if err != nil {
		return nil
	}
	var recs []readinessRecord
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var r readinessRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			h.t.Fatalf("unparseable readiness record %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	return recs
}

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
	// Every started attempt is recorded: 4 checks x 2 endpoints, one run,
	// monotonic timing, rc/code/outcome and the bounded stdout/stderr.
	recs := h.readinessRecords()
	if len(recs) != 8 || h.readinessPhase("started", "") != 8 {
		t.Fatalf("ended records = %d, started = %d, want 8 and 8 (every started attempt, recorded before and after)", len(recs), h.readinessPhase("started", ""))
	}
	var last int64
	for i, r := range recs {
		if r.Run == "" || r.Run != recs[0].Run || r.Check != i/2+1 || r.StartedMS < last || r.EndedMS < r.StartedMS || r.TimeoutS <= 0 || r.TimeoutS > 3 {
			t.Fatalf("record %d malformed: %+v", i, r)
		}
		last = r.StartedMS
		if r.Stderr == nil || !strings.Contains(*r.Stderr, "stub stderr") || r.Body == nil {
			t.Fatalf("record %d lacks stdout/stderr: %+v", i, r)
		}
	}
	if recs[0].Endpoint != "application" || recs[0].HTTPCode != "000" || recs[0].RC != 7 || recs[0].Outcome != "transport error rc=7 (http 000)" {
		t.Fatalf("first application record = %+v, want a recorded transport failure", recs[0])
	}
	if recs[3].Endpoint != "management" || recs[3].HTTPCode != "503" || *recs[3].Body != "{}" || recs[3].Outcome != "http 503" {
		t.Fatalf("second management record = %+v, want 503 with its body", recs[3])
	}
	if recs[7].Outcome != "ok" || *recs[7].Body != `{"needsSetup":true}` {
		t.Fatalf("last management record = %+v", recs[7])
	}
}

// Each signal late on its own: completion waits for the late one.
func TestFirstBoot_Readiness_EachSignalIndependentlyLate(t *testing.T) {
	for name, seqs := range map[string][2][]string{
		"application late": {{"000", "503", "200"}, nil},
		"management late":  {nil, {"000", "200 not-json", setupPending}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newFBHarness(t)
			h.setReadiness(seqs[0], seqs[1])
			out, code := h.run("READY_TIMEOUT_S=30; step_finish")
			if code != 0 || !h.exists("appliance/state/complete.done") {
				t.Fatalf("step_finish (%d):\n%s", code, out)
			}
			if hc, sc := h.readyCalls("health"), h.readyCalls("setup"); hc != 4 || sc != 4 {
				t.Fatalf("checks: health=%d setup=%d, want 4 and 4 (the late signal gated completion)\n%s", hc, sc, out)
			}
		})
	}
}

// A probe that never answers is killed within the bound; the wait still ends
// within the bound and the killed attempt is on record.
func TestFirstBoot_Readiness_HungProbeFailsWithinTheBound(t *testing.T) {
	h := newFBHarness(t)
	h.setReadiness([]string{"hang"}, nil)
	start := time.Now()
	out, code := h.run("READY_TIMEOUT_S=3; step_finish")
	elapsed := time.Since(start)
	if code == 0 || h.exists("appliance/state/complete.done") {
		t.Fatalf("a hung probe must not complete provisioning (%d):\n%s", code, out)
	}
	if elapsed > 8*time.Second {
		t.Fatalf("a hung probe stretched a 3 s bound to %v", elapsed)
	}
	recs := h.readinessRecords()
	if len(recs) == 0 || recs[0].Endpoint != "application" || !recs[0].Killed || recs[0].RC != 124 || !strings.Contains(recs[0].Outcome, "killed at") {
		t.Fatalf("the killed attempt is not on record: %+v", recs)
	}
	if rf := h.readinessFailed(); !strings.Contains(rf, "killed at") {
		t.Fatalf("readiness.failed = %q, want the killed probe named", rf)
	}
}

// A check whose record cannot be written does not count as ready.
func TestFirstBoot_Readiness_UnrecordedCheckDoesNotCount(t *testing.T) {
	h := newFBHarness(t)
	recs := filepath.Join(h.root, "records-are-a-directory")
	if err := os.MkdirAll(recs, 0o750); err != nil {
		t.Fatal(err)
	}
	out, code := h.run("READY_TIMEOUT_S=3; READY_RECORDS=" + recs + "; step_finish")
	if code == 0 || h.exists("appliance/state/complete.done") {
		t.Fatalf("completion recorded without attempt records (%d):\n%s", code, out)
	}
	if rf := h.readinessFailed(); !strings.Contains(rf, "attempt record not written") {
		t.Fatalf("readiness.failed = %q", rf)
	}
	// The started record lands, the ended one cannot: a passing check whose
	// result is not on record does not count. A python3 wrapper first on PATH
	// fails exactly the first phase=ended write of the application check, so
	// with every service up completion needs checks 2 and 3, not 1 and 2.
	mid := newFBHarness(t)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	wrap := filepath.Join(mid.root, "wrap")
	if err := os.MkdirAll(wrap, 0o750); err != nil {
		t.Fatal(err)
	}
	mid.writeExec(filepath.Join(wrap, "python3"), `#!/usr/bin/env bash
e=; ap=; for a in "$@"; do [[ "$a" == phase=ended ]] && e=1; [[ "$a" == endpoint=application ]] && ap=1; done
if [[ -n $e && -n $ap && ! -f "$FB_HARNESS/ended-broken-once" ]]; then touch "$FB_HARNESS/ended-broken-once"; exit 1; fi
exec `+py+` "$@"
`)
	out, code = mid.run("PATH=" + wrap + ":$PATH; READY_TIMEOUT_S=30; step_finish")
	if code != 0 || !mid.exists("appliance/state/complete.done") {
		t.Fatalf("step_finish (%d):\n%s", code, out)
	}
	if hc := mid.readyCalls("health"); hc != 3 {
		t.Fatalf("health checks = %d, want 3: the first check's result was not on record and must not count", hc)
	}
	if s, e := mid.readinessPhase("started", "application"), mid.readinessPhase("ended", "application"); s != 3 || e != 2 {
		t.Fatalf("application records: started %d, ended %d; want 3 and 2 (the unrecorded end is visible as a started-only check)", s, e)
	}
}

// After completion a later run of the step re-checks nothing (complete.done
// short-circuits it) — and an interrupted, never-completed run resumes the
// wait on the next start (covered by the recovery half of the permanent-
// failure test).
func TestFirstBoot_Readiness_CompletedStepIsNotRerun(t *testing.T) {
	h := newFBHarness(t)
	if out, code := h.run("READY_TIMEOUT_S=30; step_finish"); code != 0 {
		t.Fatalf("first run (%d):\n%s", code, out)
	}
	before := h.readyCalls("health")
	h.setReadiness([]string{"000"}, []string{"000"})
	if out, code := h.run("READY_TIMEOUT_S=3; step_finish"); code != 0 {
		t.Fatalf("a completed step must stay complete (%d):\n%s", code, out)
	}
	if h.readyCalls("health") != before {
		t.Fatal("a completed step re-ran the readiness gate")
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
	for _, want := range []string{"application /health: transport error rc=7 (http 000)", "management /api/setup/status: transport error rc=7 (http 000)", "checks"} {
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
		{"application only", []string{"200"}, []string{"000"}, "management /api/setup/status: transport error rc=7 (http 000)"},
		{"management only", []string{"503"}, []string{setupPending}, "application /health: http 503"},
		{"management 200 without needsSetup", []string{"200"}, []string{"200 {}"}, "http 200, body check invalid (no boolean needsSetup)"},
		{"management needsSetup not a boolean", []string{"200"}, []string{`200 {"needsSetup":"yes"}`}, "no boolean needsSetup"},
		{"management body not JSON", []string{"200"}, []string{"200 <html>starting</html>"}, "no boolean needsSetup"},
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
			if h.readinessFailed() == "" || !h.reasonOnRecord(tc.reason) {
				t.Fatalf("readiness.failed = %q and no check's outcome names %q", h.readinessFailed(), tc.reason)
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

// The check-count cap (timeout/interval + confirmations + 1) bounds the
// wait independently of the clock: with the pauses stubbed out, the cap ends
// a 60 s wait after exactly 60/10+2+1 = 9 checks.
func TestFirstBoot_Readiness_CheckCountBoundsTheWait(t *testing.T) {
	h := newFBHarness(t)
	h.stub("sleep", ":")
	h.setReadiness([]string{"000"}, nil)
	out, code := h.run("READY_TIMEOUT_S=60; READY_INTERVAL_S=10; READY_CONFIRM=2; step_finish")
	if code == 0 || h.exists("appliance/state/complete.done") {
		t.Fatalf("an unbounded or permissive wait (%d):\n%s", code, out)
	}
	if hc := h.readyCalls("health"); hc != 9 {
		t.Fatalf("health checks = %d, want the cap 9\n%s", hc, out)
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
	if _, gateSrc, ok := strings.Cut(src, "wait_for_readiness() {"); !ok || strings.Contains(strings.SplitN(gateSrc, "\n}\n", 2)[0], "SECONDS") {
		t.Fatal("the readiness wait must use the monotonic clock (mono_ms), not bash SECONDS")
	}
	gate, rec := strings.Index(fin, "wait_for_readiness || return 1"), strings.Index(fin, "done_step complete")
	if gate < 0 || rec < 0 || gate > rec {
		t.Fatal("step_finish must run the readiness gate before recording completion")
	}
}

// R10-R1: an HTTP 200 (with a valid body) whose transport failed is not an
// answer: curl timeout (28), partial transfer (18) and size cap (63) each
// keep completion unrecorded, and the record keeps the transport status.
func TestFirstBoot_Readiness_TransportErrorWith200NeverCounts(t *testing.T) {
	cases := []struct {
		name          string
		health, setup []string
		endpoint      string
		rc            int
	}{
		{"application 200 after a curl timeout", []string{"rc28:200 {}"}, nil, "application", 28},
		{"management 200 with a partial transfer", nil, []string{`rc18:200 {"needsSetup":true}`}, "management", 18},
		{"management 200 over the size cap", nil, []string{`rc63:200 {"needsSetup":true}`}, "management", 63},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFBHarness(t)
			h.setReadiness(tc.health, tc.setup)
			out, code := h.run("READY_TIMEOUT_S=2; step_finish")
			if code == 0 || h.exists("appliance/state/complete.done") {
				t.Fatalf("completion recorded on a failed transport (%d):\n%s", code, out)
			}
			want := fmt.Sprintf("transport error rc=%d (http 200)", tc.rc)
			if h.readinessFailed() == "" || !h.reasonOnRecord(want) {
				t.Fatalf("readiness.failed = %q and no check's outcome names %q", h.readinessFailed(), want)
			}
			// Every finished check of that endpoint is this transport error, or
			// one cut short by the deadline; none is ok.
			ended, seen := h.readinessRecords(), false
			for i := range ended {
				r := &ended[i]
				if r.Endpoint != tc.endpoint {
					continue
				}
				switch {
				case r.Outcome == want && r.RC == tc.rc && r.HTTPCode == "200":
					seen = true
				case strings.HasPrefix(r.Outcome, "transport killed at"):
				default:
					t.Fatalf("record %+v, want rc %d http 200 outcome %q", *r, tc.rc, want)
				}
			}
			if !seen {
				t.Fatalf("no %s record shows %q", tc.endpoint, want)
			}
		})
	}
}

// R10-T1 on a deterministic monotonic clock (mono_ms reads $FB_HARNESS/clock;
// start 100000, deadline 110000): work that FINISHES after the deadline is
// never accepted, and no work starts once the budget is spent.
func TestFirstBoot_Readiness_DeadlineIsTerminal(t *testing.T) {
	clock := `mono_ms() { cat "$FB_HARNESS/clock"; }; echo 100000 > "$FB_HARNESS/clock"; READY_TIMEOUT_S=10; `
	t.Run("management answers after the deadline", func(t *testing.T) {
		h := newFBHarness(t)
		h.writeExec(filepath.Join(h.root, "advance.setup"), "110001\n")
		out, code := h.run(clock + "step_finish")
		if code == 0 || h.exists("appliance/state/complete.done") {
			t.Fatalf("an answer after the deadline was accepted (%d):\n%s", code, out)
		}
		if rf := h.readinessFailed(); !strings.Contains(rf, "answered after the deadline (http 200)") {
			t.Fatalf("readiness.failed = %q", rf)
		}
	})
	t.Run("body check finishes after the deadline", func(t *testing.T) {
		h := newFBHarness(t)
		parse := filepath.Join(h.root, "late-parse")
		h.writeExec(parse, "#!/usr/bin/env bash\necho 110001 > \"$FB_HARNESS/clock\"\nexec python3 \"$@\"\n")
		out, code := h.run(clock + "READY_PARSE=" + parse + "; step_finish")
		if code == 0 || h.exists("appliance/state/complete.done") {
			t.Fatalf("a body check finished after the deadline was accepted (%d):\n%s", code, out)
		}
		if rf := h.readinessFailed(); !strings.Contains(rf, "body check finished after the deadline") {
			t.Fatalf("readiness.failed = %q", rf)
		}
	})
	t.Run("confirmation after the deadline is not accepted", func(t *testing.T) {
		// Checks 1 and 2 pass in time; the clock passes the deadline while
		// check 2's management result is being recorded, before acceptance.
		h := newFBHarness(t)
		py, err := exec.LookPath("python3")
		if err != nil {
			t.Fatal(err)
		}
		wrap := filepath.Join(h.root, "wrap")
		if err := os.MkdirAll(wrap, 0o750); err != nil {
			t.Fatal(err)
		}
		h.writeExec(filepath.Join(wrap, "python3"), `#!/usr/bin/env bash
e=; m=; c=; for a in "$@"; do [[ "$a" == phase=ended ]] && e=1; [[ "$a" == endpoint=management ]] && m=1; [[ "$a" == check=2 ]] && c=1; done
`+py+` "$@"; rc=$?
[[ -n $e && -n $m && -n $c ]] && echo 110001 > "$FB_HARNESS/clock"
exit $rc
`)
		out, code := h.run(clock + "PATH=" + wrap + ":$PATH; step_finish")
		if code == 0 || h.exists("appliance/state/complete.done") {
			t.Fatalf("a confirmation reached after the deadline was accepted (%d):\n%s", code, out)
		}
		if rf := h.readinessFailed(); !strings.Contains(rf, "confirmed after the deadline") {
			t.Fatalf("readiness.failed = %q", rf)
		}
	})
	t.Run("no check starts with no budget left", func(t *testing.T) {
		h := newFBHarness(t)
		h.writeExec(filepath.Join(h.root, "advance.health"), "110000\n")
		out, code := h.run(clock + "step_finish")
		if code == 0 || h.exists("appliance/state/complete.done") {
			t.Fatalf("completion recorded with the budget spent (%d):\n%s", code, out)
		}
		if n := h.readinessPhase("started", "management"); n != 0 {
			t.Fatalf("%d management checks started with no time left; a spent budget must not become a fresh 1 ms", n)
		}
		if rf := h.readinessFailed(); !strings.Contains(rf, "management /api/setup/status: not checked") {
			t.Fatalf("readiness.failed = %q", rf)
		}
	})
}

// slowStartRecord makes ONE start-record write slow on the fake monotonic
// clock: after the record for <endpoint> check <check> is written, the clock
// reads <to>, as if the write had blocked until then. It returns the PATH
// prefix that puts the wrapping python3 (record_json's interpreter) first.
func (h *fbHarness) slowStartRecord(endpoint string, check int, to int64) string {
	h.t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		h.t.Fatal(err)
	}
	wrap := filepath.Join(h.root, "slow-record")
	if err := os.MkdirAll(wrap, 0o750); err != nil {
		h.t.Fatal(err)
	}
	h.writeExec(filepath.Join(wrap, "python3"), fmt.Sprintf(`#!/usr/bin/env bash
s=; e=; c=; for a in "$@"; do [[ "$a" == phase=started ]] && s=1; [[ "$a" == endpoint=%s ]] && e=1; [[ "$a" == check=%d ]] && c=1; done
`+py+` "$@"; rc=$?
[[ -n $s && -n $e && -n $c ]] && echo %d > "$FB_HARNESS/clock"
exit $rc
`, endpoint, check, to))
	return "PATH=" + wrap + ":$PATH; "
}

func (h *fbHarness) maxTimes(endpoint string) []string {
	h.t.Helper()
	b, _ := os.ReadFile(filepath.Join(h.root, "maxtime.log"))
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ep, mt, ok := strings.Cut(l, " "); ok && ep == endpoint {
			out = append(out, mt)
		}
	}
	return out
}

func (h *fbHarness) endedRecord(endpoint string, check int) *readinessRecord {
	h.t.Helper()
	recs := h.readinessRecords()
	for i := range recs {
		if recs[i].Endpoint == endpoint && recs[i].Check == check {
			return &recs[i]
		}
	}
	return nil
}

// R10-T1 (ASTRA, 961e89ab): the start-record write blocks, so the request's
// budget must be computed AFTER it. Fake monotonic clock: start 100000,
// deadline 110000; the write for one check moves the clock as a slow write
// would.
const fakeClock10s = `mono_ms() { cat "$FB_HARNESS/clock"; }; echo 100000 > "$FB_HARNESS/clock"; READY_TIMEOUT_S=10; `

// A start-record write that exhausts the budget: no request starts.
func TestFirstBoot_Readiness_StartRecordWrite_ExhaustedBudgetLaunchesNothing(t *testing.T) {
	clock := fakeClock10s
	{
		h := newFBHarness(t)
		out, code := h.run(clock + h.slowStartRecord("application", 1, 110001) + "step_finish")
		if code == 0 || h.exists("appliance/state/complete.done") {
			t.Fatalf("completion recorded with the budget spent by the start record (%d):\n%s", code, out)
		}
		if n := h.readyCalls("health"); n != 0 {
			t.Fatalf("%d health requests launched after the start record spent the budget", n)
		}
		r := h.endedRecord("application", 1)
		if r == nil || r.Launched == nil || *r.Launched || r.LaunchMS != nil || r.EndedMS != 110001 ||
			r.Outcome != "not executed: deadline reached after the start record" {
			t.Fatalf("application check 1 record = %+v, want a terminal not-executed record", r)
		}
		if h.readinessPhase("started", "application") != 1 || h.readinessPhase("started", "management") != 0 {
			t.Fatalf("started records: application %d, management %d; want 1 and 0",
				h.readinessPhase("started", "application"), h.readinessPhase("started", "management"))
		}
		if rf := h.readinessFailed(); !strings.Contains(rf, "application /health: not executed: deadline reached after the start record") {
			t.Fatalf("readiness.failed = %q", rf)
		}
	}
}

// A start-record write that spends part of the budget: the request gets only
// the rest. 200 ms remain after the write. The request answers 200 only after
// 2 s: cut by the timeout wrapper at the refreshed 0.200 s it is a transport
// kill; with the 3 s it would have had before the write it would complete and
// count. No wall-clock bound: the outcome itself shows the budget used.
func TestFirstBoot_Readiness_StartRecordWrite_ShortensTheRequest(t *testing.T) {
	clock := fakeClock10s
	{
		h := newFBHarness(t)
		h.setReadiness([]string{`sleep2:200 {"status":"ok"}`, "000"}, nil)
		out, code := h.run(clock + h.slowStartRecord("application", 1, 109800) + "step_finish")
		if code == 0 || h.exists("appliance/state/complete.done") {
			t.Fatalf("completion recorded without two good checks (%d):\n%s", code, out)
		}
		if mt := h.maxTimes("health"); len(mt) == 0 || mt[0] != "0.200" {
			t.Fatalf("health --max-time values = %v, want the first to be 0.200 (the budget left after the write)", mt)
		}
		r := h.endedRecord("application", 1)
		if r == nil || r.Launched == nil || !*r.Launched || r.LaunchMS == nil || *r.LaunchMS != 109800 ||
			r.LaunchWaitMS == nil || *r.LaunchWaitMS != 9800 || r.TimeoutS != 0.2 || !r.Killed ||
			r.Outcome != "transport killed at 0.200s (http 000)" {
			t.Fatalf("application check 1 record = %+v, want launched at 109800 with 0.2 s and killed", r)
		}
	}
}

// Late health never records complete after a slow start record.
func TestFirstBoot_Readiness_StartRecordWrite_LateHealthNeverCompletes(t *testing.T) {
	clock := fakeClock10s
	{
		// (a) The write leaves 200 ms; the answer arrives after the deadline.
		h := newFBHarness(t)
		h.writeExec(filepath.Join(h.root, "advance.health"), "110001\n")
		out, code := h.run(clock + h.slowStartRecord("application", 1, 109800) + "step_finish")
		if code == 0 || h.exists("appliance/state/complete.done") {
			t.Fatalf("a late answer after a slow start record was accepted (%d):\n%s", code, out)
		}
		if rf := h.readinessFailed(); !strings.Contains(rf, "answered after the deadline (http 200)") {
			t.Fatalf("readiness.failed = %q", rf)
		}
		// (b) Check 1 passes in time; the confirming check's start record
		// spends the budget, so the confirmation is never made.
		h2 := newFBHarness(t)
		out, code = h2.run(clock + h2.slowStartRecord("application", 2, 110001) + "step_finish")
		if code == 0 || h2.exists("appliance/state/complete.done") {
			t.Fatalf("completion recorded although the confirming check never ran (%d):\n%s", code, out)
		}
		if n := h2.readyCalls("health"); n != 1 {
			t.Fatalf("health requests = %d, want 1 (the confirming request must not launch)", n)
		}
		if r := h2.endedRecord("application", 2); r == nil || r.Launched == nil || *r.Launched {
			t.Fatalf("application check 2 record = %+v, want not launched", r)
		}
	}
}

// R10-E1: a body check that hangs is killed and recorded as a timeout with its
// own status and duration; invalid JSON is recorded as invalid, not killed.
func TestFirstBoot_Readiness_BodyCheckOutcomeIsRecorded(t *testing.T) {
	h := newFBHarness(t)
	parse := filepath.Join(h.root, "hung-parse")
	h.writeExec(parse, "#!/usr/bin/env bash\nexec sleep 30\n")
	out, code := h.run("READY_TIMEOUT_S=3; READY_PARSE=" + parse + "; step_finish")
	if code == 0 || h.exists("appliance/state/complete.done") {
		t.Fatalf("a hung body check completed provisioning (%d):\n%s", code, out)
	}
	var mg *readinessRecord
	for _, r := range h.readinessRecords() {
		if r.Endpoint == "management" {
			r := r
			mg = &r
			break
		}
	}
	if mg == nil || mg.RC != 0 || mg.ParseRC == nil || *mg.ParseRC != 124 || !mg.ParseKilled ||
		mg.ParseElapsedMS == nil || *mg.ParseElapsedMS < 500 || mg.ParseTimeoutS == nil ||
		!strings.Contains(mg.ParseOutcome, "killed at") || !strings.Contains(mg.Outcome, "http 200, body check killed at") {
		t.Fatalf("hung body check record = %+v", mg)
	}

	inv := newFBHarness(t)
	inv.setReadiness(nil, []string{"200 <html>starting</html>"})
	if _, code := inv.run("READY_TIMEOUT_S=2; step_finish"); code == 0 {
		t.Fatal("invalid JSON completed provisioning")
	}
	for _, r := range inv.readinessRecords() {
		if r.Endpoint == "management" && (r.ParseRC == nil || *r.ParseRC != 3 || r.ParseKilled || r.ParseOutcome != "invalid (no boolean needsSetup)") {
			t.Fatalf("invalid-JSON record = %+v", r)
		}
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
