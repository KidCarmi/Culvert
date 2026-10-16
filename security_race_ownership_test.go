package main

import (
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// ─────────────────────────────────────────────────────────────────────────────
// Race-suite ownership wall (CI-REDESIGN stage 2B).
//
// On a main push the full `-race` + coverage suite used to run TWICE in two
// workflows: qa-gate.yml's `qa-logic` (which since stage 2A also produces the
// authoritative coverage profile) and security-release-gate.yml's `tests-race`,
// with the same seed and the same package scope, for one verdict.
//
// Stage 2B gives it ONE owner per event rather than deleting a job, because the
// two workflows do not run on the same events. qa-gate.yml has no tag trigger,
// so deleting `tests-race` outright would leave version tags, Security's weekly
// cron and Security-only dispatches with NO race evidence at all. (Stage 6B
// gave QA a weekly schedule of its own — the equivalence audit, on another day
// and not Security's evidence — which changes none of this.)
//
// Two properties have to hold together, and this file pins both:
//
//  1. the ownership condition tests the EVENT and the REF. Keying on the branch
//     alone ("not main") would suppress the scheduled and manual runs too,
//     whose ref is also main — the events where nothing else runs the suite;
//
//  2. on every event where Security still OWNS the suite, a skip must REFUSE.
//     needs-verdict reads a skipped need as a pass, so without an explicit
//     `require-success` a `tests-race` that silently failed to start would
//     sail through the same door that makes the intentional main-push skip
//     acceptable. One skip is by design; every other one is a hole.
//
// The release verdict is deliberately NOT changed by this stage: both
// workflows stay `mandatory` in .github/release-evidence.txt and publication
// still requires a successful main-push run of each for the exact release SHA.
// The behavioural half of that — Security green with QA absent, failed,
// cancelled, skipped, pending, or green for the wrong SHA/event/ref — is
// exercised against the REAL predicate in
// .github/scripts/test/release-gating-cases.sh (§ STAGE 2B), driven from
// TestReleasePublicationGating_Behaviour.
// ─────────────────────────────────────────────────────────────────────────────

const (
	securityWorkflowPath = ".github/workflows/security-release-gate.yml"
	securityRaceJob      = "tests-race"
	securityAggregateJob = "release-approved"
	securityAggregateNm  = "✅ Security Gate — APPROVED"
	qaRaceOwnerJob       = "qa-race"
	securityCovArtifact  = "coverage-report"
)

// raceOwnedHerePredicate is the ONE condition deciding whether Security owns
// the race suite for an event. It is written in the workflow twice — the job's
// `if:` and the aggregate's `require-success` — because a job-level `if:`
// cannot read `env`, so it cannot be factored out in YAML. Both copies are
// pinned equal to this string.
const raceOwnedHerePredicate = "github.event_name == 'schedule' || " +
	"github.event_name == 'workflow_dispatch' || " +
	"(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v'))"

// normaliseExpr collapses the whitespace and line folding a YAML block scalar
// introduces, so the same expression written across three lines and on one line
// compare equal.
func normaliseExpr(s string) string { return strings.Join(strings.Fields(s), " ") }

func securityDoc(t *testing.T) wfDoc {
	t.Helper()
	return loadWorkflow(t, securityWorkflowPath)
}

// ─── 1. The ownership condition itself ───────────────────────────────────────

// TestSecurityRace_OwnershipMatrix pins the event/ref matrix the stage is
// defined by. Rather than restating the boolean, it EVALUATES the workflow's
// own condition for each event and asserts the resulting decision, so a
// rewritten-but-equivalent expression still passes and a rewritten-and-wrong
// one fails.
func TestSecurityRace_OwnershipMatrix(t *testing.T) {
	job := securityDoc(t).Jobs[securityRaceJob]
	got := normaliseExpr(job.If)
	if got == "" {
		t.Fatalf("job %q has no `if:` — it would run on every event, restoring the duplicate main-push execution", securityRaceJob)
	}

	for _, tc := range []struct {
		name  string
		event string
		ref   string
		want  bool
		why   string
	}{
		{"pull request", "pull_request", "refs/heads/main", false,
			"PR pass-through is unchanged: scanning lives in the Fast/Deep PR Gates"},
		{"push to main", "push", "refs/heads/main", false,
			"THE stage-2B change: the main-push suite is owned by qa-gate.yml's " + qaRaceOwnerJob},
		{"version tag push", "push", "refs/tags/v1.2.3", true,
			"qa-gate.yml has NO tag trigger, so nothing else runs the suite for a tag"},
		{"schedule", "schedule", "refs/heads/main", true,
			"the weekly cron's ref is main, and Security's scan must carry its own race evidence — keying on the branch would silently suppress it"},
		{"manual dispatch on main", "workflow_dispatch", "refs/heads/main", true,
			"a Security-only dispatch must still be able to run the suite on main"},
		{"manual dispatch on a branch", "workflow_dispatch", "refs/heads/some-branch", true,
			"dispatch runs the suite wherever it is aimed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if evaluated := evalRaceOwnership(t, got, tc.event, tc.ref); evaluated != tc.want {
				t.Errorf("event=%s ref=%s: the workflow's condition yields %v, want %v.\n%s\ncondition: %s",
					tc.event, tc.ref, evaluated, tc.want, tc.why, got)
			}
		})
	}
}

// evalRaceOwnership evaluates the subset of GitHub expression syntax this
// condition uses against a given (event, ref). It is deliberately a tiny
// evaluator over the REAL string from the workflow rather than a re-declaration
// of the matrix: a test that only compared the expression to a constant would
// pass for a condition that is equivalent-looking and wrong.
func evalRaceOwnership(t *testing.T, expr, event, ref string) bool {
	t.Helper()
	work := expr
	// The stage-5B unsharded audit's opt-in dispatch input is a boolean that
	// defaults to false and does not exist at all on push/pull_request/tag
	// events, so it evaluates to false for every event this matrix models.
	// Only this ONE input is understood; any other `inputs.*` still fails
	// loudly below.
	work = strings.ReplaceAll(work, "inputs.unsharded_audit", "false")
	// always() only widens WHEN a job runs relative to its needs' results; for
	// "does this event reach the job at all" it is true.
	work = strings.ReplaceAll(work, "always()", "true")
	work = strings.ReplaceAll(work, "github.event_name", "\x00EVENT\x00")
	work = strings.ReplaceAll(work, "github.ref", "\x00REF\x00")

	// startsWith(<ref>, '<prefix>') → true/false
	sw := regexp.MustCompile(`startsWith\(\s*\x00REF\x00\s*,\s*'([^']*)'\s*\)`)
	work = sw.ReplaceAllStringFunc(work, func(m string) string {
		prefix := sw.FindStringSubmatch(m)[1]
		return boolLit(strings.HasPrefix(ref, prefix))
	})

	// <event|ref> ==|!= '<literal>' → true/false.
	//
	// `!=` is handled as well as `==` on purpose. The tempting wrong condition
	// for this stage is a branch test — `github.ref != 'refs/heads/main'` — and
	// if the evaluator could not read it, this test would reject it for being
	// unparsable rather than for being WRONG. Supporting the form is what lets
	// the matrix below prove that it silently suppresses the scheduled and
	// manual runs, which is the actual defect.
	cmp := regexp.MustCompile(`\x00(EVENT|REF)\x00\s*(==|!=)\s*'([^']*)'`)
	work = cmp.ReplaceAllStringFunc(work, func(m string) string {
		g := cmp.FindStringSubmatch(m)
		actual := event
		if g[1] == "REF" {
			actual = ref
		}
		equal := actual == g[3]
		if g[2] == "!=" {
			equal = !equal
		}
		return boolLit(equal)
	})

	if strings.Contains(work, "\x00") {
		t.Fatalf("the ownership condition uses a context this test cannot evaluate; extend evalRaceOwnership rather than deleting the matrix.\ngot: %s", expr)
	}
	v, err := evalBool(work)
	if err != nil {
		t.Fatalf("cannot evaluate the ownership condition %q (reduced to %q): %v", expr, work, err)
	}
	return v
}

func boolLit(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// evalBool evaluates a reduced boolean expression of `true`/`false`, `&&`,
// `||` and parentheses, by collapsing innermost parenthesised groups until
// none are left and then evaluating one flat disjunction-of-conjunctions.
//
// Written by hand because pulling in an expression library to read six tokens
// would be a larger dependency than the thing it checks — but kept to a
// reduction loop rather than a parser, because a recursive-descent parser here
// is more machinery than the grammar warrants.
func evalBool(s string) (bool, error) {
	group := regexp.MustCompile(`\(([^()]*)\)`)
	for strings.Contains(s, "(") {
		reduced := group.ReplaceAllStringFunc(s, func(m string) string {
			v, err := evalFlatBool(group.FindStringSubmatch(m)[1])
			if err != nil {
				return "?"
			}
			return boolLit(v)
		})
		if reduced == s {
			return false, errBoolSyntax // unbalanced parentheses
		}
		s = reduced
	}
	return evalFlatBool(s)
}

// evalFlatBool evaluates a parenthesis-free expression: `||` over `&&` over
// the literals `true` and `false`.
func evalFlatBool(s string) (bool, error) {
	for _, clause := range strings.Split(s, "||") {
		all, seen := true, false
		for _, lit := range strings.Split(clause, "&&") {
			switch strings.TrimSpace(lit) {
			case "true":
				seen = true
			case "false":
				seen, all = true, false
			default:
				return false, errBoolSyntax
			}
		}
		if !seen {
			return false, errBoolSyntax
		}
		if all {
			return true, nil
		}
	}
	return false, nil
}

var errBoolSyntax = errBool("unparsable boolean expression")

type errBool string

func (e errBool) Error() string { return string(e) }

// ─── 2. The two copies of the predicate cannot drift ─────────────────────────

// TestSecurityRace_OwnershipPredicateIsSingleSourced pins the job's `if:` and
// the aggregate's `require-success` to the SAME condition.
//
// They are two copies of one decision because a job-level `if:` cannot read
// `env`. If they drift the failure is silent in one direction and wedging in
// the other: a suite that runs unrequired (so an unexpected skip passes), or a
// gate that demands a job which never starts.
func TestSecurityRace_OwnershipPredicateIsSingleSourced(t *testing.T) {
	doc := securityDoc(t)

	jobIf := normaliseExpr(doc.Jobs[securityRaceJob].If)
	if jobIf != raceOwnedHerePredicate {
		t.Errorf("job %q `if:` is not the canonical ownership predicate.\n got: %s\nwant: %s",
			securityRaceJob, jobIf, raceOwnedHerePredicate)
	}

	req := securityRequireSuccessInput(t)
	if req == "" {
		t.Fatalf("the aggregate passes no `require-success` — an unexpected `tests-race` skip on a tag, schedule or dispatch would then be read as a pass")
	}
	if !strings.Contains(req, securityRaceJob) {
		t.Errorf("the aggregate's `require-success` never names %q: %s", securityRaceJob, req)
	}
	inner := normaliseExpr(extractGuard(req))
	if inner != raceOwnedHerePredicate {
		t.Errorf("the aggregate's `require-success` guard has drifted from the job's `if:`.\n got: %s\nwant: %s\n"+
			"Both are copies of one decision; update them together.", inner, raceOwnedHerePredicate)
	}

	// Two arms, in evaluation order. The owned-suite arm judges the suite AND
	// the scans; the main-push arm judges the scans only, because QA owns the
	// suite there and `tests-race` legitimately skips (the matrix above).
	arms := securityRequireArms(t, req)
	if want := append([]string{securityRaceJob}, securityScanJobs...); !slices.Equal(arms[0], want) {
		t.Errorf("the owned-suite arm must require %v; got %v", want, arms[0])
	}
	if !slices.Equal(arms[1], securityScanJobs) {
		t.Errorf("the main-push arm must require every scan (%v); got %v", securityScanJobs, arms[1])
	}
	if slices.Contains(arms[1], securityRaceJob) {
		t.Errorf("the main-push arm must NOT require %q — QA owns the suite on a push and this job skips there; requiring it would refuse every healthy main push", securityRaceJob)
	}
	if !strings.HasSuffix(normaliseExpr(req), "|| '' }}") {
		t.Errorf("a pull request must require nothing (the pass-through shape depends on it); require-success = %s", req)
	}
}

// securityScanJobs are the BLOCKING scans: they run on every
// non-pull-request event AND are members of the aggregate's `needs:`, so they
// must all be `success` for a main push to be release evidence.
//
// Two jobs are deliberately absent, for different reasons, and both absences
// are load-bearing. `tests-race` runs on tags, the schedule and dispatches but
// NOT on a main push (QA owns the suite there), so it belongs to the
// owned-suite arm only. `sbom` is informational and is not in `needs:` at all
// — require-success names jobs that needs-verdict reads out of the needs
// context, so requiring a non-member would refuse EVERY run and wedge main.
var securityScanJobs = []string{
	"sast-gosec",
	"vuln-govulncheck",
	"vuln-trivy-fs",
	"vuln-trivy-image",
	"secrets-gitleaks",
	"license-check",
	"sast-staticcheck",
	"lint-dockerfile",
}

// securityRequireArms returns each `&& '<list>'` arm of the aggregate's
// require-success, in evaluation order.
func securityRequireArms(t *testing.T, req string) [][]string {
	t.Helper()
	ms := regexp.MustCompile(`&& '([^']*)'`).FindAllStringSubmatch(req, -1)
	if len(ms) != 2 {
		t.Fatalf("require-success must carry exactly two required-job arms (owned-suite, main-push); got %d in %q", len(ms), req)
	}
	out := make([][]string, 0, 2)
	for _, m := range ms {
		if m[1] == "" {
			t.Fatalf("an arm of require-success is empty — that arm requires nothing: %q", req)
		}
		out = append(out, strings.Split(m[1], ","))
	}
	return out
}

// TestSecurityRace_RequiredJobsAreAllNeeded pins the invariant that makes a
// require-success list safe: needs-verdict reads its verdicts out of the
// `needs` context, so a job named in require-success but absent from the
// aggregate's `needs:` is not "missing evidence" — it is evidence that can
// never arrive, and the gate refuses EVERY run.
//
// This is not hypothetical. `sbom` runs on every non-PR event and looks like
// the other scans, but it is deliberately informational and NOT in `needs:`;
// including it would have wedged main on the next push while every synthetic
// test payload that listed it still passed. The subset check is the only thing
// that catches it, because a test fixture built from the same wrong list
// cannot.
func TestSecurityRace_RequiredJobsAreAllNeeded(t *testing.T) {
	needed := jobNeeds(securityDoc(t).Jobs[securityAggregateJob])
	if len(needed) == 0 {
		t.Fatalf("aggregate %q lists no needs — the selector is stale", securityAggregateJob)
	}
	for i, arm := range securityRequireArms(t, securityRequireSuccessInput(t)) {
		for _, job := range arm {
			if !needed[job] {
				t.Errorf("require-success arm %d names %q, which is NOT in the aggregate's `needs:` — needs-verdict would never see a verdict for it and the gate would refuse every run", i, job)
			}
		}
	}
}

// TestSecurityRace_MainPushRefusesScansThatNeverRan drives the REAL
// needs-verdict shell with the value the Security aggregate passes on a main
// push — the run .github/release-evidence.txt names `mandatory` and
// require-gate.sh reads.
//
// Without the push arm, needs-verdict's skipped-as-pass rule meant a main push
// in which every scan skipped still reported APPROVED; the workflow then
// concluded `success` rather than `skipped`, so require-gate.sh (which refuses
// a workflow-level `skipped`) had nothing to refuse, and a commit no scan had
// run against satisfied a mandatory release-evidence row. Every sub-case below
// fails against the pre-fix single-arm expression.
func TestSecurityRace_MainPushRefusesScansThatNeverRan(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq unavailable — the shared action's verdict is jq-based")
	}
	script := needsVerdictScript(t)
	// Read from the workflow, not restated: emptying the push arm there must
	// fail this gate.
	require := strings.Join(securityRequireArms(t, securityRequireSuccessInput(t))[1], ",")

	// The healthy main-push shape: every scan green, tests-race skipped
	// because QA owns the suite on a push.
	green := func() map[string]string {
		m := map[string]string{securityRaceJob: "skipped"}
		for _, n := range securityScanJobs {
			m[n] = "success"
		}
		return m
	}
	if out, ok := runNeedsVerdictRequiring(t, script, needsJSON(green()), require); !ok {
		t.Fatalf("a green main push must approve (tests-race skips there by design); output:\n%s", out)
	}

	// The defect itself: nothing ran.
	allSkipped := map[string]string{securityRaceJob: "skipped"}
	for _, n := range securityScanJobs {
		allSkipped[n] = "skipped"
	}
	if out, ok := runNeedsVerdictRequiring(t, script, needsJSON(allSkipped), require); ok {
		t.Fatalf("a main push in which EVERY scan skipped approved — nothing ran is not approval; output:\n%s", out)
	}

	for _, name := range securityScanJobs {
		t.Run("skipped/"+name, func(t *testing.T) {
			r := green()
			r[name] = "skipped"
			out, ok := runNeedsVerdictRequiring(t, script, needsJSON(r), require)
			if ok {
				t.Fatalf("a main push approved with %q skipped; output:\n%s", name, out)
			}
			if !strings.Contains(out, name) {
				t.Errorf("the refusal does not name %q; output:\n%s", name, out)
			}
		})
		t.Run("absent/"+name, func(t *testing.T) {
			r := green()
			delete(r, name)
			if out, ok := runNeedsVerdictRequiring(t, script, needsJSON(r), require); ok {
				t.Fatalf("a main push approved with %q absent from needs; output:\n%s", name, out)
			}
		})
	}

	// CONTROL: the requirement is scoped. A pull request passes
	// require-success='' and every job skips on its own `if:`, so the required
	// check must still report success or branch protection wedges every PR.
	if out, ok := runNeedsVerdict(t, script, needsJSON(allSkipped)); !ok {
		t.Fatalf("the PR pass-through shape must still approve; output:\n%s", out)
	}
}

// securityRequireSuccessInput returns the aggregate step's raw require-success
// input. Read from the aggregate's own step, not by scanning the file, so the
// string appearing in a comment cannot satisfy it.
func securityRequireSuccessInput(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(securityWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", securityWorkflowPath, err)
	}
	var generic struct {
		Jobs map[string]struct {
			Steps []map[string]interface{} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("parse %s: %v", securityWorkflowPath, err)
	}
	steps := generic.Jobs[securityAggregateJob].Steps
	if len(steps) == 0 {
		t.Fatalf("aggregate job %q has no steps — the selector is stale", securityAggregateJob)
	}
	for _, st := range steps {
		if !strings.Contains(toStr(st["uses"]), needsVerdictActionRef) {
			continue
		}
		with, _ := st["with"].(map[string]interface{})
		return toStr(with["require-success"])
	}
	t.Fatalf("aggregate job %q does not use %s", securityAggregateJob, needsVerdictActionRef)
	return ""
}

// extractGuard pulls the condition out of `${{ (<cond>) && 'x' || ” }}`.
func extractGuard(s string) string {
	i := strings.Index(s, "(")
	if i < 0 {
		return s
	}
	// Match the FIRST parenthesis group by depth. `strings.LastIndex(s, "&&")`
	// read the boundary correctly only while the expression had ONE arm: a
	// guard may contain its own `&&` (this file's does), and a SECOND arm
	// appended after it moved the last `&&` past the guard entirely. Depth
	// matching is stable under both.
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return strings.TrimSpace(s[i+1 : j])
			}
		}
	}
	return s
}

// ─── 3. Everything the stage must NOT change ─────────────────────────────────

// TestSecurityRace_MandatoryScansAndIdentitiesPreserved pins that stage 2B
// removed an execution, not a control.
func TestSecurityRace_MandatoryScansAndIdentitiesPreserved(t *testing.T) {
	doc := securityDoc(t)

	agg, ok := doc.Jobs[securityAggregateJob]
	if !ok {
		t.Fatalf("%s must keep the %q job", securityWorkflowPath, securityAggregateJob)
	}
	if agg.Name != securityAggregateNm {
		t.Errorf("the aggregate's display name is %q, want %q — it is a required status check", agg.Name, securityAggregateNm)
	}
	if strings.TrimSpace(agg.If) != "always()" {
		t.Errorf("the aggregate's `if:` must stay `always()` so the required check keeps reporting on PRs; got %q", agg.If)
	}

	// Every mandatory scan, plus tests-race, stays in the aggregate's needs.
	needs := jobNeeds(agg)
	for _, want := range []string{
		"sast-gosec", "vuln-govulncheck", "vuln-trivy-fs", "vuln-trivy-image",
		"secrets-gitleaks", "license-check", "sast-staticcheck", "lint-dockerfile",
		securityRaceJob,
	} {
		if !needs[want] {
			t.Errorf("the aggregate no longer needs %q — its failure would stop blocking the gate", want)
		}
	}

	// Every OTHER scan must still run on every non-PR event. Only tests-race
	// has an event-scoped owner; narrowing a scan the same way would silently
	// drop security coverage from main pushes.
	for name := range doc.Jobs {
		if name == securityAggregateJob || name == securityRaceJob {
			continue
		}
		j := doc.Jobs[name]
		if got := strings.TrimSpace(j.If); got != "" && got != "github.event_name != 'pull_request'" {
			t.Errorf("scan job %q has a narrowed condition %q. Stage 2B scopes ONLY %q by event; "+
				"every other scan must keep running on every non-PR event.", name, got, securityRaceJob)
		}
	}
}

// TestSecurityRace_ReleaseEvidenceConjunctionUnchanged pins the contract stage
// 2B leans on: publication needs BOTH workflows, so delegating the main-push
// race run to QA moves it within the release verdict rather than out of it.
func TestSecurityRace_ReleaseEvidenceConjunctionUnchanged(t *testing.T) {
	rows := readEvidenceManifest(t)
	want := map[string]bool{"security-release-gate.yml": false, "qa-gate.yml": false}
	for _, r := range rows {
		if _, tracked := want[r.workflow]; tracked && r.class == "mandatory" {
			want[r.workflow] = true
		}
	}
	for wf, found := range want {
		if !found {
			t.Errorf("%s must keep %q as a `mandatory` row: stage 2B makes the release verdict the CONJUNCTION of both "+
				"workflows' main-push runs, so demoting either would remove race coverage from release qualification",
				releaseEvidenceManifest, wf)
		}
	}
}

// TestSecurityRace_CoverageArtifactOwnership pins the artifact mapping. The
// `coverage-report` upload stays — it is this workflow's own output for the
// events it still owns — but it is no longer produced on a main push, which is
// safe only while nothing reads it.
func TestSecurityRace_CoverageArtifactOwnership(t *testing.T) {
	raw, err := os.ReadFile(securityWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", securityWorkflowPath, err)
	}
	if !strings.Contains(string(raw), "name: "+securityCovArtifact) {
		t.Errorf("%s no longer publishes %q — its standalone tag/schedule/dispatch runs would produce no coverage artifact at all",
			securityWorkflowPath, securityCovArtifact)
	}

	// No workflow may DOWNLOAD coverage-report. It is absent on main pushes
	// from stage 2B onward, so a consumer would be reading an artifact that
	// exists on some events and not others — the failure mode that makes
	// "it worked on the tag run" a debugging session.
	for _, wf := range workflowFiles(t) {
		body, err := os.ReadFile(wf)
		if err != nil {
			t.Fatalf("read %s: %v", wf, err)
		}
		text := string(body)
		if !strings.Contains(text, "download-artifact") {
			continue
		}
		if strings.Contains(text, "name: "+securityCovArtifact) && wf != securityWorkflowPath {
			t.Errorf("%s references the %q artifact. It is not published on main pushes since stage 2B; "+
				"read qa-gate.yml's `qa-coverage` profile instead.", wf, securityCovArtifact)
		}
	}
}

// workflowFiles lists .github/workflows/*.yml.
func workflowFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".github/workflows")
	if err != nil {
		t.Fatalf("read workflows dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
			out = append(out, ".github/workflows/"+e.Name())
		}
	}
	if len(out) == 0 {
		t.Fatal("no workflow files found — the selector is stale")
	}
	return out
}

// TestSecurityRace_MainPushHasExactlyOneRaceOwner pins the whole point of the
// stage across BOTH workflows: on a push to main, exactly one job runs the full
// ROOT-MODULE race suite.
//
// Since stage 5B that owner is qa-gate.yml's `qa-race`, which runs the suite
// through the reusable qa-race-shards.yml (4 root shards of one `go test -c
// -race -cover` binary + every other package), so it is recognised by its
// `uses:` rather than by a `go test -race ./...` step. The wall therefore
// counts BOTH shapes: any job that still runs a whole-module `go test -race
// ./...` on a main push, and any job that calls the sharded workflow. Exactly
// one may exist, and it must be qa-race.
//
// "Full root-module" is the load-bearing qualifier. qa-agent also runs
// `go test -race`, but against cmd/culvert-maint — a separate Go module that
// `go test ./...` from the repo root never descends into, so it is a different
// suite and not a duplicate. It is identified by its steps' working-directory
// and deliberately excluded; TestSecurityRace_OtherSuitesIntact pins that it
// still runs.
func TestSecurityRace_MainPushHasExactlyOneRaceOwner(t *testing.T) {
	var runners []raceRunner
	for _, wf := range []string{securityWorkflowPath, qaGateWorkflowPath} {
		doc := loadWorkflow(t, wf)
		generic := asMap(genericWorkflow(t, wf)["jobs"])
		steps := workflowStepsByJob(t, wf)
		for name := range doc.Jobs {
			if !jobRunsOnMainPush(t, doc.Jobs[name].If) {
				continue
			}
			if uses := toStr(asMap(generic[name])["uses"]); uses == "./"+qaRaceShardsWorkflowPath {
				runners = append(runners, raceRunner{wf, name, "uses " + uses})
				continue
			}
			for _, run := range wholeModuleRaceRuns(steps[name]) {
				runners = append(runners, raceRunner{wf, name, run})
			}
		}
	}

	if len(runners) != 1 {
		var lines []string
		for _, r := range runners {
			lines = append(lines, r.workflow+" / "+r.job+" ("+r.how+")")
		}
		t.Fatalf("a push to main must have EXACTLY ONE full root-module race execution across QA and Security; found %d: %v\n"+
			"That duplication is what stage 2B removes.", len(runners), lines)
	}
	if runners[0].job != qaRaceOwnerJob || runners[0].workflow != qaGateWorkflowPath {
		t.Errorf("the main-push race owner is %q in %s, want %q in %s",
			runners[0].job, runners[0].workflow, qaRaceOwnerJob, qaGateWorkflowPath)
	}
	// And that owner must still produce the coverage profile (stage 2A): the
	// sharded workflow's verdict publishes `qa-coverage`.
	if got := uploadedArtifacts(t, qaRaceShardsWorkflowPath, "race-verdict"); !slices.Contains(got, qaCoverageArtifact) {
		t.Errorf("the main-push race owner no longer publishes %q — stage 2A's single race+coverage run is the "+
			"reason Security can stop running the suite here. race-verdict uploads: %v", qaCoverageArtifact, got)
	}
}

// raceRunner is one job found executing the full root-module race suite.
type raceRunner struct{ workflow, job, how string }

// jobRunsOnMainPush reports whether a job with this `if:` runs on a push to
// main (no condition, the plain non-PR guard, or an event expression that
// evaluates true for that event).
func jobRunsOnMainPush(t *testing.T, ifExpr string) bool {
	t.Helper()
	cond := normaliseExpr(ifExpr)
	return cond == "" ||
		cond == "github.event_name != 'pull_request'" ||
		(strings.Contains(cond, "github.event_name") && evalRaceOwnership(t, cond, "push", "refs/heads/main"))
}

// wholeModuleRaceRuns returns the steps that run the WHOLE root module under
// the race detector — the duplicate stage 2B removed. A nested module's suite
// (a working-directory other than the root) is a different suite, and a
// package-scoped `go test -race` is not the whole module.
func wholeModuleRaceRuns(steps []map[string]interface{}) []string {
	var out []string
	for _, st := range steps {
		run := shellCodeOnly(toStr(st["run"]))
		if !strings.Contains(run, "go test") || !strings.Contains(run, "-race") || !strings.Contains(run, "./...") {
			continue
		}
		if wd := toStr(st["working-directory"]); wd != "" && wd != "." {
			continue
		}
		out = append(out, strings.TrimSpace(run))
	}
	return out
}

// workflowStepsByJob returns every job's steps as generic maps, so a step's
// `working-directory` can be read (the shared wfStep struct does not carry it).
func workflowStepsByJob(t *testing.T, path string) map[string][]map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var generic struct {
		Jobs map[string]struct {
			Steps []map[string]interface{} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string][]map[string]interface{}{}
	for name := range generic.Jobs {
		out[name] = generic.Jobs[name].Steps
	}
	if len(out) == 0 {
		t.Fatalf("%s has no jobs — the selector is stale", path)
	}
	return out
}

// TestSecurityRace_OtherSuitesIntact pins that the stage removed only the
// DUPLICATE. The shuffled determinism suite and the maintenance-agent module
// tests are separate obligations and must still run on a main push.
func TestSecurityRace_OtherSuitesIntact(t *testing.T) {
	doc := loadWorkflow(t, qaGateWorkflowPath)
	for _, tc := range []struct{ job, mustContain, why string }{
		{"qa-determinism", "-shuffle=on", "the shuffled double-run catches order-dependent tests and is not covered by the race run"},
		{"qa-agent", "cmd/culvert-maint", "the agent is a separate Go module; `go test ./...` from the root never descends into it"},
	} {
		j, ok := doc.Jobs[tc.job]
		if !ok {
			t.Errorf("qa-gate.yml lost the %q job — %s", tc.job, tc.why)
			continue
		}
		if strings.TrimSpace(j.If) != qaPRSkipCondition {
			t.Errorf("job %q must still run on every non-PR event (got if: %q)", tc.job, j.If)
		}
		var body strings.Builder
		for i := range j.Steps {
			body.WriteString(j.Steps[i].Run)
			body.WriteString(j.Steps[i].With.AllowedEndpoints)
			body.WriteByte('\n')
		}
		blob := body.String()
		if tc.job == "qa-agent" {
			// The agent job expresses its module via working-directory, so read
			// the raw job text instead of only the run bodies.
			raw, err := os.ReadFile(qaGateWorkflowPath)
			if err != nil {
				t.Fatalf("read %s: %v", qaGateWorkflowPath, err)
			}
			blob = string(raw)
		}
		if !strings.Contains(blob, tc.mustContain) {
			t.Errorf("job %q no longer references %q — %s", tc.job, tc.mustContain, tc.why)
		}
	}
}
