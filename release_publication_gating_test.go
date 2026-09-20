package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// ─────────────────────────────────────────────────────────────────────────────
// Release-publication gating: the anti-drift wall for the rule that NOTHING
// reaches a public release channel before the release predicate succeeds for
// the exact source SHA.
//
// The defect this pins, measured on ci.yml run 35507615339 (SHA 3d8c9bb, the
// review baseline):
//
//   11:40:09Z  docker "Apply version tag"  → ghcr `latest`, `v0.0.N`, `0.0.N`
//   11:40:31Z  docker "Sign proxy image"   → cosign-signed, publicly pullable
//   12:09:14Z  auto-tag "Require Security + QA gate approval" CONCLUDES
//
// The images were public for 29 minutes before the verdict existed, because the
// docker job's only gate step carried `if: startsWith(github.ref,
// 'refs/tags/v')` and a main push is not a tag ref. `latest` is a real delivery
// channel — packaging/culvert-maint/install.sh seeds a fresh install from
// `${PROXY_REPO}:latest` — so that window shipped unverified bytes to new
// installs. In the same run Install Lifecycle E2E (35507615001) FAILED before
// reaching any lifecycle assertion, and the same SHA was tagged anyway.
//
// Every assertion here is written so an UNSAFE workflow fails: a missing job, a
// missing step, or a renamed script makes the test fail rather than vacuously
// pass, and each group carries a not-vacuous check so a selector that stops
// matching cannot pass forever.
// ─────────────────────────────────────────────────────────────────────────────

const (
	releaseEvidenceManifest = ".github/release-evidence.txt"
	predicateScript         = "require-release-evidence.sh"
	promoteScript           = "promote-image-tags.sh"
	completenessScript      = "assert-release-complete.sh"
	gatingCasesScript       = ".github/scripts/test/release-gating-cases.sh"
)

// jobNeeds normalises `needs:` (a scalar or a sequence) to a set.
func jobNeeds(j wfJob) map[string]bool {
	out := map[string]bool{}
	switch v := j.Needs.(type) {
	case string:
		out[v] = true
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

// stepBody is a step's run text plus its `uses`, so a single predicate can ask
// "does this step do X" whether X is a script call or an action.
func stepBody(st wfStep) string { return st.Run + "\n" + st.Uses }

func jobMentions(j wfJob, needle string) bool {
	for _, st := range j.Steps {
		if strings.Contains(stepBody(st), needle) {
			return true
		}
	}
	return false
}

// statusOverrideRE matches any GitHub Actions status function that would run a
// job even after a failed `needs` — the one-token way to silently open every
// gate this file pins.
var statusOverrideRE = regexp.MustCompile(`\b(always|failure|cancelled|success)\s*\(`)

func mustJob(t *testing.T, doc wfDoc, name string) wfJob {
	t.Helper()
	j, ok := doc.Jobs[name]
	if !ok {
		t.Fatalf("ci.yml must carry the %q job — release publication gating depends on it", name)
	}
	return j
}

// ─── 1. The build job publishes a CANDIDATE only ─────────────────────────────

// TestPublicationGating_DockerPushesNoReleaseChannel pins that the pre-verdict
// build/push job cannot reach a public channel. It is the direct regression
// gate for the observed defect.
func TestPublicationGating_DockerPushesNoReleaseChannel(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	docker := mustJob(t, doc, "docker")

	var meta *wfStep
	for i := range docker.Steps {
		if strings.Contains(docker.Steps[i].Uses, "docker/metadata-action") {
			meta = &docker.Steps[i]
			break
		}
	}
	if meta == nil {
		t.Fatal("docker job has no docker/metadata-action step — cannot verify which tags it pushes")
	}
	tags := meta.With.Tags
	if strings.TrimSpace(tags) == "" {
		t.Fatal("docker metadata-action declares no tags: — the push would be untagged and this test would prove nothing")
	}

	// A release channel is anything a consumer resolves as "the current
	// release": `latest`, any semver directive, any branch ref, or a raw
	// version. Only the immutable per-commit candidate may appear here.
	for _, banned := range []string{
		"type=semver",
		"value=latest",
		"type=ref,event=branch",
		"outputs.version",
	} {
		if strings.Contains(tags, banned) {
			t.Errorf("docker job pushes a RELEASE CHANNEL before any verdict exists: metadata tags contain %q.\n"+
				"Channels belong in the evidence-gated promote-image job. tags:\n%s", banned, tags)
		}
	}
	if !strings.Contains(tags, "candidate_tag") {
		t.Errorf("docker job must push the candidate tag (steps.chan.outputs.candidate_tag); tags:\n%s", tags)
	}

	// The candidate tag promote-image binds on must be RUN-scoped. The
	// main-push run and the tag run share a commit, and auto-tag pushes the v*
	// tag while the main run's promote-image is still resolving — so a
	// per-commit binding can be overwritten by the other run's build, and
	// promote-image would then be looking at a digest its own run did not
	// produce.
	var chanStep *wfStep
	for i := range docker.Steps {
		if strings.Contains(docker.Steps[i].Run, "candidate_tag=") {
			chanStep = &docker.Steps[i]
			break
		}
	}
	if chanStep == nil {
		t.Fatal("docker job has no step assigning candidate_tag — the promotion binding is unresolvable")
	}
	if !strings.Contains(chanStep.Run, "CANDIDATE=\"candidate-${GITHUB_RUN_ID}\"") {
		t.Errorf("the candidate tag promote-image binds on must be run-scoped (candidate-${GITHUB_RUN_ID}); got:\n%s", chanStep.Run)
	}

	// Belt and braces: no step in the build job may repoint tags itself. The
	// removed "Apply version tag" step did exactly this.
	for _, st := range docker.Steps {
		if strings.Contains(st.Run, "imagetools create") {
			t.Errorf("docker step %q runs `imagetools create` — tag promotion must live in promote-image, behind the predicate", st.Name)
		}
	}
}

// ─── 2. Promotion is behind the predicate ────────────────────────────────────

func TestPublicationGating_PromoteImageIsEvidenceGated(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	promote := mustJob(t, doc, "promote-image")

	needs := jobNeeds(promote)
	for _, want := range []string{"docker", "catalog-pipeline"} {
		if !needs[want] {
			t.Errorf("promote-image must need %q (it promotes the digest that job built/verified); needs=%v", want, needs)
		}
	}

	// The predicate must run, and must run BEFORE the promotion.
	predIdx, promIdx := -1, -1
	for i, st := range promote.Steps {
		body := stepBody(st)
		if predIdx < 0 && strings.Contains(body, predicateScript) {
			predIdx = i
		}
		if promIdx < 0 && strings.Contains(body, promoteScript) {
			promIdx = i
		}
	}
	switch {
	case predIdx < 0:
		t.Fatalf("promote-image never calls %s — promotion would be ungated", predicateScript)
	case promIdx < 0:
		t.Fatalf("promote-image never calls %s — nothing is promoted and this test proves nothing", promoteScript)
	case predIdx > promIdx:
		t.Fatalf("promote-image runs %s (step %d) BEFORE %s (step %d) — the gate must precede the publication",
			promoteScript, promIdx, predicateScript, predIdx)
	}

	if s := promote.Steps[predIdx]; s.ContinueOnError != nil {
		t.Errorf("the predicate step carries continue-on-error:%v — a refusal would not stop the promotion", s.ContinueOnError)
	}
	if s := promote.Steps[promIdx]; s.If != "" && statusOverrideRE.MatchString(s.If) {
		t.Errorf("the promotion step's if: %q carries a status override — it could run after the predicate failed", s.If)
	}
	if statusOverrideRE.MatchString(promote.If) {
		t.Errorf("promote-image's job-level if: %q carries a status override — a failed need would no longer skip it", promote.If)
	}
	// It must not run on a branch workflow_dispatch: that path had no gate step
	// at all and republished `latest`.
	if !strings.Contains(promote.If, "refs/heads/main") || !strings.Contains(promote.If, "github.event_name == 'push'") {
		t.Errorf("promote-image's if: must restrict the branch path to a main PUSH (a workflow_dispatch on a branch previously republished `latest` ungated); if: %q", promote.If)
	}
}

// TestPublicationGating_EveryPublishingJobAssertsThePredicate walls the whole
// publication surface at once: any job that pushes a tag, uploads a release
// asset or publishes a release must invoke the predicate.
func TestPublicationGating_EveryPublishingJobAssertsThePredicate(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	// job -> why it publishes. A job added to ci.yml that publishes without a
	// row here is caught by the second half of this test.
	for _, name := range []string{
		"docker",           // pushes the candidate + cosign-signs the digest
		"catalog-pipeline", // signs the catalog + stages it on the release
		"promote-image",    // moves latest/semver
		"auto-tag",         // creates the v* tag that starts the release
		"release",          // builds, signs and stages every binary
		"publish-release",  // makes the release public
	} {
		if j, ok := doc.Jobs[name]; !ok {
			t.Errorf("ci.yml lost the %q job — the publication map in this test is stale", name)
		} else if !jobMentions(j, predicateScript) {
			t.Errorf("job %q publishes but never calls %s", name, predicateScript)
		}
	}

	// Not vacuous: no job may reach a public surface without the predicate.
	// Scan EVERY job for publication verbs and require the predicate alongside,
	// so a publication path added later cannot omit it the way the main-push
	// image path did.
	publishVerbs := []string{
		"imagetools create", "git push origin", "gh release edit",
		"gh release upload", "gh release delete-asset", "softprops/action-gh-release",
	}
	// Exemptions are DECLARED, not silent — and each must carry the substitute
	// control named here, asserted below.
	exempt := map[string]string{
		"catalog-resign": "re-sign is a freshness-only republish of an ALREADY-RELEASED bundle. " +
			"Its requirement is cryptographic, not procedural: TestReleaseResignGate verifies the " +
			"source bundle through the baked Sigstore root + pinned identity BEFORE reading any " +
			"field (SEC-F1), the dispatch ref must be the latest v* tag (SEC-F2a), and it attaches " +
			"a NEW versioned asset rather than replacing the original. Requiring the workflow-run " +
			"predicate here would be strictly worse: the re-signed tag can be months old and its " +
			"gate runs age out of the Actions retention window, so the predicate would refuse " +
			"forever and the freshness mechanism would die.",
	}
	for name, j := range doc.Jobs {
		published := ""
		for _, st := range j.Steps {
			body := stepBody(st)
			for _, verb := range publishVerbs {
				if strings.Contains(body, verb) {
					published = verb
				}
			}
		}
		if published == "" {
			continue
		}
		if _, ok := exempt[name]; ok {
			continue
		}
		if !jobMentions(j, predicateScript) {
			t.Errorf("job %q performs a publication (%q) but never calls %s — add the predicate, "+
				"or declare an exemption with its substitute control in this test", name, published, predicateScript)
		}
	}

	// An exemption that names a job which no longer publishes is stale, and an
	// exempt job that lost its substitute controls is a hole.
	for name := range exempt {
		j, ok := doc.Jobs[name]
		if !ok {
			t.Errorf("publication exemption names job %q, which no longer exists in ci.yml", name)
			continue
		}
		if !jobMentions(j, "TestReleaseResignGate") {
			t.Errorf("exempt job %q no longer runs its verify-before-read gate (TestReleaseResignGate) — "+
				"the exemption's stated substitute control is gone", name)
		}
		// The latest-v*-tag precondition (SEC-F2a), asserted on the step's
		// MECHANISM rather than its display name — a step name is not a trust
		// boundary, the same reason require-gate.sh keys on a workflow path.
		latestTagGuard := false
		for _, st := range j.Steps {
			if strings.Contains(st.Run, `grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'`) &&
				strings.Contains(st.Run, "refusing to re-sign") {
				latestTagGuard = true
			}
		}
		if !latestTagGuard {
			t.Errorf("exempt job %q no longer refuses a dispatch that is not the latest v* tag (SEC-F2a) — "+
				"without it a superseded release's freshness could be extended", name)
		}
		// It must never touch an image channel or un-draft a release.
		for _, st := range j.Steps {
			for _, banned := range []string{"imagetools create", "--draft=false"} {
				if strings.Contains(st.Run, banned) {
					t.Errorf("exempt job %q step %q performs %q — the exemption covers republishing a "+
						"verified catalog bundle, not release promotion", name, st.Name, banned)
				}
			}
		}
	}
}

// ─── 3. Release assets are staged, not published ─────────────────────────────

func TestPublicationGating_ReleaseAssetsAreStagedAsDrafts(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	seen := 0
	for name, j := range doc.Jobs {
		for _, st := range j.Steps {
			if !strings.Contains(st.Uses, "softprops/action-gh-release") {
				continue
			}
			seen++
			if st.With.Draft != true {
				t.Errorf("job %q step %q uploads a release asset with draft=%v — it must be draft: true so the release is not public until publish-release",
					name, st.Name, st.With.Draft)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no action-gh-release steps found in ci.yml — the selector is stale and this test proves nothing")
	}
}

func TestPublicationGating_PublishReleaseIsLastAndUnconditionalOnSuccess(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	pub := mustJob(t, doc, "publish-release")

	needs := jobNeeds(pub)
	for _, want := range []string{"release", "catalog-pipeline", "aggregate-subjects", "verify-reproducible", "provenance"} {
		if !needs[want] {
			t.Errorf("publish-release must need %q before making the release public; needs=%v", want, needs)
		}
	}
	if statusOverrideRE.MatchString(pub.If) {
		t.Errorf("publish-release's if: %q carries a status override — it would publish even after a failed need", pub.If)
	}
	if !jobMentions(pub, completenessScript) {
		t.Errorf("publish-release must run %s — a green needs-chain does not prove the assets actually landed", completenessScript)
	}

	// Un-drafting must happen in exactly one place, and it must be this job.
	undraft := 0
	for name, j := range doc.Jobs {
		for _, st := range j.Steps {
			if strings.Contains(st.Run, "--draft=false") {
				undraft++
				if name != "publish-release" {
					t.Errorf("job %q step %q publishes the release (--draft=false) — only publish-release may", name, st.Name)
				}
			}
		}
	}
	if undraft != 1 {
		t.Fatalf("expected exactly one --draft=false step in ci.yml, found %d — the release either never becomes public or becomes public in more than one place", undraft)
	}
}

// ─── 4. The manifest is the predicate's single source of truth ───────────────

type evidenceRow struct {
	workflow string
	class    string
}

func readEvidenceManifest(t *testing.T) []evidenceRow {
	t.Helper()
	f, err := os.Open(releaseEvidenceManifest)
	if err != nil {
		t.Fatalf("read %s: %v", releaseEvidenceManifest, err)
	}
	defer f.Close() //nolint:errcheck // read-only
	var rows []evidenceRow
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("%s: malformed row %q (want '<workflow-file> mandatory|advisory')", releaseEvidenceManifest, line)
		}
		rows = append(rows, evidenceRow{workflow: fields[0], class: fields[1]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", releaseEvidenceManifest, err)
	}
	return rows
}

func TestPublicationGating_EvidenceManifestIsWellFormed(t *testing.T) {
	rows := readEvidenceManifest(t)
	if len(rows) == 0 {
		t.Fatalf("%s declares no evidence rows — an empty predicate approves everything", releaseEvidenceManifest)
	}

	mandatory, seen := 0, map[string]bool{}
	for _, r := range rows {
		switch r.class {
		case "mandatory":
			mandatory++
		case "advisory":
		default:
			t.Errorf("%s: row %q has unknown classification %q (want mandatory|advisory)", releaseEvidenceManifest, r.workflow, r.class)
		}
		if seen[r.workflow] {
			t.Errorf("%s: %q listed twice — an ambiguous classification is a silent policy hole", releaseEvidenceManifest, r.workflow)
		}
		seen[r.workflow] = true

		// A row naming a workflow that does not exist can never produce a run,
		// so a mandatory one would refuse every release and an advisory one
		// would warn forever. Both are drift.
		path := filepath.Join(".github", "workflows", r.workflow)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: row %q names a workflow that does not exist at %s", releaseEvidenceManifest, r.workflow, path)
		}
	}
	if mandatory == 0 {
		t.Fatalf("%s has no mandatory rows — the predicate would approve every commit", releaseEvidenceManifest)
	}

	// The two verdicts the repository already treated as release-blocking must
	// stay mandatory. Demoting either is a policy change that belongs in a
	// reviewed diff, not a quiet edit.
	for _, want := range []string{"security-release-gate.yml", "qa-gate.yml"} {
		found := false
		for _, r := range rows {
			if r.workflow == want && r.class == "mandatory" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s must keep %q mandatory", releaseEvidenceManifest, want)
		}
	}

	// Rows must only name workflows that can actually produce evidence for a
	// release SHA, i.e. that run on a push to main.
	for _, r := range rows {
		raw, err := os.ReadFile(filepath.Join(".github", "workflows", r.workflow))
		if err != nil {
			continue // already reported above
		}
		var trig struct {
			On struct {
				Push struct {
					Branches []string `yaml:"branches"`
				} `yaml:"push"`
			} `yaml:"on"`
		}
		if err := yamlUnmarshalWorkflow(raw, &trig); err != nil {
			t.Errorf("%s: parse %s: %v", releaseEvidenceManifest, r.workflow, err)
			continue
		}
		onMain := false
		for _, b := range trig.On.Push.Branches {
			if b == "main" {
				onMain = true
			}
		}
		if !onMain {
			t.Errorf("%s: row %q does not run on a push to main, so it can never produce evidence for a release SHA — it belongs in the NOT APPLICABLE note, not as a row", releaseEvidenceManifest, r.workflow)
		}
	}
}

// TestPublicationGating_PredicateIsTheOnlyGateCaller pins that no job
// hand-rolls the predicate any more. Four hand-written copies are how the
// main-push publication path ended up with none.
func TestPublicationGating_PredicateIsTheOnlyGateCaller(t *testing.T) {
	raw, err := os.ReadFile(ciWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowPath, err)
	}
	body := string(raw)
	if strings.Contains(body, "require-gate.sh security-release-gate.yml") ||
		strings.Contains(body, "require-gate.sh qa-gate.yml") {
		t.Error("ci.yml still hand-writes the evidence list via require-gate.sh — every caller must go through " +
			predicateScript + " so the manifest stays the single source of truth")
	}
	if !strings.Contains(body, predicateScript) {
		t.Fatalf("ci.yml never references %s — the selector is stale", predicateScript)
	}
}

// ─── 5. Behavioural coverage, against mocked publication operations ──────────

// TestReleasePublicationGating_Behaviour drives the predicate, the promotion
// guard and the completeness check through every required scenario with `gh`,
// `docker` and `git` stubbed on PATH. Nothing contacts GitHub, ghcr.io or
// Sigstore, and no release is created.
func TestReleasePublicationGating_Behaviour(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := os.Stat(gatingCasesScript); err != nil {
		t.Fatalf("%s is missing — the behavioural coverage this test reports is gone", gatingCasesScript)
	}
	cmd := exec.Command("bash", gatingCasesScript)
	cmd.Env = append(os.Environ(), "GITHUB_STEP_SUMMARY=")
	out, err := cmd.CombinedOutput()
	t.Logf("release-gating-cases.sh:\n%s", out)
	if err != nil {
		t.Fatalf("release gating cases failed: %v", err)
	}
	// Not vacuous: a harness that silently ran zero cases must fail.
	if !strings.Contains(string(out), "passed, 0 failed") {
		t.Fatalf("harness did not report a clean pass line")
	}
	if strings.Contains(string(out), "\n0 passed") {
		t.Fatal("harness executed no cases")
	}
}

// yamlUnmarshalWorkflow is a thin alias so the manifest test can parse a
// workflow's trigger block without importing the YAML package name at every
// call site (the repo standard is goccy/go-yaml, already imported by
// release_workflow_invariants_test.go).
func yamlUnmarshalWorkflow(raw []byte, out interface{}) error { return yaml.Unmarshal(raw, out) }
