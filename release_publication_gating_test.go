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
func stepBody(st *wfStep) string { return st.Run + "\n" + st.Uses }

// jobMentions reports whether any step of j carries needle in its run body or
// its `uses`. Index-based range: wfStep is 144 bytes and this walks every step
// of every job (CLAUDE.md's rangeValCopy rule).
func jobMentions(j wfJob, needle string) bool {
	for i := range j.Steps {
		if strings.Contains(stepBody(&j.Steps[i]), needle) {
			return true
		}
	}
	return false
}

// armBetween returns the slice of a shell body from the line starting an if/elif
// arm up to the next one, and false when the arm is not present. Returning false
// rather than slicing on a -1 index keeps a resolver rewrite a legible test
// FAILURE instead of a panic (gocritic offBy1).
func armBetween(body, start, stop string) (string, bool) {
	i := strings.Index(body, start)
	if i < 0 {
		return "", false
	}
	arm := body[i:]
	if j := strings.Index(arm[len(start):], stop); j >= 0 {
		arm = arm[:len(start)+j]
	}
	return arm, true
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
	for i := range docker.Steps {
		if strings.Contains(docker.Steps[i].Run, "imagetools create") {
			t.Errorf("docker step %q runs `imagetools create` — tag promotion must live in promote-image, behind the predicate", docker.Steps[i].Name)
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
	for i := range promote.Steps {
		body := stepBody(&promote.Steps[i])
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

	assertNoUngatedPublisher(t, doc)
	assertExemptionsKeepTheirSubstituteControls(t, doc)
}

// publishVerbs are the ways a ci.yml step can reach a public surface. A step
// matching one of these must sit in a job that calls the predicate.
var publishVerbs = []string{
	"imagetools create", "git push origin", "gh release edit",
	"gh release upload", "gh release delete-asset", "softprops/action-gh-release",
}

// publicationExemptions are jobs allowed to publish WITHOUT the workflow-run
// predicate. Each is declared here with the reason, never left implicit, and
// assertExemptionsKeepTheirSubstituteControls proves the named substitute
// controls are still in place.
var publicationExemptions = map[string]string{
	"catalog-resign": "re-sign is a freshness-only republish of an ALREADY-RELEASED bundle. " +
		"Its requirement is cryptographic, not procedural: TestReleaseResignGate verifies the " +
		"source bundle through the baked Sigstore root + pinned identity BEFORE reading any " +
		"field (SEC-F1), the dispatch ref must be the latest v* tag (SEC-F2a), and it attaches " +
		"a NEW versioned asset rather than replacing the original. Requiring the workflow-run " +
		"predicate here would be strictly worse: the re-signed tag can be months old and its " +
		"gate runs age out of the Actions retention window, so the predicate would refuse " +
		"forever and the freshness mechanism would die.",
}

// jobPublishVerb returns the publication verb a job performs, or "".
func jobPublishVerb(j wfJob) string {
	found := ""
	for i := range j.Steps {
		body := stepBody(&j.Steps[i])
		for _, verb := range publishVerbs {
			if strings.Contains(body, verb) {
				found = verb
			}
		}
	}
	return found
}

// assertNoUngatedPublisher is the not-vacuous half: EVERY job is scanned for a
// publication verb, so a path added later cannot omit the predicate the way the
// main-push image path did.
func assertNoUngatedPublisher(t *testing.T, doc wfDoc) {
	t.Helper()
	for name := range doc.Jobs {
		j := doc.Jobs[name]
		verb := jobPublishVerb(j)
		if verb == "" {
			continue
		}
		if _, ok := publicationExemptions[name]; ok {
			continue
		}
		if !jobMentions(j, predicateScript) {
			t.Errorf("job %q performs a publication (%q) but never calls %s — add the predicate, "+
				"or declare an exemption with its substitute control in publicationExemptions", name, verb, predicateScript)
		}
	}
}

// assertExemptionsKeepTheirSubstituteControls: an exemption naming a job that no
// longer exists is stale, and an exempt job that lost its substitute controls is
// a hole.
func assertExemptionsKeepTheirSubstituteControls(t *testing.T, doc wfDoc) {
	t.Helper()
	for name := range publicationExemptions {
		j, ok := doc.Jobs[name]
		if !ok {
			t.Errorf("publication exemption names job %q, which no longer exists in ci.yml", name)
			continue
		}
		if !jobMentions(j, "TestReleaseResignGate") {
			t.Errorf("exempt job %q no longer runs its verify-before-read gate (TestReleaseResignGate) — "+
				"the exemption's stated substitute control is gone", name)
		}
		assertRefusesNonLatestTag(t, name, j)
		assertNeverPromotes(t, name, j)
	}
}

// assertRefusesNonLatestTag pins SEC-F2a on the step's MECHANISM rather than its
// display name — a step name is not a trust boundary, the same reason
// require-gate.sh keys on a workflow path.
func assertRefusesNonLatestTag(t *testing.T, name string, j wfJob) {
	t.Helper()
	for i := range j.Steps {
		run := j.Steps[i].Run
		if strings.Contains(run, `grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'`) &&
			strings.Contains(run, "refusing to re-sign") {
			return
		}
	}
	t.Errorf("exempt job %q no longer refuses a dispatch that is not the latest v* tag (SEC-F2a) — "+
		"without it a superseded release's freshness could be extended", name)
}

// assertNeverPromotes: the exemption covers republishing a verified catalog
// bundle, never release promotion.
func assertNeverPromotes(t *testing.T, name string, j wfJob) {
	t.Helper()
	for i := range j.Steps {
		for _, banned := range []string{"imagetools create", "draft=false"} {
			if strings.Contains(j.Steps[i].Run, banned) {
				t.Errorf("exempt job %q step %q performs %q — the exemption covers republishing a "+
					"verified catalog bundle, not release promotion", name, j.Steps[i].Name, banned)
			}
		}
	}
}

// ─── 3. Release assets are staged, not published ─────────────────────────────

func TestPublicationGating_ReleaseAssetsAreStagedAsDrafts(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	seen := 0
	for name := range doc.Jobs {
		steps := doc.Jobs[name].Steps
		for i := range steps {
			if !strings.Contains(steps[i].Uses, "softprops/action-gh-release") {
				continue
			}
			seen++
			if steps[i].With.Draft != true {
				t.Errorf("job %q step %q uploads a release asset with draft=%v — it must be draft: true so the release is not public until publish-release",
					name, steps[i].Name, steps[i].With.Draft)
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
	for name := range doc.Jobs {
		steps := doc.Jobs[name].Steps
		for i := range steps {
			if strings.Contains(steps[i].Run, "draft=false") {
				undraft++
				if name != "publish-release" {
					t.Errorf("job %q step %q publishes the release (draft=false) — only publish-release may", name, steps[i].Name)
				}
			}
		}
	}
	if undraft != 1 {
		t.Fatalf("expected exactly one draft=false step in ci.yml, found %d — the release either never becomes public or becomes public in more than one place", undraft)
	}
}

// ─── 3b. Supersession may defer a moving channel, never a version ────────────

// TestPublicationGating_ImmutableTagsAreNeverDeferred pins the split Codex
// found missing: the first shipped shape gated ONE target list on supersession,
// so a tag run overtaken by a newer tag skipped everything — including its own
// `X.Y.Z` — while publish-release still undrafted the release. The result was a
// public release whose exact version tag was absent or pointed at the main
// run's digest instead of the one its own catalog pins.
func TestPublicationGating_ImmutableTagsAreNeverDeferred(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	docker := mustJob(t, doc, "docker")

	var chanStep *wfStep
	for i := range docker.Steps {
		if strings.Contains(docker.Steps[i].Run, "immutable_tags=") {
			chanStep = &docker.Steps[i]
			break
		}
	}
	if chanStep == nil {
		t.Fatal("docker job emits no immutable_tags output — promotion cannot distinguish a version tag from a moving channel")
	}
	run := chanStep.Run

	// The MAIN path's version is speculative until auto-tag creates the tag, so
	// it must declare NO immutable target; everything it promotes is floating.
	mainArm, ok := armBetween(run, `if [ "${GITHUB_REF}" = "refs/heads/main" ]`, "elif")
	if !ok {
		t.Fatal("the channel resolver no longer has a recognisable main-push arm — this wall cannot read it")
	}
	if strings.Contains(mainArm, "IMMUTABLE=") {
		t.Errorf("the main-push arm assigns IMMUTABLE — its computed version is speculative until auto-tag "+
			"creates the tag, so a superseded main run must promote nothing. Arm:\n%s", mainArm)
	}
	if !strings.Contains(mainArm, "FLOATING=") {
		t.Errorf("the main-push arm assigns no FLOATING targets — it would promote nothing at all. Arm:\n%s", mainArm)
	}

	// The TAG path's exact version can only ever mean this tag's release.
	tagArm, ok := armBetween(run, `elif [ "${GITHUB_REF#refs/tags/v}"`, "\n          else")
	if !ok {
		t.Fatal("the channel resolver no longer has a recognisable tag arm — this wall cannot read it")
	}
	if !strings.Contains(tagArm, `IMMUTABLE="${VERSION_BARE} ${VERSION}"`) {
		t.Errorf("the tag arm must declare the exact version as IMMUTABLE so a superseded tag run still "+
			"publishes its own X.Y.Z. Arm:\n%s", tagArm)
	}
	if strings.Contains(tagArm, `FLOATING="${VERSION_BARE}`) {
		t.Errorf("the tag arm puts the exact version in FLOATING — it would be deferred when superseded. Arm:\n%s", tagArm)
	}
}

// TestPublicationGating_LatestIsDecidedNotAsserted pins the second half of the
// same class: GitHub's "Latest" designation is what scripts/install.sh resolves
// its bootstrap verifier through, so an unconditional `gh release edit --latest`
// moves fresh installs onto an older verifier whenever a superseded tag's run
// finishes after a newer release, or when an old tag's workflow is re-run.
func TestPublicationGating_LatestIsDecidedNotAsserted(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	pub := mustJob(t, doc, "publish-release")

	var publish *wfStep
	for i := range pub.Steps {
		if strings.Contains(pub.Steps[i].Run, "draft=false") {
			publish = &pub.Steps[i]
			break
		}
	}
	if publish == nil {
		t.Fatal("publish-release has no draft=false step — the release never becomes public")
	}
	run := publish.Run

	// The Latest decision must be GitHub's, taken atomically with the un-draft.
	if !strings.Contains(run, "make_latest=legacy") {
		t.Error("publish-release does not pass make_latest=legacy — the Latest designation would be asserted " +
			"by this run instead of arbitrated by GitHub, and scripts/install.sh resolves its bootstrap " +
			"verifier through /releases/latest")
	}
	// Asserting an answer this job cannot compute without a race is the defect.
	// `--latest` / `--latest=false` are both check-then-act against a tag list
	// that a concurrent tag workflow can invalidate between the read and the edit.
	if strings.Contains(run, "--latest") {
		t.Errorf("publish-release asserts --latest: a concurrent tag workflow can create a newer tag between "+
			"the check and the edit, so the answer must come from make_latest=legacy instead. run:\n%s", run)
	}
	if strings.Contains(run, "git tag --list") {
		t.Errorf("publish-release still reads a local tag list to decide Latest — even a refreshed list is a "+
			"check-then-act across concurrent tag workflows. run:\n%s", run)
	}
	// The un-draft and the Latest decision must be ONE call; splitting them
	// reopens the window this fix closes.
	if !strings.Contains(run, "draft=false") {
		t.Errorf("publish-release no longer clears the draft flag. run:\n%s", run)
	}
	undraftLine := ""
	for _, ln := range strings.Split(run, "\n") {
		if strings.Contains(ln, "draft=false") {
			undraftLine = ln
		}
	}
	if !strings.Contains(undraftLine, "make_latest=legacy") {
		t.Errorf("the un-draft and the Latest decision are not the same API call — they must be atomic. line:\n%s", undraftLine)
	}
}

// TestPublicationGating_ExactVersionsBelongToTheTagRun pins that one version
// maps to one digest. The main run and the tag run deliberately build different
// digests, so a main run promoting `vX.Y.Z` while the tag run promotes `X.Y.Z`
// left the two aliases of a single version on two different images — with
// `vX.Y.Z` on a digest that release's own catalog does not pin.
func TestPublicationGating_ExactVersionsBelongToTheTagRun(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	docker := mustJob(t, doc, "docker")

	var chanStep *wfStep
	for i := range docker.Steps {
		if strings.Contains(docker.Steps[i].Run, "immutable_tags=") {
			chanStep = &docker.Steps[i]
			break
		}
	}
	if chanStep == nil {
		t.Fatal("docker job emits no immutable_tags output — this wall cannot read the channel split")
	}
	run := chanStep.Run

	mainArm, ok := armBetween(run, `if [ "${GITHUB_REF}" = "refs/heads/main" ]`, "elif")
	if !ok {
		t.Fatal("the channel resolver no longer has a recognisable main-push arm")
	}
	for _, banned := range []string{"${VERSION}", "${VERSION_BARE}"} {
		if strings.Contains(mainArm, "FLOATING=") && strings.Contains(promoteAssignment(mainArm, "FLOATING"), banned) {
			t.Errorf("the main-push arm promotes the exact version %s — exact aliases belong to the tag run, "+
				"whose digest the release catalog pins. Arm:\n%s", banned, mainArm)
		}
	}

	tagArm, ok := armBetween(run, `elif [ "${GITHUB_REF#refs/tags/v}"`, "\n          else")
	if !ok {
		t.Fatal("the channel resolver no longer has a recognisable tag arm")
	}
	imm := promoteAssignment(tagArm, "IMMUTABLE")
	for _, want := range []string{"${VERSION_BARE}", "${VERSION}"} {
		if !strings.Contains(imm, want) {
			t.Errorf("the tag arm must promote BOTH exact aliases as immutable (missing %s) so one version "+
				"means one digest; got IMMUTABLE=%q", want, imm)
		}
	}
}

// promoteAssignment returns the right-hand side of the last `<name>=...` line in
// a shell arm, or "" when absent.
func promoteAssignment(arm, name string) string {
	out := ""
	for _, ln := range strings.Split(arm, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, name+"=") {
			out = strings.TrimPrefix(ln, name+"=")
		}
	}
	return out
}

// TestPublicationGating_PromotionIsSerializedAcrossRefs pins the other half of
// the same class: ci.yml's workflow concurrency key includes the ref, so two v*
// tags run at once, and "am I the channel tip?" is a check-then-act. Promotion
// therefore takes a ref-INDEPENDENT lock and reads the tip from the remote
// inside it.
func TestPublicationGating_PromotionIsSerializedAcrossRefs(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	promote := mustJob(t, doc, "promote-image")

	grp, cancel := promote.ConcurrencyGroupAndCancel()
	if grp == "" {
		t.Fatal("promote-image declares no concurrency group — two tag workflows can promote the same moving " +
			"channels at once and an older run can roll them back")
	}
	if strings.Contains(grp, "github.ref") || strings.Contains(grp, "github.sha") {
		t.Errorf("promote-image's concurrency group %q is per-ref, which serializes nothing across tags", grp)
	}
	if cancel {
		t.Error("promote-image sets cancel-in-progress: true — a promotion cut in half can leave the channels " +
			"pointing at a partially applied set")
	}

	var tip *wfStep
	for i := range promote.Steps {
		if strings.Contains(promote.Steps[i].Run, "tip=") {
			tip = &promote.Steps[i]
			break
		}
	}
	if tip == nil {
		t.Fatal("promote-image has no channel-tip step")
	}
	if !strings.Contains(tip.Run, "--tags origin") {
		t.Errorf("the channel-tip step does not refresh tags from the remote — a tag created after this job's "+
			"checkout would leave it believing it is still the highest, and the ancestry guard would compare "+
			"against the wrong tip. run:\n%s", tip.Run)
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
	// CommandContext, not Command: the harness must die with the test rather
	// than outlive it (noctx).
	cmd := exec.CommandContext(t.Context(), "bash", gatingCasesScript)
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

// WithFetchDepth returns the step's `with.fetch-depth`, or -1 when unset.
// actions/checkout treats 0 as "all history and tags"; an unset value is the
// default shallow clone, which sees no tags at all.
func (st wfStep) WithFetchDepth() int {
	if st.With.FetchDepth == nil {
		return -1
	}
	return *st.With.FetchDepth
}

// ConcurrencyGroupAndCancel returns a job's concurrency group and whether it
// cancels in-progress runs. An absent block yields ("", false).
func (j wfJob) ConcurrencyGroupAndCancel() (string, bool) {
	if j.Concurrency == nil {
		return "", false
	}
	return j.Concurrency.Group, j.Concurrency.CancelInProgress == true
}
