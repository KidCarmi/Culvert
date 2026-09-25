package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Build-once promotion (roadmap/CI-REDESIGN.md §21): the main push builds and
// qualifies ONE candidate image; the tag run releases those exact bytes.
//
// Before this, a tag run rebuilt the image the main push had already built
// and tested — non-reproducibly (floating alpine, apk upgrade, a monthly GeoIP
// download), so the published digest was never the qualified one, and the
// compose smoke and the Security image scan each built yet another image from
// source. These walls pin the shape that makes "qualified" and "published"
// the same digest; the behaviour is driven by
// .github/scripts/test/candidate-promotion-cases.sh.
// ─────────────────────────────────────────────────────────────────────────────

const (
	candidateCasesScript = ".github/scripts/test/candidate-promotion-cases.sh"
	candidateLib         = ".github/scripts/lib/candidate.sh"
)

// needsClosure returns every job name `name` transitively depends on.
func needsClosure(doc wfDoc, name string) map[string]bool {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(n string) {
		for dep := range jobNeeds(doc.Jobs[n]) {
			if !seen[dep] {
				seen[dep] = true
				walk(dep)
			}
		}
	}
	walk(name)
	return seen
}

func stepNamed(t *testing.T, j wfJob, job, substr string) (int, *wfStep) {
	t.Helper()
	for i := range j.Steps {
		if strings.Contains(j.Steps[i].Name, substr) {
			return i, &j.Steps[i]
		}
	}
	t.Fatalf("%s has no step named like %q", job, substr)
	return -1, nil
}

// TestBuildOnce_NothingPublicMovesForAnUnqualifiedCandidate: every job that
// creates the release tag, moves a public channel, signs the release or
// publishes it must depend — transitively, with no status-function escape —
// on qualify-candidate. A failed qualification then SKIPS all of them.
func TestBuildOnce_NothingPublicMovesForAnUnqualifiedCandidate(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	mustJob(t, doc, "qualify-candidate")
	for _, name := range []string{"auto-tag", "promote-image", "promote-release-channels", "publish-release", "catalog-pipeline", "release"} {
		j := mustJob(t, doc, name)
		if !needsClosure(doc, name)["qualify-candidate"] {
			t.Errorf("%s does not depend on qualify-candidate — it could act on a candidate that failed qualification", name)
		}
		if statusOverrideRE.MatchString(j.If) {
			t.Errorf("%s's if: carries a status function (%q) — a failed qualification would no longer skip it", name, j.If)
		}
	}
	if q := doc.Jobs["qualify-candidate"]; statusOverrideRE.MatchString(q.If) {
		t.Errorf("qualify-candidate's if: carries a status function (%q)", q.If)
	}
}

// TestBuildOnce_NoDependencyCycle: candidate → qualification → main
// promotion/auto-tag, and tag → reuse → qualification → release, must stay a
// DAG. A cycle is rejected by GitHub only at run time, on the release path.
func TestBuildOnce_NoDependencyCycle(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	for name := range doc.Jobs {
		if needsClosure(doc, name)[name] {
			t.Errorf("ci.yml job %s depends on itself through its needs chain", name)
		}
	}
}

// TestBuildOnce_QualificationRunsOnTheCandidateItself pins that the checks
// target the bound digest on both platforms, and that the main run signs a
// qualification record only after them.
func TestBuildOnce_QualificationRunsOnTheCandidateItself(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	q := mustJob(t, doc, "qualify-candidate")
	needs := jobNeeds(q)
	if !needs["docker"] || !needs["resolve-candidate"] {
		t.Errorf("qualify-candidate must need docker and resolve-candidate; needs=%v", needs)
	}
	for _, want := range []string{"refs/heads/main", "push", "refs/tags/v"} {
		if !strings.Contains(q.If, want) {
			t.Errorf("qualify-candidate must run on the main push AND on tags; if=%q lacks %q", q.If, want)
		}
	}
	_, what := stepNamed(t, q, "qualify-candidate", "Resolve what is being qualified")
	if what.Env["DIGEST"] != "${{ needs.resolve-candidate.outputs.digest }}" {
		t.Errorf("qualification must target the BOUND digest (resolve-candidate), got %q", what.Env["DIGEST"])
	}
	if !jobMentions(q, "candidate-verify-contents.sh") {
		t.Error("qualify-candidate no longer verifies platforms/revision/compiler/version file")
	}
	for _, p := range []string{"linux/amd64", "linux/arm64"} {
		found := false
		for i := range q.Steps {
			if strings.Contains(q.Steps[i].Run, "candidate-run-check.sh") && strings.Contains(q.Steps[i].Run, p) {
				found = true
			}
		}
		if !found {
			t.Errorf("qualify-candidate does not execute the candidate on %s", p)
		}
	}
	_, scan := stepNamed(t, q, "qualify-candidate", "Scan the candidate")
	for _, want := range []string{"--exit-code 1", "linux/amd64 linux/arm64", `"${IMAGE}@${DIGEST}"`, "--severity CRITICAL,HIGH", "--ignorefile .trivyignore"} {
		if !strings.Contains(scan.Run, want) {
			t.Errorf("the candidate scan lost %q — it must fail on findings, cover both platforms and scan the digest", want)
		}
	}
	_, compose := stepNamed(t, q, "qualify-candidate", "start the candidate")
	if !strings.Contains(compose.Run, "--no-build") || strings.Contains(compose.Run, "compose -f docker-compose.yml -f docker-compose.ci.yml build") {
		t.Error("the compose smoke must start the candidate with --no-build, never build a replacement")
	}
	// Docker's classic image store keeps ONE image per digest reference: the
	// run checks pull both platforms of the index before this step, so pulling
	// "${IMAGE}@${DIGEST}" (the index) here fails with "cannot overwrite
	// digest" — main run 36111817278. Pull the amd64 manifest by its own digest.
	if !strings.Contains(compose.Run, "candidate-platform-ref.sh") || strings.Contains(compose.Run, `"${IMAGE}@${DIGEST}"`) {
		t.Error("the compose smoke must pull the amd64 manifest by its own digest (candidate-platform-ref.sh), never the index digest")
	}
	ri, rec := stepNamed(t, q, "qualify-candidate", "Record the qualification")
	if !strings.Contains(rec.If, "refs/heads/main") || !strings.Contains(rec.If, "push") {
		t.Errorf("only the main push may sign a qualification record; if=%q", rec.If)
	}
	if !strings.Contains(rec.Run, "cosign attest") || !strings.Contains(rec.Run, "$CANDIDATE_QUALIFICATION_TYPE") {
		t.Error("the qualification record is no longer a signed attestation of the qualification type")
	}
	si, _ := stepNamed(t, q, "qualify-candidate", "Scan the candidate")
	ei, _ := stepNamed(t, q, "qualify-candidate", "Execute the candidate (linux/arm64")
	if ri < si || ri < ei {
		t.Error("the qualification record must be signed AFTER the scan and the execution checks")
	}
}

// TestBuildOnce_TheTagRunReusesAndNeverSilentlyRebuilds pins the docker job's
// plan: every build step is conditional on the plan, the tag path goes
// through candidate-plan-tag.sh (binding → published → main candidate →
// owner-authorized rebuild), and no other image is built from source.
func TestBuildOnce_TheTagRunReusesAndNeverSilentlyRebuilds(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	d := mustJob(t, doc, "docker")
	if jobNeeds(d)["smoke"] {
		t.Error("docker still waits for a source-built smoke image")
	}
	if _, ok := doc.Jobs["smoke"]; ok {
		t.Error("the source-built compose smoke job is back — the candidate is qualified by digest in qualify-candidate")
	}
	_, plan := stepNamed(t, d, "docker", "Plan the candidate")
	for _, want := range []string{"candidate-plan-main.sh", "candidate-plan-tag.sh"} {
		if !strings.Contains(plan.Run, want) {
			t.Errorf("the plan step no longer runs %s", want)
		}
	}
	if plan.Env["RELEASE_REBUILD_AUTHORIZED_TAG"] != "${{ vars.RELEASE_REBUILD_AUTHORIZED_TAG }}" {
		t.Error("the rebuild authorization must come from the owner-set repository variable, nothing else")
	}
	for i := range d.Steps {
		st := &d.Steps[i]
		if strings.Contains(st.Uses, "docker/build-push-action") || strings.Contains(st.Uses, "docker/metadata-action") ||
			strings.Contains(st.Uses, "docker/setup-qemu-action") || strings.Contains(st.Name, "Sign proxy image") {
			if st.If != "steps.plan.outputs.build == 'true'" {
				t.Errorf("docker step %q runs without the plan deciding to build (if=%q) — a tag run would rebuild", st.Name, st.If)
			}
		}
	}
	_, rec := stepNamed(t, d, "docker", "Record the candidate")
	for _, want := range []string{"steps.plan.outputs.build == 'true'", "refs/heads/main", "push"} {
		if !strings.Contains(rec.If, want) {
			t.Errorf("only a NEW main-push candidate is recorded; if=%q lacks %q", rec.If, want)
		}
	}
	attest := strings.Index(rec.Run, "cosign attest")
	point := strings.Index(rec.Run, "candidate-record.sh point")
	if attest < 0 || point < 0 || point < attest {
		t.Error("the discovery pointer must be written AFTER the record is signed, so a present pointer implies a record")
	}
	raw, err := os.ReadFile(ciWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "docker-compose.ci.yml build") {
		t.Error("ci.yml builds a compose image from source again — qualify the candidate instead")
	}
}

// TestBuildOnce_ReleaseSignatureIsMadeInTheTagContext pins that the reused
// digest is signed by the tag run BEFORE the release-identity verification,
// on the bound digest.
func TestBuildOnce_ReleaseSignatureIsMadeInTheTagContext(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	c := mustJob(t, doc, "catalog-pipeline")
	si, sign := stepNamed(t, c, "catalog-pipeline", "Sign the release digest in the tag context")
	vi, _ := stepNamed(t, c, "catalog-pipeline", "Verify pushed image signature")
	if si > vi {
		t.Error("the tag-context signature must be made BEFORE the release-identity verification")
	}
	if !strings.HasPrefix(sign.If, "startsWith(github.ref, 'refs/tags/v')") {
		t.Errorf("the release signature belongs to the tag run only; if=%q", sign.If)
	}
	if sign.Env["DIGEST"] != "${{ needs.resolve-candidate.outputs.digest }}" || !strings.Contains(sign.Run, "cosign sign") {
		t.Error("the tag run must cosign-sign the BOUND digest")
	}
}

// TestBuildOnce_AutoTagConsumesTheCandidateVersion pins that the version is
// decided once (by the docker job's plan) and auto-tag only checks and applies
// it, one decision at a time.
func TestBuildOnce_AutoTagConsumesTheCandidateVersion(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	a := mustJob(t, doc, "auto-tag")
	if !jobNeeds(a)["qualify-candidate"] {
		t.Error("auto-tag must wait for the candidate to qualify")
	}
	group, cancel := a.ConcurrencyGroupAndCancel()
	if group != "release-version-decision" || cancel {
		t.Errorf("auto-tag must serialize version decisions (group release-version-decision, no cancel); got %q cancel=%v", group, cancel)
	}
	_, tag := stepNamed(t, a, "auto-tag", "Tag the candidate's version")
	if !strings.Contains(tag.Run, "decide-release-version.sh") || tag.Env["VERSION"] != "${{ needs.docker.outputs.version }}" {
		t.Error("auto-tag must tag the version the candidate was built with (needs.docker.outputs.version) via decide-release-version.sh")
	}
	for i := range a.Steps {
		if strings.Contains(a.Steps[i].Run, "git tag --list") || strings.Contains(a.Steps[i].Run, "PATCH + 1") {
			t.Errorf("auto-tag step %q computes a version of its own — the candidate's version is the only one", a.Steps[i].Name)
		}
	}
}

// TestCandidateIdentity_IsNotTheReleaseIdentity: the candidate producer
// identity (ci.yml on main) must never satisfy the pinned RELEASE identity
// (ci.yml on a v* tag). Widening release_identity.env to accept it would let
// any main build pass as a release.
func TestCandidateIdentity_IsNotTheReleaseIdentity(t *testing.T) {
	lib, err := os.ReadFile(candidateLib)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^CANDIDATE_IDENTITY="([^"]+)"$`).FindSubmatch(lib)
	if m == nil {
		t.Fatal("lib/candidate.sh declares no CANDIDATE_IDENTITY")
	}
	candidate := string(m[1])
	if candidate != "https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/heads/main" {
		t.Errorf("the candidate producer identity must be exactly ci.yml on refs/heads/main, got %q", candidate)
	}
	env, err := os.ReadFile("release_identity.env")
	if err != nil {
		t.Fatal(err)
	}
	sm := regexp.MustCompile(`(?m)^CULVERT_RELEASE_SIGSTORE_SAN_REGEX=(.+)$`).FindSubmatch(env)
	if sm == nil {
		t.Fatal("release_identity.env carries no SAN regex")
	}
	san := regexp.MustCompile(strings.TrimSpace(string(sm[1])))
	if san.MatchString(candidate) {
		t.Errorf("the RELEASE identity %s accepts the main candidate identity %s — a main build would pass as a release", sm[1], candidate)
	}
	// Control: the release regex still accepts a tag-run identity, so the
	// negative above is not vacuous.
	if !san.MatchString("https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/tags/v1.2.3") {
		t.Error("control failed: the release SAN regex no longer accepts a tag-run identity")
	}
}

// TestBuildOnce_OnlyTheMainPushWritesCandidateEvidence: the pointer and the
// signed records are written by exactly two jobs of ci.yml, and nowhere else.
func TestBuildOnce_OnlyTheMainPushWritesCandidateEvidence(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	for name, j := range doc.Jobs {
		for i := range j.Steps {
			st := &j.Steps[i]
			if !strings.Contains(st.Run, "candidate-record.sh") {
				continue
			}
			if name != "docker" && name != "qualify-candidate" {
				t.Errorf("job %s writes candidate evidence (step %q)", name, st.Name)
			}
			if !strings.Contains(st.If, "refs/heads/main") || !strings.Contains(st.If, "push") {
				t.Errorf("%s step %q writes candidate evidence outside a main push (if=%q)", name, st.Name, st.If)
			}
		}
	}
	files, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if filepath.Base(f) == "ci.yml" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "candidate-commit-") || strings.Contains(string(raw), "candidate-record.sh") {
			t.Errorf("%s touches release-candidate evidence; only ci.yml's main push may", f)
		}
	}
}

// TestCandidatePromotion_Behaviour drives every state transition — handoff,
// retry reuse, partial publication, superseded and concurrent candidates,
// wrong identity/version/digest, missing platforms, unavailable evidence and
// failed qualification — against mocked registry, Sigstore, git and go.
func TestCandidatePromotion_Behaviour(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "base64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required by the candidate-promotion cases (it is on every CI runner): %v", tool, err)
		}
	}
	cmd := exec.CommandContext(t.Context(), "bash", candidateCasesScript)
	cmd.Env = append(os.Environ(), "GITHUB_STEP_SUMMARY=", "GITHUB_OUTPUT=")
	out, err := cmd.CombinedOutput()
	t.Logf("candidate-promotion-cases.sh:\n%s", out)
	if err != nil {
		t.Fatalf("candidate promotion cases failed: %v", err)
	}
	m := regexp.MustCompile(`candidate-promotion cases: (\d+) passed, 0 failed`).FindSubmatch(out)
	if m == nil {
		t.Fatal("the harness did not report a clean pass line")
	}
	if n := string(m[1]); n == "0" || len(n) < 2 {
		t.Fatalf("the harness ran only %s cases — the coverage this test reports is gone", n)
	}
}
