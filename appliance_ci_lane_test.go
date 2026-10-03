package main

// The appliance qualification lane in the Deep PR Gate (owner review, PR
// #1528): the real-image harnesses must RUN whenever the appliance, the
// backup/restore path, the deploy bundle or the harnesses change, against the
// same deep-gate-image artifact the other deep jobs consume, and the aggregate
// must count them. Pinned here because needs-verdict reads a skipped job as a
// pass: a classifier that stops marking these paths, or an aggregate that
// drops a job, turns a red harness into a green gate silently.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestApplianceLane_ClassifierRunsTheHarnessesForApplianceChanges(t *testing.T) {
	body := qaGuardScript(t, ".github/workflows/pr-deep-gate.yml", "changes", "Classify changed files")
	body = strings.ReplaceAll(body, "${{ github.event_name }}", "pull_request")
	cases := map[string][]string{
		"appliance/provision/culvert-firstboot.sh":   {"appliance=true", "packaging=true", "image_needed=true"},
		"appliance/build/build-ova.sh":               {"appliance=true", "packaging=true", "image_needed=true"},
		"appliance/build/manifest.env":               {"appliance=true", "image_needed=true"},
		"test/e2e/appliance/lifecycle-qualify.sh":    {"appliance=true", "image_needed=true"},
		"restore_inplace.go":                         {"appliance=true", "image_needed=true"},
		"backup.go":                                  {"appliance=true", "image_needed=true"},
		"scripts/install.sh":                         {"appliance=true", "packaging=true", "image_needed=true"},
		"docker-compose.yml":                         {"appliance=true", "docker=true", "image_needed=true"},
		"packaging/culvert-maint/install.sh":         {"appliance=true", "packaging=true"},
		"appliance/os-maintenance/culvert-os-update": {"appliance=true", "packaging=true"},
		// Codex P1 (PR #1528): a maintenance-agent-only change selects the
		// appliance-agent job, which consumes the gate image — so it must
		// also build it, or the job is skipped and the aggregate reads the
		// skip as a pass.
		"cmd/culvert-maint/internal/runner/runner.go": {"maint=true", "image_needed=true", "appliance=false"},
	}
	for path, wants := range cases {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			script := strings.ReplaceAll(body, "git diff --name-only HEAD^1 HEAD > changed.txt", "printf '%s\\n' '"+path+"' > changed.txt")
			out, ok := runShell(t, "export GITHUB_OUTPUT=outputs\n"+script, dir)
			if !ok {
				t.Fatalf("classifier: %s", out)
			}
			result, err := os.ReadFile(filepath.Join(dir, "outputs"))
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range wants {
				if !strings.Contains(string(result), w) {
					t.Errorf("%s: want %s in\n%s", path, w, result)
				}
			}
		})
	}
	// Control: an unrelated file must not drag the 40-minute lane in.
	t.Run("control-unrelated", func(t *testing.T) {
		dir := t.TempDir()
		script := strings.ReplaceAll(body, "git diff --name-only HEAD^1 HEAD > changed.txt", "printf '%s\\n' 'docs/operator/upstream-proxies.md' > changed.txt")
		if out, ok := runShell(t, "export GITHUB_OUTPUT=outputs\n"+script, dir); !ok {
			t.Fatalf("classifier: %s", out)
		}
		result, _ := os.ReadFile(filepath.Join(dir, "outputs"))
		if !strings.Contains(string(result), "appliance=false") {
			t.Fatalf("docs-only change must not run the appliance lane:\n%s", result)
		}
	})
}

// applianceJobShape reports the four properties every appliance job must
// carry: it depends on the gate image build, downloads that image artifact,
// loads it into docker, and runs an appliance harness against it.
func applianceJobShape(j map[string]interface{}) (needsBuild, downloadsArtifact, loadsImage, runsHarness bool) {
	needs, _ := j["needs"].([]interface{})
	for _, n := range needs {
		if toStr(n) == "build-image" {
			needsBuild = true
		}
	}
	steps, _ := j["steps"].([]interface{})
	for _, st := range steps {
		s := asMap(st)
		uses, run := toStr(s["uses"]), toStr(s["run"])
		if strings.HasPrefix(uses, "actions/download-artifact@") && toStr(asMap(s["with"])["name"]) == "deep-gate-image" {
			downloadsArtifact = true
		}
		if strings.Contains(run, "docker load -i culvert-image.tar") {
			loadsImage = true
		}
		if strings.Contains(run, "test/e2e/appliance/") && strings.Contains(run, "-qualify.sh") {
			runsHarness = true
		}
	}
	return needsBuild, downloadsArtifact, loadsImage, runsHarness
}

func TestApplianceLane_JobsConsumeTheGateImageAndAreAggregated(t *testing.T) {
	path := filepath.Join(pkgSourceDir(), ".github", "workflows", "pr-deep-gate.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	jobs := asMap(genericWorkflow(t, path)["jobs"])
	aggNeeds, _ := asMap(jobs["deep-gate-approved"])["needs"].([]interface{})
	for _, job := range []string{"appliance-lifecycle", "appliance-clamav", "appliance-agent"} {
		j := asMap(jobs[job])
		if j == nil {
			t.Fatalf("job %s missing", job)
		}
		needsBuild, downloadsArtifact, loadsImage, runsHarness := applianceJobShape(j)
		if !needsBuild || !downloadsArtifact || !loadsImage || !runsHarness {
			t.Errorf("%s: needsBuild=%v downloadsArtifact=%v loadsImage=%v runsHarness=%v", job, needsBuild, downloadsArtifact, loadsImage, runsHarness)
		}
		if !strings.Contains(toStr(j["if"]), "needs.changes.outputs.appliance == 'true'") {
			t.Errorf("%s: must be gated on the appliance classifier output (got %q)", job, toStr(j["if"]))
		}
		found := false
		for _, n := range aggNeeds {
			if toStr(n) == job {
				found = true
			}
		}
		if !found {
			t.Errorf("deep-gate-approved does not need %s — a red harness would not block the gate", job)
		}
	}
	// The real-ClamAV job must really run the real sidecar.
	if !strings.Contains(string(raw), "CULVERT_QUALIFY_REAL_CLAMAV: \"1\"") {
		t.Error("appliance-clamav must set CULVERT_QUALIFY_REAL_CLAMAV=1")
	}
}

// Every job that consumes the gate image (`needs: build-image`) must be
// selected only by classifier outputs that ALSO set image_needed; otherwise a
// change selecting the job without the build skips it, and needs-verdict
// reads a skipped job as a pass (Codex P1, PR #1528: `maint` selected
// appliance-agent while image_needed ignored it). Structural, so a future job
// or classifier edit cannot reopen the gap without failing here.
func TestApplianceLane_ImageConsumersAreCoveredByImageNeeded(t *testing.T) {
	path := filepath.Join(pkgSourceDir(), ".github", "workflows", "pr-deep-gate.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*if (\$[a-z_]+(?: \|\| \$[a-z_]+)*); then\n\s*image_needed=true`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("image_needed expression not found in the classifier")
	}
	covered := map[string]bool{}
	for _, v := range strings.Split(m[1], "||") {
		covered[strings.TrimPrefix(strings.TrimSpace(v), "$")] = true
	}
	if !covered["appliance"] || !covered["maint"] {
		t.Fatalf("image_needed must cover appliance and maint, got %v", covered)
	}
	jobs := asMap(genericWorkflow(t, path)["jobs"])
	outRef := regexp.MustCompile(`needs\.changes\.outputs\.([a-z_]+) == 'true'`)
	consumers := 0
	for name, raw := range jobs {
		j := asMap(raw)
		needs, _ := j["needs"].([]interface{})
		dependsOnImage := false
		for _, n := range needs {
			if toStr(n) == "build-image" {
				dependsOnImage = true
			}
		}
		if !dependsOnImage {
			continue
		}
		consumers++
		cond := toStr(j["if"])
		if strings.Contains(cond, "always()") {
			continue // the aggregate: it depends on every job and renders the verdict
		}
		refs := outRef.FindAllStringSubmatch(cond, -1)
		if len(refs) == 0 {
			t.Errorf("job %s needs build-image but has no classifier condition (%q)", name, cond)
		}
		for _, r := range refs {
			if r[1] != "image_needed" && !covered[r[1]] {
				t.Errorf("job %s is selected by output %q, which does not set image_needed — a %s-only change would skip it silently", name, r[1], r[1])
			}
		}
	}
	if consumers < 3 {
		t.Fatalf("expected the three appliance jobs (at least) to consume build-image, found %d", consumers)
	}
}

// CVE-2026-103111 (PR #1528 closeout): the pcre2 derivative is a REVIEW
// candidate, not a shipped artefact. Three properties keep it that way and
// keep its evidence honest: it derives from exactly the pinned official image,
// CI executes the real-ClamAV check against both images, and no shipped file
// (compose, manifest, installer) references it.
func TestClamAVCandidate_DerivesFromThePinnedOfficialImage(t *testing.T) {
	dir := pkgSourceDir()
	df, err := os.ReadFile(filepath.Join(dir, "appliance", "clamav-candidate", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "appliance", "build", "manifest.env"))
	if err != nil {
		t.Fatal(err)
	}
	pin := regexp.MustCompile(`(?m)^CLAMAV_IMAGE_INDEX_DIGEST=(sha256:[0-9a-f]{64})$`).FindSubmatch(manifest)
	if pin == nil {
		t.Fatal("CLAMAV_IMAGE_INDEX_DIGEST not found in manifest.env")
	}
	froms := regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllSubmatch(df, -1)
	if len(froms) != 1 || string(froms[0][1]) != "docker.io/clamav/clamav@"+string(pin[1]) {
		t.Fatalf("candidate must have exactly one FROM, the pinned official digest %s; got %q", pin[1], froms)
	}
	// One package, pinned to an exact version: a floating `apk upgrade` would
	// make the evidence describe an image nobody can rebuild.
	if !strings.Contains(string(df), "apk add --no-cache --upgrade 'pcre2=10.49-r0'") {
		t.Fatal("candidate must upgrade exactly pcre2 to a pinned version")
	}
}

func TestClamAVCandidate_CIQualifiesBothImagesAndNothingShipsTheCandidate(t *testing.T) {
	dir := pkgSourceDir()
	path := filepath.Join(dir, ".github", "workflows", "pr-deep-gate.yml")
	jobs := asMap(genericWorkflow(t, path)["jobs"])
	steps, _ := asMap(jobs["appliance-clamav"])["steps"].([]interface{})
	official, candidate := false, false
	for _, st := range steps {
		run := toStr(asMap(st)["run"])
		if strings.Contains(run, "docker push") {
			t.Fatal("appliance-clamav must never push an image")
		}
		if !strings.Contains(run, "clamav-image-qualify.sh") {
			continue
		}
		if strings.Contains(run, `CLAMAV_IMAGE="${CLAMAV_IMAGE_REPO}@${CLAMAV_IMAGE_INDEX_DIGEST}"`) {
			official = true
		}
		if strings.Contains(run, "docker build") && strings.Contains(run, "appliance/clamav-candidate") {
			candidate = true
		}
	}
	if !official || !candidate {
		t.Fatalf("appliance-clamav must run clamav-image-qualify.sh against the pinned official image (%v) and the built candidate (%v)", official, candidate)
	}
	for _, shipped := range []string{"docker-compose.yml", "appliance/build/manifest.env", "scripts/install.sh"} {
		raw, err := os.ReadFile(filepath.Join(dir, shipped))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "culvert-candidate/clamav") || strings.Contains(string(raw), "clamav-candidate") {
			t.Errorf("%s references the unpublished ClamAV candidate — switching the sidecar is an owner decision", shipped)
		}
	}
}
