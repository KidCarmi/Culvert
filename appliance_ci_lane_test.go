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
		// The candidate version script shapes the image build's VERSION
		// (L11): editing it must rebuild the image and run every deep job.
		".github/scripts/pr-candidate-version.sh": {"appliance=true", "image_needed=true", "release=true"},
		// The appliance console (#1540) and its regression workflow select
		// the appliance lane, which runs the console suite.
		"cmd/culvert-console/main_linux.go":       {"appliance=true"},
		"internal/appliancehost/state.go":         {"appliance=true"},
		"internal/applianceconsole/view.go":       {"appliance=true"},
		".github/workflows/appliance-console.yml": {"appliance=true"},
	}
	for path, wants := range cases {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			script := strings.ReplaceAll(body, "git diff --no-renames --name-only HEAD^1 HEAD > changed.txt", "printf '%s\\n' '"+path+"' > changed.txt")
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
		script := strings.ReplaceAll(body, "git diff --no-renames --name-only HEAD^1 HEAD > changed.txt", "printf '%s\\n' 'docs/operator/upstream-proxies.md' > changed.txt")
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

// CVE-2026-103111: the appliance RUNS the pcre2 derivative of the pinned
// official ClamAV image, built locally and never published. These tests keep
// that true end to end: it derives from exactly the pinned digest with one
// pinned package; every file that names the sidecar names the SAME local tag;
// the build context ships in the deploy bundle; and CI qualifies the image
// the appliance runs (plus the official base, for comparison) without pushing.
func TestClamAVSidecar_DerivesFromThePinnedOfficialImage(t *testing.T) {
	dir := pkgSourceDir()
	df, err := os.ReadFile(filepath.Join(dir, "appliance", "clamav", "Dockerfile"))
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
		t.Fatalf("the sidecar must have exactly one FROM, the pinned official digest %s; got %q", pin[1], froms)
	}
	// One package, pinned to an exact version: a floating `apk upgrade` would
	// make the evidence describe an image nobody can rebuild.
	if !strings.Contains(string(df), "apk add --no-cache --upgrade 'pcre2=10.49-r0'") {
		t.Fatal("the sidecar must upgrade exactly pcre2 to a pinned version")
	}
}

func TestClamAVSidecar_EveryShippedFileNamesTheSameLocalTag(t *testing.T) {
	dir := pkgSourceDir()
	read := func(rel string) string {
		raw, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	m := regexp.MustCompile(`(?m)^CLAMAV_SIDECAR_REF=(\S+)$`).FindStringSubmatch(read("appliance/build/manifest.env"))
	if m == nil {
		t.Fatal("manifest.env must pin CLAMAV_SIDECAR_REF")
	}
	ref := m[1]
	if !strings.HasPrefix(ref, "culvert/clamav:") || !strings.Contains(ref, "pcre2-10.49") {
		t.Fatalf("CLAMAV_SIDECAR_REF %q must be the local-only culvert/clamav tag naming the pcre2 fix", ref)
	}
	for _, compose := range []string{"docker-compose.yml", "docker-compose.ha.yml"} {
		c := read(compose)
		if !strings.Contains(c, "    image: "+ref+"\n    build:\n      context: ./appliance/clamav\n") {
			t.Errorf("%s: the clamav service must name image %s with build context ./appliance/clamav", compose, ref)
		}
		if strings.Contains(c, "image: clamav/clamav") {
			t.Errorf("%s still runs the official image (pcre2 10.48, CVE-2026-103111)", compose)
		}
	}
	if !strings.Contains(read("Dockerfile"), "COPY --chown=proxy:proxy appliance/clamav/Dockerfile ./deploy/appliance/clamav/Dockerfile") {
		t.Error("the deploy bundle must carry the sidecar build context, or a host without the tag cannot start ClamAV")
	}
	if !strings.Contains(read("scripts/install.sh"), `"$INSTALL_DIR/appliance/clamav/Dockerfile"`) {
		t.Error("install.sh must copy the sidecar build context into the stack directory")
	}
	if fb := read("appliance/provision/culvert-firstboot.sh"); !strings.Contains(fb, `docker image inspect "$CLAMAV_SIDECAR_REF"`) || !strings.Contains(fb, "CLAMAV_SIDECAR_ID") {
		t.Error("first boot must verify the loaded sidecar against the ID the build recorded")
	}
}

func TestClamAVSidecar_CIQualifiesTheShippedImageAndPushesNothing(t *testing.T) {
	dir := pkgSourceDir()
	path := filepath.Join(dir, ".github", "workflows", "pr-deep-gate.yml")
	jobs := asMap(genericWorkflow(t, path)["jobs"])
	steps, _ := asMap(jobs["appliance-clamav"])["steps"].([]interface{})
	official, shipped := false, false
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
		if strings.Contains(run, "docker build") && strings.Contains(run, "appliance/clamav") && strings.Contains(run, `CLAMAV_IMAGE="$CLAMAV_SIDECAR_REF"`) {
			shipped = true
		}
	}
	if !official || !shipped {
		t.Fatalf("appliance-clamav must run clamav-image-qualify.sh against the official base (%v) and the shipped sidecar built from appliance/clamav (%v)", official, shipped)
	}
}

// Upgrade-under-ENOSPC (PR #1528 closeout): the agent lane must execute the
// bounded-host harness, and the harness may only ever fill a file INSIDE its
// own loop mount — filling anything else would fill the runner's (or an
// operator's) real disk.
func TestApplianceLane_AgentJobRunsTheBoundedENOSPCHarness(t *testing.T) {
	dir := pkgSourceDir()
	jobs := asMap(genericWorkflow(t, filepath.Join(dir, ".github", "workflows", "pr-deep-gate.yml"))["jobs"])
	steps, _ := asMap(jobs["appliance-agent"])["steps"].([]interface{})
	ran := false
	for _, st := range steps {
		if strings.Contains(toStr(asMap(st)["run"]), "./test/e2e/appliance/upgrade-enospc-qualify.sh") {
			ran = true
		}
	}
	if !ran {
		t.Fatal("appliance-agent must run test/e2e/appliance/upgrade-enospc-qualify.sh")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "test", "e2e", "appliance", "upgrade-enospc-qualify.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	fills := regexp.MustCompile(`(?m)^\s*fallocate\b.*$`).FindAllString(src, -1)
	if len(fills) != 1 || !strings.Contains(fills[0], `"$MNT/.qual-fill"`) {
		t.Fatalf("the only fill must target \"$MNT/.qual-fill\" inside the loop mount; got %q", fills)
	}
	for _, want := range []string{`mount -o loop "$IMG" "$MNT"`, `-v "$MNT/docker:/var/lib/docker"`, `-v "$MNT/containerd:/var/lib/containerd"`, "mkfs.ext4 -q -F -m 0"} {
		if !strings.Contains(src, want) {
			t.Errorf("bounded-host contract missing %q", want)
		}
	}
}

// F-DISK-1 is FIXED (third_party/ristretto/CULVERT-PATCH.md), so the midwrite
// scenario is a merge gate: the step may not be advisory, and the harness must
// count a crash, an unrefused write and an insufficient recovery as FAILURES —
// a "known-failure" verdict there would let the regression pass silently.
func TestApplianceLane_FullDiskMidwriteIsARequiredGate(t *testing.T) {
	dir := pkgSourceDir()
	jobs := asMap(genericWorkflow(t, filepath.Join(dir, ".github", "workflows", "pr-deep-gate.yml"))["jobs"])
	steps, _ := asMap(jobs["appliance-agent"])["steps"].([]interface{})
	found := false
	for _, st := range steps {
		m := asMap(st)
		if !strings.Contains(toStr(m["run"]), "QUAL_ENOSPC_SCENARIO=midwrite") {
			continue
		}
		found = true
		if v, ok := m["continue-on-error"]; ok && toStr(v) != "false" {
			t.Errorf("the F-DISK-1 midwrite step must not be continue-on-error (got %v)", v)
		}
	}
	if !found {
		t.Fatal("appliance-agent must run the F-DISK-1 midwrite scenario")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "test", "e2e", "appliance", "upgrade-enospc-qualify.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, want := range []string{
		`check W survived-full-disk fail "F-DISK-1 REGRESSED`,
		`check W write-refused-with-error fail`,
		`check W recovery-step-1-sufficient fail`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("midwrite harness must fail on %q", want)
		}
	}
	start := strings.Index(src, `if [[ "$SCENARIO" == midwrite ]]; then`+"\n  # Poll")
	if start < 0 {
		t.Fatal("midwrite scenario block not found")
	}
	w := src[start:]
	end := strings.Index(w, "\n# ── E1:")
	if end < 0 {
		t.Fatal("end of the midwrite scenario block not found")
	}
	if strings.Contains(w[:end], "known-failure") {
		t.Error("the midwrite scenario still reports a known-failure verdict; F-DISK-1 is fixed, a crash is a failure")
	}
}

// V1 integration (#1528 + #1540): the console + power/lifecycle regression
// suite is a REQUIRED result — called from the Deep gate and listed in its
// aggregate — not a separate path-filtered workflow whose red is advisory.
func TestApplianceLane_ConsoleSuiteIsPartOfTheRequiredDeepGate(t *testing.T) {
	path := filepath.Join(pkgSourceDir(), ".github", "workflows", "pr-deep-gate.yml")
	jobs := asMap(genericWorkflow(t, path)["jobs"])
	j := asMap(jobs["appliance-console"])
	if j == nil {
		t.Fatal("pr-deep-gate.yml has no appliance-console job")
	}
	if toStr(j["uses"]) != "./.github/workflows/appliance-console.yml" {
		t.Errorf("appliance-console must call the console workflow, got %q", toStr(j["uses"]))
	}
	for _, out := range []string{"appliance", "maint", "deps"} {
		if !strings.Contains(toStr(j["if"]), "needs.changes.outputs."+out+" == 'true'") {
			t.Errorf("appliance-console must run for %s changes (got %q)", out, toStr(j["if"]))
		}
	}
	aggNeeds, _ := asMap(jobs["deep-gate-approved"])["needs"].([]interface{})
	found := false
	for _, n := range aggNeeds {
		found = found || toStr(n) == "appliance-console"
	}
	if !found {
		t.Error("deep-gate-approved does not need appliance-console — a red console suite would not block the gate")
	}
	cw := filepath.Join(pkgSourceDir(), ".github", "workflows", "appliance-console.yml")
	on := asMap(genericWorkflow(t, cw)["on"])
	if _, ok := on["workflow_call"]; !ok {
		t.Error("appliance-console.yml must be callable (workflow_call)")
	}
	if _, ok := on["pull_request"]; ok {
		t.Error("appliance-console.yml must not also run on pull_request: the Deep gate runs it, and a duplicate advisory run invites ignoring the required one")
	}
	raw, err := os.ReadFile(cw)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"appliance/os-maintenance/power_test.sh", "appliance/console/install_test.sh", "appliance/build/console-bundle_test.sh", "CULVERT_STORAGE_FAULTS=1", "./internal/server ./internal/journal"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("appliance-console.yml no longer runs %q", want)
		}
	}
}
