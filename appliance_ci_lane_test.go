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
		var needsBuild, downloadsArtifact, loadsImage, runsHarness bool
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
