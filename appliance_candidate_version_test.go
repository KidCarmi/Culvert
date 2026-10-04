package main

// PR #1528 §3f L11: a candidate (PR-built) image used to carry the version
// "dev" in both the proxy and its bundled maintenance agent. First boot
// installs the bundled agent only from a release-shaped stamp, so no
// candidate OVA ever had an agent and backup/restore/locking went
// unqualified. Candidates now carry vX.Y.(Z+1)-candidate.g<sha12> — a SemVer
// prerelease naming the commit built — supplied once to both builds.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const candidateVersionScript = ".github/scripts/pr-candidate-version.sh"

func runCandidateVersion(t *testing.T, sha, tags string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	f := filepath.Join(t.TempDir(), "tags")
	if err := os.WriteFile(f, []byte(tags), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), "bash", candidateVersionScript, sha, f).CombinedOutput() //nolint:gosec // repo script, test-owned args
	return strings.TrimSpace(string(out)), err
}

const candSHA = "c5551a18da30e1178861cd9b488fc2d9aa6de781"

func TestCandidateVersion_IsNextPatchPrereleaseNamingTheCommit(t *testing.T) {
	// sort -V, not lexical: v1.0.98 < v1.0.259; prerelease and junk tags ignored.
	got, err := runCandidateVersion(t, candSHA, "v1.0.98\nv1.0.259\nv1.0.300-rc1\nlatest\nv2\n")
	if err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if got != "v1.0.260-candidate.gc5551a18da30" {
		t.Fatalf("got %q", got)
	}
}

func TestCandidateVersion_RefusesRatherThanFallingBackToDev(t *testing.T) {
	for name, c := range map[string][2]string{
		"short sha":      {"c5551a18", "v1.0.259\n"},
		"uppercase sha":  {strings.ToUpper(candSHA), "v1.0.259\n"},
		"no release tag": {candSHA, "v1.0.300-rc1\nmain\n"},
	} {
		if out, err := runCandidateVersion(t, c[0], c[1]); err == nil {
			t.Errorf("%s: want a failure, got %q", name, out)
		}
	}
}

// The stamp must be accepted where it has to be (the installers' agent
// version gate) and rejected where a candidate must not pass for a release
// (the release-transition policy's bare X.Y.Z).
func TestCandidateVersion_InstallableButNeverAReleaseIdentity(t *testing.T) {
	got, err := runCandidateVersion(t, candSHA, "v1.0.259\n")
	if err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	installerGate := regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	if !installerGate.MatchString(got) {
		t.Fatalf("%q fails the installer's agent version gate", got)
	}
	src, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`) {
		t.Fatal("install.sh's agent version gate changed; re-check this test's copy of it")
	}
	if v, source := effectiveCurrentVersion(CurrentView{}, got); v != "" {
		t.Fatalf("a candidate stamp must be an UNKNOWN predecessor to the transition policy, got %q from %s", v, source)
	}
}

func TestBuildImage_SuppliesTheCandidateVersionToBothBinaries(t *testing.T) {
	wf, err := os.ReadFile(".github/workflows/_build-image.yml")
	if err != nil {
		t.Fatal(err)
	}
	w := string(wf)
	for _, want := range []string{
		".github/scripts/pr-candidate-version.sh",
		"github.event.pull_request.head.sha || github.sha",
		"VERSION=${{ steps.ver.outputs.version }}",
		`git diff --quiet "$src" "$built"`,
	} {
		if !strings.Contains(w, want) {
			t.Errorf("_build-image.yml lacks %q", want)
		}
	}
	// ONE build-arg feeds both: the proxy stage and the culvert-maint stage
	// each declare ARG VERSION and stamp it.
	df, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	d := string(df)
	if strings.Count(d, "\nARG VERSION=") < 2 || !strings.Contains(d, "-X main.version=${VERSION}") ||
		!strings.Contains(d, "-X culvert-maint/internal/server.Version=${VER}") {
		t.Fatal("Dockerfile no longer stamps VERSION into both the proxy and the bundled agent")
	}
}

// build-ova.sh's candidate gate, executed: it must accept the script's stamp
// for the SAME source commit with a matching agent, and refuse "dev", another
// commit's stamp, and an agent whose version differs.
func TestBuildOVA_CandidateVersionGate(t *testing.T) {
	src, err := os.ReadFile("appliance/build/build-ova.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, `  want_pre="-candidate.g${CANDIDATE_SOURCE:0:12}"`)
	end := strings.Index(s, `  VERSION="${APPLIANCE_VERSION:-${APP_VERSION#v}}"`)
	if start < 0 || end < start {
		t.Fatal("candidate version gate not found in build-ova.sh")
	}
	gate := s[start:end]
	run := func(app, maint, source string) bool {
		script := "set -u\ndie() { exit 1; }\nAPP_VERSION=" + app + "\nMAINT_VERSION=" + maint + "\nCANDIDATE_SOURCE=" + source + "\n" + gate + "\nexit 0\n"
		return exec.CommandContext(t.Context(), "bash", "-c", script).Run() == nil //nolint:gosec // test-owned script text
	}
	other := "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		name, app, maint, source string
		ok                       bool
	}{
		{"matching candidate", "v1.0.260-candidate.gc5551a18da30", "v1.0.260-candidate.gc5551a18da30", candSHA, true},
		{"no leading v in /app/VERSION", "1.0.260-candidate.gc5551a18da30", "v1.0.260-candidate.gc5551a18da30", candSHA, true},
		{"dev image", "dev", "dev", candSHA, false},
		{"another commit's image", "v1.0.260-candidate.g0123456789ab", "v1.0.260-candidate.g0123456789ab", candSHA, false},
		{"agent version differs", "v1.0.260-candidate.gc5551a18da30", "dev", candSHA, false},
		{"plain release stamp", "v1.0.260", "v1.0.260", candSHA, false},
		{"stamp for a different source", "v1.0.260-candidate.gc5551a18da30", "v1.0.260-candidate.gc5551a18da30", other, false},
	}
	for _, c := range cases {
		if got := run(c.app, c.maint, c.source); got != c.ok {
			t.Errorf("%s: gate accepted=%v, want %v", c.name, got, c.ok)
		}
	}
}

// The old installer said "not runnable on this host" for an agent that RAN
// and reported "dev"; that sent diagnosis to the architecture, not the stamp.
func TestInstallScript_NonReleaseAgentVersionIsReportedAsSuch(t *testing.T) {
	src, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	exec := strings.Index(s, `if ! bundled_version="$("$cand" --version 2>/dev/null)"; then`)
	notRunnable := strings.Index(s, "Bundled agent binary is not runnable on this host")
	gate := strings.Index(s, "not a release version (vX.Y.Z[-pre]) — not installing it.")
	if exec < 0 || notRunnable < exec || gate < notRunnable {
		t.Fatal("install.sh must report a failed exec and a non-release stamp separately")
	}
	if strings.Count(s, "Bundled agent binary is not runnable on this host") != 1 {
		t.Fatal(`"not runnable" must be reported only for a binary that did not run`)
	}
}
