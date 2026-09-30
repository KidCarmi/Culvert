package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func admissionGateSelectsBoth(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if !strings.Contains(line, "go test ") {
			continue
		}
		seen := map[string]bool{}
		for _, f := range fields {
			seen[f] = true
		}
		if seen["."] && seen["./internal/admission"] && seen["benchgate"] && seen["'TestBenchGate_'"] && seen["-count=1"] {
			return true
		}
	}
	return false
}

// All three shipped entry points must run both packages; omission is otherwise
// a successful go test of the wrong package. Exercise that negative control.
func TestAdmissionMigration_BenchgateSelectors(t *testing.T) {
	for wf, job := range map[string]string{"pr-fast-gate.yml": "benchgate", "qa-gate.yml": "qa-bench", "proxy-weekly-stress.yml": "benchgate"} {
		t.Run(wf, func(t *testing.T) {
			var body string
			for _, step := range qaJobStepsIn(t, filepath.Join(".github", "workflows", wf), job) {
				body += toStr(step["run"]) + "\n"
			}
			if !admissionGateSelectsBoth(body) {
				t.Fatal("benchgate must execute root and admission with result caching disabled")
			}
			for name, broken := range map[string]string{
				"omitted admission": strings.ReplaceAll(body, " ./internal/admission", ""),
				"omitted root":      strings.ReplaceAll(body, " . ./internal/admission", " ./internal/admission"),
				"wrong selector":    strings.ReplaceAll(body, "'TestBenchGate_'", "'TestMissing_'"),
				"missing tag":       strings.ReplaceAll(body, "-tags benchgate", ""),
			} {
				if admissionGateSelectsBoth(broken) {
					t.Errorf("accepted %s", name)
				}
			}
		})
	}
}

// Drive the actual floor script against real statement locations. Healthy
// unrelated files and residual security shims cannot hide an omitted engine.
func TestAdmissionMigration_CoverageRejectsOmittedEngine(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module admission.test/floors\n\ngo 1.21\n")
	files := []string{"totp.go", "security.go", "session.go", "lockout.go", "policy.go", "autoexclude.go", "autoexclude_resolve.go", "controlplane_delta.go", "controlplane_client.go", "internal/admission/engine.go", "internal/admission/freshness.go"}
	tests := map[string]string{}
	for i, file := range files {
		write(file, fmt.Sprintf("package floors\nfunc F%d() int { return %d }\n", i, i))
		tests[filepath.Dir(file)] += fmt.Sprintf("if F%d() != %d { t.Fatal(\"fixture\") };\n", i, i)
	}
	for folder, checks := range tests {
		write(filepath.Join(folder, "floors_test.go"), "package floors\nimport \"testing\"\nfunc TestFloors(t *testing.T) {"+checks+"}\n")
	}
	cmd := exec.CommandContext(t.Context(), "go", "test", "-coverprofile=all.out", "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("coverage fixture: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "all.out"))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(pkgSourceDir(), ".github", "scripts", "coverage-floor.sh")
	cases := map[string]string{"covered": string(raw)}
	for _, target := range []string{"internal/admission/engine.go", "internal/admission/freshness.go", "security.go"} {
		var omitted, zero []string
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "/"+target+":") {
				zero = append(zero, line[:strings.LastIndex(line, " ")]+" 0")
			} else {
				omitted = append(omitted, line)
				zero = append(zero, line)
			}
		}
		cases["omitted "+target] = strings.Join(omitted, "\n")
		cases["uncovered "+target] = strings.Join(zero, "\n")
	}
	for name, profile := range cases {
		t.Run(name, func(t *testing.T) {
			write("candidate.out", profile)
			// #nosec G204 -- fixed repository script, test-owned profile in a temporary module.
			cmd := exec.CommandContext(t.Context(), "bash", script, "candidate.out")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if name == "covered" {
				if err != nil {
					t.Fatalf("positive control: %v\n%s", err, out)
				}
				return
			}
			target := strings.SplitN(name, " ", 2)[1]
			if err == nil || !strings.Contains(string(out), "::error file="+target+"::") {
				t.Fatalf("floor accepted %s or failed for another reason: %v\n%s", name, err, out)
			}
		})
	}
}

func TestAdmissionMigration_TransitionLoggingUsesEngineObservation(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })
	r := withClusterRateLimiter(t, 10, time.Minute)
	for i := 0; i < 3; i++ {
		noteClusterRateLimitFreshness(r)
	}
	r.ApplyRemoteCounts(nil)
	for i := 0; i < 3; i++ {
		noteClusterRateLimitFreshness(r)
	}
	if strings.Count(buf.String(), "WARN cluster rate limiting:") != 1 || strings.Count(buf.String(), "current again") != 1 || !strings.Contains(buf.String(), "stale episodes: 1") || r.ClusterFreshness().Episodes != 1 {
		t.Fatalf("transition logging disagrees with engine: %s", buf.String())
	}
}

func TestAdmissionMigration_DeepClassifier(t *testing.T) {
	body := qaGuardScript(t, ".github/workflows/pr-deep-gate.yml", "changes", "Classify changed files")
	body = strings.ReplaceAll(body, "${{ github.event_name }}", "pull_request")
	for _, path := range []string{"admission.go", "cluster_ratelimit_wire.go", "cluster_ratelimit_freshness.go", "internal/admission/engine.go", "internal/admission/security_test.go"} {
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
			if !strings.Contains(string(result), "security=true") || !strings.Contains(string(result), "image_needed=true") {
				t.Fatalf("security path skipped: %s", result)
			}
			if strings.HasSuffix(path, "_test.go") && !strings.Contains(string(result), "tests=true") {
				t.Fatalf("determinism skipped: %s", result)
			}
		})
	}
	raw, err := os.ReadFile(".github/workflows/codeql.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"admission.go", "cluster_ratelimit*.go", "internal/**"} {
		if !strings.Contains(string(raw), "- \""+path+"\"") {
			t.Errorf("CodeQL no longer covers %s", path)
		}
	}
}
