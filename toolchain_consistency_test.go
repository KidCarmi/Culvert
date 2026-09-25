package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// ─────────────────────────────────────────────────────────────────────────────
// CI-REDESIGN §20 wall: ONE compiler builds, tests and ships Culvert.
//
// The version lives in exactly one place, the root go.mod `toolchain` line.
// Every path that selects a Go compiler must agree with it:
//
//   - CI: actions/setup-go reads the `toolchain` line from go.mod (only while
//     GOTOOLCHAIN is not yet "local"; it exports GOTOOLCHAIN=local itself), and
//     setup-go-cache records and verifies the installed compiler.
//   - Release binaries: built under that toolchain; build-release-binaries
//     verifies the compiler each binary records before it is hashed or signed.
//   - Docker builder stages (production builder + maintbuilder, E2E builder):
//     a golang image pinned by DIGEST whose tag names the same version, an
//     explicit GOTOOLCHAIN=local, an in-build assertion against go.mod, and a
//     check of the compiler recorded in the built binary.
//
// Before this wall the production images were built by whatever
// `golang:1.27-alpine` resolved to (Go 1.27.1) while CI qualified Go 1.26.6 —
// nothing compared the two. Each check below has a negative control that
// feeds it the conflicting declaration it exists to reject.
// ─────────────────────────────────────────────────────────────────────────────

// toolchainInputs is every file whose content selects a compiler, keyed by
// repository path so a violation names the file to fix.
type toolchainInputs struct {
	rootGoMod  string
	maintGoMod string
	docker     map[string]string // Dockerfiles that compile Go
	ci         map[string]string // workflows + composite actions (raw YAML)
}

const (
	toolchainSetupAction   = ".github/actions/setup-go-cache/action.yml"
	toolchainReleaseAction = ".github/actions/build-release-binaries/action.yml"
)

var toolchainDockerfiles = []string{"Dockerfile", "test/e2e/maint-agent/Dockerfile.e2e"}

func loadToolchainInputs(t *testing.T) toolchainInputs {
	t.Helper()
	in := toolchainInputs{
		rootGoMod:  string(mustRead(t, "go.mod")),
		maintGoMod: string(mustRead(t, "cmd/culvert-maint/go.mod")),
		docker:     map[string]string{},
		ci:         map[string]string{},
	}
	for _, p := range toolchainDockerfiles {
		in.docker[p] = string(mustRead(t, p))
	}
	for _, glob := range []string{".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.yml"} {
		paths, err := filepath.Glob(glob)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			in.ci[p] = string(mustRead(t, p))
		}
	}
	if len(in.ci) < 10 {
		t.Fatalf("found only %d workflow/action files — the glob no longer reaches .github", len(in.ci))
	}
	return in
}

var (
	goModToolchainRe = regexp.MustCompile(`(?m)^toolchain\s+(\S+)\s*$`)
	goModGoRe        = regexp.MustCompile(`(?m)^go\s+(\S+)\s*$`)
	stableGoRe       = regexp.MustCompile(`^go(\d+)\.(\d+)\.(\d+)$`)
	pinnedGolangRe   = regexp.MustCompile(`^golang:(\d+\.\d+\.\d+)-alpine@sha256:[0-9a-f]{64}$`)
	toolchainAssign  = regexp.MustCompile(`(?m)(^\s*|[;&|]\s*|\bexport\s+)GOTOOLCHAIN\s*=`)
)

// rootToolchain returns the root go.mod `toolchain` version ("go1.27.1").
func rootToolchain(goMod string) (tc string, violations []string) {
	m := goModToolchainRe.FindAllStringSubmatch(goMod, -1)
	if len(m) != 1 {
		return "", []string{fmt.Sprintf("go.mod must carry exactly one `toolchain` line (the compiler for CI, releases and images); found %d", len(m))}
	}
	tc = m[0][1]
	v := violations
	if !stableGoRe.MatchString(tc) {
		v = append(v, fmt.Sprintf("go.mod toolchain %q is not a stable goX.Y.Z release", tc))
	}
	if g := goModGoRe.FindStringSubmatch(goMod); g == nil {
		v = append(v, "go.mod has no `go` line")
	} else if goVersionLess(tc, "go"+g[1]) {
		v = append(v, fmt.Sprintf("go.mod toolchain %s is older than its own minimum `go %s`", tc, g[1]))
	}
	return tc, v
}

// goVersionLess compares goX.Y[.Z] versions numerically.
func goVersionLess(a, b string) bool {
	pa, pb := goVersionParts(a), goVersionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func goVersionParts(v string) [3]int {
	var out [3]int
	for i, s := range strings.SplitN(strings.TrimPrefix(v, "go"), ".", 3) {
		n, _ := strconv.Atoi(s)
		out[i] = n
	}
	return out
}

// golangStage is one Dockerfile stage built FROM a golang image.
type golangStage struct {
	file, name, image, body string
}

var dockerFromRe = regexp.MustCompile(`(?im)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$`)

func golangStages(file, src string) []golangStage {
	locs := dockerFromRe.FindAllStringSubmatchIndex(src, -1)
	var out []golangStage
	for i, l := range locs {
		image := src[l[2]:l[3]]
		name := ""
		if l[4] >= 0 {
			name = src[l[4]:l[5]]
		}
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		if strings.Contains(image, "golang") {
			out = append(out, golangStage{file: file, name: name, image: image, body: src[l[1]:end]})
		}
	}
	return out
}

func toolchainViolations(in toolchainInputs) []string {
	tc, v := rootToolchain(in.rootGoMod)
	if tc == "" {
		return v
	}
	want := strings.TrimPrefix(tc, "go")

	// The agent module deliberately carries NO toolchain line (the installer's
	// offline source-build fallback must not be sent to download one); if one
	// is ever added it must agree.
	if m := goModToolchainRe.FindStringSubmatch(in.maintGoMod); len(m) > 1 && m[1] != tc {
		v = append(v, fmt.Sprintf("cmd/culvert-maint/go.mod toolchain %s conflicts with the root go.mod toolchain %s", m[1], tc))
	}

	v = append(v, dockerToolchainViolations(in.docker, want)...)
	v = append(v, ciToolchainViolations(in.ci)...)
	return v
}

func dockerToolchainViolations(docker map[string]string, want string) []string {
	var v []string
	var stages []golangStage
	files := make([]string, 0, len(docker))
	for f := range docker {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		stages = append(stages, golangStages(f, docker[f])...)
	}
	if len(stages) < 3 {
		return append(v, fmt.Sprintf("found %d golang builder stages, want >= 3 (builder, maintbuilder, E2E builder) — the parser no longer sees them", len(stages)))
	}
	images := map[string]bool{}
	for _, s := range stages {
		where := s.file + " stage " + strconv.Quote(s.name)
		images[s.image] = true
		m := pinnedGolangRe.FindStringSubmatch(s.image)
		switch {
		case m == nil:
			v = append(v, fmt.Sprintf("%s: builder image %q must be golang:<X.Y.Z>-alpine@sha256:<digest> — a tag alone can move to another compiler", where, s.image))
		case m[1] != want:
			v = append(v, fmt.Sprintf("%s: builder image is Go %s but the go.mod toolchain is go%s", where, m[1], want))
		}
		if !regexp.MustCompile(`(?m)^ENV\s+GOTOOLCHAIN=local\s*$`).MatchString(s.body) {
			v = append(v, where+": missing `ENV GOTOOLCHAIN=local` (the go command could switch to another toolchain)")
		}
		assert, build := -1, -1
		for i, ins := range dockerInstructions(s.body) {
			if assert < 0 && strings.Contains(ins, "go env GOVERSION") && strings.Contains(ins, `s/^toolchain //p`) {
				assert = i
			}
			if build < 0 && strings.Contains(ins, "go build") {
				build = i
			}
		}
		switch {
		case assert < 0:
			v = append(v, where+": missing the compiler assertion against the go.mod toolchain line")
		case build >= 0 && assert > build:
			v = append(v, where+": the compiler assertion runs after `go build`")
		}
		if !regexp.MustCompile(`(?m)^RUN go version \S+ && `).MatchString(s.body) {
			v = append(v, where+": missing the check of the compiler recorded in the built binary")
		}
	}
	if len(images) > 1 {
		list := make([]string, 0, len(images))
		for im := range images {
			list = append(list, im)
		}
		sort.Strings(list)
		v = append(v, "golang builder stages disagree on the image: "+strings.Join(list, ", "))
	}
	return v
}

func ciToolchainViolations(ci map[string]string) []string {
	var v []string
	files := make([]string, 0, len(ci))
	for f := range ci {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		var doc interface{}
		if err := yaml.Unmarshal([]byte(ci[f]), &doc); err != nil {
			v = append(v, f+": unparsable YAML: "+err.Error())
			continue
		}
		walkYAML(doc, func(m map[string]interface{}) {
			if env, ok := m["env"].(map[string]interface{}); ok {
				if _, set := env["GOTOOLCHAIN"]; set {
					v = append(v, f+": sets GOTOOLCHAIN in an env block — setup-go then ignores the go.mod toolchain line")
				}
			}
			if run, ok := m["run"].(string); ok && toolchainAssign.MatchString(run) {
				v = append(v, f+": a run script assigns GOTOOLCHAIN")
			}
			if uses, ok := m["uses"].(string); ok && strings.HasPrefix(uses, "actions/setup-go@") {
				with, _ := m["with"].(map[string]interface{})
				if _, lit := with["go-version"]; lit {
					v = append(v, f+": actions/setup-go with a literal go-version (must read go-version-file: go.mod)")
				}
				if toStr(with["go-version-file"]) != "go.mod" {
					v = append(v, f+": actions/setup-go must use go-version-file: go.mod")
				}
			}
		})
	}
	v = append(v, verifyStepViolations(ci, toolchainSetupAction, "go env GOVERSION", "GOTOOLCHAIN")...)
	v = append(v, verifyStepViolations(ci, toolchainReleaseAction, `go version "${bin}"`, "")...)
	return v
}

// verifyStepViolations requires the action's LAST step to compare the given
// compiler probe with the go.mod toolchain line.
func verifyStepViolations(ci map[string]string, path, probe, alsoChecks string) []string {
	src, ok := ci[path]
	if !ok {
		return []string{path + ": missing"}
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return []string{path + ": unparsable YAML"}
	}
	steps, _ := asMap(doc["runs"])["steps"].([]interface{})
	if len(steps) == 0 {
		return []string{path + ": no steps"}
	}
	run := toStr(asMap(steps[len(steps)-1])["run"])
	if !strings.Contains(run, probe) || !strings.Contains(run, `s/^toolchain //p`) || !strings.Contains(run, "exit 1") ||
		(alsoChecks != "" && !strings.Contains(run, alsoChecks)) {
		return []string{path + ": the last step must compare " + strconv.Quote(probe) + " with the go.mod toolchain line and fail on a mismatch"}
	}
	return nil
}

func walkYAML(n interface{}, visit func(map[string]interface{})) {
	switch x := n.(type) {
	case map[string]interface{}:
		visit(x)
		for _, c := range x {
			walkYAML(c, visit)
		}
	case []interface{}:
		for _, c := range x {
			walkYAML(c, visit)
		}
	}
}

// TestToolchain_OneCompilerEverywhere is the wall on the real repository.
func TestToolchain_OneCompilerEverywhere(t *testing.T) {
	for _, msg := range toolchainViolations(loadToolchainInputs(t)) {
		t.Error(msg)
	}
}

// TestToolchain_RejectsConflictingDeclarations derives each conflicting
// declaration from the REAL files and requires the wall to reject it. Every
// mutation must apply, or it would test the unmodified tree and pass by
// accident.
func TestToolchain_RejectsConflictingDeclarations(t *testing.T) {
	base := loadToolchainInputs(t)
	tc, _ := rootToolchain(base.rootGoMod)
	ver := strings.TrimPrefix(tc, "go")
	builder := dockerfileFromLine(t, base.docker["Dockerfile"], "builder")
	img := strings.Fields(builder)[2]
	at := strings.Index(img, "@")
	if at < 0 {
		t.Fatalf("builder image %q carries no digest", img)
	}
	digest := img[at:]
	p := goVersionParts(tc)
	other := fmt.Sprintf("%d.%d.%d", p[0], p[1], p[2]+1)

	type mut struct {
		name, want string
		apply      func(in *toolchainInputs) bool
	}
	replaceIn := func(s *string, old, new string) bool {
		if strings.Count(*s, old) < 1 {
			return false
		}
		*s = strings.Replace(*s, old, new, 1)
		return true
	}
	replaceDocker := func(file, old, new string) func(*toolchainInputs) bool {
		return func(in *toolchainInputs) bool {
			s := in.docker[file]
			ok := replaceIn(&s, old, new)
			in.docker[file] = s
			return ok
		}
	}
	cases := []mut{
		{"go.mod names a compiler the images do not use", "builder image is Go " + ver,
			func(in *toolchainInputs) bool { return replaceIn(&in.rootGoMod, "toolchain "+tc, "toolchain go"+other) }},
		{"go.mod loses its toolchain line", "exactly one `toolchain` line",
			func(in *toolchainInputs) bool { return replaceIn(&in.rootGoMod, "toolchain "+tc+"\n", "") }},
		{"go.mod toolchain is a release candidate", "not a stable",
			func(in *toolchainInputs) bool {
				return replaceIn(&in.rootGoMod, "toolchain "+tc, "toolchain "+tc+"rc1")
			}},
		{"builder tag names another compiler", "builder image is Go " + other,
			replaceDocker("Dockerfile", "golang:"+ver+"-alpine", "golang:"+other+"-alpine")},
		{"builder back on a floating tag", "must be golang:<X.Y.Z>-alpine@sha256",
			replaceDocker("Dockerfile", img, "golang:1.27-alpine")},
		{"builder tag without a digest", "must be golang:<X.Y.Z>-alpine@sha256",
			replaceDocker("Dockerfile", img, strings.TrimSuffix(img, digest))},
		{"maintbuilder on a different digest", "disagree on the image",
			replaceDocker("Dockerfile", img+" AS maintbuilder", "golang:"+ver+"-alpine@sha256:"+strings.Repeat("0", 64)+" AS maintbuilder")},
		{"E2E builder drifts from production", "disagree on the image",
			replaceDocker("test/e2e/maint-agent/Dockerfile.e2e", img, "golang:"+ver+"-alpine@sha256:"+strings.Repeat("1", 64))},
		{"stage drops GOTOOLCHAIN=local", "missing `ENV GOTOOLCHAIN=local`",
			replaceDocker("Dockerfile", "ENV GOTOOLCHAIN=local\n", "")},
		{"E2E builder drops the compiler assertion", "missing the compiler assertion",
			replaceDocker("test/e2e/maint-agent/Dockerfile.e2e", "go env GOVERSION)\" && \\", "true)\" && \\")},
		{"maintbuilder drops the recorded-compiler check", "missing the check of the compiler recorded",
			replaceDocker("Dockerfile", "RUN go version /culvert-maint && ", "RUN true && ")},
		{"agent go.mod names another toolchain", "cmd/culvert-maint/go.mod toolchain",
			func(in *toolchainInputs) bool {
				return replaceIn(&in.maintGoMod, "\ngo 1.25\n", "\ngo 1.25\n\ntoolchain go"+other+"\n")
			}},
		{"a workflow sets GOTOOLCHAIN before setup-go", "sets GOTOOLCHAIN in an env block",
			func(in *toolchainInputs) bool {
				s := in.ci[".github/workflows/pr-fast-gate.yml"]
				ok := replaceIn(&s, "\nenv:\n", "\nenv:\n  GOTOOLCHAIN: local\n")
				in.ci[".github/workflows/pr-fast-gate.yml"] = s
				return ok
			}},
		{"setup-go given a literal version", "literal go-version",
			func(in *toolchainInputs) bool {
				s := in.ci[toolchainSetupAction]
				ok := replaceIn(&s, "go-version-file: go.mod", "go-version: \"1.27\"")
				in.ci[toolchainSetupAction] = s
				return ok
			}},
		{"setup-go-cache stops verifying the compiler", toolchainSetupAction + ": the last step",
			func(in *toolchainInputs) bool {
				s := in.ci[toolchainSetupAction]
				ok := replaceIn(&s, `have="$(go env GOVERSION)"`, `have="$(cat /dev/null)"`)
				in.ci[toolchainSetupAction] = s
				return ok
			}},
		{"release action stops verifying the binaries", toolchainReleaseAction + ": the last step",
			func(in *toolchainInputs) bool {
				s := in.ci[toolchainReleaseAction]
				ok := replaceIn(&s, `go version "${bin}"`, `echo "${bin}"`)
				in.ci[toolchainReleaseAction] = s
				return ok
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := toolchainInputs{rootGoMod: base.rootGoMod, maintGoMod: base.maintGoMod, docker: map[string]string{}, ci: map[string]string{}}
			for k, v := range base.docker {
				in.docker[k] = v
			}
			for k, v := range base.ci {
				in.ci[k] = v
			}
			if !c.apply(&in) {
				t.Fatal("mutation anchor not found — the control no longer tests anything")
			}
			got := strings.Join(toolchainViolations(in), "\n")
			if !strings.Contains(got, c.want) {
				t.Errorf("conflicting declaration accepted; want a violation containing %q, got:\n%s", c.want, got)
			}
		})
	}
}

// TestToolchain_WallSeesEveryCompilerPath guards the wall itself: the files it
// reads must still be the ones that compile Go.
func TestToolchain_WallSeesEveryCompilerPath(t *testing.T) {
	for _, p := range toolchainDockerfiles {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	var all []string
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), "Dockerfile") {
			all = append(all, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < len(toolchainDockerfiles) {
		t.Fatalf("walk found %d Dockerfiles, fewer than the %d the wall reads", len(all), len(toolchainDockerfiles))
	}
	for _, p := range all {
		src := string(mustRead(t, p))
		if len(golangStages(p, src)) == 0 || strings.Contains(strings.Join(toolchainDockerfiles, " "), p) {
			continue
		}
		t.Errorf("%s builds Go but is not covered by the toolchain wall — add it to toolchainDockerfiles", p)
	}
}
