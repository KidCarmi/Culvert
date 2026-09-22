package main

// dockerfile_crossbuild_test.go — the anti-regression wall for native
// cross-compilation in the production Dockerfile (CI-REDESIGN §11, stage 3).
//
// Both Go stages (`builder`, `maintbuilder`) run on $BUILDPLATFORM and
// cross-compile for the target, so a linux/arm64 image no longer runs the Go
// compiler under QEMU. That makes one defect possible that was impossible
// before: when the compiler runs on the BUILD platform, any `go build` that
// does not take GOARCH from the TARGET compiles for the build HOST. The image
// still builds, the manifest still says arm64, every amd64 check stays green —
// and the binary is amd64. It fails only when an arm64 host executes it.
//
// The sharp edge is that the obvious text is not enough. `GOARCH=${TARGETARCH}`
// with no `ARG TARGETARCH` in the SAME stage expands to the EMPTY string — the
// automatic platform ARGs exist in global scope but must be re-declared inside
// a stage to be visible — and an empty GOARCH means "host". A grep for the
// assignment passes that defect. So this wall models the Dockerfile: it splits
// stages, tracks which ARGs each stage has declared at each RUN, reads the
// GOOS/GOARCH a `go build` actually receives, and requires them to come from
// TARGETOS/TARGETARCH that are IN SCOPE at that RUN.
//
// It also pins the other half of the design: every stage that compiles Go is
// on $BUILDPLATFORM (otherwise the compiler is emulated again — the defect
// this stage removed), and the FINAL stage is NOT (it must stay on the target
// so an arm64 image carries an arm64 userland).
//
// The wall proves itself: TestDockerfileCrossBuild_RejectsHostArchMutations
// derives each known defect from the REAL Dockerfile and requires the checker
// to reject it, so a checker that silently stopped matching cannot pass.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// crossBuildStage is one FROM … block of a Dockerfile.
type crossBuildStage struct {
	name     string // AS <name>, or "" for an unnamed stage
	platform string // the --platform= value on FROM, "" when absent
	builds   []crossBuildRun
}

// crossBuildRun is one RUN that invokes `go build`, with the ARGs the stage
// had declared by the time it ran.
type crossBuildRun struct {
	cmd      string
	argsSeen map[string]bool
}

// dockerInstructions joins `\` continuations and drops comment lines, the way
// the Dockerfile frontend does before it parses an instruction.
func dockerInstructions(src string) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue // comments are removed even inside a continuation
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

var (
	crossFromRe  = regexp.MustCompile(`(?i)^FROM\s+(?:--platform=(\S+)\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$`)
	crossArgRe   = regexp.MustCompile(`(?i)^ARG\s+([A-Za-z_][A-Za-z0-9_]*)`)
	crossGoBuild = regexp.MustCompile(`\bgo\s+build\b`)
)

// parseCrossBuildStages returns every stage in declaration order.
func parseCrossBuildStages(t *testing.T, src string) []crossBuildStage {
	t.Helper()
	var stages []crossBuildStage
	var args map[string]bool
	for _, ins := range dockerInstructions(src) {
		upper := strings.ToUpper(ins)
		switch {
		case strings.HasPrefix(upper, "FROM "):
			m := crossFromRe.FindStringSubmatch(ins)
			if m == nil {
				t.Fatalf("cannot parse FROM instruction %q", ins)
			}
			stages = append(stages, crossBuildStage{name: m[3], platform: m[1]})
			// ARGs never carry across FROM: each stage starts with none in
			// scope. A global (pre-FROM) ARG is deliberately NOT inherited.
			args = map[string]bool{}
		case len(stages) == 0:
			// Global scope (before the first FROM). Not attributed to any
			// stage — which is exactly the Dockerfile's own scoping rule.
		case strings.HasPrefix(upper, "ARG "):
			if m := crossArgRe.FindStringSubmatch(ins); m != nil {
				args[m[1]] = true
			}
		case strings.HasPrefix(upper, "RUN ") && crossGoBuild.MatchString(ins):
			seen := make(map[string]bool, len(args))
			for k := range args {
				seen[k] = true
			}
			st := &stages[len(stages)-1]
			st.builds = append(st.builds, crossBuildRun{cmd: ins, argsSeen: seen})
		}
	}
	return stages
}

// isBuildPlatform reports whether a FROM --platform value selects the BUILD
// platform (the host that runs the build).
func isBuildPlatform(p string) bool {
	return p == "$BUILDPLATFORM" || p == "${BUILDPLATFORM}"
}

// goEnvFor returns the value the LAST assignment of `key` receives before the
// first `go build` in cmd, or ok=false when none precedes it.
func goEnvFor(cmd, key string) (string, bool) {
	loc := crossGoBuild.FindStringIndex(cmd)
	if loc == nil {
		return "", false
	}
	re := regexp.MustCompile(`(?:^|[\s;&|(])` + key + `=("[^"]*"|'[^']*'|\S*)`)
	ms := re.FindAllStringSubmatch(cmd[:loc[0]], -1)
	if len(ms) == 0 {
		return "", false
	}
	return strings.Trim(ms[len(ms)-1][1], `"'`), true
}

// argRef returns the ARG name an expansion like ${X} or $X refers to, or "".
func argRef(v string) string {
	if m := regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$|^\$([A-Za-z_][A-Za-z0-9_]*)$`).FindStringSubmatch(v); m != nil {
		return m[1] + m[2]
	}
	return ""
}

// crossBuildViolations returns every way src breaks the cross-compilation
// contract. An empty result means the Dockerfile is sound.
func crossBuildViolations(t *testing.T, src string) []string {
	t.Helper()
	stages := parseCrossBuildStages(t, src)
	if len(stages) == 0 {
		return []string{"no FROM instruction found"}
	}
	var v []string

	compiling := map[string]bool{}
	for i := range stages {
		st := &stages[i]
		if len(st.builds) == 0 {
			continue
		}
		compiling[st.name] = true
		if !isBuildPlatform(st.platform) {
			v = append(v, "stage "+q(st.name)+" runs `go build` but is not FROM --platform=$BUILDPLATFORM (platform="+q(st.platform)+"): the Go compiler would run under QEMU for every non-native target")
			continue
		}
		for _, b := range st.builds {
			v = append(v, checkCrossBuildRun(st.name, b)...)
		}
	}

	// Not vacuous: both binaries the image ships must be built by a stage the
	// checker actually recognised. If a build moves into a script, or a stage
	// is renamed, this fails and whoever did it has to re-point the wall.
	for _, want := range []string{"builder", "maintbuilder"} {
		if !compiling[want] {
			v = append(v, "no `go build` found in stage "+q(want)+": the cross-build contract cannot be checked (moved into a script or renamed? update this wall)")
		}
	}

	// The runtime (final) stage must stay on the TARGET platform.
	final := stages[len(stages)-1]
	if isBuildPlatform(final.platform) {
		v = append(v, "final stage is FROM --platform=$BUILDPLATFORM: an arm64 image would carry the build host's userland")
	}
	return v
}

func checkCrossBuildRun(stage string, b crossBuildRun) []string {
	var v []string
	for _, want := range []struct{ env, arg string }{{"GOOS", "TARGETOS"}, {"GOARCH", "TARGETARCH"}} {
		val, ok := goEnvFor(b.cmd, want.env)
		switch {
		case !ok:
			v = append(v, "stage "+q(stage)+": `go build` has no "+want.env+" — on $BUILDPLATFORM it compiles for the build HOST")
		case argRef(val) != want.arg:
			v = append(v, "stage "+q(stage)+": `go build` gets "+want.env+"="+q(val)+", want ${"+want.arg+"} — any other value ignores the image's target platform")
		case !b.argsSeen[want.arg]:
			v = append(v, "stage "+q(stage)+": "+want.env+"=${"+want.arg+"} but `ARG "+want.arg+"` is not declared in this stage before the RUN — it expands to EMPTY, and an empty "+want.env+" means the build HOST")
		}
	}
	if val, ok := goEnvFor(b.cmd, "CGO_ENABLED"); !ok || val != "0" {
		v = append(v, "stage "+q(stage)+": `go build` must keep CGO_ENABLED=0 — a cgo cross-compile needs a target C toolchain and would not produce a static binary")
	}
	return v
}

func q(s string) string { return `"` + s + `"` }

func readDockerfile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	return string(b)
}

// TestDockerfileCrossBuild_BothBinariesTargetThePlatform is the gate: the
// shipped Dockerfile cross-compiles BOTH the proxy and the bundled agent for
// the target, on the build platform, and keeps the runtime on the target.
func TestDockerfileCrossBuild_BothBinariesTargetThePlatform(t *testing.T) {
	for _, msg := range crossBuildViolations(t, readDockerfile(t)) {
		t.Error(msg)
	}
}

// TestDockerfileCrossBuild_RejectsHostArchMutations derives every known way to
// break the contract from the REAL Dockerfile and requires each to be caught.
// Each mutation must APPLY (its anchor must exist exactly once): a mutation
// whose anchor stopped matching would otherwise test the unmodified file and
// "pass" by accident.
func TestDockerfileCrossBuild_RejectsHostArchMutations(t *testing.T) {
	real := readDockerfile(t)

	const (
		builderFrom = "FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder"
		maintFrom   = "FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS maintbuilder"
		maintEnv    = "CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \\\n      -ldflags=\"-s -w -X culvert-maint"
		maintArgs   = "ARG VERSION=\nARG TARGETOS\nARG TARGETARCH\nRUN VER="
		proxyEnv    = "CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags=\"-s -w -X main.version"
		runtimeFrom = "FROM alpine:3.24\n"
	)

	mutations := []struct {
		name, old, new string
	}{
		{"builder back on the target platform (emulated compile)", builderFrom, "FROM golang:1.27-alpine AS builder"},
		{"maintbuilder back on the target platform (emulated compile)", maintFrom, "FROM golang:1.27-alpine AS maintbuilder"},
		{"agent GOARCH dropped (builds for the host)", maintEnv,
			strings.Replace(maintEnv, " GOARCH=${TARGETARCH}", "", 1)},
		{"proxy GOARCH dropped (builds for the host)", proxyEnv,
			strings.Replace(proxyEnv, " GOARCH=${TARGETARCH}", "", 1)},
		{"agent ARG TARGETARCH undeclared (GOARCH expands empty)", maintArgs,
			"ARG VERSION=\nARG TARGETOS\nRUN VER="},
		{"agent ARG TARGETARCH declared only after the RUN", maintArgs,
			"ARG VERSION=\nARG TARGETOS\nRUN VER="},
		{"proxy GOARCH hardcoded to the build host", proxyEnv,
			strings.Replace(proxyEnv, "GOARCH=${TARGETARCH}", "GOARCH=amd64", 1)},
		{"proxy GOOS hardcoded (ignores TARGETOS)", proxyEnv,
			strings.Replace(proxyEnv, "GOOS=${TARGETOS}", "GOOS=linux", 1)},
		{"agent cgo re-enabled", maintEnv,
			strings.Replace(maintEnv, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)},
		{"final stage moved to the build platform", runtimeFrom, "FROM --platform=$BUILDPLATFORM alpine:3.24\n"},
		{"agent build moved out of view (vacuous wall)", maintEnv,
			strings.Replace(maintEnv, "go build", "./build.sh", 1)},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			if n := strings.Count(real, m.old); n != 1 {
				t.Fatalf("mutation anchor must match the Dockerfile exactly once, matched %d times: %q", n, m.old)
			}
			mutated := strings.Replace(real, m.old, m.new, 1)
			if m.name == "agent ARG TARGETARCH declared only after the RUN" {
				// Re-add the declaration AFTER the build: present in the
				// stage, but not in scope when the RUN executes.
				mutated = strings.Replace(mutated, "-o /culvert-maint .", "-o /culvert-maint .\nARG TARGETARCH", 1)
			}
			if len(crossBuildViolations(t, mutated)) == 0 {
				t.Errorf("mutation %q was NOT rejected — the wall would let it ship", m.name)
			}
		})
	}
}

// TestDockerfileCrossBuild_GlobalArgIsNotInScope pins the scoping rule the
// whole wall rests on: an ARG declared before the first FROM is NOT visible
// inside a stage. If the parser ever inherited it, the undeclared-ARG defect
// would pass silently.
func TestDockerfileCrossBuild_GlobalArgIsNotInScope(t *testing.T) {
	src := "ARG TARGETOS\nARG TARGETARCH\n" +
		"FROM --platform=$BUILDPLATFORM golang AS builder\nRUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o a .\n" +
		"FROM --platform=$BUILDPLATFORM golang AS maintbuilder\nARG TARGETOS\nARG TARGETARCH\nRUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o b .\n" +
		"FROM alpine\n"
	v := crossBuildViolations(t, src)
	if len(v) == 0 {
		t.Fatal("a global-scope ARG TARGETARCH was treated as in scope inside `builder`")
	}
	for _, msg := range v {
		if !strings.Contains(msg, `"builder"`) {
			t.Errorf("only `builder` should be flagged, got: %s", msg)
		}
	}
}

// TestDockerfileCrossBuild_ControlAcceptsEquivalentSpellings is the CONTROL:
// the checker must not be so literal that an equivalent, correct Dockerfile
// fails — otherwise the cheapest way to satisfy it would be to freeze the
// file's exact bytes.
func TestDockerfileCrossBuild_ControlAcceptsEquivalentSpellings(t *testing.T) {
	src := "FROM --platform=${BUILDPLATFORM} golang AS builder\nARG TARGETOS\nARG TARGETARCH=\n" +
		"RUN export CGO_ENABLED=0 && GOOS=$TARGETOS GOARCH=\"${TARGETARCH}\" go build -o a .\n" +
		"FROM --platform=$BUILDPLATFORM golang AS maintbuilder\nARG TARGETARCH\nARG TARGETOS\n" +
		"RUN CGO_ENABLED=0 GOOS=${TARGETOS} \\\n    GOARCH=${TARGETARCH} \\\n    go build -o b .\n" +
		"FROM alpine\n"
	for _, msg := range crossBuildViolations(t, src) {
		t.Errorf("correct Dockerfile rejected: %s", msg)
	}
}
