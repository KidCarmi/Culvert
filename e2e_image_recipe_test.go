package main

// e2e_image_recipe_test.go — the wall for the maintenance-agent E2E image
// (test/e2e/maint-agent/Dockerfile.e2e) and its companion rollback image
// (test/e2e/catalog-update/Dockerfile.badhealth). CI-REDESIGN §12, stage 4.
//
// Four workflows (install-lifecycle, maint-agent-update,
// maint-agent-backup-upgrade, appliance-catalog-update) build the E2E image and
// drive real installs, upgrades, backups and rollbacks against it. It used to
// drift from production in two ways that matter:
//
//  1. DEPENDENCY DISCIPLINE. It ran `go mod tidy` inside the image build, so a
//     committed go.mod/go.sum that could not build was silently REPAIRED in the
//     layer and the E2E went green on a module graph nobody committed. It now
//     builds with -mod=readonly and proves go.mod/go.sum unchanged across both
//     the download and the compile (depfiles-guard.sh). The download check must
//     sit in the SAME RUN as `go mod download`: the next `COPY . .` overwrites
//     both files with the committed copies, so a later check sees nothing.
//
//  2. RECIPE DRIFT. Older golang/alpine images and no -trimpath/-buildvcs=false.
//
// Every parity expectation below is DERIVED from the production Dockerfile at
// test time — base images, compile flags, ldflags, GOOS/GOARCH/CGO — so this
// file holds no third copy of the version list to drift. The intentional E2E
// differences (no GeoIP, BUILD_VARIANT, no deploy bundle) are pinned too,
// because "make it look like production" is the easiest wrong fix.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	e2eDockerfilePath       = "test/e2e/maint-agent/Dockerfile.e2e"
	badhealthDockerfilePath = "test/e2e/catalog-update/Dockerfile.badhealth"
	depfilesGuardPath       = "test/e2e/maint-agent/depfiles-guard.sh"
)

// dfStage is one FROM … block: its identity plus its instructions in order.
type dfStage struct {
	name, platform, image string
	ins                   []string
}

func dfStages(t *testing.T, src string) []dfStage {
	t.Helper()
	var stages []dfStage
	for _, in := range dockerInstructions(src) {
		if strings.HasPrefix(strings.ToUpper(in), "FROM ") {
			m := crossFromRe.FindStringSubmatch(in)
			if m == nil {
				t.Fatalf("cannot parse FROM instruction %q", in)
			}
			stages = append(stages, dfStage{name: m[3], platform: m[1], image: m[2]})
			continue
		}
		if len(stages) > 0 {
			stages[len(stages)-1].ins = append(stages[len(stages)-1].ins, in)
		}
	}
	return stages
}

func dfStageNamed(stages []dfStage, name string) (dfStage, bool) {
	for _, s := range stages {
		if s.name == name {
			return s, true
		}
	}
	return dfStage{}, false
}

// goBuildRun returns the stage's single RUN that invokes `go build`.
func goBuildRun(s dfStage) (string, error) {
	var found []string
	for _, in := range s.ins {
		if strings.HasPrefix(strings.ToUpper(in), "RUN ") && crossGoBuild.MatchString(in) {
			found = append(found, in)
		}
	}
	if len(found) != 1 {
		return "", errors.New("stage " + q(s.name) + " has " + strconv.Itoa(len(found)) + " `go build` RUNs, want exactly 1")
	}
	return found[0], nil
}

var (
	dfQuotedRe  = regexp.MustCompile(`"[^"]*"`)
	dfLdflagsRe = regexp.MustCompile(`-ldflags="([^"]*)"`)
)

// buildFlags returns the `go build` flags other than -o and -ldflags.
func buildFlags(run string) map[string]bool {
	loc := crossGoBuild.FindStringIndex(run)
	flags := map[string]bool{}
	if loc == nil {
		return flags
	}
	for _, tok := range strings.Fields(dfQuotedRe.ReplaceAllString(run[loc[1]:], `""`)) {
		if strings.HasPrefix(tok, "-") && tok != "-o" && !strings.HasPrefix(tok, "-ldflags") {
			flags[tok] = true
		}
	}
	return flags
}

// ldflagsNonSymbol returns the -ldflags tokens that are not `-X sym=val`
// stamps (those carry the version and differ by design).
func ldflagsNonSymbol(run string) map[string]bool {
	out := map[string]bool{}
	m := dfLdflagsRe.FindStringSubmatch(run)
	if m == nil {
		return out
	}
	toks := strings.Fields(m[1])
	for i := 0; i < len(toks); i++ {
		if toks[i] == "-X" {
			i++
			continue
		}
		out[toks[i]] = true
	}
	return out
}

// e2eParityViolations checks the E2E builder against the production builder.
func e2eParityViolations(t *testing.T, prodSrc, e2eSrc string) []string {
	t.Helper()
	prod, e2e := dfStages(t, prodSrc), dfStages(t, e2eSrc)
	pb, ok1 := dfStageNamed(prod, "builder")
	eb, ok2 := dfStageNamed(e2e, "builder")
	if !ok1 || !ok2 {
		return []string{"both Dockerfiles must have a stage named \"builder\""}
	}
	var v []string
	if eb.image != pb.image {
		v = append(v, "E2E builder image "+q(eb.image)+" != production builder image "+q(pb.image))
	}
	if pf, ef := prod[len(prod)-1].image, e2e[len(e2e)-1].image; ef != pf {
		v = append(v, "E2E runtime image "+q(ef)+" != production runtime image "+q(pf))
	}
	if eb.platform != pb.platform {
		v = append(v, "E2E builder platform "+q(eb.platform)+" != production builder platform "+q(pb.platform))
	}
	prun, perr := goBuildRun(pb)
	erun, eerr := goBuildRun(eb)
	if perr != nil || eerr != nil {
		return append(v, "cannot locate the go build RUN in both builders")
	}
	v = append(v, compileParity(prun, erun)...)
	return v
}

func compileParity(prun, erun string) []string {
	var v []string
	ef := buildFlags(erun)
	for f := range buildFlags(prun) {
		if !ef[f] {
			v = append(v, "E2E `go build` lacks production flag "+q(f))
		}
	}
	el := ldflagsNonSymbol(erun)
	for f := range ldflagsNonSymbol(prun) {
		if !el[f] {
			v = append(v, "E2E -ldflags lacks production flag "+q(f))
		}
	}
	for _, key := range []string{"CGO_ENABLED", "GOOS", "GOARCH"} {
		pv, _ := goEnvFor(prun, key)
		if ev, ok := goEnvFor(erun, key); !ok || ev != pv {
			v = append(v, "E2E `go build` "+key+"="+q(ev)+", production uses "+q(pv))
		}
	}
	return v
}

var depMutatorRe = regexp.MustCompile(`\bgo\s+(mod\s+(tidy|edit|vendor)|get|work)\b`)

// e2eDependencyViolations checks the committed-graph-only discipline.
func e2eDependencyViolations(t *testing.T, e2eSrc string) []string {
	t.Helper()
	eb, ok := dfStageNamed(dfStages(t, e2eSrc), "builder")
	if !ok {
		return []string{"E2E Dockerfile has no \"builder\" stage"}
	}
	var v []string
	guardCopied, downloadGuarded, fullCopy := -1, -1, -1
	for i, in := range eb.ins {
		up := strings.ToUpper(in)
		switch {
		case depMutatorRe.MatchString(in):
			v = append(v, "builder rewrites the module graph at build time: "+q(depMutatorRe.FindString(in)))
		case strings.HasPrefix(up, "COPY ") && strings.Contains(in, "depfiles-guard"):
			guardCopied = i
		case strings.HasPrefix(up, "COPY ") && strings.Fields(in)[1] == ".":
			fullCopy = i
		case strings.HasPrefix(up, "RUN ") && strings.Contains(in, "go mod download"):
			if !guardedAround(in, "go mod download") {
				v = append(v, "`go mod download` is not wrapped by `depfiles-guard snapshot` … `depfiles-guard verify` in the SAME RUN")
			}
			downloadGuarded = i
		}
	}
	v = append(v, orderViolations(guardCopied, downloadGuarded, fullCopy)...)
	if run, err := goBuildRun(eb); err != nil {
		v = append(v, err.Error())
	} else {
		if !buildFlags(run)["-mod=readonly"] {
			v = append(v, "E2E `go build` must pass -mod=readonly")
		}
		if !guardedAround(run, "go build") {
			v = append(v, "`go build` is not wrapped by `depfiles-guard snapshot` … `depfiles-guard verify` in the SAME RUN")
		}
	}
	return v
}

func orderViolations(guardCopied, download, fullCopy int) []string {
	var v []string
	if download < 0 {
		v = append(v, "no `go mod download` RUN found in the builder")
	}
	if guardCopied < 0 || (download >= 0 && guardCopied > download) {
		v = append(v, "depfiles-guard must be COPYed into the builder before the download")
	}
	if fullCopy < 0 || (download >= 0 && fullCopy < download) {
		v = append(v, "the guarded download must run BEFORE `COPY . .`, which would overwrite and conceal a changed go.mod/go.sum")
	}
	return v
}

// guardedAround reports whether cmd runs `snapshot`, then step, then `verify`.
func guardedAround(cmd, step string) bool {
	s := strings.Index(cmd, "depfiles-guard snapshot")
	d := strings.Index(cmd, step)
	vv := strings.LastIndex(cmd, "depfiles-guard verify")
	return s >= 0 && d > s && vv > d
}

// e2eIntentionalDifferenceViolations pins what must STAY different.
func e2eIntentionalDifferenceViolations(t *testing.T, e2eSrc string) []string {
	t.Helper()
	stages := dfStages(t, e2eSrc)
	var v []string
	for _, s := range stages {
		if s.name == "geoip" || s.name == "maintbuilder" {
			v = append(v, "E2E image grew a "+q(s.name)+" stage; it is deliberately absent")
		}
	}
	for _, bad := range []string{"db-ip.com", "/app/deploy", "./deploy/"} {
		if strings.Contains(strings.Join(dockerInstructions(e2eSrc), "\n"), bad) {
			v = append(v, "E2E image references "+q(bad)+": no GeoIP / no deploy bundle is intentional (the installer's source fallback must stay exercised)")
		}
	}
	final := stages[len(stages)-1]
	body := strings.Join(final.ins, "\n")
	for _, want := range []string{
		`LABEL culvert.e2e.variant="${BUILD_VARIANT}"`,
		`ARG BUILD_VARIANT`, `USER proxy`, `VOLUME ["/data"]`, `wget`, `ENTRYPOINT ["./culvert"]`,
	} {
		if !strings.Contains(body, want) {
			v = append(v, "E2E runtime stage lost "+q(want))
		}
	}
	if eb, ok := dfStageNamed(stages, "builder"); ok {
		run, _ := goBuildRun(eb)
		if !strings.Contains(run, `main.version=e2e-${BUILD_VARIANT}`) || !strings.Contains(run, `"e2e-${BUILD_VARIANT}" > /app/VERSION`) {
			v = append(v, "BUILD_VARIANT must reach both the binary (-X main.version) and /app/VERSION so v1/v2 differ")
		}
	}
	return v
}

func e2eAllViolations(t *testing.T, prod, e2e, badhealth string) []string {
	t.Helper()
	v := e2eParityViolations(t, prod, e2e)
	v = append(v, e2eDependencyViolations(t, e2e)...)
	v = append(v, e2eIntentionalDifferenceViolations(t, e2e)...)
	prodStages, bh := dfStages(t, prod), dfStages(t, badhealth)
	if pf := prodStages[len(prodStages)-1].image; len(bh) == 0 || bh[0].image != pf {
		v = append(v, "Dockerfile.badhealth base image differs from production runtime image "+q(pf))
	}
	if eb, ok := dfStageNamed(dfStages(t, e2e), "builder"); ok && isBuildPlatform(eb.platform) {
		for _, st := range parseCrossBuildStages(t, e2e) {
			for _, b := range st.builds {
				v = append(v, checkCrossBuildRun(st.name, b)...)
			}
		}
	}
	return v
}

// TestE2EImage_RecipeMatchesProductionAndKeepsItsDifferences is the gate.
func TestE2EImage_RecipeMatchesProductionAndKeepsItsDifferences(t *testing.T) {
	for _, msg := range e2eAllViolations(t, readRepoFile(t, "Dockerfile"), readRepoFile(t, e2eDockerfilePath), readRepoFile(t, badhealthDockerfilePath)) {
		t.Error(msg)
	}
}

// TestE2EImage_RejectsKnownRegressions derives each defect from the REAL files
// and requires the wall to reject it. Image anchors come from the PRODUCTION
// Dockerfile, never a literal, so this test cannot pin a stale version.
func TestE2EImage_RejectsKnownRegressions(t *testing.T) {
	prod := readRepoFile(t, "Dockerfile")
	e2e := readRepoFile(t, e2eDockerfilePath)
	bh := readRepoFile(t, badhealthDockerfilePath)
	ps := dfStages(t, prod)
	pb, _ := dfStageNamed(ps, "builder")
	goImg, rtImg := pb.image, ps[len(ps)-1].image

	type mut struct{ name, file, old, new string }
	muts := []mut{
		{"build-time go mod tidy reintroduced", "e2e", "&& depfiles-guard snapshot \\\n    && CGO_ENABLED=0", "&& go mod tidy \\\n    && depfiles-guard snapshot \\\n    && CGO_ENABLED=0"},
		{"-mod=readonly dropped", "e2e", "go build -mod=readonly ", "go build "},
		{"download guard removed", "e2e", "&& depfiles-guard verify \"go mod download\"", ""},
		{"download guard moved after COPY . .", "e2e", "RUN depfiles-guard snapshot \\\n    && go mod download \\\n    && depfiles-guard verify \"go mod download\"\nCOPY . .", "COPY . .\nRUN depfiles-guard snapshot \\\n    && go mod download \\\n    && depfiles-guard verify \"go mod download\""},
		{"build guard removed", "e2e", "\\\n    && depfiles-guard verify \"go build\"", ""},
		{"-trimpath dropped", "e2e", " -trimpath -buildvcs=false \\\n       -ldflags=\"-s -w -X main.version=e2e", " -buildvcs=false \\\n       -ldflags=\"-s -w -X main.version=e2e"},
		{"-buildvcs=false dropped", "e2e", "-trimpath -buildvcs=false \\\n       -ldflags=\"-s -w -X main.version=e2e", "-trimpath \\\n       -ldflags=\"-s -w -X main.version=e2e"},
		{"builder image drifted from production", "e2e", goImg + " AS builder", goImg + "-drifted AS builder"},
		{"runtime image drifted from production", "e2e", "\nFROM " + rtImg + "\n", "\nFROM " + rtImg + "-drifted\n"},
		{"GOARCH hardcoded to the build host", "e2e", "GOARCH=${TARGETARCH} go build -mod", "GOARCH=amd64 go build -mod"},
		{"TARGETARCH undeclared (expands empty)", "e2e", "ARG TARGETOS\nARG TARGETARCH\nRUN", "ARG TARGETOS\nRUN"},
		{"deploy bundle added to look like production", "e2e", "COPY --from=builder --chown=proxy:proxy /app/VERSION ./VERSION\n", "COPY --from=builder --chown=proxy:proxy /app/VERSION ./VERSION\nCOPY --chown=proxy:proxy packaging/ ./deploy/packaging/\n"},
		{"variant label dropped", "e2e", "LABEL culvert.e2e.variant=\"${BUILD_VARIANT}\"\n", ""},
		{"badhealth image drifted from production", "bh", "FROM " + rtImg + "\n", "FROM " + rtImg + "-drifted\n"},
	}
	for _, m := range muts {
		t.Run(m.name, func(t *testing.T) {
			src := map[string]string{"e2e": e2e, "bh": bh}[m.file]
			if n := strings.Count(src, m.old); n != 1 {
				t.Fatalf("mutation anchor must match exactly once, matched %d: %q", n, m.old)
			}
			mutated := strings.Replace(src, m.old, m.new, 1)
			e, b := e2e, bh
			if m.file == "e2e" {
				e = mutated
			} else {
				b = mutated
			}
			if len(e2eAllViolations(t, prod, e, b)) == 0 {
				t.Errorf("mutation %q was NOT rejected", m.name)
			}
		})
	}
}

// runGuard executes the REAL depfiles-guard.sh in dir.
func runGuard(t *testing.T, dir, snap string, args ...string) (string, error) {
	t.Helper()
	abs, err := filepath.Abs(depfilesGuardPath)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- program is the literal "sh"; the script is the repo's own
	// depfiles-guard.sh and every argument is a literal from this test.
	cmd := exec.CommandContext(t.Context(), "sh", append([]string{abs}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "DEPFILES_GUARD_DIR="+snap)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestE2EImage_GuardDetectsDependencyChanges runs the real guard script, the
// same file the image COPYs, against real mutations of go.mod and go.sum.
func TestE2EImage_GuardDetectsDependencyChanges(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX sh on this host")
	}
	cases := []struct {
		name    string
		mutate  func(dir string) error
		wantErr bool
		want    []string
	}{
		{"unchanged files pass", func(string) error { return nil }, false, nil},
		{"go.sum edit is caught", func(d string) error { return appendFile(d, "go.sum", "example.com/x v1.0.0 h1:fake=\n") }, true,
			[]string{"go.sum", `'go mod download'`, "go mod tidy", "+example.com/x v1.0.0 h1:fake="}},
		{"go.mod edit is caught", func(d string) error { return appendFile(d, "go.mod", "require example.com/x v1.0.0\n") }, true,
			[]string{"go.mod", "+require example.com/x v1.0.0"}},
		{"deleted go.sum is caught", func(d string) error { return os.Remove(filepath.Join(d, "go.sum")) }, true, []string{"go.sum"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, snap := t.TempDir(), t.TempDir()
			writeFile(t, dir, "go.mod", "module example.com/m\n\ngo 1.26\n")
			writeFile(t, dir, "go.sum", "example.com/a v1.0.0 h1:aaa=\n")
			if out, err := runGuard(t, dir, snap, "snapshot"); err != nil {
				t.Fatalf("snapshot: %v\n%s", err, out)
			}
			if err := c.mutate(dir); err != nil {
				t.Fatal(err)
			}
			out, err := runGuard(t, dir, snap, "verify", "go mod download")
			if (err != nil) != c.wantErr {
				t.Fatalf("verify err=%v, wantErr=%v\n%s", err, c.wantErr, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("diagnostic lacks %q:\n%s", w, out)
				}
			}
		})
	}
}

// TestE2EImage_GuardRefusesVerifyWithoutSnapshot: a verify with nothing to
// compare against must fail rather than pass vacuously.
func TestE2EImage_GuardRefusesVerifyWithoutSnapshot(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX sh on this host")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module m\n")
	writeFile(t, dir, "go.sum", "")
	if out, err := runGuard(t, dir, t.TempDir(), "verify", "go build"); err == nil {
		t.Fatalf("verify without a snapshot passed:\n%s", out)
	}
}

// TestE2EImage_LateCheckIsConcealedByCopy is the CONTROL that justifies the
// ordering rule: when the committed files are copied back over a changed
// go.sum (what `COPY . .` does), a check made afterwards sees NOTHING. That is
// why the wall requires the check in the same RUN as the download.
func TestE2EImage_LateCheckIsConcealedByCopy(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX sh on this host")
	}
	dir, snap := t.TempDir(), t.TempDir()
	committed := "example.com/a v1.0.0 h1:aaa=\n"
	writeFile(t, dir, "go.mod", "module m\n")
	writeFile(t, dir, "go.sum", committed)
	if out, err := runGuard(t, dir, snap, "snapshot"); err != nil {
		t.Fatalf("snapshot: %v\n%s", err, out)
	}
	if err := appendFile(dir, "go.sum", "example.com/x v1.0.0 h1:new=\n"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "go.sum", committed) // the later COPY . . restores the committed file
	if out, err := runGuard(t, dir, snap, "verify", "go mod download"); err != nil {
		t.Fatalf("expected the concealed change to go unseen (that is the hazard), got failure:\n%s", out)
	}
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(dir, name, body string) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(body)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}
