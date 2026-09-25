package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// fixtureModule is a tiny module with every entry shape the root suite has: a
// TestMain, plain tests, subtests, a legitimate skip, a fuzz target whose seed
// corpus runs under -test.run, an example with an Output directive, a
// benchmark (excluded), a subpackage for the lane, and a package with no tests.
// PILOT_FAIL / PILOT_CRASH turn one test into a failure or a process crash.
var fixtureModule = map[string]string{
	"go.mod": "module example.com/pilot\n\ngo 1.21\n",
	"lib.go": `package pilot

func Add(a, b int) int { return a + b }

// ChildOnly runs only inside a re-exec'd child process (TestChild), the way
// the repository's helper-process tests run main() and one-shot commands.
func ChildOnly() int {
	x := 0
	for i := 0; i < 3; i++ {
		x += i
	}
	return x
}

func Sign(x int) string {
	if x > 0 {
		return "pos"
	}
	if x < 0 {
		return "neg"
	}
	return "zero"
}
`,
	"lib_test.go": `package pilot

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(m.Run()) }

func TestAdd(t *testing.T) {
	if Add(1, 2) != 3 {
		t.Fatal("add")
	}
}

func TestSign(t *testing.T) {
	for _, x := range []int{1, -1} {
		t.Run(fmt.Sprint(x), func(t *testing.T) { _ = Sign(x) })
	}
}

func TestSkipped(t *testing.T) { t.Skip("needs hardware") }

func TestMaybeFail(t *testing.T) {
	if os.Getenv("PILOT_FAIL") == "1" {
		t.Fatal("boom")
	}
}

func TestMaybeCrash(t *testing.T) {
	if os.Getenv("PILOT_CRASH") == "1" {
		panic("crash")
	}
}

func TestZLast(t *testing.T) {}

// Testify starts with "Test" but is not a test (lowercase after the prefix).
func Testify() int { return 1 }

// TestChild re-executes the test binary and exits through os.Exit, exactly as
// the repository's helper-process tests run main() and its one-shot commands
// (upstream_v2_codex_red_test.go). The child's coverage reaches the profile
// only through GOCOVERDIR, which go test sets in the ENVIRONMENT as well as
// passing -test.gocoverdir; a runner that passes only the flag loses it.
func TestChild(t *testing.T) {
	if os.Getenv("PILOT_CHILD") == "1" {
		_ = ChildOnly()
		os.Exit(0) // like the repository's one-shot helpers: exit hooks emit to GOCOVERDIR
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PILOT_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func FuzzAdd(f *testing.F) {
	f.Add(1, 2)
	f.Fuzz(func(t *testing.T, a, b int) { _ = Add(a, b) })
}

func ExampleAdd() {
	fmt.Println(Add(2, 2))
	// Output: 4
}

func BenchmarkAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Add(i, i)
	}
}
`,
	"sub/sub.go": "package sub\n\nfunc Twice(x int) int { return 2 * x }\n",
	// The lane package carries every entry shape the source enumerator must
	// get right: a test, a fuzz target, a runnable example, an example with
	// no output (compiled, never run), a benchmark (not an entry), a helper
	// whose name starts with "Test" but is not a test, and an external
	// (package sub_test) file.
	"sub/sub_test.go": `package sub

import (
	"fmt"
	"testing"
)

func TestTwice(t *testing.T) {
	if Twice(2) != 4 {
		t.Fatal("twice")
	}
}

func FuzzTwice(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, x int) { _ = Twice(x) })
}

func ExampleTwice() {
	fmt.Println(Twice(2))
	// Output: 4
}

func ExampleTwice_silent() { _ = Twice(1) }

func BenchmarkTwice(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Twice(i)
	}
}

func Testify() int { return 1 }
`,
	"sub/x_test.go": "package sub_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/pilot/sub\"\n)\n\nfunc TestExternal(t *testing.T) {\n\tif sub.Twice(1) != 2 {\n\t\tt.Fatal(\"external\")\n\t}\n}\n",
	// A package with statements and no tests, and one with neither: both are
	// legitimate, and the verdict must LIST them rather than count zeros.
	"notest/n.go":    "package notest\n\nfunc N() int { return 1 }\n",
	"types/types.go": "package types\n\n// T has no statements to instrument.\ntype T int\n\n// C is a constant.\nconst C = 1\n",
}

type fixture struct {
	t      *testing.T
	root   string
	work   string
	commit string
}

// newFixture writes the module and makes it the working directory: the pilot
// runs the binary from the package directory, as `go test` does.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	f := &fixture{t: t, root: t.TempDir(), work: t.TempDir(), commit: "0123456789abcdef"}
	for name, body := range fixtureModule {
		p := filepath.Join(f.root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(f.root)
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOTOOLCHAIN", "local")
	return f
}

func (f *fixture) path(p ...string) string { return filepath.Join(append([]string{f.work}, p...)...) }

// rs runs a subcommand and returns its exit status and output.
func (f *fixture) rs(args ...string) (code int, output string) {
	var out bytes.Buffer
	code = run(args, &out, &out)
	return code, out.String()
}

func (f *fixture) mustRS(args ...string) string {
	f.t.Helper()
	code, out := f.rs(args...)
	if code != 0 {
		f.t.Fatalf("rootshard %v exited %d:\n%s", args, code, out)
	}
	return out
}

func (f *fixture) verdict(dir string) (code int, v Verdict, output string) {
	code, output = f.rs("verdict", "-build-dir", f.path("build"), "-shards-dir", f.path("shards"),
		"-lane-dir", f.path("lane"), "-universe-dir", f.path("universe"), "-commit", f.commit, "-out-dir", f.path(dir))
	_ = readJSON(f.path(dir, "verdict.json"), &v)
	return code, v, output
}

func (f *fixture) runShard(i int, commit string) (code int, output string) {
	return f.rs("run-shard", "-plan", f.path("build", "plan.json"), "-manifest", f.path("build", "manifest.json"),
		"-binary", f.path("build", "root.test"), "-shard", sprintf("%d", i), "-out-dir", f.path("shards", shardDirName(i)),
		"-commit", commit, "-timeout", "2m")
}

// TestPilot_EndToEnd drives the real flow — one compile, a plan from the
// binary's own inventory, isolated shard processes, the non-root lane, the
// verdict and the comparison against an unsharded `go test` reference — and
// then breaks it in each way a sharded suite can silently lose evidence.
func TestPilot_EndToEnd(t *testing.T) {
	f := newFixture(t)
	commit := f.commit
	f.mustRS("build", "-out-dir", f.path("build"), "-commit", commit)
	var m Manifest
	if err := readJSON(f.path("build", "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if m.Package != "example.com/pilot" || m.Runnable != 9 || m.Benchmarks != 1 {
		t.Fatalf("manifest = %+v (want 9 runnable incl. FuzzAdd + ExampleAdd, 1 benchmark)", m)
	}
	f.mustRS("plan", "-list", f.path("build", "list.txt"), "-pkg", m.Package, "-shards", "2", "-max-regex-bytes", "40", "-out", f.path("build", "plan.json"))
	for i := 0; i < 2; i++ {
		if code, out := f.runShard(i, commit); code != 0 {
			t.Fatalf("shard %d exited %d:\n%s", i, code, out)
		}
	}
	f.mustRS("run-lane", "-out-dir", f.path("lane"), "-commit", commit, "-timeout", "2m")
	f.mustRS("universe", "-out-dir", f.path("universe"), "-commit", commit, "-timeout", "2m")
	code, v, out := f.verdict("verdict")
	if code != 0 || !v.OK {
		t.Fatalf("clean pilot rejected (exit %d):\n%s", code, out)
	}
	if v.Profiles < 3 || v.Merged.Blocks == 0 {
		t.Fatalf("verdict merged %d profiles / %d blocks", v.Profiles, v.Merged.Blocks)
	}
	checkCleanCompleteness(t, v.Completeness)

	// Every way evidence can be incomplete must be refused by the standalone
	// verdict — no unsharded reference exists at this point.
	t.Run("incomplete evidence", func(t *testing.T) { incompleteEvidence(t, f) })
	t.Run("split and reordered lane", func(t *testing.T) { splitLane(t, f, v) })

	if err := writeJSON(f.path("no-exceptions.json"), CoverageExceptions{Schema: 1}); err != nil {
		t.Fatal(err)
	}
	// The unsharded reference, exactly as qa-logic runs it.
	// #nosec G204 -- literal go command over this test's own temp paths.
	ref := exec.CommandContext(t.Context(), "go", "test", "-race", "-count=1", "-timeout=2m", "-coverprofile="+f.path("ref.out"), "-v", "./...")
	refLog, err := ref.CombinedOutput()
	if err != nil {
		t.Fatalf("reference run: %v\n%s", err, refLog)
	}
	if err := os.WriteFile(f.path("ref.log"), refLog, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out = f.rs("compare", "-ref-log", f.path("ref.log"), "-ref-profile", f.path("ref.out"),
		"-pilot-results", f.path("verdict", "results.json"), "-pilot-profile", f.path("verdict", "merged.cover.out"),
		"-list", f.path("build", "list.txt"), "-pkg", m.Package, "-out", f.path("cmp.json"), "-baseline-out", f.path("baseline.json"),
		"-coverage-exceptions", f.path("no-exceptions.json"))
	if code != 0 {
		t.Fatalf("pilot differs from the unsharded reference:\n%s", out)
	}
	var c Comparison
	if err := readJSON(f.path("cmp.json"), &c); err != nil {
		t.Fatal(err)
	}
	if c.RootPilotEntries != 9 || len(c.PilotSkipped) != 1 || c.SubtestsPilot < 3 {
		t.Fatalf("comparison = %+v", c)
	}
	// Coverage produced in a re-exec'd child (TestChild → ChildOnly) must reach
	// the pilot's profile exactly as it reaches go test's.
	if len(c.BlocksLost) != 0 {
		t.Fatalf("pilot lost coverage the unsharded reference has: %v", c.BlocksLost)
	}
	t.Run("failed test", func(t *testing.T) { failedTest(t, f, commit) })
	t.Run("crash loses execution", func(t *testing.T) { crashedShard(t, f, commit) })
	t.Run("missing shard", func(t *testing.T) { missingShard(t, f, commit) })
	t.Run("wrong identity", func(t *testing.T) { wrongIdentity(t, f, commit) })
	t.Run("unusable profile", func(t *testing.T) { unusableProfile(t, f, commit) })
}

func shardOf(t *testing.T, f *fixture, name string) int {
	t.Helper()
	var p Plan
	if err := readJSON(f.path("build", "plan.json"), &p); err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Shards {
		for _, n := range s.Names {
			if n == name {
				return s.Index
			}
		}
	}
	t.Fatalf("%s is in no shard", name)
	return -1
}

// rerun re-executes one shard (with the given env) and restores it afterwards.
func rerun(t *testing.T, f *fixture, commit string, shard int, env ...string) (code int, output string) {
	t.Helper()
	for i := 0; i+1 < len(env); i += 2 {
		t.Setenv(env[i], env[i+1])
	}
	t.Cleanup(func() {
		for i := 0; i+1 < len(env); i += 2 {
			os.Unsetenv(env[i])
		}
		os.RemoveAll(f.path("shards", shardDirName(shard)))
		if code, out := f.runShard(shard, commit); code != 0 {
			t.Errorf("restoring shard %d failed:\n%s", shard, out)
		}
	})
	os.RemoveAll(f.path("shards", shardDirName(shard)))
	return f.runShard(shard, commit)
}

func wantRejected(t *testing.T, f *fixture, want string) {
	t.Helper()
	code, v, out := f.verdict("verdict-bad")
	if code == 0 || v.OK {
		t.Fatalf("verdict accepted broken evidence:\n%s", out)
	}
	if !strings.Contains(strings.Join(v.Problems, "\n"), want) {
		t.Fatalf("problems do not name %q:\n%s", want, strings.Join(v.Problems, "\n"))
	}
}

func failedTest(t *testing.T, f *fixture, commit string) {
	if code, _ := rerun(t, f, commit, shardOf(t, f, "TestMaybeFail"), "PILOT_FAIL", "1"); code == 0 {
		t.Fatal("run-shard exited 0 on a failing test")
	}
	wantRejected(t, f, "TestMaybeFail FAILED")
}

// A panic kills the process: every entry after it has NO result. The verdict
// must call that missing execution, not a smaller passing run.
func crashedShard(t *testing.T, f *fixture, commit string) {
	shard := shardOf(t, f, "TestMaybeCrash")
	if code, _ := rerun(t, f, commit, shard, "PILOT_CRASH", "1"); code == 0 {
		t.Fatal("run-shard exited 0 on a crashed process")
	}
	code, v, _ := f.verdict("verdict-bad")
	joined := strings.Join(v.Problems, "\n")
	// A panic kills the process before testing prints a terminal event, so the
	// crashing entry itself has no result either: both it and the non-zero exit
	// must be named.
	if code == 0 || !strings.Contains(joined, "TestMaybeCrash has no result") || !strings.Contains(joined, "exit 2") {
		t.Fatalf("crash not reported:\n%s", joined)
	}
	// testing runs every selected test, THEN fuzz seed corpora, THEN examples;
	// after the crash none of those in the same process may read as passed.
	after := 0
	for _, n := range chunkOf(t, f, "TestMaybeCrash") {
		if strings.HasPrefix(n, "Fuzz") || strings.HasPrefix(n, "Example") {
			after++
			if !strings.Contains(joined, n+" has no result") {
				t.Fatalf("%s ran after the crash in the same process but is not reported as never run:\n%s", n, joined)
			}
		}
	}
	if after == 0 {
		t.Fatal("fixture no longer co-locates a fuzz target or example with the crash — this check would be vacuous")
	}
}

func chunkOf(t *testing.T, f *fixture, name string) []string {
	t.Helper()
	var p Plan
	if err := readJSON(f.path("build", "plan.json"), &p); err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Shards {
		for _, c := range s.Chunks {
			for _, n := range c.Names {
				if n == name {
					return c.Names
				}
			}
		}
	}
	t.Fatalf("%s is in no chunk", name)
	return nil
}

func missingShard(t *testing.T, f *fixture, commit string) {
	dir := f.path("shards", shardDirName(1))
	if err := os.Rename(dir, dir+".away"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Rename(dir+".away", dir) })
	wantRejected(t, f, "shard 1: no usable evidence")
}

func wrongIdentity(t *testing.T, f *fixture, commit string) {
	if code, out := f.runShard(0, "not-the-built-commit"); code == 0 || !strings.Contains(out, "incompatible shard environment") {
		t.Fatalf("a shard on another commit ran (exit %d):\n%s", code, out)
	}
	metaPath := f.path("shards", shardDirName(0), "meta.json")
	orig, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(metaPath, orig, 0o600) }) // #nosec G703 -- restores the fixture's own t.TempDir()-derived file
	var meta ShardMeta
	_ = json.Unmarshal(orig, &meta)
	meta.BinarySHA256 = strings.Repeat("0", 64)
	if err := writeJSON(metaPath, meta); err != nil {
		t.Fatal(err)
	}
	wantRejected(t, f, "ran binary")
}

func unusableProfile(t *testing.T, f *fixture, commit string) {
	p := f.path("shards", shardDirName(0), "chunk-0.cover.out")
	orig, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(p, orig, 0o600) }) // #nosec G703 -- restores the fixture's own t.TempDir()-derived file
	if err := os.WriteFile(p, []byte("mode: atomic\nexample.com/pilot/lib.go:3.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantRejected(t, f, "unusable coverage profile")
	lane := f.path("lane", "lane.cover.out")
	laneOrig, err := os.ReadFile(lane)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, orig, 0o600); err != nil { // #nosec G703 -- test rewrites its own t.TempDir()-derived evidence file
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(lane, laneOrig, 0o600) }) // #nosec G703 -- restores the fixture's own t.TempDir()-derived file
	rootBlock := slices.Concat(laneOrig, []byte("example.com/pilot/lib.go:3.1,5.2 1 0\n"))
	if err := os.WriteFile(lane, rootBlock, 0o600); err != nil { // #nosec G703 -- test rewrites its own t.TempDir()-derived profile
		t.Fatal(err)
	}
	wantRejected(t, f, "belongs to the root package")
}

func (f *fixture) verdictLanes(dir, lanes string) (code int, v Verdict, output string) {
	code, output = f.rs("verdict", "-build-dir", f.path("build"), "-shards-dir", f.path("shards"),
		"-lane-dir", lanes, "-universe-dir", f.path("universe"), "-commit", f.commit, "-out-dir", f.path(dir))
	_ = readJSON(f.path(dir, "verdict.json"), &v)
	return code, v, output
}

// splitLane: the lane may run as disjoint parts, or with chosen packages handed
// to `go test` first. Either way the verdict judges the UNION as the one lane:
// the same package set, results and block universe as the single-process lane,
// and a missing or duplicated part is refused.
func splitLane(t *testing.T, f *fixture, whole Verdict) {
	const sub = "example.com/pilot/sub"
	f.mustRS("run-lane", "-out-dir", f.path("lane-rest"), "-commit", f.commit, "-timeout", "2m", "-exclude", sub)
	f.mustRS("run-lane", "-out-dir", f.path("lane-sub"), "-commit", f.commit, "-timeout", "2m", "-only", sub)
	code, v, out := f.verdictLanes("verdict-split", f.path("lane-rest")+","+f.path("lane-sub"))
	if code != 0 || !v.OK {
		t.Fatalf("split lane rejected (exit %d):\n%s", code, out)
	}
	if v.Merged != whole.Merged || v.Lane.Packages != whole.Lane.Packages || !reflect.DeepEqual(v.Completeness, whole.Completeness) {
		t.Fatalf("split lane differs from the whole lane:\nsplit %+v %+v %+v\nwhole %+v %+v %+v",
			v.Merged, v.Lane.Packages, v.Completeness, whole.Merged, whole.Lane.Packages, whole.Completeness)
	}
	if code, _, out := f.verdictLanes("verdict-part", f.path("lane-rest")); code == 0 {
		t.Fatalf("a lane missing its other part was accepted:\n%s", out)
	}
	if code, _, out := f.verdictLanes("verdict-dup", f.path("lane")+","+f.path("lane-sub")); code == 0 || !strings.Contains(out, "unexpected 1 ["+sub+"]") {
		t.Fatalf("a package run by two parts was accepted (exit %d):\n%s", code, out)
	}

	log := f.mustRS("run-lane", "-out-dir", f.path("lane-first"), "-commit", f.commit, "-timeout", "2m", "-first", sub)
	var meta LaneMeta
	if err := readJSON(f.path("lane-first", "meta.json"), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Packages) == 0 || meta.Packages[0] != sub {
		t.Fatalf("-first did not put %s first: %v", sub, meta.Packages)
	}
	if !strings.Contains(log, "LANE-PACKAGE start "+sub+" at ") || !strings.Contains(log, "LANE-PACKAGE running "+sub+" at ") || !strings.Contains(log, "LANE-PACKAGE pass "+sub+" at ") {
		t.Fatalf("the lane log does not record package start/end:\n%s", log)
	}
	// Which fixture package prints first is a race between tiny binaries; the
	// annotation's presence and content are what matter here.
	if !regexp.MustCompile(`::notice title=lane order \(first test output\)::1\. \S+ at [0-9.]+s;[^\n]*`+regexp.QuoteMeta(sub)).MatchString(log) &&
		!strings.Contains(log, "::notice title=lane order (first test output)::1. "+sub+" at ") ||
		!strings.Contains(log, "::notice title=lane finish #1 from last::") {
		t.Fatalf("the lane does not annotate its package order:\n%s", log)
	}
	if code, v, out := f.verdictLanes("verdict-first", f.path("lane-first")); code != 0 || !v.OK || v.Merged != whole.Merged {
		t.Fatalf("reordered lane rejected or different (exit %d):\n%s", code, out)
	}
	for _, bad := range [][]string{
		{"-first", "example.com/pilot/nope"},
		{"-exclude", sub, "-only", sub},
		{"-only", sub, "-first", "example.com/pilot/notest"},
	} {
		args := append([]string{"run-lane", "-out-dir", f.path("lane-bad"), "-commit", f.commit}, bad...)
		if code, out := f.rs(args...); code == 0 {
			t.Fatalf("run-lane %v accepted:\n%s", bad, out)
		}
	}
	if code, out := f.rs("universe", "-out-dir", f.path("universe-bad"), "-commit", f.commit, "-exclude", sub); code == 0 {
		t.Fatalf("the universe accepted a lane selection — it must stay the whole lane:\n%s", out)
	}
}
