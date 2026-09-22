package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// manifestSchema versions manifest.json.
const manifestSchema = 1

// Manifest is the build identity every shard and the verdict check against. A
// shard that ran a different binary, a different commit, a different
// toolchain or from a different checkout path is refused, not merged.
type Manifest struct {
	Schema       int      `json:"schema"`
	Package      string   `json:"package"`
	Commit       string   `json:"commit"`
	GoVersion    string   `json:"goVersion"`
	GOOS         string   `json:"goos"`
	GOARCH       string   `json:"goarch"`
	WorkDir      string   `json:"workDir"`
	BuildCommand []string `json:"buildCommand"`
	Binary       string   `json:"binary"`
	BinarySHA256 string   `json:"binarySHA256"`
	BinaryBytes  int64    `json:"binaryBytes"`
	ListSHA256   string   `json:"listSHA256"`
	Runnable     int      `json:"runnable"`
	Benchmarks   int      `json:"benchmarks"`
	// Measured costs (seconds).
	CompileSeconds  float64 `json:"compileSeconds"`
	ListSeconds     float64 `json:"listSeconds"`
	EmptyRunSeconds float64 `json:"emptyRunSeconds"`
}

// toolchain is the Go identity of the current environment.
type toolchain struct{ Version, GOOS, GOARCH string }

// buildArgs is the ONE compile of the root race+coverage test binary. It
// mirrors the unsharded reference (`go test -race -coverprofile=... ./...`):
// -race forces covermode=atomic, -cover instruments only the package under
// test (no -coverpkg in the reference either), and no -trimpath, because
// pkgSourceDir() and the source-reading tests resolve absolute paths recorded
// at compile time.
func buildArgs(binary string) []string {
	return []string{"test", "-c", "-race", "-cover", "-o", binary, "."}
}

func cmdBuild(args []string, stdout io.Writer) error {
	fs := newFlags("build")
	outDir := fs.String("out-dir", "", "directory for the binary, list.txt and manifest.json")
	commit := fs.String("commit", os.Getenv("GITHUB_SHA"), "source commit being built")
	goBin := fs.String("go", "go", "go command")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if err := required(fs, "out-dir", "commit"); err != nil {
		return err
	}
	ctx := context.Background()
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}
	tc, err := currentToolchain(ctx, *goBin)
	if err != nil {
		return err
	}
	pkg, err := goOutput(ctx, *goBin, "list", ".")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	binary, err := filepath.Abs(filepath.Join(*outDir, "root.test"))
	if err != nil {
		return fmt.Errorf("abs: %w", err)
	}
	m := Manifest{Schema: manifestSchema, Package: pkg, Commit: *commit, GoVersion: tc.Version, GOOS: tc.GOOS,
		GOARCH: tc.GOARCH, WorkDir: wd, BuildCommand: append([]string{*goBin}, buildArgs("<binary>")...), Binary: filepath.Base(binary)}
	start := time.Now()
	// #nosec G204 -- fixed go subcommand; the only variable is our own output path.
	c := exec.CommandContext(ctx, *goBin, buildArgs(binary)...)
	c.Stdout, c.Stderr = stdout, stdout
	if err := c.Run(); err != nil {
		return fmt.Errorf("compile root test binary: %w", err)
	}
	m.CompileSeconds = since(start)
	if m.BinarySHA256, m.BinaryBytes, err = fileSHA256(binary); err != nil {
		return err
	}
	scratch, err := os.MkdirTemp("", "rootshard-build-")
	if err != nil {
		return fmt.Errorf("tempdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if err := listAndMeasure(ctx, binary, scratch, *outDir, &m); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(*outDir, "manifest.json"), m); err != nil {
		return err
	}
	say(stdout, "built %s (%d bytes, sha256 %s) in %.1fs: %d runnable, %d benchmarks; empty run (TestMain) %.2fs\n",
		m.Binary, m.BinaryBytes, m.BinarySHA256, m.CompileSeconds, m.Runnable, m.Benchmarks, m.EmptyRunSeconds)
	return nil
}

// listAndMeasure discovers the inventory from the binary itself and times one
// empty run — the fixed per-process cost (process start, TestMain, coverage
// write) every additional shard or chunk pays again.
func listAndMeasure(ctx context.Context, binary, scratch, outDir string, m *Manifest) error {
	start := time.Now()
	list, err := listEntries(ctx, binary, ".*", scratch, m.WorkDir)
	if err != nil {
		return err
	}
	m.ListSeconds = since(start)
	listPath := filepath.Join(outDir, "list.txt")
	if err := os.WriteFile(listPath, list, 0o600); err != nil {
		return fmt.Errorf("write list: %w", err)
	}
	inv, err := parseList(bytes.NewReader(list))
	if err != nil {
		return err
	}
	m.Runnable, m.Benchmarks = len(inv.Runnable), len(inv.Benchmarks)
	sum := sha256.Sum256(list)
	m.ListSHA256 = hex.EncodeToString(sum[:])
	start = time.Now()
	// #nosec G204 -- runs the binary this command just compiled.
	c := exec.CommandContext(ctx, binary, "-test.paniconexit0", "-test.gocoverdir="+filepath.Join(scratch, "cov"),
		"-test.count=1", "-test.timeout=5m", "-test.run=^$", "-test.coverprofile="+filepath.Join(scratch, "empty.out"))
	c.Dir = m.WorkDir
	if err := os.MkdirAll(filepath.Join(scratch, "cov"), 0o750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("empty run failed: %w\n%s", err, out)
	}
	m.EmptyRunSeconds = since(start)
	return nil
}

// listEntries runs `<binary> -test.list <pattern>` — the binary's own view of
// what a -test.run selection with the same pattern would contain.
func listEntries(ctx context.Context, binary, pattern, scratch, dir string) ([]byte, error) {
	cov := filepath.Join(scratch, "listcov")
	if err := os.MkdirAll(cov, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	// #nosec G204 -- the prebuilt test binary with a verified selection pattern.
	c := exec.CommandContext(ctx, binary, "-test.gocoverdir="+cov, "-test.list="+pattern)
	c.Dir = dir
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("%s -test.list: %w\n%s", filepath.Base(binary), err, stderr.String())
	}
	return out, nil
}

// ShardMeta is written by run-shard whatever happens, so the verdict can tell
// a failed chunk from one that never ran.
type ShardMeta struct {
	Shard        int         `json:"shard"`
	Commit       string      `json:"commit"`
	BinarySHA256 string      `json:"binarySHA256"`
	GoVersion    string      `json:"goVersion"`
	GOOS         string      `json:"goos"`
	GOARCH       string      `json:"goarch"`
	WorkDir      string      `json:"workDir"`
	Chunks       []ChunkMeta `json:"chunks"`
	TestSeconds  float64     `json:"testSeconds"`
}

// ChunkMeta records one process.
type ChunkMeta struct {
	Index            int     `json:"index"`
	Entries          int     `json:"entries"`
	SelectionMatched bool    `json:"selectionMatched"`
	SelectionProblem string  `json:"selectionProblem,omitempty"`
	ExitCode         int     `json:"exitCode"`
	Seconds          float64 `json:"seconds"`
	ListSeconds      float64 `json:"listSeconds"`
}

func cmdRunShard(args []string, stdout io.Writer) error {
	fs := newFlags("run-shard")
	planPath := fs.String("plan", "", "plan.json")
	manPath := fs.String("manifest", "", "manifest.json from build")
	binary := fs.String("binary", "", "the prebuilt root test binary")
	shard := fs.Int("shard", -1, "shard index")
	outDir := fs.String("out-dir", "", "evidence directory")
	commit := fs.String("commit", os.Getenv("GITHUB_SHA"), "commit this job checked out")
	timeout := fs.String("timeout", "40m", "per-process -test.timeout (the reference's per-binary budget)")
	goBin := fs.String("go", "go", "go command (test2json + tests that invoke Go)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if err := required(fs, "plan", "manifest", "binary", "out-dir", "commit"); err != nil {
		return err
	}
	var p Plan
	var m Manifest
	if err := readJSON(*planPath, &p); err != nil {
		return err
	}
	if err := readJSON(*manPath, &m); err != nil {
		return err
	}
	if *shard < 0 || *shard >= len(p.Shards) {
		return fmt.Errorf("%w: shard %d out of range [0,%d)", errUsage, *shard, len(p.Shards))
	}
	ctx := context.Background()
	meta, err := checkShardEnvironment(ctx, m, *binary, *commit, *goBin)
	if err != nil {
		return err
	}
	meta.Shard = *shard
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	r := chunkRunner{ctx: ctx, binary: *binary, goBin: *goBin, pkg: m.Package, dir: meta.WorkDir,
		outDir: *outDir, timeout: *timeout, stdout: stdout}
	var failed []string
	for _, c := range p.Shards[*shard].Chunks {
		cm := r.run(c)
		meta.Chunks = append(meta.Chunks, cm)
		meta.TestSeconds += cm.Seconds
		if !cm.SelectionMatched || cm.ExitCode != 0 {
			failed = append(failed, fmt.Sprintf("chunk %d (exit %d, selection %v %s)", c.Index, cm.ExitCode, cm.SelectionMatched, cm.SelectionProblem))
		}
	}
	if err := writeJSON(filepath.Join(*outDir, "meta.json"), meta); err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("shard %d: %s", *shard, strings.Join(failed, "; "))
	}
	return nil
}

// checkShardEnvironment refuses to run a shard anywhere its evidence would not
// be comparable: another binary, commit, toolchain or checkout path. The last
// matters because runtime.Caller-derived paths (pkgSourceDir) are compiled in.
func checkShardEnvironment(ctx context.Context, m Manifest, binary, commit, goBin string) (ShardMeta, error) {
	wd, err := os.Getwd()
	if err != nil {
		return ShardMeta{}, fmt.Errorf("getwd: %w", err)
	}
	sum, _, err := fileSHA256(binary)
	if err != nil {
		return ShardMeta{}, err
	}
	tc, err := currentToolchain(ctx, goBin)
	if err != nil {
		return ShardMeta{}, err
	}
	meta := ShardMeta{Commit: commit, BinarySHA256: sum, GoVersion: tc.Version, GOOS: tc.GOOS, GOARCH: tc.GOARCH, WorkDir: wd}
	var probs []string
	if sum != m.BinarySHA256 {
		probs = append(probs, fmt.Sprintf("binary sha256 %s != manifest %s", sum, m.BinarySHA256))
	}
	if commit != m.Commit {
		probs = append(probs, fmt.Sprintf("checked-out commit %s != built commit %s", commit, m.Commit))
	}
	if wd != m.WorkDir {
		probs = append(probs, fmt.Sprintf("working directory %s != build directory %s (compiled-in source paths would not resolve)", wd, m.WorkDir))
	}
	if tc != (toolchain{m.GoVersion, m.GOOS, m.GOARCH}) {
		probs = append(probs, fmt.Sprintf("toolchain %s %s/%s != build toolchain %s %s/%s", tc.Version, tc.GOOS, tc.GOARCH, m.GoVersion, m.GOOS, m.GOARCH))
	}
	if len(probs) > 0 {
		return ShardMeta{}, fmt.Errorf("incompatible shard environment: %s", strings.Join(probs, "; "))
	}
	return meta, nil
}

type chunkRunner struct {
	ctx                                      context.Context
	binary, goBin, pkg, dir, outDir, timeout string
	stdout                                   io.Writer
}

// run executes one chunk: first proves the binary itself selects exactly the
// planned names for this regex, then runs it with the reference's per-binary
// flags (what `go test` passes: -test.paniconexit0, -test.gocoverdir,
// -test.timeout, -test.count, -test.coverprofile), streaming test2json events
// to chunk-<k>.json and the readable output to the job log.
func (r chunkRunner) run(c Chunk) ChunkMeta {
	cm := ChunkMeta{Index: c.Index, Entries: len(c.Names), ExitCode: -1}
	scratch := filepath.Join(r.outDir, fmt.Sprintf("scratch-%d", c.Index))
	start := time.Now()
	listed, err := listEntries(r.ctx, r.binary, c.Regex, scratch, r.dir)
	cm.ListSeconds = since(start)
	if err != nil {
		cm.SelectionProblem = err.Error()
	} else {
		cm.SelectionProblem = diffNames(c.Names, strings.Fields(string(listed)))
		cm.SelectionMatched = cm.SelectionProblem == ""
	}
	if !cm.SelectionMatched {
		say(r.stdout, "::error::chunk %d: the binary's own selection differs from the plan: %s\n", c.Index, cm.SelectionProblem)
		return cm
	}
	cov := filepath.Join(r.outDir, fmt.Sprintf("gocoverdir-%d", c.Index))
	if err := os.MkdirAll(cov, 0o750); err != nil {
		cm.SelectionProblem = err.Error()
		return cm
	}
	args := []string{"-test.paniconexit0", "-test.gocoverdir=" + cov, "-test.timeout=" + r.timeout, "-test.count=1",
		"-test.coverprofile=" + filepath.Join(r.outDir, fmt.Sprintf("chunk-%d.cover.out", c.Index)),
		"-test.v=test2json", "-test.run=" + c.Regex}
	start = time.Now()
	cm.ExitCode = r.stream(args, filepath.Join(r.outDir, fmt.Sprintf("chunk-%d.json", c.Index)))
	cm.Seconds = since(start)
	_ = os.RemoveAll(scratch) // listing scratch only; evidence lives beside it
	return cm
}

// stream runs the binary with stdout+stderr merged (as `go test` does) into
// `go tool test2json`, tees the events to eventsPath and prints each Output
// field, so the job log reads like the reference's -v log. Returns the test
// binary's exit code; a conversion failure is reported as -2.
func (r chunkRunner) stream(args []string, eventsPath string) int {
	f, err := os.Create(eventsPath)
	if err != nil {
		say(r.stdout, "::error::create %s: %v\n", eventsPath, err)
		return -2
	}
	defer f.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		say(r.stdout, "::error::pipe: %v\n", err)
		return -2
	}
	// #nosec G204 -- the verified prebuilt test binary; args are built above.
	bin := exec.CommandContext(r.ctx, r.binary, args...)
	bin.Dir, bin.Stdout, bin.Stderr = r.dir, pw, pw
	// #nosec G204 -- fixed go subcommand.
	conv := exec.CommandContext(r.ctx, r.goBin, "tool", "test2json", "-t", "-p", r.pkg)
	conv.Stdin, conv.Stderr = pr, r.stdout
	convOut, err := conv.StdoutPipe()
	if err == nil {
		err = conv.Start()
	}
	if err == nil {
		err = bin.Start()
	}
	pw.Close()
	pr.Close()
	if err != nil {
		say(r.stdout, "::error::start chunk: %v\n", err)
		return -2
	}
	copyErr := copyEvents(convOut, f, r.stdout)
	binErr := bin.Wait()
	convErr := conv.Wait()
	code := exitCode(binErr)
	if (convErr != nil || copyErr != nil) && code == 0 {
		say(r.stdout, "::error::test2json: %v %v\n", convErr, copyErr)
		return -2
	}
	return code
}

// copyEvents tees test2json lines to w and prints their Output fields to log.
// A failed write to w is RETURNED — a truncated events file would read as a
// shorter run — while a failed write to the log is not (see say).
func copyEvents(r io.Reader, w, log io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	bw := bufio.NewWriter(w)
	for sc.Scan() {
		line := sc.Bytes()
		// bufio errors are sticky and surface from Flush below.
		_, _ = bw.Write(line)
		_ = bw.WriteByte('\n')
		var ev testEvent
		if json.Unmarshal(line, &ev) == nil && ev.Action == "output" {
			say(log, "%s", ev.Output)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read events: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write events: %w", err)
	}
	return nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -2
}

// diffNames reports how two name sets differ, or "" when equal.
func diffNames(want, got []string) string {
	w := map[string]int{}
	for _, n := range want {
		w[n]++
	}
	for _, n := range got {
		w[n]--
	}
	var missing, extra []string
	for _, n := range sortedKeys(w) {
		switch {
		case w[n] > 0:
			missing = append(missing, n)
		case w[n] < 0:
			extra = append(extra, n)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	return fmt.Sprintf("missing %s; unexpected %s", headList(missing, 5), headList(extra, 5))
}

// headList renders at most n items plus a count of the rest.
func headList(xs []string, n int) string {
	if len(xs) == 0 {
		return "none"
	}
	if len(xs) <= n {
		return fmt.Sprintf("%d %v", len(xs), xs)
	}
	return fmt.Sprintf("%d %v…", len(xs), xs[:n])
}

// LaneMeta records the non-root package lane.
type LaneMeta struct {
	Commit    string   `json:"commit"`
	GoVersion string   `json:"goVersion"`
	GOOS      string   `json:"goos"`
	GOARCH    string   `json:"goarch"`
	WorkDir   string   `json:"workDir"`
	Excluded  string   `json:"excluded"`
	Packages  []string `json:"packages"`
	Command   []string `json:"command"`
	ExitCode  int      `json:"exitCode"`
	Seconds   float64  `json:"seconds"`
}

// nonRootPackages is every package `go list ./...` returns EXCEPT the exact
// root import path — not a directory prefix such as internal/, so cmd/ and any
// future top-level package are covered automatically.
func nonRootPackages(ctx context.Context, goBin string) (root string, pkgs []string, err error) {
	root, err = goOutput(ctx, goBin, "list", ".")
	if err != nil {
		return "", nil, err
	}
	all, err := goOutput(ctx, goBin, "list", "./...")
	if err != nil {
		return "", nil, err
	}
	found := false
	for _, p := range strings.Fields(all) {
		if p == root {
			found = true
			continue
		}
		pkgs = append(pkgs, p)
	}
	if !found {
		return "", nil, fmt.Errorf("root package %s is not in `go list ./...`", root)
	}
	if len(pkgs) == 0 {
		return "", nil, errors.New("no non-root packages — refusing an empty lane")
	}
	sort.Strings(pkgs)
	return root, pkgs, nil
}

func cmdRunLane(args []string, stdout io.Writer) error {
	fs := newFlags("run-lane")
	outDir := fs.String("out-dir", "", "evidence directory")
	commit := fs.String("commit", os.Getenv("GITHUB_SHA"), "commit this job checked out")
	timeout := fs.String("timeout", "40m", "per-binary -timeout (the reference's)")
	goBin := fs.String("go", "go", "go command")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if err := required(fs, "out-dir", "commit"); err != nil {
		return err
	}
	ctx := context.Background()
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}
	tc, err := currentToolchain(ctx, *goBin)
	if err != nil {
		return err
	}
	root, pkgs, err := nonRootPackages(ctx, *goBin)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	goArgs := append([]string{"test", "-race", "-count=1", "-timeout=" + *timeout,
		"-coverprofile=" + filepath.Join(*outDir, "lane.cover.out"), "-json"}, pkgs...)
	meta := LaneMeta{Commit: *commit, GoVersion: tc.Version, GOOS: tc.GOOS, GOARCH: tc.GOARCH, WorkDir: wd,
		Excluded: root, Packages: pkgs, Command: append([]string{*goBin}, goArgs[:6]...)}
	f, err := os.Create(filepath.Join(*outDir, "lane.json"))
	if err != nil {
		return fmt.Errorf("create lane.json: %w", err)
	}
	defer f.Close()
	start := time.Now()
	// #nosec G204 -- fixed go subcommand over `go list` output.
	c := exec.CommandContext(ctx, *goBin, goArgs...)
	out, err := c.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	c.Stderr = stdout
	if err := c.Start(); err != nil {
		return fmt.Errorf("start go test: %w", err)
	}
	copyErr := copyEvents(out, f, stdout)
	meta.ExitCode = exitCode(c.Wait())
	if copyErr != nil && meta.ExitCode == 0 {
		meta.ExitCode = -2
		say(stdout, "::error::lane events: %v\n", copyErr)
	}
	meta.Seconds = since(start)
	if err := writeJSON(filepath.Join(*outDir, "meta.json"), meta); err != nil {
		return err
	}
	if meta.ExitCode != 0 {
		return fmt.Errorf("non-root lane: go test exited %d", meta.ExitCode)
	}
	return nil
}

func currentToolchain(ctx context.Context, goBin string) (toolchain, error) {
	out, err := goOutput(ctx, goBin, "env", "GOVERSION", "GOOS", "GOARCH")
	if err != nil {
		return toolchain{}, err
	}
	f := strings.Fields(out)
	if len(f) != 3 {
		return toolchain{}, fmt.Errorf("unexpected `go env` output %q", out)
	}
	return toolchain{f[0], f[1], f[2]}, nil
}

func goOutput(ctx context.Context, goBin string, args ...string) (string, error) {
	// #nosec G204 -- fixed go subcommands.
	c := exec.CommandContext(ctx, goBin, args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func fileSHA256(path string) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func since(t time.Time) float64 {
	return float64(time.Since(t).Milliseconds()) / 1000
}
