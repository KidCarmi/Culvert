//go:build lifecycle_conformance

// Command lifecyclemutate runs mutation testing of the REAL maintenance-agent code, in
// isolated copies only: nothing in the checkout is changed and nothing is pushed.
// For every mutant: (1) the agent's existing tests, (2) the model-conformance tests.
//
//	go run -tags lifecycle_conformance ./internal/lifecyclemodel/cmd/lifecyclemutate \
//	    <culvert checkout> -out results.json [-cap N] [-workers N]
//
// Scheduled campaign only: far too slow for a pull request (about 1h40m on 4 cores for
// 350 mutants).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var existingPkgs = []string{"./internal/server/", "./internal/ops/", "./internal/journal/"}

// result is a mutant plus what the two suites said about it.
type result struct {
	mutant
	Status              string  `json:"status"` // tested | does_not_compile
	KilledByExisting    *bool   `json:"killed_by_existing,omitempty"`
	KilledByConformance *bool   `json:"killed_by_conformance,omitempty"`
	ConformanceSignal   *string `json:"conformance_signal,omitempty"`
	ConfirmedSerially   bool    `json:"confirmed_serially,omitempty"`
}

func (r *result) tested() bool { return r.Status == "tested" }

type summary struct {
	Candidates              int `json:"candidates"`
	Sampled                 int `json:"sampled"`
	DoNotCompile            int `json:"do_not_compile"`
	Tested                  int `json:"tested"`
	KilledByExistingTests   int `json:"killed_by_existing_tests"`
	KilledByConformance     int `json:"killed_by_conformance"`
	KilledByBoth            int `json:"killed_by_both"`
	KilledOnlyByExisting    int `json:"killed_only_by_existing"`
	KilledOnlyByConformance int `json:"killed_only_by_conformance"`
	SurvivedBoth            int `json:"survived_both"`
}

type fileSummary struct {
	Tested          int `json:"tested"`
	Existing        int `json:"existing"`
	Conformance     int `json:"conformance"`
	OnlyConformance int `json:"only_conformance"`
	Survived        int `json:"survived"`
}

type output struct {
	Summary summary                 `json:"summary"`
	PerFile map[string]*fileSummary `json:"per_file"`
	Mutants []result                `json:"mutants"`
}

// goTest runs `go test -count=1 args...` in dir and returns its exit code (124 on
// timeout) and combined output.
func goTest(dir string, args ...string) (code int, output string) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", append([]string{"test", "-count=1"}, args...)...) //nolint:gosec // fixed argv
	cmd.Dir = dir
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return 124, "timeout"
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &ee):
		return ee.ExitCode(), string(out)
	}
	return 1, string(out) + err.Error()
}

// existing runs the agent's own tests. No build tag: the conformance code is not compiled.
func existing(dir string) (code int, output string) {
	return goTest(dir, append([]string{"-timeout", "200s"}, existingPkgs...)...)
}

func conformance(dir string) (code int, output string) {
	return goTest(dir, "-tags", "lifecycle_conformance", "-run", "TestModelConformance", "-timeout", "200s", "./internal/server/")
}

// signal is the first line of the conformance output that says what disagreed.
func signal(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "MISMATCH") || strings.Contains(l, "PROPERTY") || strings.Contains(l, "never reached") ||
			(strings.Contains(l, "journal") && !strings.Contains(l, "Errorf") && !strings.Contains(l, "---")) {
			r := []rune(strings.TrimSpace(l))
			if len(r) > 160 {
				r = r[:160]
			}
			return string(r)
		}
	}
	return ""
}

// runMutant applies m to the copy in dir, runs both suites and ALWAYS restores the file.
func runMutant(dir string, m mutant) (res result, err error) {
	path := filepath.Join(dir, m.File)
	orig, err := os.ReadFile(path) //nolint:gosec // inside our own temp copy
	if err != nil {
		return result{}, err
	}
	lines := strings.Split(string(orig), "\n")
	lines[m.Line-1] = m.New
	defer func() {
		if werr := os.WriteFile(path, orig, 0o600); werr != nil { //nolint:gosec // inside our own temp copy
			err = errors.Join(err, fmt.Errorf("restore %s: %w", path, werr))
		}
	}()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil { //nolint:gosec // inside our own temp copy
		return result{}, err
	}
	rc, out := existing(dir)
	if strings.Contains(out, "[build failed]") || strings.Contains(out, "[setup failed]") {
		return result{mutant: m, Status: "does_not_compile"}, nil
	}
	rc2, out2 := conformance(dir)
	ke, kc, sig := rc != 0, rc2 != 0, signal(out2)
	return result{mutant: m, Status: "tested", KilledByExisting: &ke, KilledByConformance: &kc, ConformanceSignal: &sig}, nil
}

// stride is the deterministic sample: every step-th candidate, at most limit of them.
func stride(all []mutant, limit int) (chosen []mutant, step int) {
	step = max(1, (len(all)+limit-1)/limit)
	for i := 0; i < len(all); i += step {
		chosen = append(chosen, all[i])
	}
	return chosen, step
}

// runAll tests the chosen mutants, one goroutine per worker directory, sequentially
// within a directory. Results come back in worker order.
func runAll(dirs []string, chosen []mutant) ([]result, error) {
	parts := make([][]result, len(dirs))
	errs := make([]error, len(dirs))
	var wg sync.WaitGroup
	for w := range dirs {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(chosen); i += len(dirs) {
				r, err := runMutant(dirs[w], chosen[i])
				if err != nil {
					errs[w] = err
					return
				}
				parts[w] = append(parts[w], r)
			}
		}(w)
	}
	wg.Wait()
	var res []result
	for _, p := range parts {
		res = append(res, p...)
	}
	return res, errors.Join(errs...)
}

// confirm re-runs, serially and unloaded, every kill seen by only one suite: it must
// reproduce, so that a timing flake under parallel load is never counted as a detection.
func confirm(dir string, res []result) error {
	var disputed []*result
	for i := range res {
		if r := &res[i]; r.tested() && *r.KilledByExisting != *r.KilledByConformance {
			disputed = append(disputed, r)
		}
	}
	fmt.Printf("confirming %d single-suite kills serially\n", len(disputed))
	for _, r := range disputed {
		again, err := runMutant(dir, r.mutant)
		if err != nil {
			return err
		}
		ke := *r.KilledByExisting && again.tested() && *again.KilledByExisting
		kc := *r.KilledByConformance && again.tested() && *again.KilledByConformance
		r.KilledByExisting, r.KilledByConformance, r.ConfirmedSerially = &ke, &kc, true
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func summarize(res []result, candidates, sampled int) output {
	sort.SliceStable(res, func(i, j int) bool {
		a, b := &res[i], &res[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Op < b.Op
	})
	s := summary{Candidates: candidates, Sampled: sampled}
	per := map[string]*fileSummary{}
	for i := range res {
		r := &res[i]
		if !r.tested() {
			s.DoNotCompile++
			continue
		}
		e, c := *r.KilledByExisting, *r.KilledByConformance
		s.Tested++
		s.KilledByExistingTests += b2i(e)
		s.KilledByConformance += b2i(c)
		s.KilledByBoth += b2i(e && c)
		s.KilledOnlyByExisting += b2i(e && !c)
		s.KilledOnlyByConformance += b2i(c && !e)
		s.SurvivedBoth += b2i(!e && !c)
		d := per[r.File]
		if d == nil {
			d = &fileSummary{}
			per[r.File] = d
		}
		d.Tested++
		d.Existing += b2i(e)
		d.Conformance += b2i(c)
		d.OnlyConformance += b2i(c && !e)
		d.Survived += b2i(!e && !c)
	}
	return output{Summary: s, PerFile: per, Mutants: res}
}

func marshal(v any) []byte {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false) // mutants are Go source: keep < > & readable
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		panic(err) // plain data: cannot fail
	}
	return []byte(sb.String())
}

type options struct {
	checkout string
	out      string
	limit    int
	workers  int
	list     bool
}

func parseArgs(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("lifecyclemutate", flag.ContinueOnError)
	fs.StringVar(&o.out, "out", "", "write the full results to this JSON file (required)")
	fs.IntVar(&o.limit, "cap", 240, "maximum number of mutants (deterministic stride sample)")
	fs.IntVar(&o.workers, "workers", runtime.NumCPU(), "parallel worker copies")
	fs.BoolVar(&o.list, "list", false, "only write the candidate mutants to -out; run nothing")
	// The checkout may come before or after the flags.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		o.checkout, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.checkout == "" && fs.NArg() == 1 {
		o.checkout = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return o, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if o.checkout == "" || o.out == "" || o.limit < 1 || o.workers < 1 {
		return o, errors.New("usage: lifecyclemutate <culvert checkout> -out results.json [-cap N] [-workers N]")
	}
	return o, nil
}

// workerCopies copies cmd/culvert-maint of the checkout into n directories under work.
func workerCopies(src, work string, n int) ([]string, error) {
	dirs := make([]string, n)
	for w := range dirs {
		dirs[w] = filepath.Join(work, fmt.Sprintf("w%d", w))
		if err := os.CopyFS(dirs[w], os.DirFS(src)); err != nil {
			return nil, fmt.Errorf("copy %s: %w", src, err)
		}
	}
	return dirs, nil
}

// baseline requires both suites to be green three times on the unmutated copy.
func baseline(dir string) error {
	for i := 0; i < 3; i++ {
		rc, out := existing(dir)
		if rc != 0 {
			return fmt.Errorf("baseline not green (existing tests, run %d, exit %d):\n%s", i+1, rc, out)
		}
		if rc, out = conformance(dir); rc != 0 {
			return fmt.Errorf("baseline not green (conformance, run %d, exit %d):\n%s", i+1, rc, out)
		}
	}
	return nil
}

func run(o options) error {
	src := filepath.Join(o.checkout, "cmd", "culvert-maint")
	if o.list {
		all, err := candidates(src)
		if err != nil {
			return err
		}
		return os.WriteFile(o.out, marshal(all), 0o600)
	}
	work, err := os.MkdirTemp("", "mut")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	dirs, err := workerCopies(src, work, o.workers)
	if err != nil {
		return err
	}
	all, err := candidates(dirs[0])
	if err != nil {
		return err
	}
	chosen, step := stride(all, o.limit)
	if err := baseline(dirs[0]); err != nil {
		return err
	}
	fmt.Printf("%d candidate mutants, testing %d (every %dth); baseline green 3/3\n", len(all), len(chosen), step)
	res, err := runAll(dirs, chosen)
	if err != nil {
		return err
	}
	if err := confirm(dirs[0], res); err != nil {
		return err
	}
	out := summarize(res, len(all), len(chosen))
	if err := os.WriteFile(o.out, marshal(out), 0o600); err != nil {
		return err
	}
	fmt.Print(string(marshal(out.Summary)), string(marshal(out.PerFile)))
	return nil
}

func main() {
	o, err := parseArgs(os.Args[1:])
	if err == nil {
		err = run(o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lifecyclemutate:", err)
		os.Exit(2)
	}
}
