// Package runner is the agent's command-execution boundary. Every
// docker-compose invocation goes through here; nothing else in the
// agent calls exec.Cmd directly.
//
// Contract (D1.6 plan § 4.1, non-negotiable):
//
//   - No shell. No sh -c, no bash -c, no shell expansion. exec.Cmd
//     with explicit argv only.
//   - Fixed command templates. Every operation maps to a Template
//     defined in this file's registry. Operators cannot extend.
//   - Validated bounded args. Each Template's Validators is consulted
//     before the runner is invoked.
//   - Fixed working directory from config (compose_project_dir).
//   - Environment allowlist; os.Environ() is NOT inherited.
//   - Bounded stdout/stderr capture (default 1 MiB).
//   - Per-command timeout (SIGTERM → 5s grace → SIGKILL).
//
// D1.6a registers exactly one template: TemplateComposeStatus
// ("docker compose -f <compose_file> ps"). D1.6b/c add backup,
// restore, cleanup, pull, manifest-inspect templates as they land,
// each with a matching sudoers entry per the parity test.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// TemplateID identifies a registered command template.
type TemplateID string

const (
	// TemplateComposeStatus runs `docker compose -f <compose_file> ps`
	// in the configured project directory. Used by /v1/status. The
	// only template that exists in D1.6a.
	TemplateComposeStatus TemplateID = "compose.status"
)

// Template is a fixed command pattern with positional arguments. The
// runner builds argv = baseArgv + perOp positional args; each Template
// declares its arg count and validators.
type Template struct {
	ID       TemplateID
	BaseArgv []string

	// Sudoers is the documentation-of-record for what command line
	// must be allow-listed in /etc/sudoers.d/culvert-maint for this
	// template. The static parity test cross-checks this string
	// against the on-disk sudoers file.
	Sudoers string

	// StateChanging mirrors ops.IsStateChanging; included on the
	// template so the parity test and any later sudoers-generator can
	// distinguish state-changing templates.
	StateChanging bool
}

// Registry returns the closed set of templates the agent will ever
// invoke. The static parity test asserts this set matches
// /etc/sudoers.d/culvert-maint exactly.
//
// To add a new template: add it here AND add a matching line to
// packaging/sudoers/culvert-maint AND add the runner method that
// invokes it AND the API handler that calls the runner method (per
// the D1.6 implementation plan § 4.6 four-step contract).
func Registry() []Template {
	return []Template{
		{
			ID:            TemplateComposeStatus,
			BaseArgv:      []string{"docker", "compose", "-f", "{compose_file}", "ps"},
			Sudoers:       "/usr/bin/docker compose -f {compose_file} ps",
			StateChanging: false,
		},
	}
}

// templateByID returns a *Template or nil.
func templateByID(id TemplateID) *Template {
	for i := range Registry() {
		t := Registry()[i]
		if t.ID == id {
			return &t
		}
	}
	return nil
}

// Result is the captured output of a single command. Stdout / Stderr
// are bounded; Truncated is set when capture hit the cap.
type Result struct {
	Argv      []string      `json:"argv"`
	ExitCode  int           `json:"exit_code"`
	Stdout    []byte        `json:"-"`
	Stderr    []byte        `json:"-"`
	Truncated bool          `json:"truncated"`
	Duration  time.Duration `json:"duration"`
}

// Runner is the per-agent command runner. Construct with New.
type Runner struct {
	composeProjectDir string
	composeFile       string
	useSudo           bool
	envAllow          []string
	captureMax        int
	stageTimeout      time.Duration

	// dockerBinary is overridable in tests. Default "docker".
	dockerBinary string
	// sudoBinary is overridable in tests. Default "sudo".
	sudoBinary string

	// hooksForTesting allow tests to substitute the exec layer. nil
	// in production.
	execStartFn func(*exec.Cmd) error
	execWaitFn  func(*exec.Cmd) error
}

// Options configures a Runner.
type Options struct {
	ComposeProjectDir string
	ComposeFile       string
	UseSudo           bool
	StageTimeout      time.Duration

	// CaptureMax bounds per-stream capture (stdout, stderr) in bytes.
	// Default 1 MiB if zero.
	CaptureMax int

	// EnvAllow is the closed list of env-var names to forward. The
	// child process gets ONLY these (plus the runner-supplied PATH /
	// HOME / LANG / TZ defaults). os.Environ() is NOT inherited.
	EnvAllow []string

	// DockerBinary defaults to "docker". Tests override.
	DockerBinary string
	// SudoBinary defaults to "sudo". Tests override.
	SudoBinary string
}

const (
	defaultCaptureMax = 1 << 20 // 1 MiB
	sigtermGrace      = 5 * time.Second
)

// New constructs a Runner. composeProjectDir must be absolute.
func New(opts Options) (*Runner, error) {
	if opts.ComposeProjectDir == "" {
		return nil, errors.New("runner: ComposeProjectDir required")
	}
	if opts.ComposeFile == "" {
		return nil, errors.New("runner: ComposeFile required")
	}
	if opts.StageTimeout <= 0 {
		return nil, errors.New("runner: StageTimeout must be positive")
	}
	captureMax := opts.CaptureMax
	if captureMax == 0 {
		captureMax = defaultCaptureMax
	}
	docker := opts.DockerBinary
	if docker == "" {
		docker = "docker"
	}
	sudo := opts.SudoBinary
	if sudo == "" {
		sudo = "sudo"
	}
	envAllow := append([]string(nil), opts.EnvAllow...)
	return &Runner{
		composeProjectDir: opts.ComposeProjectDir,
		composeFile:       opts.ComposeFile,
		useSudo:           opts.UseSudo,
		envAllow:          envAllow,
		captureMax:        captureMax,
		stageTimeout:      opts.StageTimeout,
		dockerBinary:      docker,
		sudoBinary:        sudo,
	}, nil
}

// ComposeStatus runs the TemplateComposeStatus template. Returns the
// captured result or an error.
func (r *Runner) ComposeStatus(ctx context.Context) (*Result, error) {
	tmpl := templateByID(TemplateComposeStatus)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeStatus not registered")
	}
	argv := r.buildArgv(tmpl)
	return r.run(ctx, argv)
}

// buildArgv expands a Template's BaseArgv with the configured compose
// file path. Placeholders like "{compose_file}" are replaced exactly.
// argv[0] is the executable; the runner prepends "sudo" if useSudo.
//
// D1.6a templates have no operator-supplied positional args. D1.6b/c
// expansions will accept validated args via additional methods.
func (r *Runner) buildArgv(tmpl *Template) []string {
	out := make([]string, 0, len(tmpl.BaseArgv)+2)
	if r.useSudo {
		out = append(out, r.sudoBinary, "-n")
	}
	for _, a := range tmpl.BaseArgv {
		switch a {
		case "docker":
			out = append(out, r.dockerBinary)
		case "{compose_file}":
			out = append(out, r.composeFile)
		default:
			out = append(out, a)
		}
	}
	return out
}

// run executes argv with bounded stdout/stderr capture, fixed cwd, env
// allowlist, and per-command timeout (with SIGTERM → SIGKILL grace).
// Single straight-line orchestration; splitting into per-step helpers
// would scatter the cleanup paths and obscure the SIGTERM/SIGKILL
// ordering.
//
//nolint:cyclop // single-pass orchestration; splitting obscures SIGTERM/SIGKILL ordering
func (r *Runner) run(ctx context.Context, argv []string) (*Result, error) {
	if len(argv) == 0 {
		return nil, errors.New("runner: empty argv")
	}

	runCtx, cancel := context.WithTimeout(ctx, r.stageTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...) // #nosec G204 -- argv comes from a fixed template registry, never operator input
	cmd.Dir = r.composeProjectDir
	cmd.Env = r.buildEnv()

	stdout := newBoundedBuffer(r.captureMax)
	stderr := newBoundedBuffer(r.captureMax)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Override default Cancel behaviour: send SIGTERM, then SIGKILL after grace.
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}
	cmd.WaitDelay = sigtermGrace // exec applies SIGKILL after this

	start := time.Now()
	startErr := r.startCmd(cmd)
	if startErr != nil {
		return nil, fmt.Errorf("runner: start: %w", startErr)
	}
	waitErr := r.waitCmd(cmd)
	dur := time.Since(start)

	res := &Result{
		Argv:      append([]string(nil), argv...),
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Truncated: stdout.Truncated() || stderr.Truncated(),
		Duration:  dur,
	}

	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, fmt.Errorf("runner: command exited %d", res.ExitCode)
		}
		// Context cancelled / killed.
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return res, fmt.Errorf("runner: command timed out after %s", r.stageTimeout)
		}
		return res, fmt.Errorf("runner: wait: %w", waitErr)
	}
	res.ExitCode = 0
	return res, nil
}

func (r *Runner) startCmd(cmd *exec.Cmd) error {
	if r.execStartFn != nil {
		return r.execStartFn(cmd)
	}
	return cmd.Start()
}

func (r *Runner) waitCmd(cmd *exec.Cmd) error {
	if r.execWaitFn != nil {
		return r.execWaitFn(cmd)
	}
	return cmd.Wait()
}

// buildEnv returns the env to forward to the child process. The runner
// builds env from scratch — os.Environ() is NOT inherited. Defaults:
// PATH, HOME, LANG, TZ. Plus EnvAllow names (whose values are read
// from the agent process env at exec time).
func (r *Runner) buildEnv() []string {
	defaults := map[string]string{
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME": "/var/lib/culvert-maint",
		"LANG": "C.UTF-8",
		"TZ":   "UTC",
	}
	env := make([]string, 0, len(defaults)+len(r.envAllow))
	for k, v := range defaults {
		env = append(env, k+"="+v)
	}
	for _, name := range r.envAllow {
		v, ok := lookupEnv(name)
		if !ok {
			continue
		}
		env = append(env, name+"="+v)
	}
	return env
}

// lookupEnv is a thin wrapper to make the env source mockable in
// future tests; D1.6a uses os.Getenv via the wrapper.
var lookupEnv = syscallGetenv

// boundedBuffer is an io.Writer that caps total bytes captured. Writes
// past the cap silently drop and set the truncated flag. Always
// returns len(p) so the parent writer (exec.Cmd) doesn't block.
// Single-owner discipline: exec.Cmd writes its stdout/stderr serially
// per stream.
type boundedBuffer struct {
	cap       int
	buf       bytes.Buffer
	truncated bool
}

// newBoundedBuffer constructs a buffer that caps at capBytes total.
func newBoundedBuffer(capBytes int) *boundedBuffer {
	return &boundedBuffer{cap: capBytes}
}

// Write appends to the buffer up to the cap; bytes past the cap are
// silently dropped and the truncated flag is set.
func (b *boundedBuffer) Write(p []byte) (int, error) {
	remain := b.cap - b.buf.Len()
	if remain <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remain {
		_, _ = b.buf.Write(p[:remain])
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

// Bytes returns the captured bytes.
func (b *boundedBuffer) Bytes() []byte { return b.buf.Bytes() }

// Truncated reports whether any write exceeded the cap.
func (b *boundedBuffer) Truncated() bool { return b.truncated }

// String returns the captured bytes as a string. Used by tests.
func (b *boundedBuffer) String() string { return b.buf.String() }

// FormatStringForFlow converts a path-or-string into a defensive copy
// suitable for inclusion in a logged argv. Strips any newline or NUL
// to keep argv-rendering safe for human-readable output.
func FormatStringForFlow(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}
