package mcpacceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// maxLogBytes bounds each captured stdout/stderr file.
const maxLogBytes = 1 << 20

// Process is one running built-binary instance under harness ownership.
type Process struct {
	pc      procConfig
	binary  string
	cmd     *exec.Cmd
	logDir  string
	stdout  *boundedFile
	stderr  *boundedFile
	started bool
}

// boundedFile caps the bytes written to a log file.
type boundedFile struct {
	f       *os.File
	written int64
}

func newBoundedFile(path string) (*boundedFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &boundedFile{f: f}, nil
}

func (b *boundedFile) Write(p []byte) (int, error) {
	if b.written >= maxLogBytes {
		return len(p), nil // silently drop past the cap; never block the child
	}
	remaining := maxLogBytes - b.written
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := b.f.Write(p)
	b.written += int64(n)
	return len(p), err
}

// Close closes the underlying log file.
func (b *boundedFile) Close() error { return b.f.Close() }

// startProcess launches the built binary for one process config and blocks until
// the MCP health surface reports the expected active posture (never merely
// "process alive"). All waits are bounded by the run control timeouts.
func (h *Harness) startProcess(ctx context.Context, pc procConfig) (*Process, error) {
	logDir := filepath.Join(filepath.Dir(pc.configPath), "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, err
	}
	stdout, err := newBoundedFile(filepath.Join(logDir, "stdout.log"))
	if err != nil {
		return nil, err
	}
	stderr, err := newBoundedFile(filepath.Join(logDir, "stderr.log"))
	if err != nil {
		return nil, err
	}
	// #nosec G204 -- binary path and flags are harness-controlled, not user input.
	cmd := exec.CommandContext(ctx, h.binary,
		"-config", pc.configPath,
		"-ui-no-tls",
		"-port", itoa(pc.proxyPort),
		"-ui-port", itoa(pc.uiPort),
		"-user", pc.adminUser,
		"-pass", pc.adminPass,
		"-metrics-token", pc.metricsToken,
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Isolate the child's working directory so any side files it writes to cwd (e.g.
	// the ClusterStore's cluster.json) land in the harness-owned work root, never the
	// caller's directory.
	cmd.Dir = filepath.Dir(pc.configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own process group for clean teardown
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("start binary: %w", err)
	}
	p := &Process{pc: pc, binary: h.binary, cmd: cmd, logDir: logDir, stdout: stdout, stderr: stderr, started: true}
	if err := p.waitReady(ctx, h.spec.Run.startup(), h.uiClient); err != nil {
		_ = p.stop(h.spec.Run.shutdown())
		return nil, err
	}
	return p, nil
}

// healthView is the bounded slice of GET /api/mcp/health we parse for readiness.
type healthView struct {
	Gateway struct {
		Runtime struct {
			State            string `json:"state"`
			ListenerReady    bool   `json:"listener_ready"`
			Posture          string `json:"posture"`
			ExecutionEnabled bool   `json:"execution_enabled"`
		} `json:"runtime"`
		PolicyRevision     uint64 `json:"policy_revision"`
		PolicySnapshotHash string `json:"policy_snapshot_hash"`
	} `json:"gateway"`
}

// waitReady polls the MCP health surface until the gateway runtime is ready in the
// observe posture with execution disabled, or the bounded timeout elapses.
func (p *Process) waitReady(ctx context.Context, timeout time.Duration, cli *http.Client) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		if p.exited() {
			return fmt.Errorf("binary exited during startup (see %s)", p.logDir)
		}
		res := adminGet(ctx, cli, p.pc.uiPort, p.pc.adminUser, p.pc.adminPass, "/api/mcp/health")
		if res.status == 200 {
			var hv healthView
			if json.Unmarshal(res.body, &hv) == nil {
				last = hv.Gateway.Runtime.State
				if hv.Gateway.Runtime.State == "ready" && hv.Gateway.Runtime.ListenerReady &&
					hv.Gateway.Runtime.Posture == "observe" && !hv.Gateway.Runtime.ExecutionEnabled {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("readiness timeout after %s (last state=%q)", timeout, last)
}

// startProcessRaw launches the binary and waits only for the admin surface to
// respond (process up) — NOT for the MCP listener to be ready. Used for the
// disabled-binds-nothing and emergency-disable scenarios where the MCP listener is
// deliberately absent.
func (h *Harness) startProcessRaw(ctx context.Context, pc procConfig) (*Process, error) {
	logDir := filepath.Join(filepath.Dir(pc.configPath), "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, err
	}
	stdout, err := newBoundedFile(filepath.Join(logDir, "stdout.log"))
	if err != nil {
		return nil, err
	}
	stderr, err := newBoundedFile(filepath.Join(logDir, "stderr.log"))
	if err != nil {
		return nil, err
	}
	// #nosec G204 -- binary path and flags are harness-controlled, not user input.
	cmd := exec.CommandContext(ctx, h.binary,
		"-config", pc.configPath, "-ui-no-tls",
		"-port", itoa(pc.proxyPort), "-ui-port", itoa(pc.uiPort),
		"-user", pc.adminUser, "-pass", pc.adminPass, "-metrics-token", pc.metricsToken,
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Dir = filepath.Dir(pc.configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("start binary: %w", err)
	}
	p := &Process{pc: pc, binary: h.binary, cmd: cmd, logDir: logDir, stdout: stdout, stderr: stderr, started: true}
	deadline := time.Now().Add(h.spec.Run.startup())
	for time.Now().Before(deadline) {
		if p.exited() {
			_ = p.stop(h.spec.Run.shutdown())
			return nil, fmt.Errorf("binary exited during startup (see %s)", logDir)
		}
		res := adminGet(ctx, h.uiClient, pc.uiPort, pc.adminUser, pc.adminPass, "/healthz")
		if res.status == 200 {
			return p, nil
		}
		select {
		case <-ctx.Done():
			_ = p.stop(h.spec.Run.shutdown())
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	_ = p.stop(h.spec.Run.shutdown())
	return nil, fmt.Errorf("admin surface not ready after %s", h.spec.Run.startup())
}

// health fetches the current health view (for evidence).
func (p *Process) health(ctx context.Context, cli *http.Client) (healthView, httpResult) {
	res := adminGet(ctx, cli, p.pc.uiPort, p.pc.adminUser, p.pc.adminPass, "/api/mcp/health")
	var hv healthView
	if res.status == 200 {
		_ = json.Unmarshal(res.body, &hv)
	}
	return hv, res
}

// exited reports whether the child process has already terminated.
func (p *Process) exited() bool {
	if p.cmd.ProcessState != nil {
		return true
	}
	// Non-blocking probe: signal 0 checks liveness.
	if p.cmd.Process == nil {
		return true
	}
	err := p.cmd.Process.Signal(syscall.Signal(0))
	return err != nil
}

// stop gracefully terminates the process group (SIGTERM), waits up to timeout,
// then force-kills. It never leaks a child or blocks unbounded.
func (p *Process) stop(timeout time.Duration) error {
	if !p.started || p.cmd.Process == nil {
		return nil
	}
	defer func() {
		_ = p.stdout.Close()
		_ = p.stderr.Close()
	}()
	pgid := -p.cmd.Process.Pid
	_ = syscall.Kill(pgid, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		_ = syscall.Kill(pgid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("process %d did not exit after SIGKILL", p.cmd.Process.Pid)
		}
		return nil
	}
}

// tripwire is a local HTTP server that counts inbound requests and performs NO
// side effect. In Observe the binary composes no executor, so a correct run leaves
// the count at zero — an externally-observable non-execution proof.
type tripwire struct {
	ln    net.Listener
	srv   *http.Server
	count atomic.Int64
	once  sync.Once
}

func startTripwire() (*tripwire, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tw := &tripwire{ln: ln}
	tw.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tw.count.Add(1)
			w.WriteHeader(http.StatusNotImplemented) // never performs a side effect
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = tw.srv.Serve(ln) }()
	return tw, nil
}

func (tw *tripwire) inbound() int64 { return tw.count.Load() }

func (tw *tripwire) close() {
	tw.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tw.srv.Shutdown(ctx)
	})
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }
