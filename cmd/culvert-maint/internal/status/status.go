// Package status implements the StatusProvider consumed by GET /v1/status.
//
// D1.6a behavior:
//   - calls runner.ComposeStatus to query the running compose stack;
//     the runner template runs `docker compose -f <compose_path> ps
//     --format json`
//   - parses Compose v2 NDJSON output line-by-line with bufio.Scanner;
//     also accepts the JSON-array form some Compose versions emit
//   - reports compose_stack_up=true ONLY when the `proxy` service is
//     in the "running" state — sidecar-only states (clamav up, proxy
//     down) do NOT count as stack-up to avoid overclaiming
//   - on parse or runner error, surfaces the cause in compose_error
//     and reports compose_stack_up=false rather than failing the
//     request
//   - flags the docker_group_lab privilege mode in the response so the
//     GUI/CP can display a "broad privilege" warning
package status

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"culvert-maint/internal/config"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
	"culvert-maint/internal/runtimehealth"
	"culvert-maint/internal/server"
)

// proxyServiceName is the name of the Culvert proxy service inside the
// supplied docker-compose.yml. Its `running` state is the canonical
// signal for compose_stack_up=true.
const proxyServiceName = "proxy"

// Provider is the production StatusProvider.
type Provider struct {
	cfg    *config.Config
	mgr    *ops.Manager
	runner *runner.Runner
	// journal is the crash-recovery journal. Optional: nil reports no
	// interrupted operations (tests, and builds that do not journal).
	journal *journal.Journal
	// reconcile is the opt-in startup reconcile's tracker. nil (the default,
	// reconcile_on_startup = "off") adds nothing to the status.
	reconcile *server.ReconcileTracker
	// diedIn: op id → docker command the previous agent process died inside,
	// as this agent start found it (WithDiedInCommand). Read-only after wiring.
	diedIn map[string]string
	// health is the runtime health evidence (ADR-0062 slice 5), and
	// healthEvery its sampling interval. nil (runtime_health_interval off)
	// adds nothing to the status.
	health      *runtimehealth.Store
	healthEvery time.Duration
	// now overrides time.Now (tests).
	now func() time.Time
}

// WithRuntimeHealth makes the provider report the runtime health evidence
// (Status.RuntimeHealth). Only wired when runtime_health_interval is on.
// Returns p.
func (p *Provider) WithRuntimeHealth(st *runtimehealth.Store, every time.Duration) *Provider {
	p.health, p.healthEvery = st, every
	return p
}

// runtimeHealthStaleAfter: a sample older than this many intervals describes
// the past, not the present.
const runtimeHealthStaleAfter = 3

// addRuntimeHealth fills Status.RuntimeHealth from the evidence files. It
// reads files only, no Docker: the running image is the one composeSnapshot
// already captured (absent when the stack is down or the capture failed).
func (p *Provider) addRuntimeHealth(st *server.Status) {
	if p.health == nil {
		return
	}
	now := time.Now().UTC()
	if p.now != nil {
		now = p.now()
	}
	rh := &server.RuntimeHealthStatus{IntervalSeconds: int64(p.healthEvery / time.Second)}
	running := ""
	if st.RunningImage != nil {
		running = st.RunningImage.ImageID
	}
	smp, err := p.health.ReadLatest()
	if err != nil {
		rh.State, rh.Reason, rh.Error = runtimehealth.StateUnknown, "evidence_unreadable", "the runtime health evidence could not be read"
	} else {
		rh.State, rh.Reason = runtimehealth.Classify(smp, running, now, runtimeHealthStaleAfter*p.healthEvery)
		if smp != nil {
			at := smp.ObservedAt
			rh.ObservedAt, rh.ImageID, rh.Detail = &at, smp.ImageID, smp.Detail
		}
	}
	lg, lerr := p.health.ReadLastGood()
	switch {
	case lerr != nil:
		rh.LastGoodError = "the last-known-good record could not be read"
	case lg != nil:
		rh.LastGood = &server.RuntimeLastGood{ImageID: lg.ImageID, Ref: lg.Ref, Digest: lg.Digest, PassedAt: lg.PassedAt, Gate: lg.Gate}
	}
	st.RuntimeHealth = rh
}

// WithJournal makes the provider report the operations a previous agent
// process left unfinished (Status.InterruptedOperations). Returns p.
func (p *Provider) WithJournal(j *journal.Journal) *Provider {
	p.journal = j
	return p
}

// WithDiedInCommand gives the provider what THIS agent start concluded about
// command attribution (op id → command; journal/intent.go). It is held in
// memory only and never written: a restarted agent knows nothing of it.
func (p *Provider) WithDiedInCommand(m map[string]string) *Provider {
	p.diedIn = m
	return p
}

// WithReconcile makes the provider report the startup reconcile
// (Status.Reconcile, Status.RecoveryRequired and each interrupted operation's
// reconcile_outcome). Only wired when reconcile_on_startup = "converge".
// Returns p.
func (p *Provider) WithReconcile(t *server.ReconcileTracker) *Provider {
	p.reconcile = t
	return p
}

// addReconcile fills the reconcile fields from the tracker.
func (p *Provider) addReconcile(st *server.Status) {
	if p.reconcile == nil {
		return
	}
	snap := p.reconcile.Snapshot()
	st.Reconcile = &snap
	rr := p.reconcile.RecoveryRequired()
	for i := range st.InterruptedOperations {
		if r, ok := p.reconcile.RecordFor(st.InterruptedOperations[i].OpID); ok {
			st.InterruptedOperations[i].SetReconcile(r)
		} else if st.InterruptedOperations[i].TerminalOutcome != "" {
			// A failed operation of this process kept its record because it
			// could not prove the state it left safe (ADR-0062 slice 1, owner
			// decision): an operator must act, or a later success retire it.
			// The startup reconcile has not seen it, so it decides nothing here.
			rr = true
		}
	}
	st.RecoveryRequired = &rr
}

// New constructs a Provider.
func New(cfg *config.Config, mgr *ops.Manager, r *runner.Runner) (*Provider, error) {
	if cfg == nil {
		return nil, errors.New("status: cfg required")
	}
	if mgr == nil {
		return nil, errors.New("status: ops manager required")
	}
	if r == nil {
		return nil, errors.New("status: runner required")
	}
	return &Provider{cfg: cfg, mgr: mgr, runner: r}, nil
}

// Snapshot implements server.StatusProvider.
func (p *Provider) Snapshot(ctx context.Context) (server.Status, error) {
	st := p.composeSnapshot(ctx)
	p.addInterrupted(&st)
	p.addPinnedTag(ctx, &st)
	p.addReconcile(&st)
	p.addRuntimeHealth(&st)
	return st, nil
}

// addInterrupted fills the interrupted-operation report. The list comes from
// the journal alone, so it is complete when Docker is down; the live fact it
// adds (which image is running) is reported as unknown when Docker cannot be
// read. Read-only, and it makes no docker call of its own.
func (p *Provider) addInterrupted(st *server.Status) {
	if p.journal == nil {
		return
	}
	recs, err := p.journal.List()
	if err != nil {
		// The text of a journal error can quote file content; say only that
		// the list is unknown.
		st.InterruptedOperationsError = "the crash-recovery journal could not be read; see the agent log"
		return
	}
	for i := range recs {
		rec := &recs[i]
		// A record whose operation ended with its end state proven safe is
		// kept only because its terminal audit entry or its removal did not
		// complete; startup finishes both. It is not a recovery situation and
		// is not reported as one (Codex review on #2102).
		if rec.TerminalOutcome != "" && rec.TerminalSafe {
			continue
		}
		// A record whose operation THIS process knows — running, or terminal
		// with its record about to be removed — is not an interruption. Only
		// an operation startup marked, or one no longer in memory at all, is.
		// Except: a record that carries a terminal outcome was KEPT by its
		// operation, which ended failed without proving the state it left safe
		// (ADR-0062 slice 1). It is listed as soon as the operation is
		// terminal, in this process as after a restart (where startup marks it
		// with its real reason, not agent_restart_interrupted).
		if op := p.mgr.Get(rec.OpID); op != nil && op.FailureReason != string(ops.ReasonAgentRestartInterrupted) &&
			(!op.State.IsTerminal() || rec.TerminalOutcome == "") {
			continue
		}
		d := server.DescribeInterrupted(rec, p.cfg.ProxyRepo)
		d.DiedInCommand = p.diedIn[rec.OpID]
		if st.RunningImage != nil {
			d.SetRunningImage(server.ClassifyRunning(rec, p.cfg.ProxyRepo, true, st.RunningImage.ImageID, st.RunningImage.RepoDigests))
		} else {
			d.SetRunningImage(server.ClassifyRunning(rec, p.cfg.ProxyRepo, false, "", nil))
		}
		st.InterruptedOperations = append(st.InterruptedOperations, d)
	}
}

// pinnedTagReadBudget bounds the fixed-tag read of one status call. A var so a
// test can shorten it.
var pinnedTagReadBudget = 5 * time.Second

// addPinnedTag reports where the fixed proxy tag is and whether the running
// container is on the same image. Read-only: one `docker image inspect`.
//
// It is reported on every status, not only while an interrupted operation is
// outstanding. A journal record is one way the tag and the container come
// apart, not the only one: an apply whose `up` failed can go terminal — record
// retired — with the tag left on the target (realignPinnedTagAfterFailedUp
// names the cases), and the tag can be moved by hand. In each of those the
// next `docker compose up -d` changes the image the proxy runs, and before
// this nothing in the status said so.
//
// Two things a reader must know. During a running apply or rollback the tag is
// moved before the container is recreated, so matches_running is false for
// that moment; it is a divergence only when no operation is running. And the
// tag is read even when the compose read failed: a compose file that no longer
// loads is one of the ways the tag is left ahead, and exactly then it must be
// visible. A daemon that does not answer costs at most pinnedTagReadBudget.
func (p *Provider) addPinnedTag(ctx context.Context, st *server.Status) {
	pt := &server.PinnedTagStatus{}
	// One local image inspect answers in milliseconds. It gets its own short
	// budget so that a slow daemon costs a status call at most this long, not
	// a whole stage timeout: the status endpoint is polled, and its callers
	// time out in seconds.
	tctx, cancel := context.WithTimeout(ctx, pinnedTagReadBudget)
	defer cancel()
	id, perr := p.runner.PinnedTagImageID(tctx)
	if perr != nil {
		pt.Error = "the fixed tag could not be inspected"
	} else {
		pt.ImageID = id
		if st.RunningImage != nil && st.RunningImage.ImageID != "" {
			same := st.RunningImage.ImageID == id
			pt.MatchesRunning = &same
		}
	}
	st.PinnedTag = pt
}

// composeSnapshot is the compose-stack half of the status: privilege mode,
// lock holder, services and the running image.
func (p *Provider) composeSnapshot(ctx context.Context) server.Status {
	st := server.Status{
		PrivilegeMode:             string(p.cfg.PrivilegeMode),
		ComposeProjectDir:         p.cfg.ComposeProjectDir,
		ComposeFile:               p.cfg.ComposeFile,
		ComposeOverrideConfigured: p.cfg.ComposeOverrideFile != "",
	}
	if p.cfg.PrivilegeMode == config.PrivilegeDockerGroupLab {
		st.PrivilegeWarning = "docker_group_lab is dev/lab only and effectively root-equivalent; not for production"
	}

	// Lock holder, if any.
	if h := p.mgr.Holder(); h != nil {
		st.LockHeldBy = h
	}

	// Compose status — best effort. If `docker compose ps` errors (e.g.
	// stack not running, daemon down), we surface the error string but
	// keep the response 200 so the GUI can still render the rest.
	res, err := p.runner.ComposeStatus(ctx)
	if err != nil {
		st.ComposeError = err.Error()
		// Keep what stderr we got so operators can read it.
		if res != nil && len(res.Stderr) > 0 {
			st.ComposeError = strings.TrimSpace(string(res.Stderr))
			if st.ComposeError == "" {
				st.ComposeError = err.Error()
			}
		}
		return st
	}
	services, perr := parseComposePS(res.Stdout)
	if perr != nil {
		st.ComposeError = "parse_compose_ps: " + perr.Error()
		return st
	}
	st.ComposeServices = services
	// compose_stack_up is true only when the proxy service is running.
	// Sidecar-only states (clamav up, proxy down) deliberately do NOT
	// count — the operator-facing meaning of "stack up" is "the
	// product is reachable", which requires proxy.
	for _, s := range services {
		if s.Name == proxyServiceName && strings.EqualFold(s.State, "running") {
			st.ComposeStackUp = true
			break
		}
	}

	// P1.1: best-effort running-image digest capture. Only attempted when
	// the proxy is actually running — there is nothing to capture
	// otherwise, and the guard keeps the common down-stack path free of
	// extra docker calls. Reuses the already-allowlisted, read-only
	// CaptureRunningProxyImage (#357): no new privileged command, no
	// sudoers change, digest-only, no release/channel/version awareness.
	// Any failure is swallowed — the digest is an optional enrichment, so
	// it must never set compose_error or change the 200 response.
	if st.ComposeStackUp {
		st.RunningImage = p.captureRunningImage(ctx)
	}
	return st
}

// captureRunningImage returns the digest-only identity of the running
// proxy image, or nil on ANY failure (best-effort — P1.1). The runner
// already bounds each underlying docker command with its own per-command
// timeout (SIGTERM→SIGKILL), so a hung inspect cannot stall status
// indefinitely; a failure here simply yields no digest. Only content
// digests are surfaced — never the container id or any image metadata.
func (p *Provider) captureRunningImage(ctx context.Context) *server.RunningImage {
	ri, err := p.runner.CaptureRunningProxyImage(ctx)
	if err != nil || ri == nil {
		return nil
	}
	return &server.RunningImage{
		ImageID:     ri.RunningImageID,
		RepoDigests: ri.RepoDigests,
	}
}

// parseComposePS parses `docker compose ps --format json` output.
// Compose v2 emits one JSON object per line (NDJSON). Some versions
// emit a single JSON array; we fall back to that shape if NDJSON
// parsing yields nothing usable.
//
// Mixed warning/log lines are tolerated — non-`{` lines and blank
// lines are skipped silently. Lines that DO start with `{` but fail
// to JSON-decode are tracked: if every `{`-prefixed line fails to
// parse, parseComposePS returns an error so the caller can surface
// "parse_compose_ps: …" in compose_error rather than reporting an
// empty stack (which would look identical to "compose stack down"
// to the GUI).
func parseComposePS(stdout []byte) ([]server.ServiceStatus, error) {
	if len(stdout) == 0 {
		return nil, nil
	}
	// Heuristic: if the first non-whitespace byte is '[' it's the
	// array form; otherwise treat as NDJSON.
	trimmed := bytes.TrimLeft(stdout, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return parseComposePSArray(stdout)
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var (
		services    []server.ServiceStatus
		candidates  int
		parsed      int
		firstParseE error
	)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		candidates++
		var entry composePSEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			if firstParseE == nil {
				firstParseE = err
			}
			continue
		}
		parsed++
		services = append(services, entry.toServiceStatus())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if candidates > 0 && parsed == 0 {
		return nil, errors.New("all NDJSON lines failed to decode: " + firstParseE.Error())
	}
	return services, nil
}

func parseComposePSArray(stdout []byte) ([]server.ServiceStatus, error) {
	var entries []composePSEntry
	if err := json.Unmarshal(stdout, &entries); err != nil {
		return nil, err
	}
	services := make([]server.ServiceStatus, 0, len(entries))
	for _, e := range entries {
		services = append(services, e.toServiceStatus())
	}
	return services, nil
}

// composePSEntry mirrors the relevant subset of `docker compose ps
// --format json` output.
type composePSEntry struct {
	Name    string `json:"Name"`
	Service string `json:"Service"`
	State   string `json:"State"`
	Status  string `json:"Status"`
	Image   string `json:"Image"`
}

func (e composePSEntry) toServiceStatus() server.ServiceStatus {
	name := e.Service
	if name == "" {
		name = e.Name
	}
	state := e.State
	if state == "" {
		state = e.Status
	}
	return server.ServiceStatus{
		Name:  name,
		State: state,
		Image: e.Image,
	}
}
