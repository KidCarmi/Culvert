package mcpacceptance

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// HarnessVersion is the acceptance-harness contract version (independent of the
// tested artifact's version).
const HarnessVersion = "qual6-observe-acceptance/1"

// Harness drives a built artifact through the real MCP boundaries and produces the
// evidence bundle. It owns every child process, tripwire, and temporary secret.
type Harness struct {
	spec        *Spec
	binary      string
	workDir     string // holds fixtures/secrets/logs; NEVER the evidence dir
	evidenceDir string
	sourceSHA   string

	fixture       *Fixture
	uiClient      *http.Client
	metricsClient *http.Client
	mcpBearer     *http.Client // https, trusts fixture CA, no client cert (bearer flow)

	secrets *SecretScan
	now     func() time.Time

	tokenA string
	tokenB string

	tripwireA *tripwire
	tripwireB *tripwire
	procA     *Process
	procB     *Process

	summary *Summary
	start   time.Time
}

// Options configure a harness run.
type Options struct {
	// SourceSHA is the harness's own source commit (for provenance of the run).
	SourceSHA string
	// Now injects a clock for deterministic tests. Defaults to time.Now.
	Now func() time.Time
}

// NewHarness validates the spec and prepares a harness. The evidence directory is
// created; a separate temp work directory holds secrets and is never referenced by
// the evidence bundle.
func NewHarness(spec *Spec, opts Options) (*Harness, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := os.MkdirAll(spec.EvidenceDir, 0o700); err != nil {
		return nil, err
	}
	// Require a fresh evidence directory: a reused directory could leave a prior
	// run's secret_scan_violations.json or logs beside a new PASS summary, mixing
	// evidence across runs. The harness never deletes operator data — it refuses.
	if entries, err := os.ReadDir(spec.EvidenceDir); err != nil {
		return nil, err
	} else if len(entries) > 0 {
		return nil, fmt.Errorf("acceptance: evidence_dir %q is not empty; provide a fresh directory per run", spec.EvidenceDir)
	}
	work, err := os.MkdirTemp("", "mcp-acceptance-work-")
	if err != nil {
		return nil, err
	}
	return &Harness{
		spec:        spec,
		binary:      spec.Artifact.BinaryPath,
		workDir:     work,
		evidenceDir: spec.EvidenceDir,
		sourceSHA:   opts.SourceSHA,
		secrets:     NewSecretScan(),
		now:         opts.Now,
	}, nil
}

// Run executes the full acceptance and returns the finalized summary. The overall
// status is FAIL if any required criterion fails, does not run, artifact identity
// is not authoritative when required, the secret scan trips, execution is detected,
// or cleanup fails. Run never begins Observe, never calls BeginWindow, and never
// changes rollout state.
func (h *Harness) Run(ctx context.Context) (*Summary, error) {
	h.start = h.now()
	defer h.cleanup()
	if err := h.setup(ctx); err != nil {
		return nil, err
	}
	h.runScenarios(ctx)
	return h.finalize()
}

// setup performs the pre-scenario prologue: the pre-traffic artifact-binding gate,
// the pinned binary copy, the two-tenant fixture, tripwires, clients, tokens, and
// the two readiness-gated artifact processes. Any failure aborts before traffic.
func (h *Harness) setup(ctx context.Context) error {
	artifact, err := bindArtifact(h.spec)
	if err != nil {
		return err
	}
	cfgHash, err := h.spec.ConfigHash()
	if err != nil {
		return err
	}
	runID, err := randToken(12)
	if err != nil {
		return err
	}
	h.summary = &Summary{
		SchemaVersion:        EvidenceSchemaVersion,
		Authoritative:        artifact.Authoritative,
		HarnessVersion:       HarnessVersion,
		HarnessSourceSHA:     h.sourceSHA,
		Artifact:             artifact,
		AcceptanceConfigHash: cfgHash,
		RunID:                runID,
		StartUTC:             utcStamp(h.start),
	}
	// Pin the exact hashed bytes: copy the binary to a harness-owned path and run
	// THAT for every process/restart, so a deployment, updater, or attacker replacing
	// binary_path after the hash cannot make the bundle report one digest while
	// different bytes are tested. The copy's digest must equal the recorded one.
	pinned, err := pinBinary(h.spec.Artifact.BinaryPath, filepath.Join(h.workDir, "pinned-culvert"), artifact.Digest)
	if err != nil {
		return err
	}
	h.binary = pinned
	if err := h.prepareFixture(); err != nil {
		return err
	}
	pa, pb, err := h.buildProcesses()
	if err != nil {
		return err
	}
	if err := h.buildClients(); err != nil {
		return err
	}
	if err := h.mintTokens(); err != nil {
		return err
	}
	if h.procA, err = h.startProcess(ctx, pa); err != nil {
		return fmt.Errorf("start process A: %w", err)
	}
	if h.procB, err = h.startProcess(ctx, pb); err != nil {
		return fmt.Errorf("start process B: %w", err)
	}
	h.recordArtifactVersion(ctx)
	return nil
}

// buildProcesses starts the non-execution tripwires and renders the tenant-A and
// tenant-B process fixtures pointed at them.
func (h *Harness) buildProcesses() (procConfig, procConfig, error) {
	var err error
	if h.tripwireA, err = startTripwire(); err != nil {
		return procConfig{}, procConfig{}, err
	}
	if h.tripwireB, err = startTripwire(); err != nil {
		return procConfig{}, procConfig{}, err
	}
	pa, err := h.fixture.buildProc("A", h.fixture.tenantA, h.fixture.serverA, "none", tripEndpoint(h.tripwireA))
	if err != nil {
		return procConfig{}, procConfig{}, err
	}
	pb, err := h.fixture.buildProc("B", h.fixture.tenantB, h.fixture.serverB, "none", tripEndpoint(h.tripwireB))
	if err != nil {
		return procConfig{}, procConfig{}, err
	}
	return pa, pb, nil
}

// recordArtifactVersion probes the running binary's version and, in authoritative
// mode, records a failed criterion on a mismatch with the expected version.
func (h *Harness) recordArtifactVersion(ctx context.Context) {
	h.summary.Artifact.Version = probeVersion(ctx, h.uiClient, h.procA.pc.uiPort)
	if h.spec.Mode == ModeAuthoritative && h.spec.Artifact.ExpectedVersion != "" &&
		h.summary.Artifact.Version != h.spec.Artifact.ExpectedVersion {
		h.record(CriterionResult{ID: "artifact.version", Name: "artifact version matches expected", Group: "artifact",
			Required: true, Status: StatusFail, Expected: h.spec.Artifact.ExpectedVersion, Observed: h.summary.Artifact.Version,
			Reason: "version_mismatch"})
	}
}

// runScenarios executes every acceptance scenario at the real binary boundary, in
// order. Kept separate from Run so each stays a small, testable unit.
func (h *Harness) runScenarios(ctx context.Context) {
	h.runStartup(ctx)
	h.runTLS(ctx)
	h.runOAuth(ctx)
	h.runHostOrigin(ctx)
	h.runProtocol(ctx)
	h.runInventory(ctx)
	h.runTenantMatrix(ctx)
	h.runPolicy(ctx)
	h.runDurableEvidence(ctx)
	h.runMetrics(ctx)
	h.runManagement(ctx)
	h.runRestart(ctx)
	h.runEmergencyDisable(ctx)
	h.runNonExecution(ctx)
}

// prepareFixture builds the two-tenant environment (dev) or ingests operator
// material (authoritative). Both paths use the SAME config/inventory/policy
// renderer so there is one strict code path.
func (h *Harness) prepareFixture() error {
	switch h.spec.Mode {
	case ModeDev:
		fx, err := NewFixture(filepath.Join(h.workDir, "fixture"), h.secrets)
		if err != nil {
			return err
		}
		h.fixture = fx
		return nil
	case ModeAuthoritative:
		fx, err := NewFixtureFromEnv(filepath.Join(h.workDir, "fixture"), h.spec.Environment, h.secrets)
		if err != nil {
			return err
		}
		h.fixture = fx
		return nil
	}
	return fmt.Errorf("unknown mode")
}

func (h *Harness) buildClients() error {
	rt := h.spec.Run.request()
	h.uiClient = plainClient(rt)
	h.metricsClient = plainClient(rt)
	c, err := mcpTLSClient(h.fixture.caPEM, h.fixture.clientCertFile, h.fixture.clientKeyFile, false, rt)
	if err != nil {
		return err
	}
	h.mcpBearer = c
	return nil
}

func (h *Harness) mintTokens() error {
	base := tokenParams{
		issuer: h.fixture.issuer, clientID: h.fixture.clientID, audience: h.fixture.canonicalResource,
		scope: h.fixture.scope, subject: "user-1", kid: h.fixture.kid,
	}
	pa := base
	pa.tenant = h.fixture.tenantA
	ta, err := mintBearer(h.fixture.signer, pa)
	if err != nil {
		return err
	}
	pb := base
	pb.tenant = h.fixture.tenantB
	tb, err := mintBearer(h.fixture.signer, pb)
	if err != nil {
		return err
	}
	h.tokenA, h.tokenB = ta, tb
	h.secrets.Add("bearer_token", ta)
	h.secrets.Add("bearer_token", tb)
	return nil
}

// record appends a criterion result with monotonic-ish timing derived from the run
// start (bounded, deterministic-friendly).
func (h *Harness) record(cr CriterionResult) {
	if cr.StartMS == 0 {
		cr.StartMS = h.elapsedMS()
	}
	if cr.EndMS == 0 {
		cr.EndMS = h.elapsedMS()
	}
	h.summary.Criteria = append(h.summary.Criteria, cr)
}

// runCriterion times fn and records the result.
func (h *Harness) runCriterion(id, name, group string, required bool, expected string, fn func() (Status, string, string, []string)) {
	startMS := h.elapsedMS()
	status, observed, reason, ev := fn()
	h.summary.Criteria = append(h.summary.Criteria, CriterionResult{
		ID: id, Name: name, Group: group, Required: required, Status: status,
		Expected: expected, Observed: observed, Reason: reason, Evidence: ev,
		StartMS: startMS, EndMS: h.elapsedMS(),
	})
}

func (h *Harness) elapsedMS() int64 { return h.now().Sub(h.start).Milliseconds() }

// finalize computes derived summary fields, writes the evidence bundle, runs the
// secret scan, builds the tamper manifest, and returns the summary.
func (h *Harness) finalize() (*Summary, error) {
	// Non-execution tripwire assertion folds into the summary.
	h.summary.EndUTC = utcStamp(h.now())

	// Overall = PASS only if every REQUIRED criterion is present AND passed, and the
	// artifact is authoritative when the mode demands it. A missing required
	// criterion is a FAIL (no best-effort PASS).
	overall, missing := computeOverall(h.summary.Criteria, expectedRequiredIDs(),
		h.summary.Authoritative, h.spec.Mode == ModeAuthoritative)
	for _, id := range missing {
		h.summary.Notes = append(h.summary.Notes, "missing_required_criterion: "+id)
	}
	h.summary.Overall = overall

	// Write bounded log copies as evidence references.
	h.copyLogs()

	// Serialize the summary, then secret-scan the whole bundle.
	sumJSON, err := canonicalJSON(h.summary)
	if err != nil {
		return h.summary, err
	}
	if err := writeFile(h.evidenceDir, "summary.json", sumJSON); err != nil {
		return h.summary, err
	}
	viols, err := h.secrets.Scan(h.evidenceDir)
	if err != nil {
		return h.summary, err
	}
	if len(viols) > 0 {
		// Secret containment failure: mark FAIL, emit only a bounded classification,
		// never the offending value. Re-serialize the summary with the FAIL verdict.
		h.summary.Overall = StatusFail
		vb, _ := canonicalJSON(viols)
		_ = writeFile(h.evidenceDir, "secret_scan_violations.json", vb)
		h.summary.Notes = append(h.summary.Notes, fmt.Sprintf("secret_scan_failed: %d bounded violation(s)", len(viols)))
		sumJSON, _ = canonicalJSON(h.summary)
		_ = writeFile(h.evidenceDir, "summary.json", sumJSON)
	}

	// Tamper-evidence manifest over the whole bundle (excludes itself).
	man, err := buildManifest(h.evidenceDir)
	if err != nil {
		return h.summary, err
	}
	mj, err := canonicalJSON(man)
	if err != nil {
		return h.summary, err
	}
	if err := writeFile(h.evidenceDir, "manifest.json", mj); err != nil {
		return h.summary, err
	}
	return h.summary, nil
}

// copyLogs writes bounded copies of each process's stderr into the evidence dir.
func (h *Harness) copyLogs() {
	for _, p := range []*Process{h.procA, h.procB} {
		if p == nil {
			continue
		}
		src := filepath.Join(p.logDir, "stderr.log")
		b, err := os.ReadFile(src) // #nosec G304 -- harness-owned log
		if err != nil {
			continue
		}
		if int64(len(b)) > maxLogBytes {
			b = b[:maxLogBytes]
		}
		_ = writeFile(h.evidenceDir, filepath.Join("logs", "proc-"+p.pc.name+".stderr.log"), b)
	}
}

// cleanup terminates children and tripwires; it never deletes the evidence bundle
// and never deletes operator-owned state outside the harness work root.
func (h *Harness) cleanup() {
	if h.procA != nil {
		_ = h.procA.stop(h.spec.Run.shutdown())
	}
	if h.procB != nil {
		_ = h.procB.stop(h.spec.Run.shutdown())
	}
	if h.tripwireA != nil {
		h.tripwireA.close()
	}
	if h.tripwireB != nil {
		h.tripwireB.close()
	}
	// Remove the harness-owned work root (fixtures + secrets), never the evidence.
	if h.workDir != "" {
		_ = os.RemoveAll(h.workDir)
	}
}

// tripEndpoint renders the inventory endpoint pointing at a tripwire (never dialed
// in Observe; catches any stray execution dial).
func tripEndpoint(tw *tripwire) string {
	return fmt.Sprintf("mcp+https://%s/mcp", tw.ln.Addr().String())
}
