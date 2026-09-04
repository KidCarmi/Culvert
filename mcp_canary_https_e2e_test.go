package main

// mcp_canary_https_e2e_test.go — CONTROLLED LOCAL HTTPS end-to-end proof that one
// accepted execution reservation yields AT MOST ONE physical side-effect-bearing
// tool invocation, and that the durable record of that invocation stays truthful
// on every exit path (review blockers #6/#8, §16).
//
// WHY A REAL SERVER. Every other live-tier E2E in this tree counts invocations at
// the Go interface (recordingUpstream). That measures what the executor INTENDED
// to send. Blocker #6 is about what the PEER RECEIVES: the retry loop lives below
// that seam, inside upstreamclient.Client, so an interface-level counter reads 1
// while the peer is POSTed twice. These tests therefore drive the REAL production
// upstream client — the same construction as newProductionUpstreamClient, retry-free
// limits included — against a local httptest TLS server, and count POSTs AT THE WIRE.
//
// CONTAINMENT. Loopback only. The listener is created by httptest and closed by
// t.Cleanup; the SSRF guard is relaxed for loopback only, through the existing
// ssrf.AllowLoopbackForTest seam, and restored. No external egress, no production
// credential, no real MCP server, no Canary activation of any real node: the rollout
// state is a per-test global that resetLiveTierGlobals restores.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// ── controlled peer ─────────────────────────────────────────────────────────

// peerRequest is one observed physical POST. It is the WITNESS record: the peer is
// the only party that can say an invocation actually arrived.
type peerRequest struct {
	AttemptID string
	Method    string
	Auth      bool
}

// controlledPeer is a local TLS MCP server that counts every POST it fully reads.
// It is the independent observer for these tests: Culvert's own counters are the
// thing under test, so they cannot also be the measurement.
type controlledPeer struct {
	srv *httptest.Server
	pin string

	mu       sync.Mutex
	requests []peerRequest

	// behave decides what the peer does once it has RECEIVED the invocation. It runs
	// after the body is drained and the request is recorded, so "received then
	// dropped" is recorded as received — which is the whole point.
	behave func(w http.ResponseWriter, r *http.Request)
}

func (p *controlledPeer) observed() []peerRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]peerRequest(nil), p.requests...)
}

func (p *controlledPeer) count() int { return len(p.observed()) }

// countFor is the witness lookup by attempt id — the shape the real Witness adapter
// will have (§11): it reports facts, never a verdict.
func (p *controlledPeer) countFor(attemptID string) int {
	n := 0
	for _, r := range p.observed() {
		if r.AttemptID == attemptID {
			n++
		}
	}
	return n
}

// respondOK is the default behavior: a well-formed JSON-RPC result.
func respondOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"u-s1","result":{"ok":true}}`)
}

// receiveThenDrop is the AMBIGUOUS shape: the peer reads the whole invocation — so
// it may already have acted — and then closes without answering. This is exactly
// the (idempotent, pre-response) classification that authorizes a re-send under the
// historical retry defaults.
func receiveThenDrop(w http.ResponseWriter, _ *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}

// startControlledPeer boots the local TLS peer and returns it with its SPKI pin.
func startControlledPeer(t *testing.T, behave func(http.ResponseWriter, *http.Request)) *controlledPeer {
	t.Helper()
	p := &controlledPeer{behave: behave}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain FIRST: after this the invocation has demonstrably reached the peer,
		// whatever happens next.
		_, _ = io.Copy(io.Discard, r.Body)
		p.mu.Lock()
		p.requests = append(p.requests, peerRequest{
			AttemptID: r.Header.Get(upstreamclient.AttemptHeader),
			Method:    r.Method,
			Auth:      r.Header.Get("Authorization") != "",
		})
		p.mu.Unlock()
		p.behave(w, r)
	}))
	t.Cleanup(p.srv.Close)

	cert := p.srv.TLS.Certificates[0]
	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse test leaf: %v", err)
		}
		leaf = parsed
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	p.pin = base64.StdEncoding.EncodeToString(sum[:])
	return p
}

// loopbackResolver pins resolution to the peer's loopback address so no DNS is used
// and no address outside the test can be reached.
type loopbackResolver struct{ addr netip.Addr }

func (r loopbackResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{r.addr}, nil
}

// realUpstreamFor builds the REAL production-shaped upstream client (retry-free
// limits, the same as newProductionUpstreamClient) pointed at the controlled peer.
func realUpstreamFor(t *testing.T, p *controlledPeer) *upstreamclient.Client {
	t.Helper()
	ipStr, _, err := net.SplitHostPort(strings.TrimPrefix(p.srv.URL, "https://"))
	if err != nil {
		t.Fatalf("split peer addr: %v", err)
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		t.Fatalf("parse peer addr: %v", err)
	}
	lim, err := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	if err != nil {
		t.Fatalf("RetryFreeLimits: %v", err)
	}
	// The ONE production knob relaxed for containment: the destination policy must
	// admit a loopback address, because the controlled peer IS on loopback. Nothing
	// else is loosened — retry mode, inspection limits, gateway limits, pinned
	// identity verification and the redirect rules are the production values, and the
	// production policy's own private-address refusal is pinned elsewhere.
	pol, err := destination.NewPolicy(destination.PolicyConfig{Schemes: []string{"https"}, AllowPrivate: true})
	if err != nil {
		t.Fatalf("destination.NewPolicy: %v", err)
	}
	c, err := upstreamclient.New(upstreamclient.Config{
		Limits:           lim,
		Resolver:         loopbackResolver{addr: addr},
		Policy:           pol,
		InspectionLimits: limits.DefaultGatewayInspection(),
		Clock:            time.Now,
	}, limits.DefaultGateway())
	if err != nil {
		t.Fatalf("upstreamclient.New: %v", err)
	}
	return c
}

// peerExecInput is liveExecInput retargeted at the controlled peer (endpoint + pin).
func peerExecInput(p *controlledPeer, opClass policy.OperationClass) mcpruntime.ExecInput {
	in := liveExecInput(opClass, "t1", "p1")
	in.Server = &registry.ServerRecord{
		ID: "s1", Endpoint: registry.Endpoint(p.srv.URL), PinnedIdentity: registry.Identity(p.pin),
		Enabled: true, Verification: registry.VerifyVerified,
	}
	return in
}

// peerRig is one fully armed live tier pointed at the controlled peer, plus the
// durable events manager backing it — the tests read the SAME ledger the executor
// writes, never a parallel bookkeeping copy.
type peerRig struct {
	cfg    *mcpruntime.Config
	events *events.Manager
}

// armCanaryWithRealPeer wires the FULL live tier — real gate, real budget, real
// executor — to the REAL upstream client against the controlled peer.
func armCanaryWithRealPeer(t *testing.T, p *controlledPeer, budgetTotal int) *peerRig {
	t.Helper()
	return armCanaryWithRealPeerTrust(t, p, budgetTotal, true)
}

// armCanaryWithRealPeerTrust is armCanaryWithRealPeer with the live-approval seam
// under test control, so a gate denial can be driven without changing anything else.
func armCanaryWithRealPeerTrust(t *testing.T, p *controlledPeer, budgetTotal int, trustOK bool) *peerRig {
	t.Helper()
	return armCanaryWithRealPeerGate(t, p, budgetTotal, trustOK, nil)
}

// armCanaryWithRealPeerGate is the full rig with ONE composition-layer gate seam
// optionally forced by the caller, so a concurrency case can drive (say) generation
// revalidation without changing anything else about the production path.
//
// tweak is applied to a gate built AFTER the global reset, and that ordering is
// load-bearing: liveRealGate binds `admit` as a METHOD VALUE on the live-tier
// singleton, so a gate constructed before resetLiveTierGlobals points at the
// pre-reset tier — which is never armed. Building it in the caller silently denied
// every admission (found while writing the concurrency matrix).
func armCanaryWithRealPeerGate(t *testing.T, p *controlledPeer, budgetTotal int, trustOK bool, tweak func(*mcpLiveSideEffectGate)) *peerRig {
	t.Helper()
	restore := ssrf.AllowLoopbackForTest()
	t.Cleanup(restore)

	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())

	gw := getMCPRollout().gateway
	prevCfg := gw.CurrentConfig()
	if err := gw.SetConfig(*gwCanaryCfg(1), "test", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("SetConfig canary: %v", err)
	}
	t.Cleanup(func() { _ = gw.SetConfig(prevCfg, "test-restore", time.Unix(0, 2).UnixNano()) })

	gate := liveRealGate(rollout.CapabilityGateway, trustOK)
	if tweak != nil {
		tweak(gate)
	}
	ev := liveTestEvents(t)
	cfg := &mcpruntime.Config{}
	if err := composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream: realUpstreamFor(t, p), Events: ev,
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
		LiveGate:        gate,
	}); err != nil {
		t.Fatalf("compose live tier: %v", err)
	}
	if err := mcpLiveTierFor(rollout.CapabilityGateway).arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if _, err := globalCanaryRuntime.beginCanaryActivation(rollout.CapabilityGateway, runtimeTestBudget(budgetTotal), time.Unix(0, 1)); err != nil {
		t.Fatalf("beginCanaryActivation: %v", err)
	}
	return &peerRig{cfg: cfg, events: ev}
}

func (r *peerRig) exec(in mcpruntime.ExecInput) mcpruntime.ExecOutput {
	ex := r.cfg.Deps.Executor
	return ex.Execute(context.Background(), in, ex.Resolve(in))
}

// recover derives the attempt ledger from the REAL durable spool the executor wrote
// to — the restart path, not a test-side mirror.
func (r *peerRig) recover(t *testing.T) execution.RecoveryReport {
	t.Helper()
	sp := r.events.Spool(model.CapGateway)
	if sp == nil {
		t.Fatal("no gateway spool")
	}
	rep, err := execution.RecoverAttempts(sp)
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	return rep
}

// findAttempt locates one attempt in a recovery report, orphan or settled.
func findAttempt(rep execution.RecoveryReport, id string) (execution.RecoveredAttempt, bool) {
	for _, a := range rep.Orphans {
		if a.AttemptID == id {
			return a, true
		}
	}
	for _, a := range rep.Settled {
		if a.AttemptID == id {
			return a, true
		}
	}
	return execution.RecoveredAttempt{}, false
}

// ── §16 cases ───────────────────────────────────────────────────────────────

// TestHTTPSE2E_SuccessIsExactlyOnePhysicalPOST is the POSITIVE CONTROL for every
// gate below: the happy path must actually reach the peer, exactly once, carrying a
// well-formed attempt id. A change that broke the path outright would make the
// "at most one" gates pass vacuously; this one fails.
func TestHTTPSE2E_SuccessIsExactlyOnePhysicalPOST(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)
	out := rig.exec(peerExecInput(p, policy.OpRead))

	if got := p.count(); got != 1 {
		t.Fatalf("one reservation must produce exactly one physical POST, got %d (out=%+v)", got, out)
	}
	if !out.Executed {
		t.Fatalf("a peer that answered must be reported executed, out=%+v", out)
	}
	obs := p.observed()[0]
	if !strings.HasPrefix(obs.AttemptID, "att_") {
		t.Fatalf("the peer must be able to correlate the invocation by attempt id, got %q", obs.AttemptID)
	}
}

// TestHTTPSE2E_AmbiguousDropIsStillExactlyOnePOST is the primary blocker-#6 gate at
// the wire. The peer receives the invocation and drops. Under the historical retry
// defaults this shape produces a SECOND POST (proven by the control in
// internal/mcp/upstreamclient/retryfree_test.go). Through the production live path
// it must produce exactly one.
func TestHTTPSE2E_AmbiguousDropIsStillExactlyOnePOST(t *testing.T) {
	p := startControlledPeer(t, receiveThenDrop)
	rig := armCanaryWithRealPeer(t, p, 10)
	out := rig.exec(peerExecInput(p, policy.OpRead))

	if got := p.count(); got != 1 {
		t.Fatalf("an ambiguous drop must NOT be re-sent: one reservation, %d physical POSTs (out=%+v)", got, out)
	}
}

// TestHTTPSE2E_AmbiguityIsNeverRecordedAsNotExecuted pins the §6 direction of
// uncertainty at the wire: the peer received the bytes and may have acted, so the
// durable record must not claim the invocation did not happen.
func TestHTTPSE2E_AmbiguityIsNeverRecordedAsNotExecuted(t *testing.T) {
	p := startControlledPeer(t, receiveThenDrop)
	rig := armCanaryWithRealPeer(t, p, 10)
	_ = rig.exec(peerExecInput(p, policy.OpRead))

	if p.count() != 1 {
		t.Fatalf("setup: the peer must have received the invocation, got %d", p.count())
	}
	rep := rig.recover(t)
	rec, ok := findAttempt(rep, p.observed()[0].AttemptID)
	if !ok {
		t.Fatalf("the received invocation must be attributable in durable evidence: %+v", rep)
	}
	// A transport failure after the peer read the request is NOT proof of absence.
	if rec.TerminalSendState == model.SendDefinitelyNotSent {
		t.Fatal("a peer that received the bytes must never be recorded as definitely_not_sent")
	}
	if !rec.TerminalSendState.MayHaveReachedPeer() && rec.State == execution.AttemptSettled {
		t.Fatalf("ambiguity must stay possibly-effective, got %q", rec.TerminalSendState)
	}
}

// TestHTTPSE2E_BudgetBoundsPhysicalPOSTs is the N/N+1 accounting proof AT THE WIRE:
// with MaxTotalExecutions = 3, the peer sees exactly 3 POSTs no matter how many
// requests are offered, and the 4th is refused before any bytes leave.
func TestHTTPSE2E_BudgetBoundsPhysicalPOSTs(t *testing.T) {
	const budget = 3
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, budget)

	for i := 0; i < budget+2; i++ {
		_ = rig.exec(peerExecInput(p, policy.OpRead))
	}
	if got := p.count(); got != budget {
		t.Fatalf("MaxTotalExecutions=%d must bound PHYSICAL POSTs; peer saw %d", budget, got)
	}
	// N+1 must be refused, not merely un-counted: the peer saw nothing new.
	before := p.count()
	_ = rig.exec(peerExecInput(p, policy.OpRead))
	if p.count() != before {
		t.Fatalf("the N+1st request reached the peer: %d -> %d", before, p.count())
	}
}

// TestHTTPSE2E_EachPOSTCarriesADistinctAttemptID pins that the wire-level records
// are individually attributable — the property a witness needs to answer "how many
// invocations for THIS attempt", and the property that makes count>1 detectable as
// a breach rather than invisible.
func TestHTTPSE2E_EachPOSTCarriesADistinctAttemptID(t *testing.T) {
	const n = 3
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, n)
	for i := 0; i < n; i++ {
		_ = rig.exec(peerExecInput(p, policy.OpRead))
	}
	seen := map[string]bool{}
	for _, r := range p.observed() {
		if r.AttemptID == "" {
			t.Fatal("a metered physical invocation must carry an attempt id")
		}
		if seen[r.AttemptID] {
			t.Fatalf("two physical POSTs shared one attempt id (%q) — a witness could not tell them apart", r.AttemptID)
		}
		seen[r.AttemptID] = true
		if got := p.countFor(r.AttemptID); got != 1 {
			t.Fatalf("attempt %q maps to %d physical invocations, want exactly 1", r.AttemptID, got)
		}
	}
}

// TestHTTPSE2E_GateDenialSendsNoBytes proves the negative side of the accounting: a
// request refused at the composition-layer gate produces ZERO physical POSTs, so
// the peer count is a faithful measure and not merely correlated with it. The
// success test above is its control on the same fixture.
func TestHTTPSE2E_GateDenialSendsNoBytes(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeerTrust(t, p, 10, false) // no live approval
	out := rig.exec(peerExecInput(p, policy.OpRead))
	if got := p.count(); got != 0 {
		t.Fatalf("a gate-denied request must send no bytes, peer saw %d POSTs (out=%+v)", got, out)
	}
}

// TestHTTPSE2E_AuxiliaryTrafficIsNotMetered pins §4: lifecycle/discovery traffic
// invokes no tool. It must neither consume an execution reservation nor be counted
// as a physical side-effect-bearing invocation.
func TestHTTPSE2E_AuxiliaryTrafficIsNotMetered(t *testing.T) {
	for _, m := range []string{"initialize", "notifications/initialized", "tools/list"} {
		t.Run(m, func(t *testing.T) {
			if upstreamclient.ClassifyMethod(m).SideEffectBearing() {
				t.Fatalf("%q must be classified as auxiliary, not side-effect-bearing", m)
			}
		})
	}
	// CONTROL: the metered method on the same classifier is side-effect-bearing, so
	// the gate above cannot pass by classifying everything as auxiliary.
	if !upstreamclient.ClassifyMethod("tools/call").SideEffectBearing() {
		t.Fatal("control: tools/call must be side-effect-bearing")
	}
	if !upstreamclient.ClassifyMethod("some/unknown/method").SideEffectBearing() {
		t.Fatal("control: an unknown method must fail closed as side-effect-bearing")
	}
}

// ── crash window, DLP block, and the wire-level differential control ─────────

// truncatedReader replays a durable event stream up to (and including) a chosen
// sequence, which is exactly what a crash leaves behind: everything committed
// before the process died and nothing after. It reads the REAL spool, so the events
// are the ones the executor actually wrote.
type truncatedReader struct {
	src   execution.EvidenceReader
	upTo  uint64 // inclusive; 0 ⇒ no truncation
	pages int
}

func (r *truncatedReader) CommittedForExport(part model.Partition, afterSeq uint64, maxRecords int) ([]model.Event, []uint64, uint64, error) {
	evs, seqs, cursor, err := r.src.CommittedForExport(part, afterSeq, maxRecords)
	if err != nil || r.upTo == 0 {
		return evs, seqs, cursor, err
	}
	keptE, keptS := make([]model.Event, 0, len(evs)), make([]uint64, 0, len(seqs))
	for i := range evs {
		if seqs[i] <= r.upTo {
			keptE, keptS = append(keptE, evs[i]), append(keptS, seqs[i])
		}
	}
	return keptE, keptS, cursor, nil
}

// spoolEvents returns every committed gateway event with its sequence.
func (r *peerRig) spoolEvents(t *testing.T, part model.Partition) ([]model.Event, []uint64) {
	t.Helper()
	sp := r.events.Spool(model.CapGateway)
	if sp == nil {
		t.Fatal("no gateway spool")
	}
	var allE []model.Event
	var allS []uint64
	var after uint64
	for {
		evs, seqs, cursor, err := sp.CommittedForExport(part, after, 512)
		if err != nil {
			t.Fatalf("CommittedForExport: %v", err)
		}
		allE, allS = append(allE, evs...), append(allS, seqs...)
		if len(evs) == 0 || cursor <= after {
			return allE, allS
		}
		after = cursor
	}
}

// spoolEventsAll returns the committed events across every partition the recovery
// path scans, with per-partition sequences kept alongside.
func (r *peerRig) spoolEventsAll(t *testing.T) ([]model.Event, []uint64) {
	t.Helper()
	var allE []model.Event
	var allS []uint64
	for _, part := range []model.Partition{model.PartCrit, model.PartOrd} {
		e, s := r.spoolEvents(t, part)
		allE, allS = append(allE, e...), append(allS, s...)
	}
	return allE, allS
}

// seqOfPhase finds the sequence of the first event of a phase for an attempt id.
func seqOfPhase(evs []model.Event, seqs []uint64, phase model.Phase, attemptID string) (uint64, bool) {
	for i := range evs {
		if evs[i].Phase != phase {
			continue
		}
		switch phase {
		case model.PhaseSendIntent, model.PhaseOutcome:
			if evs[i].Outcome != nil && evs[i].Outcome.AttemptID == attemptID {
				return seqs[i], true
			}
		}
	}
	return 0, false
}

// TestHTTPSE2E_CrashAfterPeerReceiptLeavesARecoverableOrphan is the blocker-#8
// crash-window case at the wire. The peer HAS received the invocation. The ledger
// is then truncated at the durable send intent — precisely what a crash between the
// send and the outcome commit leaves — and the surviving evidence must be enough to
// re-derive the attempt as an UNRESOLVED orphan.
//
// The two properties that make the window resolvable rather than merely lost:
// the intent is durable and ordered BEFORE the outcome, and its absence of an
// outcome derives reconciliation_required — never "not executed".
func TestHTTPSE2E_CrashAfterPeerReceiptLeavesARecoverableOrphan(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("setup: the controlled execution must succeed, out=%+v", out)
	}
	if p.count() != 1 {
		t.Fatalf("setup: the peer must have received exactly one invocation, got %d", p.count())
	}
	attemptID := p.observed()[0].AttemptID

	// Scan BOTH partitions the recovery path scans. The send intent and the terminal
	// outcome are deliberately ORDINARY criticality (they are emitted after the side
	// effect and must not drive the critical domain degraded), so a P-CRIT-only scan
	// would find neither.
	evs, seqs := rig.spoolEventsAll(t)
	intentSeq, ok := seqOfPhase(evs, seqs, model.PhaseSendIntent, attemptID)
	if !ok {
		t.Fatal("no durable send intent for a physically-sent invocation: the crash window would be unrecoverable")
	}
	outcomeSeq, ok := seqOfPhase(evs, seqs, model.PhaseOutcome, attemptID)
	if !ok {
		t.Fatal("no terminal outcome for a completed invocation")
	}
	if intentSeq >= outcomeSeq {
		t.Fatalf("the intent must be durable BEFORE the outcome, got intent=%d outcome=%d", intentSeq, outcomeSeq)
	}

	// The crash: everything through the intent survived, the outcome did not.
	sp := rig.events.Spool(model.CapGateway)
	rep, err := execution.RecoverAttempts(&truncatedReader{src: sp, upTo: intentSeq})
	if err != nil {
		t.Fatalf("RecoverAttempts on the crash-truncated ledger: %v", err)
	}
	rec, found := findAttempt(rep, attemptID)
	if !found {
		t.Fatalf("the crash window must be re-derivable from durable evidence alone: %+v", rep)
	}
	if rec.State != execution.AttemptReconciliationRequired {
		t.Fatalf("an intent with no outcome must rest at reconciliation_required, got %q", rec.State)
	}
	if rec.TerminalSendState == model.SendDefinitelyNotSent {
		t.Fatal("a crash must never be resolved as definitely_not_sent")
	}
	if rec.Reconciliation.Resolved() {
		t.Fatalf("an unreconciled orphan must not be resolved by recovery alone, got %q", rec.Reconciliation)
	}

	// CONTROL: with the outcome present, the SAME ledger settles the same attempt.
	// Without this the gate above could pass on a report that recovers nothing.
	full, err := execution.RecoverAttempts(sp)
	if err != nil {
		t.Fatalf("RecoverAttempts on the full ledger: %v", err)
	}
	settled, found := findAttempt(full, attemptID)
	if !found || settled.State != execution.AttemptSettled {
		t.Fatalf("control: the untruncated ledger must settle the attempt, got %+v", full)
	}
}

// TestHTTPSE2E_DLPBlockAfterPeerResponseStaysExecuted is the §16 DLP case: the peer
// answered, so the tool RAN — Culvert refusing to hand the response to the client
// changes nothing about that. Recording such a request as not-executed would be the
// laundering of a real physical effect into a non-event.
func TestHTTPSE2E_DLPBlockAfterPeerResponseStaysExecuted(t *testing.T) {
	secret := "-----BEGIN RSA PRIVATE KEY-----\\nMIIB\\n-----END RSA PRIVATE KEY-----"
	p := startControlledPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"u-s1","result":{"leak":"`+secret+`"}}`)
	})
	rig := armCanaryWithRealPeer(t, p, 10)
	out := rig.exec(peerExecInput(p, policy.OpRead))

	if p.count() != 1 {
		t.Fatalf("setup: the peer must have been invoked exactly once, got %d", p.count())
	}
	if out.Disposition != mcpruntime.DispRejected {
		t.Fatalf("setup: the response must be refused before egress, out=%+v", out)
	}
	rep := rig.recover(t)
	rec, found := findAttempt(rep, p.observed()[0].AttemptID)
	if !found {
		t.Fatalf("a DLP-blocked invocation must still be attributable: %+v", rep)
	}
	if rec.TerminalSendState != model.SendPeerResponseReceived {
		t.Fatalf("the peer answered, so the send state must be peer_response_received, got %q", rec.TerminalSendState)
	}
	if !rec.TerminalSendState.MayHaveReachedPeer() {
		t.Fatal("a DLP block on egress must never make the physical invocation disappear")
	}
}

// TestHTTPSE2E_ControlDefaultLimitsWouldResendAtTheWire is the DIFFERENTIAL CONTROL
// for the ambiguous-drop gate, measured on the SAME local peer through the SAME
// client type. It proves the retry-free gate is not vacuous: the identical server
// shape produces MORE than one physical POST under the historical default limits.
// If this ever reports 1, the ambiguous-drop gate has stopped proving anything.
func TestHTTPSE2E_ControlDefaultLimitsWouldResendAtTheWire(t *testing.T) {
	restore := ssrf.AllowLoopbackForTest()
	defer restore()

	p := startControlledPeer(t, receiveThenDrop)
	ipStr, _, err := net.SplitHostPort(strings.TrimPrefix(p.srv.URL, "https://"))
	if err != nil {
		t.Fatalf("split peer addr: %v", err)
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		t.Fatalf("parse peer addr: %v", err)
	}
	pol, err := destination.NewPolicy(destination.PolicyConfig{Schemes: []string{"https"}, AllowPrivate: true})
	if err != nil {
		t.Fatalf("destination.NewPolicy: %v", err)
	}
	c, err := upstreamclient.New(upstreamclient.Config{
		Limits:           upstreamclient.DefaultLimits(), // the HISTORICAL retrying limits
		Resolver:         loopbackResolver{addr: addr},
		Policy:           pol,
		InspectionLimits: limits.DefaultGatewayInspection(),
		Clock:            time.Now,
	}, limits.DefaultGateway())
	if err != nil {
		t.Fatalf("upstreamclient.New: %v", err)
	}
	_, callErr := c.Call(context.Background(),
		upstreamclient.Target{ServerID: "s1", Endpoint: p.srv.URL, PinnedIdentity: p.pin},
		"tools/call", nil, upstreamclient.CallOptions{Idempotent: true, WireID: "ctl-1"})
	if callErr == nil {
		t.Fatal("control setup: the dropped connection must surface as an error")
	}
	if got := p.count(); got <= 1 {
		t.Fatalf("control: default limits must re-send after a pre-response drop, peer saw %d POSTs", got)
	}
}

// TestHTTPSE2E_SuccessfulExecutionIsSettledNotOrphaned is the REGRESSION GATE for
// the defect this harness found: the terminal outcome event carried no DecisionRef,
// so model.Event.Validate rejected it, and because the outcome commit is
// best-effort the record vanished. Every completed execution then looked, on
// restart, exactly like a crash — the ledger reported an unresolved orphan for work
// that had demonstrably finished, which is blocker #8's failure mode reintroduced
// by the mechanism meant to close it.
//
// It was invisible to unit tests because they commit through a test sink that does
// not validate; only reading the REAL spool exposes it. That is the reason this
// gate is here and not in the executor package.
func TestHTTPSE2E_SuccessfulExecutionIsSettledNotOrphaned(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("setup: the controlled execution must succeed, out=%+v", out)
	}
	attemptID := p.observed()[0].AttemptID

	rep := rig.recover(t)
	if len(rep.Orphans) != 0 {
		t.Fatalf("a completed execution must leave NO orphan; the terminal outcome was lost: %+v", rep.Orphans)
	}
	rec, found := findAttempt(rep, attemptID)
	if !found || rec.State != execution.AttemptSettled {
		t.Fatalf("the completed attempt must be settled, got found=%v rec=%+v", found, rec)
	}
	if rec.TerminalSendState != model.SendPeerResponseReceived {
		t.Fatalf("a peer that answered must settle as peer_response_received, got %q", rec.TerminalSendState)
	}
}

// TestHTTPSE2E_EveryTerminalOutcomeIsPersistable pins the SHAPE of the outcome
// event against the real validator, so a future field change that makes the outcome
// unpersistable fails here rather than degrading silently into evidence loss. It is
// the unit-level companion to the gate above: that one proves the record survives
// the round trip, this one proves WHY, on every phase the attempt path emits.
func TestHTTPSE2E_EveryTerminalOutcomeIsPersistable(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)
	_ = rig.exec(peerExecInput(p, policy.OpRead))

	evs, _ := rig.spoolEventsAll(t)
	var intents, outcomes int
	for i := range evs {
		if err := evs[i].Validate(); err != nil {
			t.Fatalf("a committed event does not validate (%v): %+v", err, evs[i])
		}
		switch evs[i].Phase {
		case model.PhaseSendIntent:
			intents++
		case model.PhaseOutcome:
			outcomes++
			if evs[i].Outcome.DecisionRef == "" {
				t.Fatal("a terminal outcome without a decision ref cannot be persisted; it would be lost silently")
			}
		}
	}
	// One physical invocation ⇒ exactly one intent and exactly one outcome. A second
	// of either would mean the ledger double-counts physical effects.
	if intents != 1 || outcomes != 1 {
		t.Fatalf("one physical invocation must yield exactly one intent and one outcome, got %d/%d", intents, outcomes)
	}
}
