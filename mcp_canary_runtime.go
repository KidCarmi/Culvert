package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Canary activation RUNTIME — generation lifecycle + durable budget/abort state (§3/§4/§7/§8,
// Canary Activation Gate). This is the composition-layer owner that ties the pure engines together:
//
//   - an ACTIVATION GENERATION (monotonic, bumped on each Shadow→Canary activation) that keys the
//     budget enforcer and the abort controller, so a demotion/reactivation structurally invalidates
//     the previous generation's runtime state;
//   - canary.BudgetEnforcer (§3): the per-activation blast-radius budget, spend persisted BEFORE the
//     side-effect boundary so a restart never replays it;
//   - canary.AbortController (§4): the per-activation whole-Canary abort latch, persisted so an abort
//     survives a restart.
//
// DORMANT BY CONSTRUCTION. This file composes NO LiveExecutor, contacts NO upstream, materializes NO
// credential, and calls NO arming hook. beginCanaryActivation is the seam a FUTURE, separately-
// reviewed live activation would call once the live tier is armed and the §2 preflight passes; NO
// production path invokes it in this build (mirroring the uncalled markGatewayExecDepsReady), so no
// generation is ever bumped, no budget is ever armed, and no execution is ever reserved in
// production. It exists so the budget/abort/generation contract is real, durable, and restart-safe —
// exercised through a controlled test seam — before the engine that changes the outside world is
// ever composed.

// canaryRuntimeSchemaVersion is the durable-state schema version (fail-closed on any other value).
const canaryRuntimeSchemaVersion = 1

// canaryRuntimeState is the restart-durable, node-local DTO for one capability's Canary activation
// runtime. It carries ONLY the generation, build identity, the active budget, and the scalar
// budget/abort snapshots — never a tenant/subject/secret.
type canaryRuntimeState struct {
	SchemaVersion  int                   `json:"schema_version"`
	Capability     string                `json:"capability"`
	BuildVersion   string                `json:"build_version"`
	Generation     uint64                `json:"generation"`
	Active         bool                  `json:"active"` // an enforcer/controller are armed for Generation
	Budget         canary.Budget         `json:"budget"`
	BudgetSnapshot canary.BudgetSnapshot `json:"budget_snapshot"`
	AbortSnapshot  canary.AbortSnapshot  `json:"abort_snapshot"`
}

// canaryCapRuntime is one capability's in-memory activation runtime.
type canaryCapRuntime struct {
	mu         sync.Mutex
	generation uint64
	active     bool
	budget     canary.Budget
	enforcer   *canary.BudgetEnforcer
	aborter    *canary.AbortController
}

// canaryRuntime holds the two isolated capability runtimes.
type canaryRuntime struct {
	gateway    canaryCapRuntime
	management canaryCapRuntime
}

var globalCanaryRuntime = &canaryRuntime{}

func (rt *canaryRuntime) capRuntime(capb rollout.Capability) *canaryCapRuntime {
	if capb == rollout.CapabilityManagement {
		return &rt.management
	}
	return &rt.gateway
}

// canaryRuntimeStatePath is the per-capability durable state path under dataDir.
func canaryRuntimeStatePath(capb rollout.Capability) string {
	name := "mcp_canary_runtime_gateway.json"
	if capb == rollout.CapabilityManagement {
		name = "mcp_canary_runtime_management.json"
	}
	return filepath.Join(dataDir, name)
}

// errCanaryBudgetInvalid marks an activation refused because its budget is not first-Canary valid.
var errCanaryBudgetInvalid = errors.New("canary_budget_invalid")

// canaryDemotePersist is the persist step of demoteCanary, isolated as a seam so a test can inject
// a durable-write failure that leaves the prior active record on disk — exercising the fail-closed
// remove path that prevents a failed demotion from reviving on restart (Codex P1). Production is the
// real persistLocked.
var canaryDemotePersist = (*canaryRuntime).persistLocked

// beginCanaryActivation bumps the activation generation and arms a fresh budget enforcer + abort
// controller for it, then persists. It is the FUTURE-arming seam (never invoked in this build). It
// composes no executor and reaches no upstream — it only initialises the accounting a live Canary
// would consult. A budget that is not first-Canary valid is refused fail-closed. Returns the new
// generation.
func (rt *canaryRuntime) beginCanaryActivation(capb rollout.Capability, budget canary.Budget, now time.Time) (uint64, error) {
	if canary.ValidateBudget(budget) != canary.BudgetOK {
		return 0, errCanaryBudgetInvalid
	}
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.generation++ // monotonic — a re-activation NEVER reuses a prior generation
	gen := cr.generation
	cr.active = true
	cr.budget = budget
	cr.enforcer = canary.NewBudgetEnforcer(budget, gen, now)
	cr.aborter = canary.NewAbortController(gen)
	if err := rt.persistLocked(capb, cr); err != nil {
		return gen, err
	}
	return gen, nil
}

// demoteCanary invalidates the current activation: it disarms the enforcer and controller so no
// further execution can be reserved, and persists. The generation is NOT reused — the next
// beginCanaryActivation bumps it, so the demoted generation's budget/abort snapshots can never be
// restored into, or reused by, the new activation. This is the runtime half of a rollback/demotion.
//
// A demotion is a SAFETY narrowing, so the durable state MUST fail closed: if persisting the
// disarmed record fails, the on-disk file would still say Active:true for this generation and a
// restart would re-arm it, silently undoing the rollback (Codex P1). To prevent that revival the
// durable file is best-effort REMOVED on a persist failure — a missing file restores to the dormant
// default (nothing armed), which is the safe direction. Only if BOTH the disarmed write and the
// remove fail is the demotion not durably fail-closed, and that is RETURNED so the caller never
// reports a durable rollback that a restart could reverse.
func (rt *canaryRuntime) demoteCanary(capb rollout.Capability) error {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.active = false
	cr.enforcer = nil
	cr.aborter = nil
	cr.budget = canary.Budget{}
	if err := canaryDemotePersist(rt, capb, cr); err != nil {
		// Persisting the disarmed record failed — remove the durable file so a restart cannot
		// restore the prior Active:true record. A removal that succeeds fails the runtime closed to
		// dormant; a removal that also fails leaves the stale record, so surface the original error.
		if rerr := os.Remove(canaryRuntimeStatePath(capb)); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			logger.Printf("MCP canary runtime: demote persist AND remove for %s failed; a restart may revive the activation: persist=%q remove=%q",
				capb.String(), sanitizeLog(err.Error()), sanitizeLog(rerr.Error()))
			return err
		}
		logger.Printf("MCP canary runtime: demote persist for %s failed; removed durable state to fail closed to dormant: %q", capb.String(), sanitizeLog(err.Error()))
		return err
	}
	return nil
}

// currentGeneration returns the capability's current activation generation (0 = never activated).
func (rt *canaryRuntime) currentGeneration(capb rollout.Capability) uint64 {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.generation
}

// reserveCanaryExecution is the pre-side-effect gate a live Canary would call: it refuses unless an
// activation is armed AND the abort controller is execution-eligible AND the budget grants a slot.
// A whole-Canary budget exhaustion (total spent / window elapsed) trips the abort controller
// (budget_exhausted) so the Canary stops, not just the request. The budget spend is persisted BEFORE
// returning a grant so a restart cannot replay it. Fail-closed: any not-armed / aborted / persist
// failure denies.
func (rt *canaryRuntime) reserveCanaryExecution(capb rollout.Capability, now time.Time) canary.BudgetOutcome {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.enforcer == nil || cr.aborter == nil {
		return canary.BudgetDeniedInvalid
	}
	gen := cr.generation
	if !cr.aborter.ExecutionEligible(gen) {
		return canary.BudgetDeniedInvalid // the Canary is aborted — no execution
	}
	outcome := cr.enforcer.Reserve(gen, now)
	if outcome.WholeCanaryExhaustion() {
		// The blast-radius budget is spent — a whole-Canary breach. Latch the abort.
		cr.aborter.Trip("budget_exhausted", gen, now)
	}
	// Persist the spend/abort BEFORE the caller could cross the side-effect boundary. On a persist
	// failure the in-memory spend is already consumed (monotonic — never replayed), and we deny.
	if err := rt.persistLocked(capb, cr); err != nil {
		logger.Printf("MCP canary runtime: persist after reserve for %s failed (fail-closed): %q", capb.String(), sanitizeLog(err.Error()))
		if outcome.Granted() {
			return canary.BudgetDeniedInvalid
		}
	}
	return outcome
}

// releaseCanaryExecution returns one in-flight concurrency slot after an execution completes. It
// does not persist (the monotonic total was already made durable at reserve).
func (rt *canaryRuntime) releaseCanaryExecution(capb rollout.Capability) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if cr.enforcer != nil {
		cr.enforcer.Release()
	}
}

// tripCanaryAbort feeds a safety-trip code to the capability's abort controller and persists if the
// state may have changed. It returns the TripResult so a caller can distinguish a per-request
// fail-closed (Canary continues) from a whole-Canary latch. A not-armed runtime fails closed to a
// latch result.
func (rt *canaryRuntime) tripCanaryAbort(capb rollout.Capability, code string, now time.Time) canary.TripResult {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.aborter == nil {
		return canary.TripCanaryLatched
	}
	res := cr.aborter.Trip(code, cr.generation, now)
	if res == canary.TripCanaryLatched {
		if err := rt.persistLocked(capb, cr); err != nil {
			logger.Printf("MCP canary runtime: persist after abort for %s failed: %q", capb.String(), sanitizeLog(err.Error()))
		}
	}
	return res
}

// executionEligible reports whether a live Canary execution could proceed right now (armed,
// eligible, budget remaining). Read-only.
func (rt *canaryRuntime) executionEligible(capb rollout.Capability) bool {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.enforcer == nil || cr.aborter == nil {
		return false
	}
	return cr.aborter.ExecutionEligible(cr.generation) && cr.enforcer.Remaining() > 0
}

// persistLocked writes the capability's durable runtime state. Caller holds cr.mu.
func (rt *canaryRuntime) persistLocked(capb rollout.Capability, cr *canaryCapRuntime) error {
	st := canaryRuntimeState{
		SchemaVersion: canaryRuntimeSchemaVersion,
		Capability:    capb.String(),
		BuildVersion:  version,
		Generation:    cr.generation,
		Active:        cr.active,
		Budget:        cr.budget,
	}
	if cr.enforcer != nil {
		st.BudgetSnapshot = cr.enforcer.Snapshot()
	}
	if cr.aborter != nil {
		st.AbortSnapshot = cr.aborter.Snapshot()
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if werr := fileutil.AtomicWrite(canaryRuntimeStatePath(capb), raw, 0o600); werr != nil {
		if errors.Is(werr, fileutil.ErrReplacedNotSynced) {
			return nil
		}
		return werr
	}
	return nil
}

// restore re-establishes both capabilities' Canary activation runtime from durable state. A missing
// file is a fresh runtime (generation 0, nothing armed). A corrupt/unknown-schema/capability-
// mismatched file is QUARANTINED and treated as fresh (fail-closed). A build-version mismatch
// disarms the enforcer/controller (a materially changed runtime does not resume a live budget) while
// preserving the monotonic generation, so a re-activation on the new build bumps past it.
func (rt *canaryRuntime) restore() {
	for _, capb := range []rollout.Capability{rollout.CapabilityGateway, rollout.CapabilityManagement} {
		rt.restoreCapability(capb)
	}
}

func (rt *canaryRuntime) restoreCapability(capb rollout.Capability) {
	path := canaryRuntimeStatePath(capb)
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed operator-owned path under dataDir
	if err != nil {
		return // missing (fresh) or unreadable — keep the safe zero runtime
	}
	var st canaryRuntimeState
	if derr := strictDecodeCanaryRuntimeJSON(raw, &st); derr != nil {
		quarantineCorruptStateFile("mcp_canary_runtime", path, derr)
		return
	}
	if st.SchemaVersion != canaryRuntimeSchemaVersion || st.Capability != capb.String() {
		quarantineCorruptStateFile("mcp_canary_runtime", path, fmt.Errorf("schema/capability mismatch"))
		return
	}
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.generation = st.Generation
	// A build-version mismatch disarms the runtime: a live budget/abort from a different build must
	// not resume on a materially changed runtime (fail-closed). The monotonic generation is kept so
	// a fresh activation bumps past the stale one.
	if !st.Active || st.BuildVersion != version || st.Generation == 0 {
		cr.active = false
		cr.enforcer = nil
		cr.aborter = nil
		cr.budget = canary.Budget{}
		return
	}
	// Rebuild the enforcer + controller for the SAME generation. RestoreBudgetEnforcer /
	// RestoreAbortController are generation-strict, so a snapshot from a different generation cannot
	// resurrect state here. A budget that no longer validates (or a corrupt snapshot) disarms.
	cr.budget = st.Budget
	cr.enforcer = canary.RestoreBudgetEnforcer(st.Budget, st.Generation, st.BudgetSnapshot)
	cr.aborter = canary.RestoreAbortController(st.Generation, st.AbortSnapshot)
	if cr.enforcer == nil || cr.aborter == nil {
		cr.active = false
		cr.enforcer = nil
		cr.aborter = nil
		cr.budget = canary.Budget{}
		return
	}
	cr.active = true
}

// strictDecodeCanaryRuntimeJSON decodes exactly one JSON value into v, rejecting unknown fields and
// trailing data (the tooltrust/attestation discipline — a tampered record is corruption).
func strictDecodeCanaryRuntimeJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON value")
	}
	return nil
}
