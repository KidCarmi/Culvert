package main

// startup_sequence_order_test.go — the start-up order: identity early, role
// activation after the stores, traffic gates after the activation.
//
// Three layers, strongest first:
//
//  1. startup_sequence_binary_test.go (build tag proxybinload) starts the REAL
//     BINARY per role, so the order under test is main()'s own.
//  2. The structural guards here read runStartupSequence — the one sequence
//     main() runs — and fail if a store loader is added after the activation,
//     an activation before the loaders, or a listener before the gates.
//  3. The TestClusterHalves_* tests here run the real early half, the real
//     store loaders and the real activation (a real gRPC listener, polled by a
//     real client) in-process. They order the PHASES by hand — runStartupSequence
//     itself cannot run inside the test binary: it registers flags on the
//     process flag set (once per process), starts unstoppable goroutines over
//     ~100 package globals, and exits the process on a fatal — which is why
//     layer 1 exists and layer 2 pins the order they assume.

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/blocklist"
	"github.com/KidCarmi/Culvert/internal/halease"
)

// ── structural guards on the one sequence ───────────────────────────────────

// startupPhase is the phase a step of runStartupSequence belongs to.
type startupPhase int

const (
	phaseIdentity   startupPhase = 1 // node services, cluster identity and trust
	phaseStores     startupPhase = 2 // configuration stores and their reconciliation
	phaseActivation startupPhase = 3 // the cluster role starts acting
	phaseTraffic    startupPhase = 4 // traffic gates and listeners
)

// startupStepPhases classifies EVERY step of runStartupSequence. A step that
// is not listed fails TestStartupSequence_PhasesNeverGoBackwards, so adding a
// step forces a decision about where it belongs — a store loader placed after
// the activation, or a listener before it, cannot slip in unclassified.
var startupStepPhases = map[string]startupPhase{
	"initAuth": phaseIdentity, "initSession": phaseIdentity, "initObservability": phaseIdentity,
	"initLogStore": phaseIdentity, "initGeoIP": phaseIdentity, "initUIAccessPolicy": phaseIdentity,
	"initPAC": phaseIdentity, "initLegacyAuthProviders": phaseIdentity, "initMetricsToken": phaseIdentity,
	"initClusterIdentity": phaseIdentity, "enterStartupIdentityPhase": phaseIdentity,

	"enterStartupStoresPhase": phaseStores,
	"initConnAndRateLimit":    phaseStores, "initBlocklist": phaseStores, "initRootCA": phaseStores,
	"initPolicy": phaseStores, "initURLCategories": phaseStores, "initFileBlocking": phaseStores,
	"reconcileObjectRefNames": phaseStores, "initSSLBypassAndDPI": phaseStores, "initH2InspectServer": phaseStores,
	"initRewriteAndDefaultAction": phaseStores, "initScanning": phaseStores, "initUpstreamProxy": phaseStores,
	"initCDR": phaseStores, "initMTLSAndOCSP": phaseStores, "initBackgroundServices": phaseStores,
	// initSOCKS5 BINDS in the store phase but serves nothing: it arms the
	// pre-posture gate first (TestCHAOS102_Wall_*), released in phaseTraffic.
	"initSOCKS5": phaseStores, "initPersistentAdminState": phaseStores, "initPolicyLearning": phaseStores,
	"initMCPRuntime": phaseStores, "initMCPToolTrust": phaseStores, "initMCPRollout": phaseStores,
	"initMCPDistribution": phaseStores, "loadReleaseManagement": phaseStores, "resolveReleaseStartupConfig": phaseStores,

	// The activation, then the one reconciliation that publishes (it must
	// follow the role being active), then the node is marked ready.
	"enterStartupActivationPhase": phaseActivation, "activateClusterRoles": phaseActivation,
	// Re-applies the persisted hit history onto the rules a data plane's
	// replay just replaced. Not a store loader: it reads the in-memory
	// baseline phase 2 loaded and touches no file.
	"restoreHitCountsAfterActivation": phaseActivation,
	"pacReconcileAllLifecycles":       phaseActivation, "markNodeReady": phaseActivation,

	"openTrafficGates": phaseTraffic, "startAdminUI": phaseTraffic, "buildAndStartProxyServer": phaseTraffic,
}

// startupSequenceCalls is the bare-identifier calls of runStartupSequence in
// source order.
func startupSequenceCalls(t *testing.T) []string {
	t.Helper()
	seq := funcDeclForTest(t, parseMainPkgFileForTest(t, "main.go"), "runStartupSequence")
	var out []string
	ast.Inspect(seq.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				out = append(out, id.Name)
			}
		}
		return true
	})
	if len(out) < 30 {
		t.Fatalf("runStartupSequence has only %d calls; this guard is not reading the boot sequence", len(out))
	}
	return out
}

// TestStartupSequence_PhasesNeverGoBackwards: identity → stores → activation →
// traffic, each step classified, exactly one activation.
func TestStartupSequence_PhasesNeverGoBackwards(t *testing.T) {
	calls := startupSequenceCalls(t)
	if err := startupPhaseOrderError(calls); err != "" {
		t.Fatal(err)
	}
	// Negative controls: the predicate rejects the shapes it exists to reject.
	swap := func(a, b string) []string {
		out := append([]string(nil), calls...)
		ia, ib := -1, -1
		for i, c := range out {
			switch c {
			case a:
				ia = i
			case b:
				ib = i
			}
		}
		out[ia], out[ib] = out[ib], out[ia]
		return out
	}
	for name, bad := range map[string][]string{
		"the old order (activation before the stores)": swap("activateClusterRoles", "initConnAndRateLimit"),
		"a store loader after the activation":          swap("activateClusterRoles", "loadReleaseManagement"),
		"the SOCKS5 gate opened before the activation": swap("openTrafficGates", "activateClusterRoles"),
		"an unclassified new step":                     append(append([]string(nil), calls...), "initSomethingNew"),
		"a second activation":                          append(append([]string(nil), calls[:len(calls)-3]...), "activateClusterRoles", "openTrafficGates", "startAdminUI", "buildAndStartProxyServer"),
		"ready marked before the activation":           swap("markNodeReady", "activateClusterRoles"),
		"hit history re-restored before the replay":    swap("restoreHitCountsAfterActivation", "activateClusterRoles"),
		"a traffic gate opened before ready":           swap("markNodeReady", "openTrafficGates"),
		"the stores phase entered after a store":       swap("enterStartupStoresPhase", "initBlocklist"),
		"the activation phase entered after the role":  swap("enterStartupActivationPhase", "activateClusterRoles"),
	} {
		if startupPhaseOrderError(bad) == "" {
			t.Errorf("control: the phase guard accepted %s", name)
		}
	}
}

func startupPhaseOrderError(calls []string) string {
	last, lastName, activations := startupPhase(0), "", 0
	for _, c := range calls {
		ph, ok := startupStepPhases[c]
		if !ok {
			return fmt.Sprintf("runStartupSequence calls %s, which startupStepPhases does not classify: decide whether it is "+
				"identity, a store loader/reconciliation (must precede activateClusterRoles), or a traffic gate/listener (must follow it)", c)
		}
		if ph < last {
			return fmt.Sprintf("runStartupSequence runs %s (phase %d) after %s (phase %d): the cluster role must not start acting before "+
				"every configuration store has loaded, and no traffic gate may open before the activation", c, ph, lastName, last)
		}
		if c == "activateClusterRoles" {
			activations++
		}
		last, lastName = ph, c
	}
	if activations != 1 {
		return fmt.Sprintf("runStartupSequence activates the cluster role %d times, want exactly once", activations)
	}
	return startupLifecycleMarkerError(calls)
}

// startupLifecycleMarkerError pins where the lifecycle (node_lifecycle.go) is
// advanced relative to the steps: each phase is ENTERED before its first step,
// and the node is marked ready after the role is active and before any traffic
// gate opens.
func startupLifecycleMarkerError(calls []string) string {
	at := func(name string) int {
		for i, c := range calls {
			if c == name {
				return i
			}
		}
		return -1
	}
	for _, pair := range [][2]string{
		{"enterStartupIdentityPhase", "initAuth"},
		{"initClusterIdentity", "enterStartupStoresPhase"},
		{"enterStartupStoresPhase", "initConnAndRateLimit"},
		{"loadReleaseManagement", "enterStartupActivationPhase"},
		{"enterStartupActivationPhase", "activateClusterRoles"},
		{"activateClusterRoles", "restoreHitCountsAfterActivation"},
		{"restoreHitCountsAfterActivation", "markNodeReady"},
		{"activateClusterRoles", "pacReconcileAllLifecycles"},
		{"pacReconcileAllLifecycles", "markNodeReady"},
		{"markNodeReady", "openTrafficGates"},
	} {
		a, b := at(pair[0]), at(pair[1])
		if a < 0 || b < 0 {
			return fmt.Sprintf("runStartupSequence no longer calls %s (%d) / %s (%d)", pair[0], a, pair[1], b)
		}
		if a > b {
			return fmt.Sprintf("runStartupSequence calls %s after %s: the lifecycle must be advanced before the steps of the phase it names", pair[0], pair[1])
		}
	}
	if at("enterStartupIdentityPhase") != 0 {
		return "enterStartupIdentityPhase must be the first statement of runStartupSequence: until it runs the node reads as unmanaged, i.e. ready"
	}
	return ""
}

// startupActivationEntryPoints are the functions that make a role ACT. Nothing
// that runs before activateClusterRoles may reach one.
var startupActivationEntryPoints = []string{
	"activateControlPlane", "enableControlPlane", "enableControlPlaneResilient", "startControlPlaneWithHAResume",
	"startHAStandby", "startControlPlaneListener", "startDataPlane", "runDataPlane", "applyDPLastGoodConfigSnapshot",
}

// startupCallees is calleeNames with ONE documented exception: the closure
// prepareDataPlane RETURNS is the data plane's late half — handing it back
// un-run is the whole point of the split — so its body is not a call
// prepareDataPlane makes. Every other closure counts as called.
func startupCallees(fn *ast.FuncDecl) map[string]bool {
	if fn.Name.Name != "prepareDataPlane" {
		return calleeNames(fn)
	}
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ReturnStmt:
			for _, r := range x.Results {
				if _, isLit := r.(*ast.FuncLit); isLit {
					return false
				}
			}
		case *ast.CallExpr:
			switch f := x.Fun.(type) {
			case *ast.Ident:
				out[f.Name] = true
			case *ast.SelectorExpr:
				out[f.Sel.Name] = true
			}
		}
		return true
	})
	return out
}

// TestStartupSequence_NothingBeforeTheActivationActivates: by bare-name call
// graph over the production files, no step of phases 1–2 — the early cluster
// half included — reaches a role activation, the last-good replay or the
// listener bind.
func TestStartupSequence_NothingBeforeTheActivationActivates(t *testing.T) {
	funcs := startupProdFuncs(t)
	entry := map[string]bool{}
	for _, e := range startupActivationEntryPoints {
		if funcs[e] == nil {
			t.Fatalf("activation entry point %s no longer exists; this guard's list is stale", e)
		}
		entry[e] = true
	}
	var offenders []string
	for _, step := range startupSequenceCalls(t) {
		if startupStepPhases[step] >= phaseActivation {
			break
		}
		if via := startupReaches(funcs, entry, step); via != "" {
			offenders = append(offenders, step+" → "+via)
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("start-up steps that run BEFORE activateClusterRoles reach a role activation: %v", offenders)
	}
	// Not vacuous: the activation itself reaches them.
	if startupReaches(funcs, entry, "activate") == "" {
		t.Error("control: the call graph cannot see that (*clusterActivation).activate activates anything")
	}
}

// startupMainCallees is EVERYTHING main() may call: process-level plumbing
// (argv, data dir, single-writer lock, restore recovery, file config, logger,
// lifecycle context), the one start-up sequence, and the serve loop. An
// allowlist, not a denylist: a new `initFoo(s)` written straight into main()
// — outside the sequence, and so outside every phase guard — fails here
// whatever it is called.
var startupMainCallees = map[string]bool{
	// one-shot subcommands and argv
	"maybeRunBootstrapResolve": true, "maybeRunPolicyPreflight": true, "parseFlags": true,
	"checkPositionalArgs": true, "handleOneShotCommands": true, "runEnrollmentMode": true,
	// the persisted-state root
	"applyDataDirFromEnv": true, "checkInterruptedRestore": true, "checkDataDirSingleWriter": true,
	"recoverInPlaceRestoreAtBoot": true, "checkDataEpochAtBoot": true, "dataDirOverridden": true,
	"logDataDirWriterLockNotice": true,
	// process configuration, logger, lifecycle
	"setInsecureFlag": true, "loadFileConfigAndFlags": true, "initUIExtras": true, "initLogger": true,
	"initMemoryBackstop": true, "initLifecycleContext": true, "appLifecycleCancel": true,
	// the sequence, then serving
	"runStartupSequence": true, "installSignalHandlers": true, "runProxyUntilShutdown": true,
	// stderr + exit on a refused boot
	"Fprintf": true, "Printf": true, "Exit": true,
}

// TestStartupSequence_MainRunsTheOneSequence: main() runs runStartupSequence
// and, besides it, only the process-level plumbing in startupMainCallees.
func TestStartupSequence_MainRunsTheOneSequence(t *testing.T) {
	callees := calleeNames(funcDeclForTest(t, parseMainPkgFileForTest(t, "main.go"), "main"))
	if !callees["runStartupSequence"] {
		t.Error("main() does not call runStartupSequence")
	}
	if bad := startupMainUnexpectedCallees(callees); len(bad) > 0 {
		t.Errorf("main() calls %v, which startupMainCallees does not allow: a start-up step belongs in runStartupSequence "+
			"(where the phase guards see it); genuine process-level plumbing must be added to the allowlist deliberately", bad)
	}
	// Negative controls: a step smuggled into main() under any name is caught.
	for _, extra := range []string{"initFoo", "initPolicy", "loadSomething", "activateClusterRoles"} {
		with := map[string]bool{extra: true}
		for c := range callees {
			with[c] = true
		}
		if len(startupMainUnexpectedCallees(with)) == 0 {
			t.Errorf("control: the allowlist accepted %s in main()", extra)
		}
	}
}

func startupMainUnexpectedCallees(callees map[string]bool) []string {
	var bad []string
	for c := range callees {
		if !startupMainCallees[c] {
			bad = append(bad, c)
		}
	}
	sort.Strings(bad)
	return bad
}

// startupStoreLoaders is the set a phase-4 step must not reach: every phase
// 1–2 step, and every plain `load*` function one of them calls directly (the
// loader each init shim delegates to), plus the admin-settings restore.
func startupStoreLoaders(funcs map[string]*ast.FuncDecl) map[string]bool {
	loaders := map[string]bool{"LoadAdminSettings": true, "tryLoadBlocklistFile": true}
	for step, ph := range startupStepPhases {
		if ph >= phaseActivation {
			continue
		}
		loaders[step] = true
		fn := funcs[step]
		if fn == nil {
			continue
		}
		for callee := range calleeNames(fn) {
			if strings.HasPrefix(callee, "load") && funcs[callee] != nil && funcs[callee].Recv == nil {
				loaders[callee] = true
			}
		}
	}
	return loaders
}

// TestStartupSequence_NothingAfterTheActivationLoadsAStore: the phase guard
// classifies the STEPS of the sequence; this closes the hole underneath it. A
// store loader nested inside the activation, a traffic gate, the admin UI
// start or the proxy build would run after the role started acting while the
// sequence still read as correctly ordered.
func TestStartupSequence_NothingAfterTheActivationLoadsAStore(t *testing.T) {
	funcs := startupProdFuncs(t)
	loaders := startupStoreLoaders(funcs)
	if !loaders["loadBlocklist"] || !loaders["loadPersistentAdminState"] || !loaders["initPolicy"] {
		t.Fatalf("the loader set is missing known loaders (%d entries); this guard is not reading the boot steps", len(loaders))
	}
	for step, ph := range startupStepPhases {
		if ph < phaseActivation {
			continue
		}
		if via := startupReaches(funcs, loaders, step); via != "" {
			t.Errorf("%s (phase %d) reaches the store loader %s: every store must be loaded BEFORE the cluster role activates", step, ph, via)
		}
	}
	// Not vacuous: a phase-2 step reaches one (itself).
	if startupReaches(funcs, loaders, "initBlocklist") == "" {
		t.Error("control: the call graph cannot see that initBlocklist loads a store")
	}
}

// startupProdFuncs is every function of the production root files by bare
// name: plain functions, and a method only where no plain function has that
// name (an over-approximation, the safe direction).
func startupProdFuncs(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		for _, d := range parseMainPkgFileForTest(t, p).Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, taken := funcs[fn.Name.Name]; fn.Recv == nil || !taken {
				funcs[fn.Name.Name] = fn
			}
		}
	}
	return funcs
}

// startupReaches reports the first member of entry reachable from root by
// bare-name calls, or "".
func startupReaches(funcs map[string]*ast.FuncDecl, entry map[string]bool, root string) string {
	seen := map[string]bool{}
	stack := []string{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[n] {
			continue
		}
		seen[n] = true
		if entry[n] {
			return n
		}
		if fn := funcs[n]; fn != nil {
			for callee := range startupCallees(fn) {
				stack = append(stack, callee)
			}
		}
	}
	return ""
}

// ── in-process: the real halves around the real store loaders ───────────────

// suEnv is one node's start-up under test.
type suEnv struct {
	clusterDB  string
	policyFile string
	blockFile  string
}

func suResetUnenrolledPullThrottle() {
	unenrolledConfigPull.mu.Lock()
	unenrolledConfigPull.attempts = map[string][]time.Time{}
	unenrolledConfigPull.mu.Unlock()
}

// suClientLoopsStarted counts data-plane client hand-offs (see suIsolate).
var suClientLoopsStarted atomic.Int32

// suIsolate isolates every global the two cluster halves and the store loaders
// used here touch, and seeds the node's durable state: a policy file with two
// rules, a blocklist file with one host.
func suIsolate(t *testing.T) *suEnv {
	t.Helper()
	gcMarshalCache.reset()
	gcDeltaRemainderCache.reset()
	// These tests drive the halves by hand: the lifecycle is unmanaged unless
	// a test sets a phase itself, and whatever it leaves is put back.
	prevPhase := nodeLifecyclePhase.Swap(int32(nodePhaseUnmanaged))
	t.Cleanup(func() { nodeLifecyclePhase.Store(prevPhase) })
	// The probes here are unenrolled loopback pollers; the per-IP pull
	// throttle must not carry one test's polls into the next.
	suResetUnenrolledPullThrottle()
	t.Cleanup(suResetUnenrolledPullThrottle)
	tempHADir(t)
	env := &suEnv{clusterDB: cpIsolateActivation(t)}
	cpChaosSetup(t)
	cpInsecure(t)
	bindFreshAdmissionOwners(t)

	feed := bl.FeedList()
	origBL, origPolicy, origHA, origClusterStore := bl, policyStore, globalHA, globalClusterStore
	origDefault, origBase, origTrust := defaultPolicyAction(), cfg.ProxyBaseURL(), trustForwardedHeaders
	origLG, _ := dpLastGoodConfigSnapshotState.Load().(dpLastGoodConfigSnapshotStatus)
	origClient, origDPMode := activeDPClient.Load(), audit.DPMode()
	origPollFailing, origPollSince := dpControlPlanePollFailing.Load(), dpCPPollFailingSince.Load()
	origBW, origNG := globalBandwidth, globalNodeGroups
	restoreEpoch := resetDPLastSeenEpochForTest()
	// The data-plane client's loops cannot be joined, and they read package
	// globals this fixture restores; record the hand-off instead of starting
	// them. The real loops run in the real-binary tests.
	// initPolicy (loadStores) wires the policy-draft coordinator to the policy
	// file's sibling; give it back.
	policyDraft.mu.Lock()
	origDraftPath, origDraftState, origDraftCand := policyDraft.path, policyDraft.state, policyDraft.cand
	policyDraft.mu.Unlock()
	t.Cleanup(func() {
		policyDraft.mu.Lock()
		policyDraft.path, policyDraft.state, policyDraft.cand = origDraftPath, origDraftState, origDraftCand
		policyDraft.mu.Unlock()
	})
	origLoops := dpStartClientLoops
	dpStartClientLoops = func(context.Context, *DataPlaneClient, string, string, string, string) { suClientLoopsStarted.Add(1) }
	suClientLoopsStarted.Store(0)
	globalHA = &HAState{}
	globalClusterStore = newTestClusterStore(t)
	t.Cleanup(func() {
		globalHA.Stop()
		if c := activeDPClient.Load(); c != nil && c != origClient {
			c.mu.Lock()
			if c.conn != nil {
				_ = c.conn.Close() //nolint:errcheck // test teardown
			}
			c.mu.Unlock()
		}
		dpStartClientLoops = origLoops
		bl, policyStore, globalHA, globalClusterStore = origBL, origPolicy, origHA, origClusterStore
		bl.ReplaceFeedEntries(feed)
		setDefaultPolicyAction(origDefault)
		SetProxyBaseURL(origBase)
		trustForwardedHeaders = origTrust
		dpLastGoodConfigSnapshotState.Store(origLG)
		activeDPClient.Store(origClient)
		audit.SetDPMode(origDPMode)
		dpControlPlanePollFailing.Store(origPollFailing)
		dpCPPollFailingSince.Store(origPollSince)
		globalBandwidth, globalNodeGroups = origBW, origNG
		restoreEpoch()
		gcMarshalCache.reset()
		gcDeltaRemainderCache.reset()
	})

	dir := t.TempDir()
	env.policyFile, env.blockFile = filepath.Join(dir, "policy_rules.json"), filepath.Join(dir, "blocklist.txt")
	env.seedPolicyFile(t, "on-disk-a", "on-disk-b")
	if err := os.WriteFile(env.blockFile, []byte("blocked-on-disk.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A new process: zero-value stores, the default action atomic's zero state.
	policyStore, bl = &PolicyStore{}, blocklist.New()
	setDefaultPolicyAction("deny")
	return env
}

func suRules(names ...string) []PolicyRule {
	out := make([]PolicyRule, 0, len(names))
	for i, n := range names {
		out = append(out, PolicyRule{Priority: i + 1, Name: n, DestFQDN: n + ".example.com", Action: ActionAllow})
	}
	return out
}

// loadStores is phase 2 for the stores these tests assert on, through the REAL
// boot steps where one can run in-process:
//
//	initPolicy(s)                    the step itself (policy file + draft wiring)
//	initRewriteAndDefaultAction(s)   the step itself (default-action derivation)
//	tryLoadBlocklistFile             initBlocklist's file half
//
// The rest of phase 2 cannot run inside the test binary, which is why the
// real-binary tests are the authority on the sequence: initBlocklist also
// starts the feed syncer goroutine; initRootCA mints/loads the inspection CA
// and starts the CA auto-rotation loop; initURLCategories opens the feed
// database and starts its syncers; initBackgroundServices and
// initPersistentAdminState start janitor/upload/hit-counter workers and apply
// the admin settings to dozens of package globals; initSOCKS5 binds a socket;
// the initMCP* steps compose listener runtimes — none of them joinable or
// restorable from a test. configuredDefault is the node's own config.yaml
// default_action ("" = unset, derived from the rule count).
func (e *suEnv) loadStores(t *testing.T, configuredDefault string) {
	t.Helper()
	tryLoadBlocklistFile(e.blockFile)
	noFlag := ""
	s := &startupState{policyFile: &noFlag, fc: &FileConfig{DefaultAction: configuredDefault}}
	s.fc.Proxy.PolicyFile = e.policyFile
	initPolicy(s)
	initRewriteAndDefaultAction(s)
}

// seedPolicyFile replaces the node's on-disk policy with rules named names.
func (e *suEnv) seedPolicyFile(t *testing.T, names ...string) {
	t.Helper()
	seed := &PolicyStore{}
	if err := seed.Load(e.policyFile); err != nil {
		t.Fatal(err)
	}
	seed.ReplaceAll(suRules(names...))
	if err := seed.SaveErr(); err != nil {
		t.Fatal(err)
	}
}

func suRuleNames(rules []PolicyRule) string {
	out := make([]string, 0, len(rules))
	for i := range rules {
		out = append(out, rules[i].Name)
	}
	return strings.Join(out, ",")
}

// suPoll is a data plane's first full poll of addr over a real gRPC connection.
func suPoll(t *testing.T, addr string) (ConfigSnapshot, error) {
	t.Helper()
	c, err := NewDataPlaneClient("su-probe", addr, "", "", "")
	if err != nil {
		t.Fatalf("probe client: %v", err)
	}
	t.Cleanup(func() {
		c.mu.Lock()
		if c.conn != nil {
			_ = c.conn.Close() //nolint:errcheck // test teardown
		}
		c.mu.Unlock()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := c.call(ctx, methodGetConfig, json.RawMessage(`{}`))
	if err != nil {
		return ConfigSnapshot{}, err
	}
	var snap ConfigSnapshot
	if uerr := json.Unmarshal(raw, &snap); uerr != nil {
		t.Fatalf("decode served snapshot: %v", uerr)
	}
	return snap, nil
}

func suWantLoadedConfig(t *testing.T, when string, snap ConfigSnapshot) {
	t.Helper()
	if got := suRuleNames(snap.PolicyRules); got != "on-disk-a,on-disk-b" {
		t.Errorf("%s: served rules = [%s], want the control plane's loaded [on-disk-a,on-disk-b]", when, got)
	}
	if len(snap.BlockedHosts) != 1 || snap.BlockedHosts[0] != "blocked-on-disk.example" {
		t.Errorf("%s: served blocklist = %v, want [blocked-on-disk.example]", when, snap.BlockedHosts)
	}
	if snap.DefaultAction != "allow" {
		t.Errorf("%s: served default action = %q, want the configured allow", when, snap.DefaultAction)
	}
}

// TestClusterHalves_ControlPlane_IdentityEarly_ServesOnlyLoadedConfig: the
// early half initialises the cluster CA (so the Root-CA slice's start-up
// rotation check has a CA to check) and nothing else — no role, no publish, no
// listener. After the stores load, the activation publishes, binds, and the
// first poller is served the loaded rules, blocklist and default action.
func TestClusterHalves_ControlPlane_IdentityEarly_ServesOnlyLoadedConfig(t *testing.T) {
	env := suIsolate(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)

	if globalClusterCA.CACertFingerprint() == "" {
		t.Error("the early half did not initialise the cluster CA: the start-up CA rotation check (initRootCA → StartCAAutoRotation) would find nothing to check until its 24 h tick")
	}
	if r := cpRoleNow(); r != "standalone" {
		t.Errorf("role after the early half = %q, want standalone (the role is claimed by the activation, on an observed bind)", r)
	}
	if v := globalConfigStore.Version(); v != 0 {
		t.Errorf("the early half published a snapshot (version %d) before any store loaded", v)
	}
	if cpGRPCListenerState().Configured {
		t.Error("the early half started the control-plane listener")
	}
	if _, err := suPoll(t, addr); !isCPStartingStatus(err) {
		t.Errorf("before the activation a poller must be answered %s by the early listener, got: %v", cpStartingStatusMarker, err)
	}

	env.loadStores(t, "allow")
	act.activate()
	cpWaitFor(t, 15*time.Second, "the control-plane listener", func() bool { return cpGRPCListenerState().Serving })

	snap, err := suPoll(t, addr)
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	suWantLoadedConfig(t, "first poll after activation", snap)
	if r := cpRoleNow(); r != "control-plane" {
		t.Errorf("role after the activation = %q, want control-plane", r)
	}
	act.activate() // at most once: a second call must not start a second listener
}

// TestClusterHalves_ControlPlane_ActivationBeforeStoresServesEmptyConfig is the
// negative control for the test above: the SAME halves in the OLD order serve
// a snapshot with no rules, no blocklist and the zero-state default action,
// and nothing republishes after the stores load. It documents the defect the
// order fixes; the structural guards are what keep the order.
func TestClusterHalves_ControlPlane_ActivationBeforeStoresServesEmptyConfig(t *testing.T) {
	env := suIsolate(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)
	act.activate() // the old position: before the store loaders
	cpWaitFor(t, 15*time.Second, "the control-plane listener", func() bool { return cpGRPCListenerState().Serving })
	env.loadStores(t, "allow")

	snap, err := suPoll(t, addr)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(snap.PolicyRules) != 0 || len(snap.BlockedHosts) != 0 || snap.DefaultAction != "deny" {
		t.Fatalf("control: the old order now serves rules=%d hosts=%d default=%s — it no longer reproduces the defect",
			len(snap.PolicyRules), len(snap.BlockedHosts), snap.DefaultAction)
	}
}

// TestClusterHalves_ControlPlane_DelayedBindServesLoadedConfigAndAddressList:
// CHAOS-71's resilient boot path with a persisted HA leader (legacy mode). The
// port is taken when the activation runs: the node stays standalone and
// retries. When the bind lands, leadership resumes, the address list is
// published, and what a poller is served is still the loaded configuration.
func TestClusterHalves_ControlPlane_DelayedBindServesLoadedConfigAndAddressList(t *testing.T) {
	env := suIsolate(t)
	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)
	if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok", Term: 2}); err != nil {
		t.Fatalf("seed HA config: %v", err)
	}
	env.loadStores(t, "allow")
	act.activate()
	if cpGRPCListenerState().Serving || cpRoleNow() != "standalone" {
		t.Fatalf("control: the bind was supposed to fail (serving=%v role=%s)", cpGRPCListenerState().Serving, cpRoleNow())
	}

	release()
	cpWaitFor(t, 20*time.Second, "the delayed bind", func() bool { return cpGRPCListenerState().Serving })
	cpWaitFor(t, 10*time.Second, "the leadership resume", func() bool { return globalHA.Status().Role == "leader" })
	cpWaitFor(t, 10*time.Second, "the address list", func() bool { return len(globalConfigStore.Get().CPAddresses) > 0 })

	snap, err := suPoll(t, addr)
	if err != nil {
		t.Fatalf("poll after the delayed bind: %v", err)
	}
	suWantLoadedConfig(t, "after the delayed bind", snap)
	if got := strings.Join(snap.CPAddresses, ","); !strings.Contains(got, addr) || !strings.Contains(got, "10.0.0.9:50051") {
		t.Errorf("served CP address list = [%s], want this node (%s) and its peer", got, addr)
	}
}

// TestClusterHalves_ControlPlane_LeaseLeaderResumeCommitsItsEpoch: lease mode
// (ADR-0005). The boot-path resume must find a committed snapshot to carry the
// new fencing epoch — the reason the first publish cannot be held back past
// the bind. With the activation after the stores, the order inside it is
// unchanged (publish → bind → resume), so the resume commits its epoch onto a
// snapshot that is, now, the loaded configuration.
func TestClusterHalves_ControlPlane_LeaseLeaderResumeCommitsItsEpoch(t *testing.T) {
	env := suIsolate(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)
	globalHA.SetLeaseProvider(halease.NewFake(time.Minute), "cp-a") // armHALease's effect, with the in-memory backend
	if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok", Term: 2}); err != nil {
		t.Fatalf("seed HA config: %v", err)
	}
	env.loadStores(t, "allow")
	act.activate()
	cpWaitFor(t, 15*time.Second, "the control-plane listener", func() bool { return cpGRPCListenerState().Serving })
	cpWaitFor(t, 15*time.Second, "the lease-mode leadership resume", func() bool { return globalHA.Status().Role == "leader" })

	epoch := globalHA.CurrentEpoch()
	if epoch == 0 {
		t.Fatal("the resumed leader holds no fencing epoch: the resume was refused (no committed snapshot to carry it?)")
	}
	snap, err := suPoll(t, addr)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if snap.Epoch != epoch {
		t.Errorf("served snapshot carries epoch %d, the leader holds %d: the epoch was advertised without being committed", snap.Epoch, epoch)
	}
	suWantLoadedConfig(t, "lease-mode leader", snap)
}

// TestClusterHalves_DataPlane_ReplayAfterStores_KeepsControlPlaneState: a data
// plane restart. The early half claims the role and touches no store. After
// the policy file and the boot default-action derivation, the late half
// replays the last-good snapshot: its rules win over a STALE policy file and
// are written back to it, and the default action is the control plane's — in
// both directions the derivation used to get wrong (rules ⇒ deny over the
// control plane's allow; no rules ⇒ allow over its deny).
func TestClusterHalves_DataPlane_ReplayAfterStores_KeepsControlPlaneState(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fileRules []string // the node's own (stale) policy file
		derived   string   // what boot derives from that file with no configured default
		cpDefault string   // the last-good snapshot's default action
		cpRules   []string // the last-good snapshot's rules (nil: the snapshot carries none)
		wantRules []string
	}{
		// Derivation says deny (the file has rules); the control plane says allow.
		{"cp_allow_over_derived_deny", []string{"on-disk-a", "on-disk-b"}, "deny", "allow", []string{"from-control-plane"}, []string{"from-control-plane"}},
		// Derivation says allow (the file has NO rules); the control plane says
		// deny — the fail-open direction. The snapshot carries no rules either
		// (policy_rules is omitted when empty), so only the default action moves.
		{"cp_deny_over_derived_allow", nil, "allow", "deny", nil, nil},
		// Both agree: the control: rules still replaced.
		{"cp_deny_matches_derived_deny", []string{"on-disk-a", "on-disk-b"}, "deny", "deny", []string{"from-control-plane"}, []string{"from-control-plane"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := suIsolate(t)
			env.seedPolicyFile(t, tc.fileRules...)
			persistDPLastGoodConfigSnapshot(ConfigSnapshot{Version: 7, DefaultAction: tc.cpDefault, PolicyRules: suRules(tc.cpRules...)})
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, DPAddr: "127.0.0.1:1", DPNodeID: "dp-under-test"}, ctx, nil)
			suWantDataPlaneEarlyHalfOnly(t)

			env.loadStores(t, "")
			if got := defaultPolicyAction(); got != tc.derived {
				t.Fatalf("control: boot derived default action %q from the policy file, this case needs %q", got, tc.derived)
			}
			act.activate()

			if got := suRuleNames(policyStore.List()); got != strings.Join(tc.wantRules, ",") {
				t.Errorf("active rules after restart = [%s], want %v", got, tc.wantRules)
			}
			onDisk, err := os.ReadFile(env.policyFile)
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.cpRules) > 0 && (!strings.Contains(string(onDisk), "from-control-plane") || strings.Contains(string(onDisk), "on-disk-a")) {
				t.Errorf("the replayed rules were not persisted over the stale policy file:\n%s", onDisk)
			}
			if got := defaultPolicyAction(); got != tc.cpDefault {
				t.Errorf("default action after restart = %q, want the control plane's %q (boot had derived %q)", got, tc.cpDefault, tc.derived)
			}
			c := activeDPClient.Load()
			if c == nil || c.lastVersion.Load() != 7 || suClientLoopsStarted.Load() != 1 {
				t.Fatalf("the data-plane client was not started, once, on the replayed version (client=%v loops=%d)", c != nil, suClientLoopsStarted.Load())
			}
		})
	}
}

// suWantDataPlaneEarlyHalfOnly: after the early half a data plane has its role
// and nothing else — no client, no replayed rules.
func suWantDataPlaneEarlyHalfOnly(t *testing.T) {
	t.Helper()
	if r := cpRoleNow(); r != "data-plane" {
		t.Errorf("role after the early half = %q, want data-plane (later init steps classify the node by it)", r)
	}
	if activeDPClient.Load() != nil {
		t.Error("the early half started the data-plane client")
	}
	if n := policyStore.ConfiguredRuleCount(); n != 0 {
		t.Errorf("the early half replayed the last-good snapshot (%d rules) into a store that has not loaded", n)
	}
}

// TestClusterHalves_DataPlane_ReplayBeforeStoresLosesControlPlaneState is the
// negative control: the same halves in the OLD order (replay first). The
// stale policy file wins and the default action is re-derived.
func TestClusterHalves_DataPlane_ReplayBeforeStoresLosesControlPlaneState(t *testing.T) {
	env := suIsolate(t)
	persistDPLastGoodConfigSnapshot(ConfigSnapshot{Version: 7, DefaultAction: "allow", PolicyRules: suRules("from-control-plane")})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, DPAddr: "127.0.0.1:1", DPNodeID: "dp-under-test"}, ctx, nil)
	act.activate() // the old position
	env.loadStores(t, "")
	if rules, def := suRuleNames(policyStore.List()), defaultPolicyAction(); rules != "on-disk-a,on-disk-b" || def != "deny" {
		t.Fatalf("control: the old order now yields rules=[%s] default=%s — it no longer reproduces the defect", rules, def)
	}
}

// TestClusterHalves_DataPlane_FirstEnrolmentNoLastGood: nothing to replay. The
// node keeps its file-loaded policy and derived default action and starts
// polling from version 0.
func TestClusterHalves_DataPlane_FirstEnrolmentNoLastGood(t *testing.T) {
	env := suIsolate(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, DPAddr: "127.0.0.1:1", DPNodeID: "dp-new"}, ctx, nil)
	env.loadStores(t, "")
	act.activate()
	if got := suRuleNames(policyStore.List()); got != "on-disk-a,on-disk-b" || defaultPolicyAction() != "deny" {
		t.Errorf("first enrolment: rules=[%s] default=%s, want the node's own file state", got, defaultPolicyAction())
	}
	if c := activeDPClient.Load(); c == nil || c.lastVersion.Load() != 0 || suClientLoopsStarted.Load() != 1 {
		t.Error("first enrolment: the client must start polling, once, from version 0")
	}
}

// TestClusterHalves_BothWired_ControlPlaneStillWinsTheRole: a node wired as a
// control plane AND a data plane. The data-plane claim is not made early, so
// the control plane activates first and the data plane is refused — the
// outcome before the split.
func TestClusterHalves_BothWired_ControlPlaneStillWinsTheRole(t *testing.T) {
	env := suIsolate(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr, DPAddr: "127.0.0.1:1", DPNodeID: "dp"}, ctx, nil)
	if r := cpRoleNow(); r != "standalone" {
		t.Errorf("role after the early half of a dual-wired node = %q, want standalone", r)
	}
	env.loadStores(t, "allow")
	act.activate()
	if r := cpRoleNow(); r != "control-plane" {
		t.Errorf("role = %q, want control-plane (the data-plane claim must be refused)", r)
	}
	if activeDPClient.Load() != nil {
		t.Error("the data-plane client started on a node that is a control plane")
	}
	if c := checkClusterPosture(); c.Status != diagFail {
		t.Errorf("the refused data-plane claim is not operator-visible: cluster_posture = %s %q", c.Status, c.Message)
	}
}

// TestClusterHalves_Standalone_NothingToActivate: no cluster wiring.
func TestClusterHalves_Standalone_NothingToActivate(t *testing.T) {
	env := suIsolate(t)
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB}, t.Context(), nil)
	env.loadStores(t, "")
	act.activate()
	if cpRoleNow() != "standalone" || globalConfigStore.Version() != 0 || activeDPClient.Load() != nil || cpGRPCListenerState().Configured {
		t.Errorf("a standalone node activated something: role=%s version=%d", cpRoleNow(), globalConfigStore.Version())
	}
	var nilAct *clusterActivation
	nilAct.activate() // must not panic
}

// TestClusterHalves_DataPlane_IdentityIsValidatedInTheEarlyHalf: a data plane
// whose mTLS certificate, key or CA cannot be loaded must stop in phase 1 —
// before any store loads, any listener binds, or the last-good replay rewrites
// local files. prepareDataPlane validates the material itself (a failure there
// is fatal; TestBinaryStartup_DataPlane_BadIdentityStopsBeforeTheStores shows
// the process exit), and the client built in the late half can then only fail
// for a reason that is not the node's identity.
func TestClusterHalves_DataPlane_IdentityIsValidatedInTheEarlyHalf(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateDPClientIdentity("", "", ""); err != nil {
		t.Errorf("no certificate configured (insecure development mode) must not be an identity failure: %v", err)
	}
	for name, files := range map[string][3]string{
		"unreadable certificate": {filepath.Join(dir, "missing.crt"), junk, ""},
		"garbage key pair":       {junk, junk, ""},
	} {
		if err := validateDPClientIdentity(files[0], files[1], files[2]); err == nil {
			t.Errorf("%s: validateDPClientIdentity accepted it", name)
		}
	}

	// Structure: the validation is in the early half, ahead of everything the
	// late half does, and the late half is not where it first happens.
	file := parseMainPkgFileForTest(t, "dp_enrollment.go")
	early, late := funcDeclForTest(t, file, "prepareDataPlane"), funcDeclForTest(t, file, "runDataPlane")
	if !startupCallees(early)["validateDPClientIdentity"] {
		t.Fatal("prepareDataPlane does not validate the data plane's mTLS identity: a node with an unloadable " +
			"certificate would load every store, bind SOCKS5 and replay its last-good snapshot before exiting")
	}
	if !calleeNames(late)["NewDataPlaneClient"] || !calleeNames(late)["applyDPLastGoodConfigSnapshot"] {
		t.Fatal("runDataPlane no longer replays and builds the client; this guard's premise is stale")
	}
	if startupCallees(early)["applyDPLastGoodConfigSnapshot"] || startupCallees(early)["NewDataPlaneClient"] {
		t.Error("prepareDataPlane replays or builds the client: that is the late half")
	}
}

// TestStartupSequence_PRGateRunsTheRealBinary: nothing in the default test
// build can run runStartupSequence, so the PR gate must start the real binary.
// The Fast PR Gate has a job that builds once and runs TestBinaryStartup_*,
// and the gate's aggregate needs it (a failure there fails the gate).
func TestStartupSequence_PRGateRunsTheRealBinary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), ".github", "workflows", "pr-fast-gate.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	job := strings.Index(wf, "\n  startup-sequence:\n")
	if job < 0 {
		t.Fatal("pr-fast-gate.yml has no startup-sequence job: the real start-up sequence is not executed by the PR gate")
	}
	body := wf[job:]
	if end := strings.Index(body[1:], "\n  # ───"); end > 0 {
		body = body[:end+1]
	}
	for _, want := range []string{"go build -o", "-tags proxybinload", "-run 'TestBinaryStartup_'", "CULVERT_BIN:"} {
		if !strings.Contains(body, want) {
			t.Errorf("the startup-sequence job does not contain %q", want)
		}
	}
	aggAt := strings.Index(wf, "\n  fast-gate-approved:\n")
	if aggAt < 0 {
		t.Fatal("pr-fast-gate.yml has no fast-gate-approved aggregate job")
	}
	if !strings.Contains(wf[aggAt:], "\n      - startup-sequence\n") {
		t.Error("the Fast PR Gate aggregate does not need startup-sequence: a failing start-up test would not fail the gate")
	}
}

// ── hit history survives the replay ─────────────────────────────────────────

// suSeedHitHistory writes hit_counters.json for the named rules and runs the
// phase-2 restore exactly as loadPersistentAdminState does (loadHitCounters →
// RestoreHitCounts). Returns the file path.
func suSeedHitHistory(t *testing.T, hits map[string]int64) string {
	t.Helper()
	withCleanRuleMet(t)
	recs := map[string]persistedRuleCounter{}
	for name, n := range hits {
		recs[name] = persistedRuleCounter{Hits: n, LastHit: 1_700_000_000}
	}
	raw, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hit_counters.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loadHitCounters(path)
	RestoreHitCounts()
	return path
}

func suHitCounts() map[string]int64 {
	out := map[string]int64{}
	rules := policyStore.List()
	for i := range rules {
		out[rules[i].Name] = rules[i].HitCount
	}
	return out
}

func suPersistedHitCounts(t *testing.T, path string) map[string]int64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs map[string]persistedRuleCounter
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatalf("hit counter file: %v", err)
	}
	out := map[string]int64{}
	for name, r := range recs {
		out[name] = r.Hits
	}
	return out
}

// TestClusterHalves_DataPlane_HitHistorySurvivesTheReplay: a data plane with
// persisted hit history restarts. The last-good replay replaces every rule —
// here with the SAME rules — and a replaced rule starts at zero. The step that
// follows the activation puts the history back, so the next save persists the
// counts, not zeros. Without that step (the negative control inside) both the
// live counts and the saved file are zero: the history is lost for good.
func TestClusterHalves_DataPlane_HitHistorySurvivesTheReplay(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reRestore bool
		want      int64
	}{
		{"with_the_post_activation_restore", true, 41},
		{"negative_control_without_it", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := suIsolate(t)
			env.seedPolicyFile(t, "kept-rule", "other-rule")
			persistDPLastGoodConfigSnapshot(ConfigSnapshot{Version: 7, DefaultAction: "deny", PolicyRules: suRules("kept-rule", "other-rule")})
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, DPAddr: "127.0.0.1:1", DPNodeID: "dp-hits"}, ctx, nil)

			env.loadStores(t, "")
			hitFile := suSeedHitHistory(t, map[string]int64{"kept-rule": 41, "other-rule": 7})
			if got := suHitCounts()["kept-rule"]; got != 41 {
				t.Fatalf("control: phase 2 restored %d hits, want 41", got)
			}

			act.activate() // the replay: PolicyStore.ReplaceAll
			if got := suHitCounts()["kept-rule"]; got != 0 {
				t.Fatalf("control: the replay left %d hits on a replaced rule; this test's premise (ReplaceAll zeroes counters) no longer holds", got)
			}
			if tc.reRestore {
				restoreHitCountsAfterActivation()
			}

			if got := suHitCounts()["kept-rule"]; got != tc.want {
				t.Errorf("live hit count after start-up = %d, want %d", got, tc.want)
			}
			saveHitCounters(hitFile) // the periodic / shutdown saver
			if got := suPersistedHitCounts(t, hitFile)["kept-rule"]; got != tc.want {
				t.Errorf("persisted hit count after the next save = %d, want %d", got, tc.want)
			}
			if tc.reRestore {
				if got := suHitCounts()["other-rule"]; got != 7 {
					t.Errorf("other-rule = %d hits, want 7", got)
				}
			}
		})
	}
}

// TestClusterHalves_ControlPlane_HitHistoryIsNotDoubled: on a node whose
// activation replaces no rule — a control plane — the second restore adds
// nothing, however often it runs.
func TestClusterHalves_ControlPlane_HitHistoryIsNotDoubled(t *testing.T) {
	env := suIsolate(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)
	env.loadStores(t, "allow")
	hitFile := suSeedHitHistory(t, map[string]int64{"on-disk-a": 41, "on-disk-b": 7})
	act.activate()
	cpWaitFor(t, 15*time.Second, "the control-plane listener", func() bool { return cpGRPCListenerState().Serving })
	restoreHitCountsAfterActivation()
	restoreHitCountsAfterActivation()
	if got := suHitCounts(); got["on-disk-a"] != 41 || got["on-disk-b"] != 7 {
		t.Errorf("hit counts after a control-plane start-up = %v, want on-disk-a=41 on-disk-b=7 (not doubled)", got)
	}
	saveHitCounters(hitFile)
	if got := suPersistedHitCounts(t, hitFile); got["on-disk-a"] != 41 || got["on-disk-b"] != 7 {
		t.Errorf("persisted hit counts = %v, want 41 / 7", got)
	}
}
