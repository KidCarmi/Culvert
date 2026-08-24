package main

// QUAL-4 — node-local Gateway policy composition tests (unit / composition surface).
// The authenticated end-to-end decision proof (evaluate → durably commit → read back →
// non-execution) lives in mcp_policy_e2e_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

// gwPolicyDoc builds a valid Gateway policy source document at the given revision
// with the given rules[] body (a raw JSON fragment; "" ⇒ no rules ⇒ pure default-deny).
func gwPolicyDoc(rev int, rules string) string {
	return `{"schema_version":1,"capability":"gateway","policy_revision":` + itoaPolTest(rev) +
		`,"default_action":"DENY","rules":[` + rules + `]}`
}

// allowDiscoveryRule permits tools/list (discovery) — an ALLOW-class decision that
// does NOT reference a specific tool, so it reaches user-rule evaluation regardless of
// catalog quarantine state.
const allowDiscoveryRule = `{"id":"ALLOW_DISCOVERY","priority":10,"action":"ALLOW",` +
	`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
	`"conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}],` +
	`"obligations":{"logging":"standard"}}`

// broadAllowRule permits everything (priority 1). Used to prove a hard override
// (quarantined tool) beats even a broad user ALLOW.
const broadAllowRule = `{"id":"BROAD_ALLOW","priority":1,"action":"ALLOW",` +
	`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],` +
	`"obligations":{"logging":"standard"}}`

func itoaPolTest(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// writeMCPPolicyFile writes content to a temp file and returns its path.
func writeMCPPolicyFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return p
}

// scWithPolicy returns a minimal enabled config carrying only a policy file (enough to
// exercise compose without the full listener config).
func scWithPolicy(path string) mcpObserveStartupConfig {
	return mcpObserveStartupConfig{Enabled: true, QualificationPolicyFile: path}
}

// ── resolver plumbs the field (purely) ───────────────────────────────────────

func TestMCPPolicy_ResolverPlumbsField(t *testing.T) {
	fc := &FileConfig{}
	fc.MCP.Gateway.QualificationPolicyFile = "/etc/culvert/policy.json"
	sc := resolveMCPObserveStartupConfig(fc)
	if sc.QualificationPolicyFile != "/etc/culvert/policy.json" {
		t.Fatalf("resolver did not plumb policy file: %q", sc.QualificationPolicyFile)
	}
	// A zero config yields no policy file (default-disabled).
	if resolveMCPObserveStartupConfig(&FileConfig{}).QualificationPolicyFile != "" {
		t.Fatal("default config must carry no policy file")
	}
}

// ── absent ⇒ not_configured (QUAL-3 preserved) ───────────────────────────────

func TestMCPPolicy_ComposeAbsentIsNotConfigured(t *testing.T) {
	h := newMCPPolicyHolder()
	for _, sc := range []mcpObserveStartupConfig{
		{Enabled: false, QualificationPolicyFile: writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule))},
		{Enabled: true, QualificationPolicyFile: ""},
	} {
		snap, prov, state, reason, err := h.compose(sc)
		if err != nil || state != mcpPolNotConfigured || snap != nil || prov != nil || reason != "" {
			t.Fatalf("absent policy: got snap=%v prov=%v state=%q reason=%q err=%v", snap, prov, state, reason, err)
		}
	}
	// A nil provider means Deps.Policy stays nil ⇒ decision telemetry pending-policy.
	if h.composed() {
		t.Fatal("holder must not report composed with no policy")
	}
}

// ── valid ⇒ loaded + published + single source of truth ──────────────────────

func TestMCPPolicy_ComposeValidLoadsAndPublishes(t *testing.T) {
	h := newMCPPolicyHolder()
	path := writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule))
	snap, prov, state, reason, err := h.compose(scWithPolicy(path))
	if err != nil || state != mcpPolLoaded || snap == nil || prov == nil || reason != "" {
		t.Fatalf("valid compose: state=%q reason=%q err=%v snap=%v prov=%v", state, reason, err, snap, prov)
	}
	if snap.Capability() != policy.CapGateway {
		t.Fatalf("snapshot capability = %v, want gateway", snap.Capability())
	}
	// Before publish the store is empty (compose does not publish).
	if h.gw.Current() != nil {
		t.Fatal("compose must not publish; the store must stay empty until publish()")
	}
	if err := h.publish(state, reason, snap); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Single source of truth: the runtime provider, the admin store adapter, and the
	// holder all return the IDENTICAL published snapshot from the SAME store.
	if h.gw.Current() != snap {
		t.Fatal("published snapshot not visible via the store")
	}
	if prov.PolicySnapshot(protocol.Gateway) != snap {
		t.Fatal("provider must return the published snapshot for Gateway")
	}
	gwStore, ok := h.stores().Store("gateway")
	if !ok || gwStore != h.gw || gwStore.Current() != snap {
		t.Fatal("admin store adapter must read the SAME gateway store the provider reads")
	}
	// Status reflects the snapshot truthfully.
	st := h.status()
	if st.State != string(mcpPolLoaded) || st.Revision != uint64(snap.Revision()) ||
		st.Hash != snap.Hash() || st.RuleCount != snap.RuleCount() ||
		st.DefaultAction != "DENY" || st.Source != "qualification_startup" ||
		!st.EvaluationEnabled || st.EnforcementEnabled || st.ExecutionEnabled || st.FleetDistributed {
		t.Fatalf("status not truthful: %+v", st)
	}
}

// ── Management isolation ──────────────────────────────────────────────────────

func TestMCPPolicy_ManagementIsolation(t *testing.T) {
	h := newMCPPolicyHolder()
	path := writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule))
	snap, prov, state, reason, err := h.compose(scWithPolicy(path))
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if err := h.publish(state, reason, snap); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// A Gateway snapshot can never be served as a Management policy.
	if prov.PolicySnapshot(protocol.Management) != nil {
		t.Fatal("provider must return nil for the Management capability")
	}
	// The Management store is never published to.
	if h.mgt.Current() != nil {
		t.Fatal("management store must never carry a snapshot")
	}
	mgtStore, ok := h.stores().Store("management")
	if !ok || mgtStore.Current() != nil {
		t.Fatal("admin management store must stay empty")
	}
}

// ── invalid ⇒ fail closed, no partial snapshot ───────────────────────────────

func TestMCPPolicy_ComposeInvalidFailsClosed(t *testing.T) {
	oversize := "{" + strings.Repeat(" ", maxPolicyFileBytes) + "}"
	cases := []struct {
		name    string
		content string
		path    string // overrides content when set
		reason  string
	}{
		{"unreadable", "", filepath.Join(t.TempDir(), "does-not-exist.json"), "qualification_policy_unreadable"},
		{"empty", "", "", "qualification_policy_empty"},
		{"oversize", oversize, "", "qualification_policy_oversize"},
		{"uncompilable_json", "{ not json", "", "qualification_policy_uncompilable"},
		{"malformed_rule", gwPolicyDoc(1, `{"id":"R","priority":1,"action":"YOLO","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]}`), "", "qualification_policy_uncompilable"},
		{"wrong_capability", `{"schema_version":1,"capability":"management","policy_revision":1,"default_action":"DENY","rules":[]}`, "", "qualification_policy_wrong_capability"},
		{"dup_rule_ids", gwPolicyDoc(1, `{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]},{"id":"R","priority":2,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]}`), "", "qualification_policy_uncompilable"},
		{"dup_priority", gwPolicyDoc(1, `{"id":"A","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]},{"id":"B","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]}`), "", "qualification_policy_uncompilable"},
		// one bad rule rejects the WHOLE snapshot (no partial compile).
		{"one_bad_rule_rejects_whole", gwPolicyDoc(1, allowDiscoveryRule+`,{"id":"BAD","priority":11,"action":"DENY","reason":"nope","remediation":"none","conditions":[]}`), "", "qualification_policy_uncompilable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newMCPPolicyHolder()
			path := tc.path
			if path == "" {
				path = writeMCPPolicyFile(t, tc.content)
			}
			snap, prov, state, reason, err := h.compose(scWithPolicy(path))
			if err == nil || state != mcpPolInvalid || snap != nil || prov != nil {
				t.Fatalf("expected fail-closed invalid, got snap=%v prov=%v state=%q err=%v", snap, prov, state, err)
			}
			if reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
			// The error message is bounded + secret-free (never the path or content).
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "YOLO") {
				t.Fatalf("error leaked path/content: %v", err)
			}
			// No partial snapshot is ever active.
			if h.gw.Current() != nil || h.composed() {
				t.Fatal("an invalid policy must leave no active snapshot")
			}
		})
	}
}

func TestMCPPolicy_ComposeTraversalRejected(t *testing.T) {
	h := newMCPPolicyHolder()
	_, _, state, reason, err := h.compose(scWithPolicy("../../etc/passwd"))
	if err == nil || state != mcpPolInvalid || reason != "qualification_policy_traversal" {
		t.Fatalf("traversal must fail closed: state=%q reason=%q err=%v", state, reason, err)
	}
}

// ── deterministic hash (same bytes ⇒ same snapshot hash) ─────────────────────

func TestMCPPolicy_DeterministicHash(t *testing.T) {
	doc := gwPolicyDoc(1, allowDiscoveryRule)
	h1 := newMCPPolicyHolder()
	h2 := newMCPPolicyHolder()
	s1, _, _, _, err1 := h1.compose(scWithPolicy(writeMCPPolicyFile(t, doc)))
	s2, _, _, _, err2 := h2.compose(scWithPolicy(writeMCPPolicyFile(t, doc)))
	if err1 != nil || err2 != nil || s1 == nil || s2 == nil {
		t.Fatalf("compose errors: %v %v", err1, err2)
	}
	if s1.Hash() != s2.Hash() {
		t.Fatalf("hash not deterministic: %q vs %q", s1.Hash(), s2.Hash())
	}
	if s1.Hash() == "" {
		t.Fatal("hash must be non-empty")
	}
}

// ── publish failure (stale/duplicate revision) folds to invalid ──────────────

func TestMCPPolicy_PublishStaleRevisionFailsClosed(t *testing.T) {
	h := newMCPPolicyHolder()
	// Publish revision 2 first.
	s2, _, st2, r2, err := h.compose(scWithPolicy(writeMCPPolicyFile(t, gwPolicyDoc(2, allowDiscoveryRule))))
	if err != nil {
		t.Fatalf("compose rev2: %v", err)
	}
	if err := h.publish(st2, r2, s2); err != nil {
		t.Fatalf("publish rev2: %v", err)
	}
	// Now a revision-1 snapshot is stale for the store ⇒ publish must fold to invalid.
	s1, _, st1, r1, err := h.compose(scWithPolicy(writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule))))
	if err != nil {
		t.Fatalf("compose rev1: %v", err)
	}
	if err := h.publish(st1, r1, s1); err == nil {
		t.Fatal("publishing a stale revision must fail closed")
	}
	if h.status().State != string(mcpPolInvalid) {
		t.Fatalf("stale publish must fold to invalid, got %q", h.status().State)
	}
	// The previously published snapshot is retained (no downgrade).
	if h.gw.Current() != s2 {
		t.Fatal("a failed publish must not replace the active snapshot")
	}
}

// ── health / label truthfulness ──────────────────────────────────────────────

func TestMCPPolicy_StatusStates(t *testing.T) {
	// not_configured
	h := newMCPPolicyHolder()
	if st := h.status(); st.State != "not_configured" || st.EvaluationEnabled || st.Source != "" {
		t.Fatalf("not_configured status = %+v", st)
	}
	// invalid (bounded reason, never healthy/empty)
	_ = h.publish(mcpPolInvalid, "qualification_policy_uncompilable", nil)
	if st := h.status(); st.State != "invalid" || st.Reason != "qualification_policy_uncompilable" || st.EvaluationEnabled {
		t.Fatalf("invalid status = %+v", st)
	}
	// loaded
	s, _, ls, lr, err := h.compose(scWithPolicy(writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule))))
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if err := h.publish(ls, lr, s); err != nil {
		t.Fatalf("publish: %v", err)
	}
	st := h.status()
	if st.State != "loaded" || !st.EvaluationEnabled || st.EnforcementEnabled || st.ExecutionEnabled || st.FleetDistributed {
		t.Fatalf("loaded status posture wrong: %+v", st)
	}
}

func TestMCPPolicy_DecisionTelemetryLabelFor(t *testing.T) {
	cases := []struct {
		policyComposed, telemReady bool
		want                       string
	}{
		{false, false, "pending_policy"},
		{false, true, "pending_policy"},
		{true, false, "pending_telemetry"},
		{true, true, "ready"},
	}
	for _, c := range cases {
		if got := decisionTelemetryLabelFor(c.policyComposed, c.telemReady); got != c.want {
			t.Fatalf("label(%v,%v) = %q, want %q", c.policyComposed, c.telemReady, got, c.want)
		}
	}
}

// ── loadMCPObserveRuntime wiring: composes provider / fails closed / disabled ─

func TestMCPPolicy_LoadRuntimeComposesProvider(t *testing.T) {
	mcpPolicy.resetForTest()
	t.Cleanup(func() { mcpPolicy.resetForTest() })
	pki := newMCPTestPKI(t)
	sc := pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls")
	sc.QualificationPolicyFile = writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule))

	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveConfigured {
		t.Fatalf("state=%q reason=%q, want configured", act.State, act.Reason)
	}
	if cfg.Deps.Policy == nil {
		t.Fatal("Deps.Policy must be composed when a policy file is present")
	}
	// Still Observe-only: no executor/upstream/broker/inspection.
	if cfg.Deps.Executor != nil || cfg.Deps.Inspection != nil {
		t.Fatal("no executor/inspection may be composed (Observe-only)")
	}
	// The provider serves the composed snapshot for Gateway and nil for Management.
	if cfg.Deps.Policy.PolicySnapshot(protocol.Gateway) == nil {
		t.Fatal("provider must serve the composed Gateway snapshot")
	}
	if cfg.Deps.Policy.PolicySnapshot(protocol.Management) != nil {
		t.Fatal("provider must isolate Management")
	}
	if !mcpPolicyComposed() {
		t.Fatal("global holder must report composed")
	}
	// Single source of truth: the admin store the singleton reads == the runtime's
	// snapshot.
	gwStore, _ := mcpPolicy.stores().Store("gateway")
	if gwStore.Current() != cfg.Deps.Policy.PolicySnapshot(protocol.Gateway) {
		t.Fatal("admin store and runtime provider must share one snapshot")
	}
}

func TestMCPPolicy_LoadRuntimeInvalidFailsClosed(t *testing.T) {
	mcpPolicy.resetForTest()
	t.Cleanup(func() { mcpPolicy.resetForTest() })
	pki := newMCPTestPKI(t)
	sc := pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls")
	sc.QualificationPolicyFile = writeMCPPolicyFile(t, "{ not a policy")

	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveInvalid || act.Reason != "qualification_policy_invalid" {
		t.Fatalf("state=%q reason=%q, want invalid/qualification_policy_invalid", act.State, act.Reason)
	}
	if cfg.Enabled() {
		t.Fatal("an invalid policy must produce a nothing-binds config")
	}
	if mcpPolicyComposed() {
		t.Fatal("an invalid policy must not report composed")
	}
	if st := mcpPolicy.status(); st.State != "invalid" {
		t.Fatalf("holder state = %q, want invalid", st.State)
	}
}

func TestMCPPolicy_LoadRuntimeAbsentIsPendingPolicy(t *testing.T) {
	mcpPolicy.resetForTest()
	t.Cleanup(func() { mcpPolicy.resetForTest() })
	pki := newMCPTestPKI(t)
	sc := pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls") // no policy file
	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveConfigured {
		t.Fatalf("state=%q reason=%q", act.State, act.Reason)
	}
	if cfg.Deps.Policy != nil {
		t.Fatal("no policy file ⇒ Deps.Policy must stay nil (QUAL-3 behavior)")
	}
	if mcpPolicyComposed() {
		t.Fatal("no policy file ⇒ not composed")
	}
	if got := decisionTelemetryLabel(false); got != "pending_policy" {
		t.Fatalf("decision telemetry = %q, want pending_policy", got)
	}
}

// ── startup-failure invalidation (Codex P2) ──────────────────────────────────

// A published snapshot must be cleared when the listener fails to construct/start, so
// the admin surface never advertises an active policy (holder status AND the
// store-backed /api/mcp/policy read) for a listener that is not running.
func TestMCPPolicy_InvalidateOnStartupFailure(t *testing.T) {
	h := newMCPPolicyHolder()
	s, _, ls, lr, err := h.compose(scWithPolicy(writeMCPPolicyFile(t, gwPolicyDoc(1, allowDiscoveryRule))))
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if err := h.publish(ls, lr, s); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !h.composed() || h.gw.Current() == nil {
		t.Fatal("precondition: snapshot must be active")
	}
	h.invalidateForStartupFailure()
	// Holder status (/api/mcp/overview) reports invalid, not loaded.
	if h.composed() || h.status().State != string(mcpPolInvalid) || h.status().EvaluationEnabled {
		t.Fatalf("holder must be invalid after startup failure: %+v", h.status())
	}
	if h.status().Reason != "runtime_start_failed" {
		t.Fatalf("reason = %q, want runtime_start_failed", h.status().Reason)
	}
	// Store-backed read (/api/mcp/policy) also reports no active snapshot.
	gwStore, _ := h.stores().Store("gateway")
	if gwStore.Current() != nil {
		t.Fatal("store must be cleared so apiMCPPolicy shows no active snapshot")
	}
	// A not-loaded holder is untouched (idempotent / safe).
	h2 := newMCPPolicyHolder()
	h2.invalidateForStartupFailure()
	if h2.status().State != string(mcpPolNotConfigured) {
		t.Fatalf("not-loaded holder must stay not_configured, got %q", h2.status().State)
	}
}

// ── the provider satisfies the runtime seam ──────────────────────────────────

func TestMCPPolicy_ProviderImplementsSeam(t *testing.T) {
	var _ mcpruntime.PolicyProvider = gatewayPolicyProvider{h: newMCPPolicyHolder()}
}
