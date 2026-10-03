package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The /ready and /health surfaces must tell "services running", "setup
// complete" and "ready to enforce" apart (appliance readiness F). Both rows
// are report-only on the default verdict and gating under ?strict=1.
func TestReadiness_SetupAndPostureRows(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	t.Cleanup(func() { setDefaultPolicyAction("deny") })

	// Fresh install shape: no admin, no rules, passthrough.
	setDefaultPolicyAction("allow")
	rep, code := computeReadiness()
	if code != 200 {
		t.Fatalf("report-only rows must not gate the default verdict; code=%d checks=%+v", code, rep.Checks)
	}
	if c := rep.Checks["setup_complete"]; c == nil || c.Status != "fail" {
		t.Fatalf("setup_complete must fail before setup: %+v", c)
	}
	if c := rep.Checks["policy_posture"]; c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "passthrough") {
		t.Fatalf("policy_posture must report passthrough on a fresh install: %+v", c)
	}
	h := computeHealth()
	if h.SetupComplete || h.PolicyDefaultAction != "allow" {
		t.Fatalf("/health must mirror the posture: %+v", h)
	}

	// Strict callers gate on them.
	rr := httptest.NewRecorder()
	handleReady(rr, httptest.NewRequest("GET", "/ready?strict=1", http.NoBody))
	if rr.Code != 503 {
		t.Fatalf("strict readiness must fail before setup/enforcement, got %d", rr.Code)
	}

	// Setup completed + default-deny: both rows ok.
	if err := cfg.SetAuth("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	setDefaultPolicyAction("deny")
	rep, _ = computeReadiness()
	if c := rep.Checks["setup_complete"]; c == nil || c.Status != "ok" {
		t.Fatalf("setup_complete must be ok after setup: %+v", c)
	}
	if c := rep.Checks["policy_posture"]; c == nil || c.Status != "ok" || c.Detail != "default-deny" {
		t.Fatalf("policy_posture must be ok under default-deny: %+v", c)
	}
	if h := computeHealth(); !h.SetupComplete || h.PolicyDefaultAction != "deny" {
		t.Fatalf("/health must mirror the posture: %+v", h)
	}
}

// Disabled rules are skipped by evaluation, so a rulebase whose every rule is
// disabled under default-allow is passthrough and must not read as enforcing
// (Codex P2, PR #1528).
func TestReadiness_PostureCountsOnlyEnabledRules(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	t.Cleanup(func() { setDefaultPolicyAction("deny") })
	setDefaultPolicyAction("allow")
	off := false
	policyStore.Add(PolicyRule{Name: "disabled-only", Action: ActionBlockPage, DestFQDN: "*", Enabled: &off})
	if _, n, _ := policyPosture(); n != 0 {
		t.Fatalf("a disabled rule counted toward the posture: %d", n)
	}
	rep, _ := computeReadiness()
	if c := rep.Checks["policy_posture"]; c == nil || c.Status != "fail" {
		t.Fatalf("all-disabled rules under default-allow must be passthrough: %+v", c)
	}
	// CONTROL: one enabled rule is enough to leave passthrough.
	policyStore.Add(PolicyRule{Name: "live", Action: ActionBlockPage, DestFQDN: "*"})
	if _, n, _ := policyPosture(); n != 1 {
		t.Fatalf("enabled rule count = %d, want 1", n)
	}
	if c, _ := computeReadiness(); c.Checks["policy_posture"].Status != "ok" {
		t.Fatalf("one enabled rule must read as enforcing: %+v", c.Checks["policy_posture"])
	}
}

// Under default-allow a rulebase of plain Allow rules allows everything either
// way, so it must not read as enforcing (Codex P2, PR #1528, second round).
// The posture follows applyPolicyDecision: only Drop, Block_Page, Redirect, or
// an Allow carrying a file profile can refuse a request.
func TestReadiness_PostureCountsOnlyRulesThatConstrainTraffic(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	t.Cleanup(func() { setDefaultPolicyAction("deny") })
	setDefaultPolicyAction("allow")
	posture := func() *readinessCheck { rep, _ := computeReadiness(); return rep.Checks["policy_posture"] }

	policyStore.Add(PolicyRule{Name: "allow-a", Action: ActionAllow, DestFQDN: "a.example"})
	policyStore.Add(PolicyRule{Name: "allow-b", Action: ActionAllow, DestFQDN: "b.example"})
	_, enabled, constraining := policyPosture()
	if enabled != 2 || constraining != 0 {
		t.Fatalf("plain Allow rules: enabled=%d constraining=%d, want 2/0", enabled, constraining)
	}
	if c := posture(); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "passthrough") {
		t.Fatalf("Allow-only rules under default-allow must be passthrough: %+v", c)
	}
	// An action string outside the four constants reaches no branch of the
	// decision switch, so it blocks nothing.
	policyStore.Add(PolicyRule{Name: "bogus-action", Action: "block", DestFQDN: "*"})
	if c := posture(); c.Status != "fail" {
		t.Fatalf("an unrecognised action must not count as enforcement: %+v", c)
	}
	// An Allow with file filtering but no profile cannot block (FileProfileBlocked's guard).
	policyStore.Add(PolicyRule{Name: "allow-filter-no-profile", Action: ActionAllow, DestFQDN: "c.example", FileFiltering: true, FileProfile: FileProfileNone})
	if c := posture(); c.Status != "fail" {
		t.Fatalf("file filtering without a profile blocks nothing: %+v", c)
	}
	// CONTROLS: each constraining shape on its own leaves passthrough.
	for _, r := range []PolicyRule{
		{Name: "drop", Action: ActionDrop, DestFQDN: "d.example"},
		{Name: "blockpage", Action: ActionBlockPage, DestFQDN: "e.example"},
		{Name: "redirect", Action: ActionRedirect, DestFQDN: "f.example", RedirectURL: "https://intranet.example/"},
		{Name: "allow-with-profile", Action: ActionAllow, DestFQDN: "g.example", FileFiltering: true, FileProfile: "Executables"},
	} {
		t.Run(r.Name, func(t *testing.T) {
			snapshotPolicyStoreForTest(t)
			policyStore.Add(r)
			if c := posture(); c == nil || c.Status != "ok" {
				t.Fatalf("%s must read as enforcing: %+v", r.Name, c)
			}
		})
	}
	// /health keeps reporting ENABLED rules, not the constraining subset.
	if h := computeHealth(); h.PolicyRules != 4 {
		t.Fatalf("/health policy_rules = %d, want 4 enabled rules (allow-a, allow-b, bogus-action, allow-filter-no-profile)", h.PolicyRules)
	}
}

// The maintenance agent's upgrade gate requires the /ready rows that were
// "ok" before an upgrade to be "ok" after (cmd/culvert-maint
// internal/health.PreservedReadyChecks). A renamed or dropped row would read
// as "regressed" on every upgrade and roll it back, so the names are pinned
// against what this proxy actually emits.
func TestReadiness_AgentPreservedRowsExist(t *testing.T) {
	setupProxyTest(t)
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "cmd", "culvert-maint", "internal", "health", "health.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`var PreservedReadyChecks = \[\]string\{([^}]*)\}`).FindSubmatch(src)
	if m == nil {
		t.Fatal("PreservedReadyChecks not found in the agent's health package")
	}
	rep, _ := computeReadiness()
	var names []string
	for _, q := range regexp.MustCompile(`"([a-z_]+)"`).FindAllSubmatch(m[1], -1) {
		names = append(names, string(q[1]))
	}
	if len(names) < 4 {
		t.Fatalf("parsed only %v — the wall is vacuous", names)
	}
	for _, name := range names {
		if name == "ca" {
			// Emitted only once a CA is configured (absent ⇒ never in a
			// baseline, so never required); pinned by its writer instead.
			if !strings.Contains(string(mustReadSource(t, "healthcheck.go")), `checks["ca"] = &readinessCheck{Status: "ok"}`) {
				t.Fatal("the proxy no longer emits an ok `ca` row")
			}
			continue
		}
		if rep.Checks[name] == nil {
			t.Errorf("agent preserves /ready row %q but the proxy does not emit it", name)
		}
	}
}

func mustReadSource(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
