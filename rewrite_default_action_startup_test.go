package main

// rewrite_default_action_startup_test.go — PR3 expansion Batch 3
// coverage.

import (
	"log"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

var rewriteDefaultLoggerMu sync.Mutex

func ensureRewriteDefaultTestLogger(t *testing.T) {
	t.Helper()
	rewriteDefaultLoggerMu.Lock()
	defer rewriteDefaultLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// resetRewriteDefaultGlobals snapshots/restores rewriter.rules,
// rewriter.nextID, and defaultPolicyActionAllow for isolation under
// -shuffle.
func resetRewriteDefaultGlobals(t *testing.T) {
	t.Helper()
	rewriter.mu.RLock()
	origRules := append([]RewriteRule(nil), rewriter.rules...)
	origNext := rewriter.nextID
	rewriter.mu.RUnlock()
	origAction := atomic.LoadInt32(&defaultPolicyActionAllow)
	t.Cleanup(func() {
		rewriter.mu.Lock()
		rewriter.rules = origRules
		rewriter.nextID = origNext
		rewriter.mu.Unlock()
		atomic.StoreInt32(&defaultPolicyActionAllow, origAction)
	})
}

func TestResolveRewriteDefaultActionStartupConfig_CopiesFields(t *testing.T) {
	fc := &FileConfig{
		Rewrite:       []RewriteRule{{Host: "example.com"}},
		DefaultAction: "deny",
	}
	got := resolveRewriteDefaultActionStartupConfig(fc)
	if len(got.Rules) != 1 {
		t.Errorf("Rules: got %d", len(got.Rules))
	}
	if got.DefaultAction != "deny" {
		t.Errorf("DefaultAction: got %q", got.DefaultAction)
	}
}

func TestLoadRewriteAndDefaultAction_ExplicitDeny(t *testing.T) {
	resetRewriteDefaultGlobals(t)
	ensureRewriteDefaultTestLogger(t)
	cfg := rewriteDefaultActionStartupConfig{DefaultAction: "deny"}
	loadRewriteAndDefaultAction(cfg, 0)
	if defaultPolicyAction() != "deny" {
		t.Errorf("expected deny; got %q", defaultPolicyAction())
	}
}

func TestLoadRewriteAndDefaultAction_ExplicitAllow(t *testing.T) {
	resetRewriteDefaultGlobals(t)
	ensureRewriteDefaultTestLogger(t)
	cfg := rewriteDefaultActionStartupConfig{DefaultAction: "allow"}
	loadRewriteAndDefaultAction(cfg, 5)
	if defaultPolicyAction() != "allow" {
		t.Errorf("expected allow; got %q", defaultPolicyAction())
	}
}

func TestLoadRewriteAndDefaultAction_EmptyWithNoRulesDefaultsAllow(t *testing.T) {
	resetRewriteDefaultGlobals(t)
	ensureRewriteDefaultTestLogger(t)
	loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{}, 0)
	if defaultPolicyAction() != "allow" {
		t.Errorf("expected allow fallback (no rules); got %q", defaultPolicyAction())
	}
}

func TestLoadRewriteAndDefaultAction_EmptyWithRulesDefaultsDeny(t *testing.T) {
	resetRewriteDefaultGlobals(t)
	ensureRewriteDefaultTestLogger(t)
	loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{}, 3)
	if defaultPolicyAction() != "deny" {
		t.Errorf("expected deny fallback (rules present); got %q", defaultPolicyAction())
	}
}

func TestLoadRewriteAndDefaultAction_AppliesRewriteRules(t *testing.T) {
	resetRewriteDefaultGlobals(t)
	ensureRewriteDefaultTestLogger(t)
	cfg := rewriteDefaultActionStartupConfig{
		Rules: []RewriteRule{
			{Host: "a.example"},
			{Host: "b.example"},
		},
		DefaultAction: "deny",
	}
	loadRewriteAndDefaultAction(cfg, 0)
	if got := len(rewriter.List()); got != 2 {
		t.Errorf("rewriter rule count: got %d, want 2", got)
	}
}

func TestLoadRewriteAndDefaultAction_NoRulesSkipsRewriterSet(t *testing.T) {
	resetRewriteDefaultGlobals(t)
	ensureRewriteDefaultTestLogger(t)
	// Pre-populate to verify the loader does NOT clobber when cfg.Rules is empty.
	rewriter.SetRules([]RewriteRule{{Host: "preexisting.example"}})
	before := len(rewriter.List())
	loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{DefaultAction: "deny"}, 0)
	if got := len(rewriter.List()); got != before {
		t.Errorf("rewriter should be untouched; before=%d after=%d", before, got)
	}
}
