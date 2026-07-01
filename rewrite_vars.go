package main

import "github.com/KidCarmi/Culvert/internal/rewrite"

// Per-host HTTP header rewrite rules moved to internal/rewrite (ADR-0002).
// package main keeps the process-wide rewriter singleton and the unqualified
// type names here so every consumer stays unchanged: RewriteRule is a config/
// API/cluster DTO threaded through config.go, admin_settings.go, configversion.go,
// controlplane.go, ui_config.go, ui_policy.go; rewriter.{SetRules,List,Add,
// RemoveByID,ApplyRequest,ApplyResponse} is called from main.go, proxy.go, and
// the startup slice. No new exported API beyond Snapshot (test-support).
type (
	RewriteRule = rewrite.Rule // package func is rewrite.Rule (revive: rewrite.RewriteRule is repetitive)
	Rewriter    = rewrite.Rewriter
)

var rewriter = rewrite.NewRewriter()
