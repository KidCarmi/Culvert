package main

// Policy Learning Mode startup slice — loader (ADR-0025, slice M1).

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/policylearn"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// loadPolicyLearning wires the learning engine. ORDER IS THE CONTRACT:
//  1. Disabled (the M1 constant, and the shipped default forever after) is a
//     TRUE no-op: no engine constructed, no file touched, no goroutine, the
//     singleton stays nil, and the shutdown hook (registered unconditionally
//     in main_shutdown.go) no-ops on the nil singleton.
//  2. When enabled (test-only in M1), the engine is constructed BEFORE any
//     traffic could observe it, with the process quarantine seam and a
//     baseline capture reading the policy generation (read-only — ADR-0025
//     forbids mutation, not observation, and the read happens in ROOT wiring,
//     never inside the walled package).
func loadPolicyLearning(cfg policyLearningStartupConfig) {
	if !cfg.Enabled {
		return
	}
	eng, err := policylearn.New(policylearn.Config{
		StorePath:      cfg.StorePath,
		SubjectKeyPath: cfg.SubjectKeyPath,
		Now:            time.Now,
		Baseline: func() policylearn.Baseline {
			gen, _ := policyStore.policyVersion()
			return policylearn.Baseline{
				PolicyGeneration: gen,
				DefaultAction:    defaultPolicyAction(),
			}
		},
		// M3: category resolution runs ONLY in the learning drain — never the
		// request hot path. The two-tier lookup is read-only against the live
		// category stores (the same semantic environment the policy engine
		// consults); the session's CategoryEpoch pin makes generation drift
		// visible rather than silently blended.
		Categories: func(host string) (string, string) {
			category, tier, _ := lookupHostCategory(host)
			return category, tier
		},
		CategoryEpoch: learnCategoryEpoch,
		// M4: the fail-closed recommendable-category ALLOWLIST, seeded from the
		// embedded business-category set. Engine-config only — no admin surface
		// exists yet (that lands with GUI parity in a later slice). The engine's
		// default community-tier cap ("community") matches lookupHostCategory's
		// tier taxonomy.
		RecommendableCategories: urlcat.DefaultBusinessCategoryNames(),
		Quarantine: func(path string, err error) {
			quarantineCorruptStateFile("policy_learning", path, err)
		},
		MaxRetainedSessions: cfg.MaxRetainedSessions,
		MaxSessionDuration:  cfg.MaxSessionDuration,
	})
	if err != nil {
		// Fail-safe: learning is advisory — a broken learning store must never
		// block proxy startup. Log and stay disabled (nil singleton).
		logger.Printf("Policy learning disabled: %v", err)
		return
	}
	policyLearnEngine.Store(eng)
}
