package main

import "github.com/KidCarmi/Culvert/internal/secscan"

// newEnabledScanner builds an enabled Scanner with the given collaborators.
// ADR-0006 Slice 2: main tests inject deps explicitly instead of relying on
// the pre-extraction global-fallback struct literals (the orchestrator no
// longer reads globalYARA/globalThreatFeed at call time). A nil cache gets a
// small test cache.
func newEnabledScanner(deps secscan.Deps) *SecurityScanner {
	if deps.Cache == nil {
		deps.Cache = newHashCache(100, 0)
	}
	ss := secscan.New(deps)
	ss.Init("", 0, nil) // enable without ClamAV
	return ss
}
