package main

// Policy Learning Mode startup slice — resolver (ADR-0025, slice M1).
//
// M1 ships DEAD infrastructure: the engine skeleton exists (internal/policylearn)
// but Enabled is a CONSTANT false — there is deliberately no CLI flag, no YAML
// key, no env var, and no admin API that can turn it on, because enablement is
// an admin-surface feature that must land WITH its API + GUI (the GUI-parity
// rule) in a later slice. Until then the loader is a guaranteed no-op: no
// engine, no file, no goroutine, no shutdown work.

import (
	"path/filepath"
	"time"
)

type policyLearningStartupConfig struct {
	Enabled             bool          // M1: constant false (see header)
	StorePath           string        // <dataDir>/policy_learning.json
	SubjectKeyPath      string        // <dataDir>/policy_learning_subject.key (M3 pseudonym key; separate from the store)
	MaxRetainedSessions int           // engine default when 0
	MaxSessionDuration  time.Duration // engine default when 0
}

// resolvePolicyLearningStartupConfig derives the slice config. Pure and
// deterministic (startup-slice contract): no globals, no clock, no I/O. The
// *FileConfig parameter is accepted for contract-table uniformity; M1 reads
// nothing from it (no config surface exists yet — see header).
func resolvePolicyLearningStartupConfig(_ *FileConfig, dataDirVal string) policyLearningStartupConfig {
	return policyLearningStartupConfig{
		Enabled:        false, // M1 invariant: learning cannot be enabled in production builds
		StorePath:      filepath.Join(dataDirVal, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(dataDirVal, "policy_learning_subject.key"),
	}
}
