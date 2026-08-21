package main

// Policy Learning Mode startup slice — resolver (ADR-0025, slices M1 + M5A).
//
// The resolver derives only the node-local PATHS and engine bounds. Enablement
// is deliberately NOT here: there is no YAML key, env var, or CLI flag — the
// governed AdminSettings surface (loaded before this slice materializes, see
// loadPolicyLearning) is the single enablement path, so the resolver stays a
// pure path derivation.

import (
	"path/filepath"
	"time"
)

type policyLearningStartupConfig struct {
	StorePath           string        // <dataDir>/policy_learning.json
	SubjectKeyPath      string        // <dataDir>/policy_learning_subject.key (M3 pseudonym key; separate from the store)
	MaxRetainedSessions int           // engine default when 0
	MaxSessionDuration  time.Duration // engine default when 0
}

// resolvePolicyLearningStartupConfig derives the slice config. Pure and
// deterministic (startup-slice contract): no globals, no clock, no I/O. The
// *FileConfig parameter is accepted for contract-table uniformity; the slice
// reads nothing from it (enablement is AdminSettings-governed — see header).
func resolvePolicyLearningStartupConfig(_ *FileConfig, dataDirVal string) policyLearningStartupConfig {
	return policyLearningStartupConfig{
		StorePath:      filepath.Join(dataDirVal, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(dataDirVal, "policy_learning_subject.key"),
	}
}
