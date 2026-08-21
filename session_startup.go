package main

// session_startup.go — startup-time loader for the session slice (PR3
// expansion, Batch 2). Seeds the HMAC secret, optionally loads persisted
// revocations, and applies the session TTL.

import (
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// loadSession applies cfg: seed the random session secret, override it
// from config if provided, attach the revocations file (if any) and load
// existing entries, then apply the TTL. Returns a non-fatal error only
// for the revocations-load path; callers typically log and continue.
func loadSession(cfg sessionStartupConfig) error {
	// Only fall through to the config-file secret when CULVERT_SESSION_SECRET
	// did not already supply the key — an explicit env value must win over
	// config.yaml's session_secret, not the other way around (session.go's
	// documented priority: env > config file > random).
	if envSet := initSessionSecret(); !envSet {
		initSessionSecretFromConfig(cfg.Secret)
	}

	if cfg.RevocationsFile != "" {
		session.SetRevocationsPath(cfg.RevocationsFile)
		if err := sessionRevoked.LoadRevocations(); err != nil {
			return fmt.Errorf("load revocations: %w", err)
		}
	}

	if cfg.TimeoutHours > 0 {
		SetSessionTTL(time.Duration(cfg.TimeoutHours) * time.Hour)
		logger.Printf("Session: timeout %dh", cfg.TimeoutHours)
	}
	return nil
}
