package main

import "github.com/KidCarmi/Culvert/internal/lockout"

// Login lockout + admin-API rate limiting moved to internal/lockout (ADR-0002).
// package main keeps the process-wide singletons and the legacy unqualified
// names here so the existing loginLimiter.*/apiLimiter.* call sites and the
// constant references in the test suite stay unchanged. No new exported API.
type (
	LoginLimiter   = lockout.LoginLimiter
	APIRateLimiter = lockout.APIRateLimiter
)

var (
	loginLimiter = lockout.NewLoginLimiter()
	apiLimiter   = lockout.NewAPIRateLimiter()
)

// LockoutMsg is re-exposed unqualified so ui_auth.go and the test suite keep
// calling it without the package qualifier (the package func is lockout.Msg;
// revive flags lockout.LockoutMsg as repetitive).
var LockoutMsg = lockout.Msg

// Legacy constant names retained for the test suite (d0_mutation_safety_test.go,
// lockout_isolation_test.go). Production handlers reference only the methods.
const (
	lockoutMaxAttempts = lockout.MaxAttempts
	lockoutWindow      = lockout.Window
	lockoutDuration    = lockout.Duration
	apiRateBurst       = lockout.Burst
	apiRateWindow      = lockout.RateWindow
)
