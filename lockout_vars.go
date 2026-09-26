package main

import "github.com/KidCarmi/Culvert/internal/lockout"

// Login lockout + admin-API rate limiting moved to internal/lockout (ADR-0002).
// package main keeps the process-wide singletons and the legacy unqualified
// names here so the existing loginLimiter.*/apiLimiter.* call sites and the
// constant references in the test suite stay unchanged. No new exported API.
type (
	LoginLimiter   = lockout.LoginLimiter
	APIRateLimiter = lockout.APIRateLimiter
	LockedEntry    = lockout.LockedEntry
)

var (
	loginLimiter = lockout.NewLoginLimiter()
	apiLimiter   = lockout.NewAPIRateLimiter()
	// SEC-BASICAUTH-4: a per-IP Basic FAILURE budget (basicAuthFailLimiter)
	// stood here and was REMOVED. Keyed on the client alone, it let an
	// unauthenticated caller exhaust the allowance with cheap unknown-username
	// probes — a map miss each, no bcrypt — and every administrator sharing
	// that address (a NAT, a CGNAT range, an L7 proxy with no
	// trusted_proxy_cidrs) was then refused while presenting a CORRECT
	// password, repeatable once per window.
	//
	// Do not reintroduce a refusal keyed on the client on this path: any bound
	// must DELAY or EVICT, never DENY a request whose credentials were never
	// checked. See ui_basic_auth.go for what replaced each half of its job.
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
