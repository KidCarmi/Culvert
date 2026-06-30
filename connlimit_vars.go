package main

import "github.com/KidCarmi/Culvert/internal/connlimit"

// Per-IP connection limiting moved to internal/connlimit (ADR-0002). package
// main keeps the process-wide singleton and the unqualified type name here so
// the consumers stay unchanged: proxy.go (Acquire/Release on the hot path),
// admin_settings.go / ui_config.go (Enabled/MaxPerIP for the snapshot + admin
// API), controlplane.go (CP snapshot sync), and the conn+rate-limit startup
// slice. No new exported API beyond New + Enabled (the latter replaces a
// whitebox enabled.Load() that several call sites reached for directly).
type ConnLimiter = connlimit.ConnLimiter

// newConnLimiter constructs a fresh limiter (default cap, disabled). Used for
// the global below and by the test suite, which previously built ConnLimiter
// with a struct literal over the now-unexported fields.
var newConnLimiter = connlimit.New

var connLimiter = newConnLimiter()
