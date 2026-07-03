package main

// plugin.go — package-main glue for the middleware plugin API, moved to
// internal/plugin (ADR-0002). The alias shim keeps the proxy/SOCKS5 hot-path
// call sites, external plugin authors (RegisterPlugin), and the test suite
// using the original unqualified names.

import "github.com/KidCarmi/Culvert/internal/plugin"

// Decision / Middleware re-exposed unqualified (engine types are
// plugin.Decision / .Middleware).
type (
	Decision   = plugin.Decision
	Middleware = plugin.Middleware
)

// Decision values re-exposed for plugin implementations and the hot path.
const (
	DecisionAllow = plugin.DecisionAllow
	DecisionBlock = plugin.DecisionBlock
)

// RegisterPlugin / pluginDecision / pluginOnResponse re-exposed for plugin
// authors and the proxy/SOCKS5 pipelines; pluginReplace is the chain-swap
// test support (returns the previous chain).
var (
	RegisterPlugin   = plugin.Register
	pluginDecision   = plugin.Decide
	pluginOnResponse = plugin.OnResponse
	pluginReplace    = plugin.Replace
)
