// Package plugin is the Culvert middleware plugin API: the Middleware
// contract, the process-wide plugin chain, and the panic-safe dispatch the
// proxy hot path calls. Extracted from package main per ADR-0002; the
// unqualified names (RegisterPlugin, pluginDecision, ...) remain available in
// main via the plugin.go alias shim.
package plugin

import (
	"net/http"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// Decision is the outcome of a plugin's OnRequest evaluation.
type Decision int

// Decision values returned by Middleware.OnRequest.
const (
	DecisionAllow Decision = iota // pass request through
	DecisionBlock                 // reject the request
)

// Middleware is the interface all Culvert plugins must implement.
//
// Example:
//
//	type MyPlugin struct{}
//	func (p *MyPlugin) Name() string { return "my-plugin" }
//	func (p *MyPlugin) OnRequest(ip, method, host string) Decision { return DecisionAllow }
//	func (p *MyPlugin) OnResponse(resp *http.Response) {}
//
// Register with: RegisterPlugin(&MyPlugin{})
type Middleware interface {
	// Name returns a human-readable identifier (used in logs).
	Name() string
	// OnRequest is called before each request is forwarded.
	// Return DecisionBlock to reject; DecisionAllow to pass through.
	OnRequest(clientIP, method, host string) Decision
	// OnResponse is called after a successful upstream response.
	// It may modify response headers. Called with nil if no response exists.
	OnResponse(resp *http.Response)
}

// chain is the global plugin chain. It is appended to at init time (before
// the proxy serves traffic) and read lock-free on the hot path — same
// contract as the pre-extraction package-main slice.
var chain []Middleware

// Register appends a Middleware to the global plugin chain.
// Call this from init() or before the proxy starts.
func Register(m Middleware) {
	chain = append(chain, m)
	obs.Printf("Plugin registered: %s", m.Name())
}

// Replace swaps the entire plugin chain and returns the previous one.
// Test support: pair the calls to restore the original chain. Not safe
// concurrently with traffic (the chain is read lock-free on the hot path).
func Replace(ps []Middleware) []Middleware {
	old := chain
	chain = ps
	return old
}

// Decide runs all plugins in order and returns DecisionBlock on the
// first plugin that blocks, or DecisionAllow if all pass.
// A panicking plugin is recovered and treated as a pass-through to avoid
// bringing down the proxy — but the panic is also reported to obs.ReportPanic
// (component "plugin:<name>") so it lands in the same crash-records
// metric/audit pipeline as every other recovered panic in the process,
// instead of being visible only in the process log. A silently panicking
// plugin fails open on every request; an admin needs a way to notice that
// without grepping stdout.
func Decide(clientIP, method, host string) Decision {
	for _, p := range chain {
		decision := func() (d Decision) {
			defer func() {
				if r := recover(); r != nil {
					obs.Printf("Plugin[%s] panicked: %v — treated as Allow", p.Name(), r)
					obs.ReportPanic("plugin:"+p.Name(), r)
					d = DecisionAllow
				}
			}()
			return p.OnRequest(clientIP, method, host)
		}()
		if decision == DecisionBlock {
			obs.Printf("Plugin[%s] blocked %s -> %s %s", p.Name(), clientIP, method, host)
			return DecisionBlock
		}
	}
	return DecisionAllow
}

// OnResponse notifies all plugins of a completed response.
func OnResponse(resp *http.Response) {
	for _, p := range chain {
		func() {
			defer func() {
				if r := recover(); r != nil {
					obs.Printf("Plugin[%s] panicked in OnResponse: %v", p.Name(), r)
					obs.ReportPanic("plugin:"+p.Name(), r)
				}
			}()
			p.OnResponse(resp)
		}()
	}
}
