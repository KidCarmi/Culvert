package main

import "net/http"

// Decision is the outcome of a plugin's OnRequest evaluation.
type Decision int

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

var plugins []Middleware

// RegisterPlugin appends a Middleware to the global plugin chain.
// Call this from init() or before the proxy starts.
func RegisterPlugin(m Middleware) {
	plugins = append(plugins, m)
	logger.Printf("Plugin registered: %s", m.Name())
}

// pluginDecision runs all plugins in order and returns DecisionBlock on the
// first plugin that blocks, or DecisionAllow if all pass.
// A panicking plugin is recovered and treated as a pass-through to avoid
// bringing down the proxy.
func pluginDecision(clientIP, method, host string) Decision {
	for _, p := range plugins {
		decision := func() (d Decision) {
			defer func() {
				if r := recover(); r != nil {
					logger.Printf("Plugin[%s] panicked: %v — treated as Allow", p.Name(), r)
					d = DecisionAllow
				}
			}()
			return p.OnRequest(clientIP, method, host)
		}()
		if decision == DecisionBlock {
			logger.Printf("Plugin[%s] blocked %s -> %s %s", p.Name(), clientIP, method, host)
			return DecisionBlock
		}
	}
	return DecisionAllow
}

// pluginOnResponse notifies all plugins of a completed response.
func pluginOnResponse(resp *http.Response) {
	for _, p := range plugins {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Printf("Plugin[%s] panicked in OnResponse: %v", p.Name(), r)
				}
			}()
			p.OnResponse(resp)
		}()
	}
}
