package main

import (
	"net/http"
	"testing"
)

// testPlugin is a simple plugin used only in tests.
type testPlugin struct {
	name      string
	decision  Decision
	responses []*http.Response
}

func (p *testPlugin) Name() string { return p.name }
func (p *testPlugin) OnRequest(_, _, _ string) Decision { return p.decision }
func (p *testPlugin) OnResponse(resp *http.Response) {
	p.responses = append(p.responses, resp)
}

func withPlugins(ps []Middleware, fn func()) {
	orig := plugins
	plugins = ps
	defer func() { plugins = orig }()
	fn()
}

func TestPluginDecision_AllAllow(t *testing.T) {
	p1 := &testPlugin{name: "p1", decision: DecisionAllow}
	p2 := &testPlugin{name: "p2", decision: DecisionAllow}
	withPlugins([]Middleware{p1, p2}, func() {
		if got := pluginDecision("1.1.1.1", "GET", "example.com"); got != DecisionAllow {
			t.Errorf("expected Allow, got %v", got)
		}
	})
}

func TestPluginDecision_FirstBlocks(t *testing.T) {
	p1 := &testPlugin{name: "blocker", decision: DecisionBlock}
	p2 := &testPlugin{name: "after",   decision: DecisionAllow}
	withPlugins([]Middleware{p1, p2}, func() {
		if got := pluginDecision("1.1.1.1", "GET", "evil.com"); got != DecisionBlock {
			t.Errorf("expected Block, got %v", got)
		}
	})
}

func TestPluginDecision_SecondBlocks(t *testing.T) {
	p1 := &testPlugin{name: "ok",      decision: DecisionAllow}
	p2 := &testPlugin{name: "blocker", decision: DecisionBlock}
	withPlugins([]Middleware{p1, p2}, func() {
		if got := pluginDecision("1.1.1.1", "GET", "evil.com"); got != DecisionBlock {
			t.Errorf("expected Block, got %v", got)
		}
	})
}

func TestPluginOnResponse_CallsAll(t *testing.T) {
	p1 := &testPlugin{name: "p1", decision: DecisionAllow}
	p2 := &testPlugin{name: "p2", decision: DecisionAllow}
	resp := &http.Response{StatusCode: 200}
	withPlugins([]Middleware{p1, p2}, func() {
		pluginOnResponse(resp)
	})
	if len(p1.responses) != 1 || p1.responses[0] != resp {
		t.Error("p1 should have received the response")
	}
	if len(p2.responses) != 1 || p2.responses[0] != resp {
		t.Error("p2 should have received the response")
	}
}

func TestPluginOnResponse_Nil(t *testing.T) {
	p := &testPlugin{name: "p", decision: DecisionAllow}
	withPlugins([]Middleware{p}, func() {
		pluginOnResponse(nil) // must not panic
	})
}

func TestRegisterPlugin(t *testing.T) {
	withPlugins(nil, func() {
		p := &testPlugin{name: "reg", decision: DecisionAllow}
		RegisterPlugin(p)
		if len(plugins) != 1 {
			t.Errorf("expected 1 plugin after Register, got %d", len(plugins))
		}
	})
}
