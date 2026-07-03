package plugin

import (
	"net/http"
	"testing"
)

// fakePlugin is a minimal Middleware used only in these tests. Package main
// keeps its own testPlugin (shared with the proxy handler tests) — this
// duplicate is 15 lines and keeps the engine suite in-package for coverage.
type fakePlugin struct {
	name      string
	decision  Decision
	panicOn   bool
	responses int
}

func (p *fakePlugin) Name() string { return p.name }
func (p *fakePlugin) OnRequest(_, _, _ string) Decision {
	if p.panicOn {
		panic("boom")
	}
	return p.decision
}
func (p *fakePlugin) OnResponse(*http.Response) {
	if p.panicOn {
		panic("boom")
	}
	p.responses++
}

func withChain(ps []Middleware, fn func()) {
	orig := Replace(ps)
	defer Replace(orig)
	fn()
}

func TestDecide_AllAllow(t *testing.T) {
	withChain([]Middleware{&fakePlugin{name: "a"}, &fakePlugin{name: "b"}}, func() {
		if got := Decide("1.1.1.1", "GET", "example.com"); got != DecisionAllow {
			t.Errorf("Decide = %v, want Allow", got)
		}
	})
}

func TestDecide_FirstBlockWins(t *testing.T) {
	second := &fakePlugin{name: "after"}
	withChain([]Middleware{&fakePlugin{name: "blocker", decision: DecisionBlock}, second}, func() {
		if got := Decide("1.1.1.1", "GET", "evil.com"); got != DecisionBlock {
			t.Errorf("Decide = %v, want Block", got)
		}
	})
}

func TestDecide_PanicIsAllow(t *testing.T) {
	withChain([]Middleware{&fakePlugin{name: "panicky", panicOn: true}}, func() {
		if got := Decide("1.1.1.1", "GET", "example.com"); got != DecisionAllow {
			t.Errorf("panicking plugin must be treated as Allow, got %v", got)
		}
	})
}

func TestOnResponse_CallsAllAndSurvivesPanic(t *testing.T) {
	ok1 := &fakePlugin{name: "ok1"}
	ok2 := &fakePlugin{name: "ok2"}
	withChain([]Middleware{ok1, &fakePlugin{name: "panicky", panicOn: true}, ok2}, func() {
		OnResponse(nil) // must not panic; must reach plugins after the panicking one
	})
	if ok1.responses != 1 || ok2.responses != 1 {
		t.Errorf("OnResponse calls = %d/%d, want 1/1", ok1.responses, ok2.responses)
	}
}

func TestRegisterAppendsAndReplaceRoundTrips(t *testing.T) {
	withChain(nil, func() {
		Register(&fakePlugin{name: "reg"})
		got := Replace(nil)
		Replace(got) // put it straight back — withChain restores on exit
		if len(got) != 1 || got[0].Name() != "reg" {
			t.Errorf("chain after Register = %v, want [reg]", got)
		}
	})
}
