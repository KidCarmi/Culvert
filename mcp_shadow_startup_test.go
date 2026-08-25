package main

import (
	"reflect"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// These tests pin the PRODUCTION composition of the non-executing Shadow evaluator
// (SHADOW-ACTIVATION.md §4/§5). They are in a _test.go file, so importing the execution
// package here does not trip the execution-posture wall (which scans production files
// only) — that is exactly how a test asserts against the composed production object.

// resetShadowComposition clears the node-local composition record between tests.
func resetShadowComposition(t *testing.T) {
	t.Helper()
	prevComposed := globalMCPShadow.composed.Load()
	prevRequested := globalMCPShadow.requested.Load()
	prevReason := globalMCPShadow.Reason()
	globalMCPShadow.composed.Store(false)
	globalMCPShadow.requested.Store(false)
	globalMCPShadow.setReason("")
	t.Cleanup(func() {
		globalMCPShadow.composed.Store(prevComposed)
		globalMCPShadow.requested.Store(prevRequested)
		globalMCPShadow.setReason(prevReason)
	})
}

// TestShadowComposition_ProducesNonExecutingEvaluator is the core production-composition
// proof: when Shadow readiness is on and durable events are available, Deps.Executor is
// a *execution.ShadowEvaluator (never a live *execution.Executor), the shadow readiness
// tier is armed while the live tier stays off, and the composed object's type graph
// exposes no upstream Call or credential Materialize capability.
func TestShadowComposition_ProducesNonExecutingEvaluator(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	evMgr := buildReadyTelemetry(t).Manager()

	var cfg mcpruntime.Config
	composeGatewayShadowIntoConfig(&cfg, true, evMgr)

	if cfg.Deps.Executor == nil {
		t.Fatal("shadow-ready composition must install Deps.Executor")
	}
	// It must be the non-executing evaluator, NEVER the live executor.
	if _, ok := cfg.Deps.Executor.(*execution.ShadowEvaluator); !ok {
		t.Fatalf("Deps.Executor must be *execution.ShadowEvaluator, got %T", cfg.Deps.Executor)
	}
	if _, ok := cfg.Deps.Executor.(*execution.Executor); ok {
		t.Fatal("SECURITY: the live *execution.Executor must never be composed in production")
	}
	// The shadow readiness tier is armed; the live tier is NOT (the whole point of the
	// split — composing Shadow can never make a Canary/Production transition succeed).
	if !shadowDepsConfigured(false) {
		t.Fatal("composing shadow must arm the shadow readiness tier")
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("SECURITY: composing shadow must NOT arm the live-execution tier")
	}
	if !globalMCPShadow.composed.Load() || globalMCPShadow.Reason() != "composed" {
		t.Fatalf("composition record wrong: composed=%v reason=%q", globalMCPShadow.composed.Load(), globalMCPShadow.Reason())
	}
	// Structural: the composed object holds no path to Upstream.Call or Materialize.
	if bad := shadowTypeGraphCapabilities(reflect.TypeOf(cfg.Deps.Executor)); len(bad) != 0 {
		t.Fatalf("SECURITY: the production-composed shadow evaluator exposes a live capability via %v", bad)
	}
}

// TestShadowComposition_FailClosedWhenDisabled pins that with Shadow readiness OFF the
// executor stays nil (byte-identical Observe) and neither tier is armed.
func TestShadowComposition_FailClosedWhenDisabled(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	var cfg mcpruntime.Config
	composeGatewayShadowIntoConfig(&cfg, false, buildReadyTelemetry(t).Manager())
	if cfg.Deps.Executor != nil {
		t.Fatal("shadow-disabled composition must leave Deps.Executor nil (byte-identical Observe)")
	}
	if shadowDepsConfigured(false) || liveExecDepsConfigured(false) {
		t.Fatal("a disabled composition must arm no readiness tier")
	}
	if globalMCPShadow.requested.Load() {
		t.Fatal("a disabled composition must record not-requested")
	}
}

// TestShadowComposition_FailClosedWithoutEvents pins that Shadow requires durable
// events: requested but with no events manager, it fails closed to a nil executor and
// does NOT arm the shadow tier.
func TestShadowComposition_FailClosedWithoutEvents(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	var cfg mcpruntime.Config
	composeGatewayShadowIntoConfig(&cfg, true, nil)
	if cfg.Deps.Executor != nil {
		t.Fatal("shadow without durable events must fail closed to a nil executor")
	}
	if shadowDepsConfigured(false) {
		t.Fatal("a fail-closed composition must NOT arm the shadow readiness tier")
	}
	if !globalMCPShadow.requested.Load() || globalMCPShadow.Reason() != "durable_events_unavailable" {
		t.Fatalf("fail-closed record wrong: requested=%v reason=%q", globalMCPShadow.requested.Load(), globalMCPShadow.Reason())
	}
}

// shadowTypeGraphCapabilities returns the "Field.Method" labels of any field of the
// (pointer-to-)struct type whose type exposes a Call or Materialize method — the two
// live-execution capabilities a Shadow evaluator must never hold. It mirrors the
// execution package's own capability probe but runs against the PRODUCTION-composed
// concrete type.
func shadowTypeGraphCapabilities(tt reflect.Type) []string {
	for tt.Kind() == reflect.Pointer {
		tt = tt.Elem()
	}
	if tt.Kind() != reflect.Struct {
		return nil
	}
	var found []string
	for i := 0; i < tt.NumField(); i++ {
		ft := tt.Field(i).Type
		for _, bad := range []string{"Call", "Materialize"} {
			if typeHasMethod(ft, bad) {
				found = append(found, tt.Field(i).Name+"."+bad)
			}
		}
	}
	return found
}

// typeHasMethod reports whether t (value or pointer method set) has a method named name.
func typeHasMethod(t reflect.Type, name string) bool {
	if _, ok := t.MethodByName(name); ok {
		return true
	}
	if t.Kind() != reflect.Interface && t.Kind() != reflect.Pointer {
		if _, ok := reflect.PointerTo(t).MethodByName(name); ok {
			return true
		}
	}
	return false
}
