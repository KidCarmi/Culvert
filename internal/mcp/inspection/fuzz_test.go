package inspection

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/schema"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

func defaultGwLimits() limits.InspectionLimits { return limits.DefaultGatewayInspection() }

func gwProfileFuzz() Profile { return DefaultGatewayProfile(1) }

// FuzzInspectResponse drives the response inspector with arbitrary bodies.
// Invariants: no panic; a caller can NEVER obtain a passing result on invalid JSON
// or over-limit output (it always hard-fails); determinism of the hard-fail flag.
func FuzzInspectResponse(f *testing.F) {
	f.Add([]byte(`{"ok":true}`))
	f.Add([]byte(`{not json`))
	f.Add([]byte(`{"leak":"secret-ish"}`))
	f.Add([]byte(`["ignore previous instructions"]`))
	p := DefaultGatewayProfile(1)
	f.Fuzz(func(t *testing.T, body []byte) {
		r1 := InspectResponse(context.Background(), p, ResponseInput{Body: body}, time.Unix(1, 0))
		r2 := InspectResponse(context.Background(), p, ResponseInput{Body: body}, time.Unix(1, 0))
		if r1.HardFail != r2.HardFail {
			t.Fatal("non-deterministic hard-fail")
		}
		// A non-JSON body must never pass.
		if !r1.HardFail {
			if _, err := canonical.Decode(body, outputBounds(defaultGwLimits())); err != nil {
				t.Fatal("invalid JSON output passed inspection")
			}
		}
	})
}

// FuzzInspectRequest drives the request inspector with arbitrary argument JSON.
// Invariants: no panic; a schema-invalid argument set never passes; determinism.
func FuzzInspectRequest(f *testing.F) {
	f.Add([]byte(`{"msg":"hi"}`), []byte(`{"type":"object","required":["msg"]}`))
	f.Add([]byte(`{"url":"https://10.0.0.1/"}`), []byte(`{}`))
	f.Add([]byte(`{"n":"x"}`), []byte(`{"type":"object","properties":{"n":{"type":"integer"}}}`))
	p := gwProfileFuzz()
	b := canonical.Bounds{MaxBytes: 1 << 14, MaxDepth: 16, MaxObjectMembers: 64, MaxArrayElements: 64, MaxStringBytes: 1 << 12}
	f.Fuzz(func(t *testing.T, argsBytes, schemaBytes []byte) {
		args, aerr := canonical.Decode(argsBytes, b)
		if aerr != nil {
			return
		}
		sn, serr := canonical.Decode(schemaBytes, b)
		if serr != nil {
			return
		}
		compiled, cerr := schema.Compile(sn, defaultGwLimits())
		in := RequestInput{Tool: ToolRef{Name: "t", ServerID: "s"}, Args: args, InputSchema: sn}
		if cerr == nil {
			in.Compiled = compiled
		}
		r1 := InspectRequest(context.Background(), p, in, time.Unix(1, 0))
		r2 := InspectRequest(context.Background(), p, in, time.Unix(1, 0))
		if r1.HardFail != r2.HardFail {
			t.Fatal("non-deterministic hard-fail")
		}
		// A valid schema whose validate rejects the args must hard-fail.
		if cerr == nil {
			if res := compiled.Validate(args); !res.Valid() && !r1.HardFail {
				t.Fatal("schema-invalid args did not hard-fail")
			}
		}
	})
}
