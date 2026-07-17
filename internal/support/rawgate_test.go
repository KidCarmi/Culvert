package support

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

// ── Raw-collector hard-gate (#788 merge-gate invariant) ──────────────────────
// redaction.Classify emits only maps/slices/primitives, so a struct with
// exported fields reaching the sink proves the payload bypassed the class
// model. The gate must fail such sections closed and pass everything Classify
// can legitimately emit.

type untaggedRaw struct {
	Endpoint string // no redact tag — and even a tagged struct is unwalked here
	Token    string
}

func TestRawGate_UngovernedStructRejected(t *testing.T) {
	cases := []struct {
		name string
		v    any
	}{
		{"bare struct", untaggedRaw{Endpoint: "e", Token: "t"}},
		{"pointer to struct", &untaggedRaw{}},
		{"struct in map", map[string]any{"cfg": untaggedRaw{}}},
		{"struct in slice", []any{1, "x", untaggedRaw{}}},
		{"nested", map[string]any{"a": []any{map[string]any{"b": &untaggedRaw{}}}}},
	}
	for _, tc := range cases {
		if bad := findUngovernedStruct(tc.v); bad == "" {
			t.Errorf("%s: ungoverned struct not detected", tc.name)
		}
	}
}

func TestRawGate_ClassifiedAndPrimitivePayloadsPass(t *testing.T) {
	rd := redaction.NewWithSalt([]byte("s"))
	classified := rd.Classify(struct {
		Name string `redact:"public" json:"name"`
		Key  string `redact:"secret" json:"key"`
	}{Name: "n", Key: "k"})
	cases := []struct {
		name string
		v    any
	}{
		{"nil", nil},
		{"classified output", classified.Value},
		{"wrapper map around classified", map[string]any{"last_crash": classified.Value}},
		{"primitives", map[string]any{"a": 1, "b": "x", "c": []string{"y"}, "d": true}},
		{"zero-exported-field struct (time.Time)", map[string]any{"ts": time.Time{}}},
	}
	for _, tc := range cases {
		if bad := findUngovernedStruct(tc.v); bad != "" {
			t.Errorf("%s: false positive %q", tc.name, bad)
		}
	}
}

// TestRawGate_SinkFailsSectionClosed proves the gate is ENFORCED at the sink:
// a raw collector's section fails closed, the bundle survives, and the raw
// struct's contents never reach the tar.
func TestRawGate_SinkFailsSectionClosed(t *testing.T) {
	raw := &fakeCollector{
		meta: baseMeta("rawleak", L0, redaction.ClassInternal),
		fn: func(ctx context.Context, in CollectInput, sink SectionSink) Result {
			if err := sink.WriteJSON(untaggedRaw{Endpoint: "internal.example", Token: "RAW-TOKEN-bypass"}); err != nil {
				return Result{Status: StatusFailed, Note: "sink rejected raw payload"}
			}
			return Result{Status: StatusOK, ClassMax: redaction.ClassInternal}
		},
	}
	good := okCollector("good", redaction.ClassPublic, map[string]any{"ok": true})
	res := buildWith(t, raw, good)

	if string(res.TarGz) == "" {
		t.Fatal("bundle must survive a raw collector (failure isolation)")
	}
	files := tarFiles(t, res.TarGz)
	for name, b := range files {
		if strings.Contains(string(b), "RAW-TOKEN-bypass") {
			t.Fatalf("raw payload leaked into %s", name)
		}
	}
	var found bool
	for _, s := range res.Manifest.Sections {
		if s.ID == "rawleak" {
			found = true
			if s.Status != StatusFailed {
				t.Errorf("raw section status = %q, want failed (fail-closed)", s.Status)
			}
		}
	}
	if !found {
		t.Fatal("raw section missing from manifest (must be recorded, not hidden)")
	}
}
