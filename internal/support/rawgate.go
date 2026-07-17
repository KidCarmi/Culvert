// rawgate.go — the raw-collector hard-gate (#788 merge-gate invariant).
//
// Every collector must redact at source via in.Redactor (COLLECTOR-CONTRACT):
// redaction.Classify WALKS the payload and returns only maps, slices, and
// primitives — never structs. A struct with exported fields reaching the
// section sink therefore proves the payload BYPASSED the class model (a
// "raw" collector): its redact tags — if it even has them — were never
// evaluated, no SENSITIVE field was masked, no SECRET field was dropped, and
// the free-form scrubber never ran. That is exactly the defect class this
// gate exists to stop shipping: a future raw-file collector that dumps an
// untagged (or tagged-but-unwalked) struct straight into the bundle.
//
// The gate is enforced at runtime in sectionSink.WriteJSON — fail-closed per
// section (the collector's own error path marks the section failed; the
// framework never aborts the bundle) — and pinned by rawgate_test.go plus the
// all-registered-collectors sweep in the package-main wall tests.
//
// Zero-exported-field structs (e.g. time.Time) are tolerated: they carry no
// per-field class decisions for the walker to make and marshal as opaque
// scalars.
package support

import (
	"fmt"
	"reflect"
)

// maxRawGateDepth bounds the reflection walk (cycle/adversarial-depth guard).
const maxRawGateDepth = 64

// findUngovernedStruct walks v's dynamic value tree and returns the type name
// of the first struct that carries ≥1 exported field — i.e. a payload the
// redaction class model never governed — or "" when the payload is clean
// (maps/slices/primitives, the shape redaction.Classify emits).
func findUngovernedStruct(v any) string {
	if v == nil {
		return ""
	}
	return walkForStructs(reflect.ValueOf(v), 0)
}

func walkForStructs(rv reflect.Value, depth int) string {
	if depth > maxRawGateDepth {
		// Deeper than anything Classify emits — treat as ungoverned rather than
		// risk walking an adversarial/cyclic structure forever (fail closed).
		return rv.Type().String() + " (exceeds max depth)"
	}
	switch rv.Kind() {
	case reflect.Invalid:
		return ""
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return ""
		}
		return walkForStructs(rv.Elem(), depth+1)
	case reflect.Struct:
		t := rv.Type()
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() {
				return t.String()
			}
		}
		return "" // zero exported fields (time.Time etc) — opaque scalar
	case reflect.Map:
		for it := rv.MapRange(); it.Next(); {
			if bad := walkForStructs(it.Value(), depth+1); bad != "" {
				return bad
			}
		}
		return ""
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if bad := walkForStructs(rv.Index(i), depth+1); bad != "" {
				return bad
			}
		}
		return ""
	default:
		return "" // primitives
	}
}

// errUngovernedPayload builds the fail-closed sink error for a raw payload.
func errUngovernedPayload(typeName string) error {
	return fmt.Errorf("raw-collector hard-gate: payload contains struct %s that never went through the redaction class model — run it through in.Redactor.Classify (or Struct) and write the result", typeName)
}
