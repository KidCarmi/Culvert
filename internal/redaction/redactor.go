package redaction

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Result is the outcome of redacting one value.
type Result struct {
	Value    any       // JSON-serializable redacted form
	ClassMax DataClass // highest class present AFTER redaction (<= ShareableCeiling)
	Masked   int       // count of SENSITIVE fields masked
	Dropped  int       // count of SECRET/NEVER_EXPORT fields dropped
}

// Redactor redacts collected values structurally by DataClass. Field classes are
// declared with a `redact:"public|internal|sensitive|secret|never_export"` struct
// tag; an untagged (or unknown-tagged) exported field fails closed to SENSITIVE.
type Redactor interface {
	// Struct returns the redacted, JSON-serializable form of v. Collectors call
	// this on every value before writing it to a section.
	Struct(v any) any
	// Classify is Struct plus the post-redaction class_max and mask/drop counts,
	// used by the runner for the manifest section entry and redaction report.
	Classify(v any) Result
}

type redactor struct {
	salt []byte // per-bundle; masked tokens correlate within a bundle, not across
}

// New builds a Redactor with a fresh random per-bundle salt. The salt is
// NEVER_EXPORT — never written to a bundle — so masked tokens are irreversible
// and do not correlate across bundles (REDACTION-MODEL §4).
func New() Redactor {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return &redactor{salt: b}
}

// NewWithSalt is the deterministic constructor for tests (fixed salt → fixed
// masked tokens), mirroring the injected-clock discipline of the engine tests.
func NewWithSalt(salt []byte) Redactor {
	return &redactor{salt: append([]byte(nil), salt...)}
}

func (r *redactor) Struct(v any) any { return r.Classify(v).Value }

func (r *redactor) Classify(v any) Result {
	acc := Result{ClassMax: ClassPublic}
	acc.Value = r.walk(reflect.ValueOf(v), ClassInternal, &acc)
	return acc
}

// walk redacts rv. ctx is the declared class that applies to a SCALAR leaf; for
// structs/maps/slices the elements carry their own class (struct tags) and ctx
// only propagates to scalar leaves inside containers.
func (r *redactor) walk(rv reflect.Value, ctx DataClass, acc *Result) any {
	if !rv.IsValid() {
		return nil
	}
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Struct:
		if t, ok := rv.Interface().(time.Time); ok {
			acc.ClassMax = maxClass(acc.ClassMax, ctx)
			return t.UTC().Format(time.RFC3339)
		}
		return r.walkStruct(rv, acc)
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		out := make([]any, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out = append(out, r.walk(rv.Index(i), ctx, acc))
		}
		return out
	case reflect.Map:
		out := make(map[string]any, rv.Len())
		keys := rv.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface())
		})
		for _, k := range keys {
			out[fmt.Sprint(k.Interface())] = r.walk(rv.MapIndex(k), ctx, acc)
		}
		return out
	default:
		return r.leaf(rv, ctx, acc)
	}
}

func (r *redactor) walkStruct(rv reflect.Value, acc *Result) any {
	t := rv.Type()
	out := make(map[string]any, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, skip := jsonName(f)
		if skip {
			continue
		}
		cls := fieldClass(f)
		switch {
		case cls >= ClassSecret:
			// SECRET / NEVER_EXPORT: dropped entirely, never masked-and-kept.
			acc.Dropped++
		case cls == ClassSensitive:
			out[name] = r.maskValue(rv.Field(i))
			acc.Masked++
			acc.ClassMax = maxClass(acc.ClassMax, ClassInternal) // masked ⇒ INTERNAL-safe
		default:
			acc.ClassMax = maxClass(acc.ClassMax, cls)
			out[name] = r.walk(rv.Field(i), cls, acc)
		}
	}
	return out
}

func (r *redactor) leaf(rv reflect.Value, ctx DataClass, acc *Result) any {
	if ctx == ClassSensitive {
		acc.Masked++
		acc.ClassMax = maxClass(acc.ClassMax, ClassInternal)
		return r.maskValue(rv)
	}
	acc.ClassMax = maxClass(acc.ClassMax, ctx)
	if !rv.CanInterface() {
		return nil
	}
	return rv.Interface()
}

func (r *redactor) maskValue(rv reflect.Value) any {
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() == reflect.String {
		return r.maskString(rv.String())
	}
	// Non-string SENSITIVE: reveal neither value nor magnitude/shape.
	return "REDACTED"
}

// maskString maps a SENSITIVE string to a stable per-bundle salted token; the
// same input yields the same token WITHIN a bundle (correlation) but not across
// bundles (the salt is fresh and never exported).
func (r *redactor) maskString(s string) string {
	if s == "" {
		return ""
	}
	h := hmac.New(sha256.New, r.salt)
	h.Write([]byte(s))
	return "mask_" + hex.EncodeToString(h.Sum(nil))[:12]
}

// fieldClass resolves a field's DataClass from its `redact:"..."` tag, failing
// closed to SENSITIVE for an absent or unknown tag (REDACTION-MODEL §9).
func fieldClass(f reflect.StructField) DataClass {
	tag := strings.TrimSpace(f.Tag.Get("redact"))
	if tag == "" {
		return DefaultClass
	}
	c, ok := ParseClass(tag)
	if !ok {
		return DefaultClass
	}
	return c
}

// jsonName returns the section-JSON key for a field (honoring the json tag) and
// whether the field is explicitly skipped (`json:"-"`).
func jsonName(f reflect.StructField) (string, bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", true
	}
	name := f.Name
	if tag != "" {
		if first := strings.Split(tag, ",")[0]; first != "" {
			name = first
		}
	}
	return name, false
}
