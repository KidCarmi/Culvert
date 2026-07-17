package redaction

import (
	"strings"
	"testing"
)

// These tests pin the sighted-consent-gate capture: RetainedFreeForm surfaces the
// INTERNAL free-form string values KEPT (post-scrub) in the shareable output, so
// the human approving an export can review what the precision-first scrubber
// structurally cannot catch (a bare, shapeless secret typed into a rule name /
// endpoint / message). It is a review aid, NOT a redaction control — it never
// changes what is exported, only what the approver can see.

type retSample struct {
	Version  string `json:"version" redact:"public"`    // PUBLIC — not review-worthy, never surfaced
	RuleName string `json:"ruleName" redact:"internal"` // operator free-form, KEPT
	Message  string `json:"message" redact:"internal"`  // diagnostic free-form, KEPT
	Secret   string `json:"secret" redact:"sensitive"`  // masked, never surfaced clear
}

func hasRetained(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestRetained_SurfacesInternalFreeForm(t *testing.T) {
	r := NewWithSalt([]byte("fixed-salt"))
	bareSecret := "prod-db creds Xy9qKp2mLw7zBareValue" // shapeless — the scrubber leaves it
	msg := "dial tcp 10.0.0.5:443: connect: connection refused"
	res := r.Classify(retSample{
		Version: "1.2.3", RuleName: bareSecret, Message: msg, Secret: "s3kr3t-masked-value",
	})

	if !hasRetained(res.RetainedFreeForm, bareSecret) {
		t.Errorf("consent preview must surface the INTERNAL free-form rule name so the approver can see a bare secret the scrubber cannot; got %v", res.RetainedFreeForm)
	}
	if !hasRetained(res.RetainedFreeForm, msg) {
		t.Errorf("consent preview must surface the INTERNAL diagnostic message; got %v", res.RetainedFreeForm)
	}
	// PUBLIC is not review-worthy.
	if hasRetained(res.RetainedFreeForm, "1.2.3") {
		t.Error("PUBLIC field must not be surfaced in the consent preview")
	}
	// SENSITIVE is masked before it ever reaches the kept-string path, so its
	// clear value can never appear in the preview.
	for _, s := range res.RetainedFreeForm {
		if strings.Contains(s, "s3kr3t-masked-value") {
			t.Errorf("SENSITIVE clear value leaked into the consent preview: %q", s)
		}
	}
}

func TestRetained_ScrubbedShapeNotLeaked(t *testing.T) {
	r := NewWithSalt([]byte("fixed-salt"))
	// A self-identifying token embedded in an INTERNAL message: the scrubber
	// redacts it; the retained sample must carry the SCRUBBED form (context kept),
	// never the raw credential.
	raw := "gho_0123456789012345678901234567890123456789"
	res := r.Classify(struct {
		Msg string `json:"msg" redact:"internal"`
	}{Msg: "auth failed: bearer " + raw})

	if res.Scrubbed == 0 {
		t.Fatal("expected the github token shape to be scrubbed")
	}
	for _, s := range res.RetainedFreeForm {
		if strings.Contains(s, raw) {
			t.Errorf("consent preview leaked a scrubbed credential verbatim: %q", s)
		}
	}
}

func TestRetained_BoundedAndDeduped(t *testing.T) {
	r := NewWithSalt([]byte("fixed-salt"))
	// Many identical long INTERNAL values dedupe to one; a huge count is capped.
	type many struct {
		A string `json:"a" redact:"internal"`
		B string `json:"b" redact:"internal"`
		C string `json:"c" redact:"internal"`
	}
	dup := "the same long free-form value repeated"
	res := r.Classify(many{A: dup, B: dup, C: dup})
	n := 0
	for _, s := range res.RetainedFreeForm {
		if s == dup {
			n++
		}
	}
	if n != 1 {
		t.Errorf("identical retained values must dedupe to one; got %d", n)
	}
	if len(res.RetainedFreeForm) > maxRetainedPerResult {
		t.Errorf("retained sample exceeded the per-result cap %d: %d", maxRetainedPerResult, len(res.RetainedFreeForm))
	}
}

func TestRetained_TruncatesLongValue(t *testing.T) {
	r := NewWithSalt([]byte("fixed-salt"))
	long := strings.Repeat("x", maxRetainedLen+50)
	res := r.Classify(struct {
		V string `json:"v" redact:"internal"`
	}{V: long})
	if len(res.RetainedFreeForm) != 1 {
		t.Fatalf("want one retained value, got %d", len(res.RetainedFreeForm))
	}
	// Truncated to the cap plus the ellipsis marker.
	if r := []rune(res.RetainedFreeForm[0]); len(r) != maxRetainedLen+1 {
		t.Errorf("retained value must be truncated to %d runes + ellipsis, got %d runes", maxRetainedLen, len(r))
	}
}
