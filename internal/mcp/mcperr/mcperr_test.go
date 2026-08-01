package mcperr

import (
	"errors"
	"strings"
	"testing"
)

func TestReasonCodesStable(t *testing.T) {
	// The machine strings are a contract; pin them.
	want := map[Reason]string{
		ReasonNone:                 "none",
		ReasonMalformedJSON:        "malformed_json",
		ReasonInvalidJSONRPC:       "invalid_jsonrpc",
		ReasonUnsupportedBatch:     "unsupported_batch",
		ReasonUnsupportedVersion:   "unsupported_version",
		ReasonUnsupportedMethod:    "unsupported_method",
		ReasonResourceLimit:        "resource_limit",
		ReasonInvalidLifecycle:     "invalid_lifecycle",
		ReasonUncorrelatedResponse: "uncorrelated_response",
		ReasonDuplicateCompletion:  "duplicate_completion",
		ReasonInvalidCancellation:  "invalid_cancellation",
		ReasonLateCancellation:     "late_cancellation",
	}
	for r, code := range want {
		if r.Code() != code {
			t.Fatalf("Reason(%d).Code() = %q, want %q", r, r.Code(), code)
		}
	}
}

func TestReasonOfAndIs(t *testing.T) {
	base := New(ReasonResourceLimit, "decode", "too big")
	wrapped := Wrap(ReasonMalformedJSON, "decode", "bad", base)
	if ReasonOf(wrapped) != ReasonMalformedJSON {
		t.Fatalf("ReasonOf outer = %v", ReasonOf(wrapped))
	}
	if !errors.Is(wrapped, base) {
		t.Fatal("errors.Is should match the wrapped cause")
	}
	if ReasonOf(errors.New("plain")) != ReasonNone {
		t.Fatal("plain error reason should be None")
	}
	// Is matches by reason.
	other := New(ReasonResourceLimit, "", "")
	if !errors.Is(base, other) {
		t.Fatal("same-reason errors should match via Is")
	}
}

func TestSanitizeStripsHostileBytes(t *testing.T) {
	in := "ok\x00\n\"\\\x7f" + strings.Repeat("A", 200)
	out := Sanitize(in, 32)
	if strings.ContainsAny(out, "\x00\n\"\\") || strings.Contains(out, "\x7f") {
		t.Fatalf("Sanitize left hostile bytes: %q", out)
	}
	if len(out) > 33 { // 32 + truncation marker
		t.Fatalf("Sanitize did not bound length: %d", len(out))
	}
	if !strings.HasPrefix(out, "ok") {
		t.Fatalf("Sanitize mangled safe prefix: %q", out)
	}
}

func TestErrorMessageHasNoRawInput(t *testing.T) {
	// The Error() text is a fixed shape; detail is developer-authored.
	e := New(ReasonMalformedJSON, "decode", "invalid UTF-8")
	if got := e.Error(); got != "mcp: decode: malformed_json: invalid UTF-8" {
		t.Fatalf("Error() = %q", got)
	}
}
