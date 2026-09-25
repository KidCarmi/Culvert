package upstreamclient

// Isolated deterministic fixtures for paths whose coverage previously depended
// on timing; see roadmap/CI-REDESIGN.md stage 5B.
//
// classifyTransportError's two timeout branches were reached only through live
// transport tests, where whether a stalled leg surfaces as context.Canceled,
// context.DeadlineExceeded, or a net.Error with Timeout() depends on which of
// the request context, the client deadline and the dialer fires first. The
// fixtures below hand the classifier each error shape directly.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// isolationNetTimeout is a net.Error that reports Timeout() and is NOT
// context.DeadlineExceeded, so only the net.Error branch can classify it. Its
// text carries a marker that must never reach the classified error.
type isolationNetTimeout struct{}

func (isolationNetTimeout) Error() string {
	return "read tcp 10.9.8.7:443: i/o timeout SECRET-UPSTREAM-DETAIL"
}
func (isolationNetTimeout) Timeout() bool   { return true }
func (isolationNetTimeout) Temporary() bool { return true }

const isolationRawMarker = "SECRET-UPSTREAM-DETAIL"

func assertSanitizedTimeout(t *testing.T, raw, got error, wantDetail string) {
	t.Helper()
	if r := mcperr.ReasonOf(got); r != mcperr.ReasonUpstreamTimeout {
		t.Fatalf("reason = %v, want %v", r, mcperr.ReasonUpstreamTimeout)
	}
	var ke *mcperr.Error
	if !errors.As(got, &ke) {
		t.Fatalf("classified error %T is not a kernel *mcperr.Error", got)
	}
	if ke.Detail != wantDetail {
		t.Fatalf("detail = %q, want %q", ke.Detail, wantDetail)
	}
	if strings.Contains(got.Error(), isolationRawMarker) || strings.Contains(got.Error(), "10.9.8.7") {
		t.Fatalf("classified error embeds raw transport text: %q", got.Error())
	}
	if errors.Unwrap(got) != nil {
		t.Fatalf("classified error wraps the raw cause (%v); it must be a fresh sanitized error", errors.Unwrap(got))
	}
	if errors.Is(got, raw) {
		t.Fatal("classified error still matches the raw transport error")
	}
}

// Pins transport.go classifyTransportError
// `errors.Is(err, context.DeadlineExceeded)` → ReasonUpstreamTimeout
// "deadline exceeded". Previously reached only when a live leg's deadline
// happened to fire before its cancel or its dialer timeout.
func TestIsolation_ClassifyTransportError_DeadlineExceeded(t *testing.T) {
	raw := fmt.Errorf("post %q: %s: %w", "https://10.9.8.7/mcp", isolationRawMarker, context.DeadlineExceeded)
	assertSanitizedTimeout(t, raw, classifyTransportError(raw), "deadline exceeded")
}

// Pins transport.go classifyTransportError's net.Error `Timeout()` branch →
// ReasonUpstreamTimeout "network timeout". Previously reached only when a
// socket-level deadline fired before the request context did.
func TestIsolation_ClassifyTransportError_NetTimeout(t *testing.T) {
	raw := fmt.Errorf("post %q: %w", "https://10.9.8.7/mcp", isolationNetTimeout{})
	if errors.Is(raw, context.DeadlineExceeded) {
		t.Fatal("fixture precondition: the net timeout must not also be context.DeadlineExceeded")
	}
	assertSanitizedTimeout(t, raw, classifyTransportError(raw), "network timeout")
}
