package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestLogSafeOpID_IsIdentityOnValidIDsAndStripsLineBreaks pins the barrier's
// contract: a canonical ULID (every real caller's value) passes through
// byte-identical, and the only bytes that could forge a second log record are
// removed. It deliberately does NOT assert a broader scrub — the op id is
// validated to ULID before it reaches these sites; the barrier exists for the
// analyzer, not as a second validator.
func TestLogSafeOpID_IsIdentityOnValidIDsAndStripsLineBreaks(t *testing.T) {
	const ulid = "01J9XK2Q3C8M4N5P6R7S8T9V0W"
	if !validOpID(ulid) {
		t.Fatalf("fixture %q is not a valid op id", ulid)
	}
	if got := logSafeOpID(ulid); got != ulid {
		t.Fatalf("valid id altered: %q -> %q", ulid, got)
	}
	if got := logSafeOpID("a\nb\rc"); got != "abc" {
		t.Fatalf("line breaks survived: %q", got)
	}
}

// TestWall_ReconcileLogSitesCarryTheInlineBarrier is the structural wall for
// gosec G706 (CWE-117): the two functions that take an op id that originated
// on the HTTP path (handleReconcile -> adopt/retireRecord) must spell the
// sanitizer INLINE, because the taint engine clears taint only at the
// sanitizer call site — routing through logSafeOpID would read cleaner and
// silently re-open the finding. The expression is pinned against the helper's
// body so the two cannot drift.
func TestWall_ReconcileLogSitesCarryTheInlineBarrier(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "reconcile_startup.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	src := mustRead(t, "reconcile_startup.go")
	bodyOf := func(name string) string {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name != name || fd.Body == nil {
				continue
			}
			return src[fset.Position(fd.Body.Pos()).Offset:fset.Position(fd.Body.End()).Offset]
		}
		t.Fatalf("function %s not found", name)
		return ""
	}
	const barrier = `strings.ReplaceAll(strings.ReplaceAll(opID, "\n", ""), "\r", "")`
	if !strings.Contains(bodyOf("logSafeOpID"), barrier) {
		t.Fatalf("logSafeOpID no longer carries the pinned expression %s", barrier)
	}
	for _, fn := range []string{"adopt", "retireRecord"} {
		body := bodyOf(fn)
		if !strings.Contains(body, "opID = "+barrier) {
			t.Errorf("%s: inline CWE-117 barrier missing (gosec G706 would fire): want `opID = %s` as a statement", fn, barrier)
		}
		if strings.Contains(body, "logSafeOpID(") {
			t.Errorf("%s: routes through logSafeOpID — not a barrier for the taint engine; spell it inline", fn)
		}
	}
}
