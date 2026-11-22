//go:build lifecycle_conformance

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// files are the lifecycle sources that get mutated, relative to cmd/culvert-maint.
var files = []string{
	"internal/server/reconcile_decision.go", "internal/server/reconcile_validate.go",
	"internal/server/journal_phases.go", "internal/server/inline_rollback.go",
	"internal/server/rollback_stages.go", "internal/server/handlers_upgrade_apply.go",
	"internal/ops/orchestrator.go",
}

// mutant is one single-line change of one source file.
type mutant struct {
	File string `json:"file"`
	Line int    `json:"line"` // 1-based
	Op   string `json:"op"`
	New  string `json:"new"`
	Old  string `json:"old"`
}

// swap replaces every match of an operator. match returns the byte length of the
// operator at code[i:], or 0 when there is none.
type swap struct {
	match func(code string, i int) int
	rep   string
}

func literal(tok string) func(string, int) int {
	return func(code string, i int) int {
		if strings.HasPrefix(code[i:], tok) {
			return len(tok)
		}
		return 0
	}
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// word matches tok only as a whole identifier.
func word(tok string) func(string, int) int {
	return func(code string, i int) int {
		end := i + len(tok)
		if !strings.HasPrefix(code[i:], tok) || (i > 0 && isWordByte(code[i-1])) || (end < len(code) && isWordByte(code[end])) {
			return 0
		}
		return len(tok)
	}
}

// bare matches the single byte c when it is neither preceded by a byte of notBefore
// nor followed by a byte of notAfter, so that `>` is not found inside `->` or `>=`, nor `<` inside `<-`, `<=` or `<<`.
func bare(c byte, notBefore, notAfter string) func(string, int) int {
	return func(code string, i int) int {
		if code[i] != c || (i > 0 && strings.IndexByte(notBefore, code[i-1]) >= 0) ||
			(i+1 < len(code) && strings.IndexByte(notAfter, code[i+1]) >= 0) {
			return 0
		}
		return 1
	}
}

var swaps = []swap{
	{literal("=="), "!="}, {literal("!="), "=="}, {literal("&&"), "||"}, {literal("||"), "&&"},
	{word("true"), "false"}, {word("false"), "true"},
	{literal(">="), ">"}, {bare('>', "-=<>", "="), ">="}, {bare('<', "<=", "-=<"), "<="},
}

var (
	ifLine    = regexp.MustCompile(`^(\s*)if (.+) \{\s*$`)
	deletable = regexp.MustCompile(`^\s*(acc\.\w+ = .*|rec\.\w+ = .*|racc\.\w+ = .*|s\.advanceJournalPhaseBestEffort\(.*\)|` +
		`\*failedPostRestart = true|step\.\w+ = .*|promotedReason = .*|firstReason = .*|` +
		`finalState = .*|finalReason = .*)$`)
	indent = regexp.MustCompile(`^\s*`)
)

// codePart returns the text before any // comment, with string, rune and raw-string
// literals blanked byte for byte, so that an operator is never mutated inside them and
// offsets into the result are offsets into line.
func codePart(line string) string {
	out := make([]byte, 0, len(line))
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			out = append(out, ' ')
			switch c {
			case '\\':
				out = append(out, ' ')
				i++
			case quote:
				quote = 0
			}
		case c == '"' || c == '`' || c == '\'':
			quote = c
			out = append(out, ' ')
		case strings.HasPrefix(line[i:], "//"):
			return string(out)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// lineMutants returns every mutant of one source line, operators first.
func lineMutants(file string, ln int, line string) []mutant {
	code := codePart(line)
	trimmed := strings.TrimSpace(code)
	if trimmed == "" || strings.HasPrefix(trimmed, "import") || strings.HasPrefix(trimmed, "package") ||
		strings.Contains(line, "nolint") {
		return nil
	}
	var out []mutant
	add := func(op, repl string) {
		out = append(out, mutant{File: file, Line: ln, Op: op, New: repl, Old: line})
	}
	for _, sw := range swaps {
		for i := 0; i < len(code); {
			n := sw.match(code, i)
			if n == 0 {
				i++
				continue
			}
			add(code[i:i+n]+" -> "+sw.rep, line[:i]+sw.rep+line[i+n:])
			i += n
		}
	}
	if m := ifLine.FindStringSubmatch(code); len(m) == 3 && !strings.Contains(m[2], ":=") && !strings.Contains(m[2], ";") {
		add("negate condition", m[1]+"if !("+condition(line)+") {")
	}
	if deletable.MatchString(strings.TrimRight(code, " \t\r\n\v\f")) {
		add("delete statement", indent.FindString(line)+"// mutant: deleted")
	}
	return out
}

// condition strips the leading "if " and the trailing " {" from an if line.
func condition(line string) string {
	r := []rune(strings.TrimSpace(line))
	if len(r) < 5 {
		return ""
	}
	return string(r[3 : len(r)-2])
}

// candidates lists every mutant of the lifecycle sources under root, in file and line order.
func candidates(root string) ([]mutant, error) {
	var out []mutant
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, f)) //nolint:gosec // fixed list under the given checkout
		if err != nil {
			return nil, err
		}
		for i, line := range strings.Split(string(b), "\n") {
			out = append(out, lineMutants(f, i+1, line)...)
		}
	}
	return out, nil
}
