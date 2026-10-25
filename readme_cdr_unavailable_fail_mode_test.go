package main

// readme_cdr_unavailable_fail_mode_test.go — the README's `-cdr-fail-mode` row
// is operator-facing documentation of a SECURITY POSTURE, and it asserted the
// opposite of what the code does.
//
// #1668 (SEC-CDRUNAVAIL-1) closed the fail-closed bypass on the unavailable
// path: when CDR is enabled and no instance can be called — initial dial failed
// at startup, nothing enrolled, or every circuit breaker open —
// cdrUnavailableOutcome (cdr_proxy.go) now applies `fail_mode` instead of
// returning an unconditional pass, so `closed` refuses the document with block
// reason cdrUnavailableBlockReason and counts it in statCDRFailClosed. That
// change updated docs/OPERATIONS.md §6 and config.example.yaml, and left
// README.md still telling the operator that in this exact state "CDR is skipped
// and the file passes through in either mode".
//
// Stale prose on a fail-closed guarantee is not cosmetic. An operator reading
// it concludes that `fail_mode: closed` does NOT cover a Sluice outage — the
// one case the setting exists for — and either plans a compensating control the
// appliance already applies, or (worse, in the other direction) believes a
// deployment is passing documents through when it is in fact refusing them and
// mis-diagnoses the resulting CDR_BLOCKED events. AGENTS.md's evidence order
// (source → tests → CI → configuration → deployment → prose) puts the fix in
// the prose, which is what this test pins.
//
// It asserts the DOC against the CODE's own identifiers rather than against a
// copy of the sentence, so a later change to the behaviour fails here too
// instead of silently re-introducing the drift.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// readmeCDRFailModeRow returns the README table row documenting -cdr-fail-mode.
func readmeCDRFailModeRow(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "|") && strings.Contains(line, "-cdr-fail-mode") {
			return line
		}
	}
	t.Fatal("README.md has no table row documenting -cdr-fail-mode")
	return ""
}

func TestREADMEDocumentsCDRUnavailableFailMode(t *testing.T) {
	row := readmeCDRFailModeRow(t)

	// Negative control: the retired claim. Any wording that tells the operator
	// the unavailable path passes the file through regardless of fail_mode
	// contradicts cdrUnavailableOutcome.
	for _, retired := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)passes through in either mode`),
		regexp.MustCompile(`(?i)CDR is skipped and the file passes through`),
		regexp.MustCompile(`(?i)skipped and the (file|document) passes`),
	} {
		if retired.MatchString(row) {
			t.Errorf("README -cdr-fail-mode row still carries the pre-#1668 fail-open claim %q;\n"+
				"cdrUnavailableOutcome applies fail_mode on the unavailable path (block reason %q)\nrow: %s",
				retired, cdrUnavailableBlockReason, row)
		}
	}

	// Positive control: the row must name the refusal the code actually
	// performs, by the same block reason the request log and block page carry.
	if !strings.Contains(row, cdrUnavailableBlockReason) {
		t.Errorf("README -cdr-fail-mode row does not name the block reason %q that fail_mode=closed "+
			"produces when no instance is available\nrow: %s", cdrUnavailableBlockReason, row)
	}

	// And it must still document the fail-OPEN half, which is unchanged and is
	// the default: an operator must not read the fix as "closed is now the
	// default".
	if !regexp.MustCompile(`(?i)unsanitized|unsanitised`).MatchString(row) {
		t.Errorf("README -cdr-fail-mode row no longer says that fail_mode=open delivers the file "+
			"unsanitized on the unavailable path\nrow: %s", row)
	}
}

// The behavioural half of this contract is already pinned next to the code, by
// cdr_fail_closed_unavailable_test.go (TestCDRUnavailableOutcome_AppliesFailMode
// for the decision table, TestRunCDRStage_UnavailableFailClosedRefusesTheTunnel
// for the proxy path). This file deliberately adds no second copy of it: those
// tests assert ABSOLUTE values of statCDRFailClosed, and a doc test that called
// cdrUnavailableOutcome would increment that counter and make them order-
// dependent. Reading the block-reason constant is enough to tie the prose to
// the implementation without touching any global.
