package main

import (
	"strings"
	"testing"
)

func TestOCSPCoverageDiagnostics(t *testing.T) {
	orig := globalOCSP.Enabled()
	t.Cleanup(func() {
		if orig {
			globalOCSP.Enable()
		} else {
			globalOCSP.Disable()
		}
	})

	globalOCSP.Disable()
	if rows := checkOCSPCoverage(); len(rows) != 0 {
		t.Fatalf("disabled checker must add no row, got %+v", rows)
	}

	globalOCSP.Enable()
	rows := checkOCSPCoverage()
	if len(rows) != 1 {
		t.Fatalf("enabled checker must add exactly one row, got %d", len(rows))
	}
	r := rows[0]
	if r.Code != "ocsp_coverage" || r.Status != diagWarn {
		t.Fatalf("unexpected row %+v", r)
	}
	if !strings.Contains(r.Message, "ssl_inspect_origin") || strings.Contains(r.Message, "connect_bypass") {
		t.Fatalf("message must name the unchecked enforcing path only: %q", r.Message)
	}
	if r.OperatorAction == "" {
		t.Fatal("warn row needs an operator action")
	}

	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "ocsp_coverage" {
			found = true
		}
	}
	if !found {
		t.Fatal("ocsp_coverage row missing from the assembled contract")
	}
}
