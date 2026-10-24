package main

import (
	"strings"
	"testing"
)

func TestCheckReleaseVerifyPosture(t *testing.T) {
	prev := currentReleaseManager()
	t.Cleanup(func() { setReleaseManager(prev) })

	setReleaseManager(nil)
	if got := checkReleaseVerifyPosture(); len(got) != 0 {
		t.Fatalf("no manager: want no rows, got %+v", got)
	}
	rm := newReleaseManager(nil, nil)
	rm.verifyMode = VerifyEnforce
	setReleaseManager(rm)
	if got := checkReleaseVerifyPosture(); len(got) != 0 {
		t.Fatalf("enforce: want no rows, got %+v", got)
	}
	for _, mode := range []VerifyMode{VerifyPermissive, VerifyDisabled} {
		rm := newReleaseManager(nil, nil)
		rm.verifyMode = mode
		setReleaseManager(rm)
		got := checkReleaseVerifyPosture()
		if len(got) != 1 {
			t.Fatalf("mode %s: want 1 row, got %d", mode, len(got))
		}
		c := got[0]
		if c.Code != "release_catalog_verify" || c.Status != diagWarn || c.OperatorAction == "" {
			t.Errorf("mode %s: unexpected row %+v", mode, c)
		}
		// verifyIndexSignature rejects an invalid signature only for a configured
		// scheme; permissive with none accepts every catalog, so the row must not
		// claim an unconditional rejection.
		if mode == VerifyPermissive && (!strings.Contains(c.Message, "only for a configured trust scheme") ||
			!strings.Contains(c.Message, "with no trust scheme configured every catalog is accepted")) {
			t.Errorf("permissive: rejection claim must be limited to configured schemes, got %q", c.Message)
		}
		if !strings.Contains(c.OperatorAction, envReleaseCatalogTrustKeys) ||
			!strings.Contains(c.OperatorAction, envReleaseCatalogVerify) {
			t.Errorf("mode %s: remediation must name %s and %s, got %q",
				mode, envReleaseCatalogTrustKeys, envReleaseCatalogVerify, c.OperatorAction)
		}
	}
}

func TestOperatorContract_ReleaseVerifyRowOnlyInBreakGlass(t *testing.T) {
	resetDiagVerdictGlobals(t)
	prev := currentReleaseManager()
	t.Cleanup(func() { setReleaseManager(prev) })

	rm := newReleaseManager(nil, nil)
	rm.verifyMode = VerifyDisabled
	setReleaseManager(rm)
	c := findDiagnosticCheck(buildOperatorContract(), "release_catalog_verify")
	if c == nil {
		t.Fatal("release_catalog_verify row missing from operator contract in break-glass")
	}
	if c.Status != diagWarn {
		t.Fatalf("want warn, got %+v", *c)
	}

	rm = newReleaseManager(nil, nil)
	rm.verifyMode = VerifyEnforce
	setReleaseManager(rm)
	if c := findDiagnosticCheck(buildOperatorContract(), "release_catalog_verify"); c != nil {
		t.Fatalf("enforce mode must not add a row, got %+v", *c)
	}
}
