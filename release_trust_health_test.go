package main

import "testing"

func TestCheckReleaseCatalogTrust(t *testing.T) {
	prev := currentReleaseManager()
	t.Cleanup(func() { setReleaseManager(prev) })

	setReleaseManager(nil)
	if got := checkReleaseCatalogTrust(); len(got) != 0 {
		t.Fatalf("no manager: want no rows, got %v", got)
	}
	setReleaseManager(&releaseManager{verifyMode: VerifyEnforce})
	if got := checkReleaseCatalogTrust(); len(got) != 0 {
		t.Fatalf("enforce: want no rows, got %v", got)
	}
	for _, m := range []VerifyMode{VerifyPermissive, VerifyDisabled} {
		setReleaseManager(&releaseManager{verifyMode: m})
		got := checkReleaseCatalogTrust()
		if len(got) != 1 {
			t.Fatalf("%s: want 1 row, got %d", m, len(got))
		}
		c := got[0]
		if c.Code != "release_catalog_trust" || c.Status != diagWarn || c.OperatorAction == "" {
			t.Fatalf("%s: unexpected row %+v", m, c)
		}
	}
}

func TestOperatorContractIncludesReleaseCatalogTrustWhenBreakGlass(t *testing.T) {
	resetDiagVerdictGlobals(t)
	prev := currentReleaseManager()
	t.Cleanup(func() { setReleaseManager(prev) })
	setReleaseManager(&releaseManager{verifyMode: VerifyPermissive})
	if findDiagnosticCheck(buildOperatorContract(), "release_catalog_trust") == nil {
		t.Fatal("break-glass row missing from operator contract")
	}
	setReleaseManager(&releaseManager{verifyMode: VerifyEnforce})
	if findDiagnosticCheck(buildOperatorContract(), "release_catalog_trust") != nil {
		t.Fatal("enforce mode must not add a row")
	}
}
