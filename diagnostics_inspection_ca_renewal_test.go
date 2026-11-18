package main

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

func inspectionCARenewalRows() []OperatorContractCheck {
	var out []OperatorContractCheck
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "inspection_ca_renewal" {
			out = append(out, c)
		}
	}
	return out
}

// loadImportedCAWithExpiry installs an administrator-supplied (imported) CA,
// exactly as Certificates → Upload Custom Certificate does.
func loadImportedCAWithExpiry(t *testing.T, notAfter time.Time) {
	t.Helper()
	swapInspectionCA(t)
	certPEM, keyPEM := newCAPair(t, "Imported Test CA", time.Now().Add(-time.Hour), notAfter)
	if err := certMgr.LoadCustomCA(certPEM, keyPEM); err != nil {
		t.Fatalf("LoadCustomCA: %v", err)
	}
	if certMgr.Provenance() != ca.ProvenanceImported {
		t.Fatalf("provenance = %q, want imported", certMgr.Provenance())
	}
}

func TestDiagnostics_InspectionCARenewal_ImportedNearExpiryWarns(t *testing.T) {
	loadImportedCAWithExpiry(t, time.Now().Add(10*24*time.Hour+time.Hour))
	rows := inspectionCARenewalRows()
	if len(rows) != 1 {
		t.Fatalf("want one inspection_ca_renewal row, got %d", len(rows))
	}
	r := rows[0]
	if r.Status != diagWarn {
		t.Errorf("status = %q, want warn", r.Status)
	}
	for _, want := range []string{"10 day(s)", "NOT be renewed automatically", "provenance: imported", "refused, not bypassed"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("message lacks %q: %s", want, r.Message)
		}
	}
	if !strings.Contains(r.OperatorAction, "Upload Custom Certificate") {
		t.Errorf("action does not name the GUI remedy: %s", r.OperatorAction)
	}
	if strings.Contains(r.Message, "Imported Test CA") {
		t.Errorf("row must not carry the CA subject: %s", r.Message)
	}
	// The root_ca row is unchanged: still usable, still OK.
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "root_ca" && c.Status != diagOK {
			t.Errorf("root_ca status changed to %q", c.Status)
		}
	}
}

// Negative controls: no row where the existing behavior already covers it.
func TestDiagnostics_InspectionCARenewal_NoRow(t *testing.T) {
	t.Run("imported with ample validity", func(t *testing.T) {
		loadImportedCAWithExpiry(t, time.Now().Add(365*24*time.Hour))
		if rows := inspectionCARenewalRows(); len(rows) != 0 {
			t.Fatalf("unexpected row: %+v", rows)
		}
	})
	t.Run("managed CA inside the window is renewed automatically", func(t *testing.T) {
		installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(5*24*time.Hour))
		if rows := inspectionCARenewalRows(); len(rows) != 0 {
			t.Fatalf("unexpected row for managed CA: %+v", rows)
		}
	})
	t.Run("expired CA is reported by root_ca", func(t *testing.T) {
		loadImportedCAWithExpiry(t, time.Now().Add(-time.Hour))
		if rows := inspectionCARenewalRows(); len(rows) != 0 {
			t.Fatalf("unexpected row for expired CA: %+v", rows)
		}
	})
	t.Run("no CA loaded", func(t *testing.T) {
		swapInspectionCA(t)
		if rows := inspectionCARenewalRows(); len(rows) != 0 {
			t.Fatalf("unexpected row with no CA: %+v", rows)
		}
	})
}

func TestDiagnostics_InspectionCARenewal_UnknownProvenanceAction(t *testing.T) {
	got := inspectionCARenewalAction(ca.ProvenanceUnknown)
	for _, want := range []string{caProvenanceEnv + "=culvert-managed", "=imported", "restart"} {
		if !strings.Contains(got, want) {
			t.Errorf("unknown-provenance action lacks %q: %s", want, got)
		}
	}
}
