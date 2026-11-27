package main

import (
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// formulaLead reports whether a spreadsheet would evaluate cell as a formula
// (CWE-1236): Excel, LibreOffice and Google Sheets all treat a cell whose
// first byte is one of these as an expression, not as text.
func formulaLead(cell string) bool {
	return cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0]))
}

func csvRows(t *testing.T, body string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v", err)
	}
	return rows
}

// TestExportCSV_ProxyClientCannotPlantAFormula drives the real request path:
// an UNAUTHENTICATED proxy client names a destination host that is a
// spreadsheet formula. The proxy refuses the request (default deny) and logs
// it, and the traffic-log CSV a viewer downloads from /api/export must not
// hand that host to the spreadsheet as an expression.
func TestExportCSV_ProxyClientCannotPlantAFormula(t *testing.T) {
	setupProxyTest(t)
	hosts := []string{`=HYPERLINK("x")`, "=2+5", "+1", "-1"}
	for _, h := range hosts {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+h+"/", http.NoBody)
		if err != nil {
			t.Fatalf("host %q does not parse as a request target: %v", h, err)
		}
		req.RemoteAddr = "203.0.113.9:1234"
		handleRequest(httptest.NewRecorder(), req)
	}

	w := httptest.NewRecorder()
	apiExport(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/export?format=csv", http.NoBody))
	rows := csvRows(t, w.Body.String())

	seen := map[string]bool{}
	for _, row := range rows[1:] {
		for col, cell := range row {
			if formulaLead(cell) {
				t.Errorf("row %q: column %q starts a formula: %q", row, rows[0][col], cell)
			}
		}
		// The value itself must survive, only neutralized: "'" + original.
		seen[strings.TrimPrefix(row[5], "'")] = true
	}
	for _, h := range hosts {
		if !seen[h] {
			t.Errorf("host %q is missing from the export (negative control: the entry must be logged, not dropped)", h)
		}
	}
}

// TestExportCSV_AuditCellsCannotStartAFormula pins the same rule on the audit
// export's encoder, whose Object/Detail/Before/After carry client-influenced
// values (login names, node ids, hostnames).
func TestExportCSV_AuditCellsCannotStartAFormula(t *testing.T) {
	w := httptest.NewRecorder()
	writeAuditExport(w, "csv", []AuditEntry{{
		TS: 1, Time: "t", Actor: "@admin", Action: "auth.login.fail",
		Object: "=2+5", ObjectID: "+id", Detail: "-detail", Before: "\tb", After: "plain",
	}})
	rows := csvRows(t, w.Body.String())
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want header + 1", len(rows))
	}
	want := []string{"1", "t", "'@admin", "auth.login.fail", "'=2+5", "'+id", "'-detail", "'\tb", "plain"}
	for i, cell := range rows[1] {
		if cell != want[i] {
			t.Errorf("column %q = %q, want %q", rows[0][i], cell, want[i])
		}
	}
}

// TestCSVTextCell_LeavesOrdinaryValuesAlone is the negative control: a value
// that cannot start a formula is exported byte for byte.
func TestCSVTextCell_LeavesOrdinaryValuesAlone(t *testing.T) {
	for _, v := range []string{"", "example.com", "203.0.113.9", "a=b", "x-y", "user@example.com", "'quoted"} {
		if got := csvTextCell(v); got != v {
			t.Errorf("csvTextCell(%q) = %q, want it unchanged", v, got)
		}
	}
}
