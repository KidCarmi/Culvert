package main

// csvTextCell neutralizes a text value for a CSV download (CWE-1236).
//
// encoding/csv already quotes commas, quotes and newlines, so a value cannot
// break out of its cell. What it cannot prevent is the spreadsheet evaluating
// the cell: Excel, LibreOffice and Google Sheets treat a cell that starts with
// '=', '+', '-', '@', TAB or CR as a formula. The traffic and audit exports
// carry values chosen by unauthenticated parties (a proxied request's host, a
// failed login's user name), so such a cell gets a leading apostrophe, which
// spreadsheets read as "this is text". Every other value is exported byte for
// byte, and the JSON exports are untouched.
func csvTextCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// csvTextRow applies csvTextCell to every cell of a row of text values.
func csvTextRow(cells ...string) []string {
	for i := range cells {
		cells[i] = csvTextCell(cells[i])
	}
	return cells
}
