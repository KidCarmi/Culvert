package main

import (
	"strings"
	"testing"
	"time"
)

func TestUpstreamMTLSClientCertDiagnostics(t *testing.T) {
	mtlsClientCertMu.Lock()
	orig := mtlsClientCertState
	mtlsClientCertMu.Unlock()
	t.Cleanup(func() {
		mtlsClientCertMu.Lock()
		mtlsClientCertState = orig
		mtlsClientCertMu.Unlock()
	})

	set := func(s mtlsClientCertStatus) {
		mtlsClientCertMu.Lock()
		mtlsClientCertState = s
		mtlsClientCertMu.Unlock()
	}

	set(mtlsClientCertStatus{})
	if rows := checkUpstreamMTLSClientCert(); len(rows) != 0 {
		t.Fatalf("unconfigured must add no row, got %+v", rows)
	}

	set(mtlsClientCertStatus{configured: true, loaded: true, notAfter: time.Now().Add(200 * 24 * time.Hour)})
	if rows := checkUpstreamMTLSClientCert(); len(rows) != 0 {
		t.Fatalf("healthy cert must add no row, got %+v", rows)
	}

	type tc struct {
		st      mtlsClientCertStatus
		wantMsg string
	}
	cases := map[string]tc{
		"failed load": {mtlsClientCertStatus{configured: true, file: "/secret/path/client.pem", lastError: "open /secret/path/client.pem: denied"}, "failed to load"},
		"expired":     {mtlsClientCertStatus{configured: true, loaded: true, file: "/secret/path/client.pem", notAfter: time.Now().Add(-48 * time.Hour)}, "has expired"},
		// Within the first day after expiry daysUntil truncates to 0; the row
		// must still say expired, not "expires in 0 days".
		"expired 1h ago": {mtlsClientCertStatus{configured: true, loaded: true, file: "/secret/path/client.pem", notAfter: time.Now().Add(-time.Hour)}, "has expired"},
		"expiring":       {mtlsClientCertStatus{configured: true, loaded: true, file: "/secret/path/client.pem", notAfter: time.Now().Add(5*24*time.Hour + time.Hour)}, "expires in 5 days"},
	}
	for name, c := range cases {
		set(c.st)
		rows := checkUpstreamMTLSClientCert()
		if len(rows) != 1 || rows[0].Code != "upstream_mtls_client_cert" || rows[0].Status != diagWarn {
			t.Fatalf("%s: unexpected rows %+v", name, rows)
		}
		if !strings.Contains(rows[0].Message, c.wantMsg) {
			t.Fatalf("%s: message %q does not contain %q", name, rows[0].Message, c.wantMsg)
		}
		if rows[0].OperatorAction == "" || strings.Contains(rows[0].Message, "/secret") || strings.Contains(rows[0].OperatorAction, "/secret") {
			t.Fatalf("%s: action missing or row leaks path: %+v", name, rows[0])
		}
		found := false
		for _, c := range buildOperatorContract().Checks {
			if c.Code == "upstream_mtls_client_cert" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: row missing from the assembled contract", name)
		}
	}
}
