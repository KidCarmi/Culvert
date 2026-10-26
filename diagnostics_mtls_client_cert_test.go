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

	cases := map[string]mtlsClientCertStatus{
		"failed load": {configured: true, file: "/secret/path/client.pem", lastError: "open /secret/path/client.pem: denied"},
		"expired":     {configured: true, loaded: true, file: "/secret/path/client.pem", notAfter: time.Now().Add(-48 * time.Hour)},
		"expiring":    {configured: true, loaded: true, file: "/secret/path/client.pem", notAfter: time.Now().Add(5*24*time.Hour + time.Hour)},
	}
	for name, st := range cases {
		set(st)
		rows := checkUpstreamMTLSClientCert()
		if len(rows) != 1 || rows[0].Code != "upstream_mtls_client_cert" || rows[0].Status != diagWarn {
			t.Fatalf("%s: unexpected rows %+v", name, rows)
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
