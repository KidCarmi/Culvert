package main

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// The OCSP engine tests moved to internal/ocsp (ADR-0002); these two cover
// the main-owned transport wiring (P5.3 upstream-transport contract).

func TestConfigureTransportOCSP(t *testing.T) {
	transport := &http.Transport{}
	ConfigureTransportOCSP(transport)
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should be set")
	}
	if transport.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate should be set")
	}
	if transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("VerifyConnection should be set")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("MinVersion should be TLS 1.3")
	}
}

func TestConfigureTransportOCSP_ExistingConfig(t *testing.T) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	ConfigureTransportOCSP(transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("should preserve existing MinVersion")
	}
	if transport.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate should be set")
	}
}
