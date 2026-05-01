package main

// D1.2a cold-start tests for the cluster CA cert/key pair.
//
// D1.1f covered: missing both, partial pair, matched/mismatched valid pairs.
// This file fills the remaining gap: empty / truncated / garbage PEM bytes
// where both files exist on disk but at least one is unparseable.
//
// All cases must fail closed via loadFromPEM (called by InitOrLoad once
// partial-pair detection has confirmed both files are present).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeClusterCAFiles(t *testing.T, dir string, certBytes, keyBytes []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.crt"), certBytes, 0o600); err != nil {
		t.Fatalf("write cluster-ca.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.key"), keyBytes, 0o600); err != nil {
		t.Fatalf("write cluster-ca.key: %v", err)
	}
}

func TestColdStart_ClusterCA_BadPair(t *testing.T) {
	// Seed a real CA pair to use as the "valid" half in mixed cases.
	validCert, validKey := seedClusterCAFiles(t)

	cases := []struct {
		name      string
		cert      []byte
		key       []byte
		errSubstr string // substring expected in the error message
	}{
		{
			name:      "both_empty_bytes",
			cert:      []byte{},
			key:       []byte{},
			errSubstr: "no PEM certificate block found",
		},
		{
			name:      "cert_empty_key_valid",
			cert:      []byte{},
			key:       validKey,
			errSubstr: "no PEM certificate block found",
		},
		{
			name:      "cert_valid_key_empty",
			cert:      validCert,
			key:       []byte{},
			errSubstr: "no PEM key block found",
		},
		{
			name:      "cert_garbage_no_pem",
			cert:      []byte("not a PEM block at all\n"),
			key:       validKey,
			errSubstr: "no PEM certificate block found",
		},
		{
			name:      "key_garbage_no_pem",
			cert:      validCert,
			key:       []byte("not a PEM block at all\n"),
			errSubstr: "no PEM key block found",
		},
		{
			name:      "cert_pem_header_garbled_body",
			cert:      []byte("-----BEGIN CERTIFICATE-----\nbm90IHJlYWxseSBhIGNlcnQ=\n-----END CERTIFICATE-----\n"),
			key:       validKey,
			errSubstr: "parse cluster CA cert",
		},
		{
			name: "key_pem_header_garbled_body",
			cert: validCert,
			// Valid base64 but not a real EC private key.
			key:       []byte("-----BEGIN EC PRIVATE KEY-----\nbm90IHJlYWxseSBhIGtleQ==\n-----END EC PRIVATE KEY-----\n"),
			errSubstr: "parse cluster CA key",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeClusterCAFiles(t, dir, c.cert, c.key)

			ca := &clusterCA{}
			err := ca.InitOrLoad(dir)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", c.name)
			}
			if !strings.Contains(err.Error(), c.errSubstr) {
				t.Errorf("error should contain %q, got: %v", c.errSubstr, err)
			}
			// Belt-and-braces: the in-memory CA must not be partially populated.
			if ca.cert != nil || ca.key != nil {
				t.Errorf("clusterCA should not be partially populated on parse failure (cert=%v key=%v)", ca.cert != nil, ca.key != nil)
			}
		})
	}
}
