package mcpacceptance

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// validateFixturePKI validates the operator-provided X.509 identity material for
// an authoritative run BEFORE any Culvert child process launches (the v1.0.203
// incident class: a syntactically valid spec whose qualification certificates had
// expired between preflight and execution reached the live scenario phase and
// failed 30 required criteria as a TLS-unreachable cascade).
//
// It reads the FIXTURE's effective values (not the raw spec) so it checks exactly
// what the runtime consumes: NewFixtureFromEnv has already applied the schema
// defaults (client CA falls back to the server CA; the TLS server name falls back
// to the bind host). Validated, all under standard crypto/x509 verification
// semantics (no custom ASN.1/EKU policy):
//   - the server certificate loads and matches tls_key_file (pair check);
//   - the server chain verifies against server_ca_file for server auth and for
//     the effective TLS server name;
//   - the client certificate (when configured) loads, matches client_key_file,
//     and verifies against the effective client CA for client auth;
//   - every chain verifies at `now` AND at `validThrough`.
//
// Exact time contract (documented here because the repository has no shared PKI
// clock-skew policy to reuse; none is invented): a chain must verify with
// x509.VerifyOptions.CurrentTime = now, and again with CurrentTime = validThrough,
// where validThrough = now + the requested bounded run timeout (the CLI -timeout).
// That is Go's inclusive NotBefore <= t <= NotAfter per chain certificate, with
// zero added skew. The second verification is what rejects material that is valid
// at launch but would expire before the bounded run could complete, including a CA
// expiring mid-run. This is acceptance-run safety only, not a production
// certificate-lifetime policy.
//
// Errors carry the certificate role, the configured path, and NotBefore/NotAfter
// where relevant. They never contain private key, token, or KEK material.
func validateFixturePKI(f *Fixture, now, validThrough time.Time) error {
	if f == nil {
		return errors.New("acceptance: authoritative PKI validation requires a fixture")
	}
	serverRoots, err := loadCAPool("server_ca_file", f.caFile)
	if err != nil {
		return err
	}
	serverLeaf, serverInts, err := loadLeafPair("server", f.serverCertFile, f.serverKeyFile)
	if err != nil {
		return err
	}
	if err := verifyLeafWindow("server", f.serverCertFile, serverLeaf, serverRoots, serverInts, f.serverName, x509.ExtKeyUsageServerAuth, now, validThrough); err != nil {
		return err
	}

	// The client pair is optional at the schema level (the bearer flow needs no
	// client certificate); configuring only half of it is an operator error.
	switch {
	case f.clientCertFile == "" && f.clientKeyFile == "":
		return nil
	case f.clientCertFile == "" || f.clientKeyFile == "":
		return errors.New("acceptance: qualification client certificate requires both client_cert_file and client_key_file (exactly one is configured)")
	}
	clientRoots := serverRoots
	if f.clientCAFile != "" && f.clientCAFile != f.caFile {
		if clientRoots, err = loadCAPool("client_ca_file", f.clientCAFile); err != nil {
			return err
		}
	}
	clientLeaf, clientInts, err := loadLeafPair("client", f.clientCertFile, f.clientKeyFile)
	if err != nil {
		return err
	}
	return verifyLeafWindow("client", f.clientCertFile, clientLeaf, clientRoots, clientInts, "", x509.ExtKeyUsageClientAuth, now, validThrough)
}

// loadCAPool parses a PEM CA bundle into a verification pool. The bytes are only
// public certificate material.
func loadCAPool(field, path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied trust-root path
	if err != nil {
		return nil, fmt.Errorf("acceptance: read qualification %s %q: %w", field, path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("acceptance: qualification %s %q contains no parseable CA certificate", field, path)
	}
	return pool, nil
}

// loadLeafPair loads a certificate/key pair and returns the parsed leaf plus any
// intermediates bundled in the cert file (a fullchain PEM must verify the same
// way the runtime handshake would, where the presented chain supplies them). A
// mismatched or unreadable pair fails here; the error wraps crypto/tls's pairing
// diagnostics, which never include key bytes.
func loadLeafPair(role, certFile, keyFile string) (*x509.Certificate, *x509.CertPool, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Clean(certFile), filepath.Clean(keyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("acceptance: qualification %s certificate/key pair (cert=%q) invalid: %w", role, certFile, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("acceptance: parse qualification %s certificate %q: %w", role, certFile, err)
	}
	var intermediates *x509.CertPool
	for i, der := range pair.Certificate[1:] {
		ic, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("acceptance: parse qualification %s intermediate #%d in %q: %w", role, i+1, certFile, err)
		}
		if intermediates == nil {
			intermediates = x509.NewCertPool()
		}
		intermediates.AddCert(ic)
	}
	return leaf, intermediates, nil
}

// verifyLeafWindow verifies leaf against roots (and serverName when non-empty) at
// `now`, then again at `validThrough`, classifying the failure precisely so the
// operator sees the v1.0.203 class by name instead of a generic chain error.
func verifyLeafWindow(role, path string, leaf *x509.Certificate, roots, intermediates *x509.CertPool, serverName string, eku x509.ExtKeyUsage, now, validThrough time.Time) error {
	opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{eku}}
	if serverName != "" {
		opts.DNSName = serverName
	}
	if _, err := leaf.Verify(opts); err != nil {
		return classifyVerifyError(role, path, leaf, serverName, now, err)
	}
	opts.CurrentTime = validThrough
	if _, err := leaf.Verify(opts); err != nil {
		failing := leaf
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Cert != nil {
			failing = invalid.Cert
		}
		return fmt.Errorf("acceptance: qualification %s certificate chain (cert=%q) expires before the bounded run can complete: valid now but not at %s (subject=%q notAfter=%s): %w",
			role, path, validThrough.UTC().Format(time.RFC3339), failing.Subject.CommonName, failing.NotAfter.UTC().Format(time.RFC3339), err)
	}
	return nil
}

// classifyVerifyError maps an x509 verification failure to a precise, safe pre-run
// error. Timestamps are certificate metadata (public); no key material is included.
// The reported validity window is the FAILING certificate's (a chain rejected for
// an expired CA names the CA's window, not the leaf's).
func classifyVerifyError(role, path string, leaf *x509.Certificate, serverName string, now time.Time, err error) error {
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var unknownAuth x509.UnknownAuthorityError
	failing := leaf
	if errors.As(err, &invalid) && invalid.Cert != nil {
		failing = invalid.Cert
	}
	window := fmt.Sprintf("subject=%q notBefore=%s notAfter=%s now=%s",
		failing.Subject.CommonName, failing.NotBefore.UTC().Format(time.RFC3339), failing.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	switch {
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired && now.Before(failing.NotBefore):
		return fmt.Errorf("acceptance: qualification %s certificate not yet valid (cert=%q, %s): %w", role, path, window, err)
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return fmt.Errorf("acceptance: qualification %s certificate expired (cert=%q, %s): %w", role, path, window, err)
	case errors.As(err, &hostname):
		return fmt.Errorf("acceptance: qualification %s certificate not valid for configured TLS server name %q (cert=%q): %w", role, serverName, path, err)
	case errors.As(err, &unknownAuth):
		return fmt.Errorf("acceptance: qualification %s certificate does not chain to the configured CA (cert=%q): %w", role, path, err)
	default:
		return fmt.Errorf("acceptance: qualification %s certificate chain invalid (cert=%q, %s): %w", role, path, window, err)
	}
}
