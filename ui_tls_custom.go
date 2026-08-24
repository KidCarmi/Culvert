package main

import (
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// A custom UI TLS certificate uploaded via POST /api/certs/upload
// (target="ui") used to be validated and then discarded: apiCertsUpload told
// the admin "restart required to activate" but never wrote the cert/key
// anywhere, so restarting changed nothing and the instruction was false —
// exactly the kind of broken recovery path this product review exists to
// catch. It now persists to a fixed path under dataDir (the same durability
// idiom CHAOS-50 established for the MITM CA upload) so a restart genuinely
// picks it up, and reports the true outcome instead of a canned message.
const (
	customUITLSCertFile = "ui_tls_cert.pem"
	customUITLSKeyFile  = "ui_tls_key.pem"
)

// uiCustomTLSActive records whether the RUNNING UI server was started using
// the persisted custom cert (set once at startup by resolveUITLSCertKey) —
// distinct from customUITLSFilesPresent(), which only says a cert is ON
// DISK and will take effect on the NEXT restart. Together they let an admin
// tell "uploaded" apart from "uploaded and live" instead of guessing.
var uiCustomTLSActive bool

func customUITLSCertPath() string { return filepath.Join(dataDir, customUITLSCertFile) }
func customUITLSKeyPath() string  { return filepath.Join(dataDir, customUITLSKeyFile) }

// customUITLSFilesPresent reports whether a previously uploaded UI cert/key
// pair is on disk.
func customUITLSFilesPresent() bool {
	if _, err := os.Stat(customUITLSCertPath()); err != nil {
		return false
	}
	if _, err := os.Stat(customUITLSKeyPath()); err != nil {
		return false
	}
	return true
}

// persistCustomUITLS durably writes an admin-uploaded UI cert/key pair so a
// subsequent restart activates it. The key is written 0600 (private key
// material); the cert 0644 (public, and self-signed cert generation already
// treats it as non-sensitive).
func persistCustomUITLS(certPEM, keyPEM []byte) error {
	if err := fileutil.AtomicWrite(customUITLSCertPath(), certPEM, 0644); err != nil {
		return err
	}
	return fileutil.AtomicWrite(customUITLSKeyPath(), keyPEM, 0600)
}

// resolveUITLSCertKey folds a persisted custom UI cert into startup cert/key
// resolution: an explicit -tls-cert/-tls-key (flag or YAML) always wins, and
// otherwise a GUI-uploaded cert (if any) is used before falling back to the
// auto self-signed certificate. Sets uiCustomTLSActive so the admin API can
// report whether the running server is actually using it.
func resolveUITLSCertKey(cert, key string) (string, string) {
	if cert != "" || key != "" {
		return cert, key
	}
	if customUITLSFilesPresent() {
		uiCustomTLSActive = true
		return customUITLSCertPath(), customUITLSKeyPath()
	}
	return cert, key
}
