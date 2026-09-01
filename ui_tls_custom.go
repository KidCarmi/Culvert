package main

import (
	"crypto/tls"
	"fmt"
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

// uiCustomTLSCorrupt records whether resolveUITLSCertKey found a persisted
// cert/key pair on disk that does NOT parse as a matching TLS pair. Without
// this, customUITLSFilesPresent()==true / uiCustomTLSActive==false is
// ambiguous between "uploaded, awaiting the restart that activates it"
// (normal, self-resolving) and "uploaded, but the pair is corrupt or
// mismatched and every future restart will keep falling back to the
// self-signed certificate" (broken, needs a re-upload) — the two states
// look identical to an admin polling GET /api/settings/network, and only
// the second one makes the GUI's "restart to activate" message false.
var uiCustomTLSCorrupt bool

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
	if err := fileutil.AtomicWrite(customUITLSCertPath(), certPEM, 0o644); err != nil {
		return err
	}
	return fileutil.AtomicWrite(customUITLSKeyPath(), keyPEM, 0o600)
}

// customUITLSPairValid reports whether the persisted cert/key pair on disk
// actually parses as a matching TLS key pair — the same check
// http.Server.ListenAndServeTLS performs internally via tls.LoadX509KeyPair.
// customUITLSFilesPresent() only proves the two files EXIST: persistCustomUITLS
// writes them as two separate atomic writes, so a process killed between the
// two (container OOM-kill, docker compose restart, host crash — none of them
// rare) can leave a NEW cert paired with the OLD key, both individually
// well-formed but mismatched. That pair must never reach ListenAndServeTLS,
// whose load failure is fatal (startUI calls logFatalf, which os.Exit(1)s the
// whole process) with no fallback — unlike the self-signed path right below
// it in startUI.
func customUITLSPairValid() bool {
	_, err := tls.LoadX509KeyPair(customUITLSCertPath(), customUITLSKeyPath())
	return err == nil
}

// resolveUITLSCertKey folds a persisted custom UI cert into startup cert/key
// resolution: an explicit -tls-cert/-tls-key (flag or YAML) always wins, and
// otherwise a GUI-uploaded cert (if any, and only if it still parses as a
// matching pair) is used before falling back to the auto self-signed
// certificate. Sets uiCustomTLSActive so the admin API can report whether the
// running server is actually using it.
//
// Called from loadFileConfigAndFlags, which main.go runs BEFORE initLogger —
// the package-level `logger` is still nil here, so this uses fmt.Printf with
// the "[Culvert] " prefix (the same pre-init-safe convention config.go's own
// deprecation notices use), never logger.Printf. logger.Printf on a nil
// *log.Logger panics, which would have reintroduced exactly the unrecoverable
// boot failure this function exists to prevent (Codex review, PR #1228).
func resolveUITLSCertKey(cert, key string) (certPath, keyPath string) {
	if cert != "" || key != "" {
		return cert, key
	}
	if customUITLSFilesPresent() {
		if !customUITLSPairValid() {
			uiCustomTLSCorrupt = true
			fmt.Printf("[Culvert] UITLS: persisted custom UI cert/key pair under %s does not parse as a matching TLS "+
				"pair (interrupted or corrupted upload) — ignoring it and falling back to the auto self-signed "+
				"certificate. Upload a valid pair from the Certificates panel to replace it.\n", dataDir)
			return cert, key
		}
		uiCustomTLSActive = true
		return customUITLSCertPath(), customUITLSKeyPath()
	}
	return cert, key
}
