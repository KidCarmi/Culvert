package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// errUITLSRollbackFailed marks a persistCustomUITLS failure where the
// compensating cert rollback (below) ALSO failed — typically the same
// wedged/full/read-only volume that failed the key write. Callers must not
// report "the current certificate is unchanged" on this error: the on-disk
// cert may now be the rejected upload, possibly paired with neither the old
// nor the new key. Test with errors.Is.
var errUITLSRollbackFailed = errors.New("custom UI cert/key rollback failed")

// uiTLSAtomicWrite is fileutil.AtomicWrite behind a seam, used by
// persistCustomUITLS for the KEY write and the compensating CERT rollback
// write — the two calls whose failure modes (fileutil.ErrReplacedNotSynced;
// the rollback write itself failing) are not practically reproducible
// against a real filesystem in a test (a parent-directory fsync failure is
// not portably injectable). Production always resolves to the real
// fileutil.AtomicWrite; only tests swap it.
var uiTLSAtomicWrite = fileutil.AtomicWrite

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

// adminUITLSCertMu guards the admin UI's OWN serving-certificate expiry —
// the certificate a browser actually negotiates against to reach the GUI at
// all, whether it came from an explicit -tls-cert/-tls-key (flag or YAML) or
// a GUI-uploaded pair. This is a DIFFERENT certificate from the two other
// expiries this product already surfaces: the MITM inspection root CA
// (ca.go, CHAOS-28) and the outbound upstream mTLS client cert
// (mtls_ocsp_startup.go) — neither of those covers it, and nothing parsed
// this certificate's NotAfter before. An operator running a custom admin-UI
// cert therefore had no way to see it approaching expiry short of opening
// the file by hand; once it actually expires, admin_ui_health.go's retry
// loop keeps retrying the same now-expired pair forever with no in-product
// signal beyond a rate-limited log line. Populated on every successful
// custom-cert TLS bind by noteAdminUITLSCertExpiry (ui.go); read-only via
// GET /api/settings/network. The auto self-signed fallback (10-year
// validity, internal/uitls) is deliberately not tracked here — it is not
// operator-configured and not worth an expiry warning.
var (
	adminUITLSCertMu       sync.RWMutex
	adminUITLSCertNotAfter time.Time
	adminUITLSCertKnown    bool
)

// noteAdminUITLSCertExpiry records the NotAfter of the leaf certificate in a
// custom cert/key pair the admin UI is about to serve. Best-effort: a
// malformed leaf (should be unreachable — the caller already validated the
// pair loads as a matching tls.Certificate) leaves the prior value in place
// rather than discarding a possibly-still-accurate expiry.
func noteAdminUITLSCertExpiry(cert tls.Certificate) {
	if len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	adminUITLSCertMu.Lock()
	defer adminUITLSCertMu.Unlock()
	adminUITLSCertNotAfter = leaf.NotAfter
	adminUITLSCertKnown = true
}

// adminUITLSCertExpiry returns the currently known admin-UI serving
// certificate expiry. known is false until a custom cert/key pair has
// bound successfully at least once in this process's lifetime.
func adminUITLSCertExpiry() (notAfter time.Time, known bool) {
	adminUITLSCertMu.RLock()
	defer adminUITLSCertMu.RUnlock()
	return adminUITLSCertNotAfter, adminUITLSCertKnown
}

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
//
// The two files are written as SEPARATE atomic writes, so a failure on the
// second (key) write — a wedged volume, ENOSPC, a permissions change
// mid-upload — must not leave the cert half already overwritten with the
// rejected upload: apiCertsUpload reports that failure to the admin as
// "the current UI certificate is unchanged", which would be false if a
// previously-persisted, working cert had just been silently replaced. On a
// key-write failure the cert half is rolled back to what was on disk before
// this call (or removed, if nothing was persisted yet) so the on-disk state
// genuinely matches what the admin was told.
//
// Two failure modes of the key write itself need distinct handling (Codex
// review, PR #1297):
//
//   - fileutil.ErrReplacedNotSynced means the key rename already landed —
//     the NEW key is live and visible on disk, only the best-effort parent-
//     directory fsync afterward failed. Its contract explicitly forbids a
//     compensating rollback here: restoring the OLD cert would pair it with
//     the NEW key, producing exactly the mismatched-pair hazard this
//     function exists to prevent, just inverted. The (new cert, new key)
//     pair already on disk is the one that was actually uploaded, so it is
//     left in place; the error is still returned (durability across an
//     immediate crash is not guaranteed).
//   - Any other error means the key write did not land, so the cert half is
//     rolled back — but that compensating write/remove can itself fail on
//     the same wedged/full/read-only volume that failed the key write. That
//     failure must not be silently discarded: it is wrapped in
//     errUITLSRollbackFailed so the caller can stop claiming "unchanged".
func persistCustomUITLS(certPEM, keyPEM []byte) error {
	prevCert, prevCertErr := os.ReadFile(customUITLSCertPath())
	hadPrevCert := prevCertErr == nil
	if err := fileutil.AtomicWrite(customUITLSCertPath(), certPEM, 0o644); err != nil {
		return err
	}
	if err := uiTLSAtomicWrite(customUITLSKeyPath(), keyPEM, 0o600); err != nil {
		if errors.Is(err, fileutil.ErrReplacedNotSynced) {
			return err
		}
		var rollbackErr error
		if hadPrevCert {
			rollbackErr = uiTLSAtomicWrite(customUITLSCertPath(), prevCert, 0o644)
		} else {
			rollbackErr = os.Remove(customUITLSCertPath())
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w: %w: rollback also failed: %w", err, errUITLSRollbackFailed, rollbackErr)
		}
		return err
	}
	return nil
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
