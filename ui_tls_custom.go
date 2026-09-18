package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/ca"
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
//
// THE PAIR IS A RECOVERABLE STAGED TRANSITION (FE-6B.0 round 3, Blocker 2).
// A certificate and its private key are two files, and two separate atomic
// writes at the live paths can be interrupted between them — a process
// killed after the certificate write and before the key write (OOM-kill,
// compose restart, host crash) left a NEW certificate beside the OLD key:
// individually well-formed, jointly unusable, and the previously working
// pair destroyed. The live paths are therefore never written directly:
//
//	replace:  stage cert → stage key (.next files beside the live pair)
//	          → transition marker (the COMMIT POINT; kind, operationId, cert digest)
//	          → rename key, rename cert → remove marker → sync the directory
//	delete:   transition marker (the commit point) → remove key, remove cert
//	          → remove marker → sync the directory
//
// recoverUITLSTransition, run at boot (resolveUITLSCertKey) and at every
// settlement of a UI-certificate intent, finishes whatever the marker says
// was committed and ABANDONS staged files that never reached the marker —
// so the live pair is only ever (a) the previous complete pair, or (b) the
// new complete pair, never a mixture, and a crash at any instant is repaired
// by the next boot without a guess. The key stays write-only: the marker
// carries the certificate's digest only, and a completed pair is proven by
// parsing (tls.LoadX509KeyPair), never by a key digest.
//
// A POST-RENAME synchronisation failure (fileutil.ErrReplacedNotSynced) on
// any step means that step's content IS on disk; the transition is completed
// and the caller is told its durability is UNPROVEN (errUITLSDurabilityUnproven)
// — never that nothing changed. A failure BEFORE the commit point abandons the
// staged files and leaves the previous pair intact (an ordinary error).
const (
	customUITLSCertFile       = "ui_tls_cert.pem"
	customUITLSKeyFile        = "ui_tls_key.pem"
	customUITLSStageSuffix    = ".next"
	customUITLSTransitionFile = "ui_tls_transition.json"

	uiTLSTransitionReplace = "replace"
	uiTLSTransitionDelete  = "delete"
)

var (
	// errUITLSDurabilityUnproven: the transition COMPLETED (the pair on disk
	// is the requested one) but a post-rename synchronisation failed, so the
	// result's durability across an immediate crash is unproven. Test with
	// errors.Is; the wrapped cause carries fileutil.ErrReplacedNotSynced.
	errUITLSDurabilityUnproven = errors.New("custom UI cert/key transition completed but its durability is unproven")
	// errUITLSTransitionIncomplete: the commit point (marker) was reached
	// but a later step failed; the marker stays so the next recovery
	// completes the transition. The live pair may be either generation.
	errUITLSTransitionIncomplete = errors.New("custom UI cert/key transition committed but not completed")
)

// uiTLSAtomicWrite is fileutil.AtomicWrite behind a seam, used by
// persistCustomUITLS for the KEY staging write — the write whose failure
// modes (fileutil.ErrReplacedNotSynced; a crash at that instant) a test
// injects. Production always resolves to the real fileutil.AtomicWrite; only
// tests swap it.
var uiTLSAtomicWrite = fileutil.AtomicWrite

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
func customUITLSTransitionPath() string {
	return filepath.Join(dataDir, customUITLSTransitionFile)
}
func customUITLSCertStagePath() string { return customUITLSCertPath() + customUITLSStageSuffix }
func customUITLSKeyStagePath() string  { return customUITLSKeyPath() + customUITLSStageSuffix }

// ── evidence ────────────────────────────────────────────────────────────────

// uiPairClass is the bounded state of the persisted pair: what the two live
// paths hold, decided WITHOUT collapsing "cannot look" into "nothing there"
// (FE-6B.0 round 3, Blocker 3).
const (
	uiPairAbsent      = "absent"      // neither file exists
	uiPairComplete    = "complete"    // both files exist and are readable
	uiPairIncomplete  = "incomplete"  // exactly one file exists (an interrupted cleanup or an old-binary crash)
	uiPairUnavailable = "unavailable" // a path cannot be examined or read (permissions, a directory at the path, I/O)
)

type uiPairEvidence struct {
	class       string
	certPresent bool
	keyPresent  bool
	certDigest  string // sha256 hex of the certificate file when it is readable
	valid       bool   // complete AND parses as a matching TLS pair
}

// uiPairEvidenceNow examines the live paths. Unavailability is decided
// FIRST: a stat error other than not-exist, a directory at either path or an
// unreadable certificate file is uiPairUnavailable, never absent.
func uiPairEvidenceNow() uiPairEvidence {
	certPresent, certOK := uiPairFileState(customUITLSCertPath())
	keyPresent, keyOK := uiPairFileState(customUITLSKeyPath())
	if !certOK || !keyOK {
		return uiPairEvidence{class: uiPairUnavailable}
	}
	ev := uiPairEvidence{certPresent: certPresent, keyPresent: keyPresent}
	if ev.certPresent {
		data, err := os.ReadFile(customUITLSCertPath())
		if err != nil {
			return uiPairEvidence{class: uiPairUnavailable}
		}
		ev.certDigest = hexDigest(data)
	}
	switch {
	case !ev.certPresent && !ev.keyPresent:
		ev.class = uiPairAbsent
	case ev.certPresent && ev.keyPresent:
		ev.class = uiPairComplete
		ev.valid = customUITLSPairValid()
	default:
		ev.class = uiPairIncomplete
	}
	return ev
}

// uiPairFileState reports whether a regular file exists at path (present)
// and whether that could be established at all (ok): a stat error other
// than not-exist, or a directory at the path, is NOT ok.
func uiPairFileState(path string) (present, ok bool) {
	st, err := os.Stat(path)
	switch {
	case err == nil:
		return true, !st.IsDir()
	case errors.Is(err, fs.ErrNotExist):
		return false, true
	default:
		return false, false
	}
}

// customUITLSFilesPresent reports whether a COMPLETE previously uploaded UI
// cert/key pair is on disk (a remnant of one file is not a pair).
func customUITLSFilesPresent() bool {
	return uiPairEvidenceNow().class == uiPairComplete
}

// ── the transition marker ───────────────────────────────────────────────────

// uiTLSTransition is the durable commit point of a pair transition. Every
// field is non-secret: the kind, the operation that committed it and the
// certificate's digest (a replace) — never a key digest.
type uiTLSTransition struct {
	Kind        string `json:"kind"`
	OperationID string `json:"operationId,omitempty"`
	CertDigest  string `json:"certDigest,omitempty"`
}

func writeUITLSTransition(tr uiTLSTransition) error {
	data, err := json.Marshal(tr)
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(customUITLSTransitionPath(), data, 0o600)
}

// readUITLSTransition returns the marker (nil when none) or an error when it
// exists but cannot be read or decoded — evidence that is unavailable, not
// absent.
func readUITLSTransition() (*uiTLSTransition, error) {
	data, err := os.ReadFile(customUITLSTransitionPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tr uiTLSTransition
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, err
	}
	if tr.Kind != uiTLSTransitionReplace && tr.Kind != uiTLSTransitionDelete {
		return nil, fmt.Errorf("unknown transition kind %q", tr.Kind)
	}
	return &tr, nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func renameIfExists(from, to string) error {
	if _, err := os.Stat(from); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return os.Rename(from, to)
}

// abandonUITLSStage removes staged files that never reached the commit
// point. Best-effort: a leftover is abandoned again by the next recovery.
func abandonUITLSStage() {
	_ = os.Remove(customUITLSCertStagePath()) // #nosec G104 -- best-effort cleanup
	_ = os.Remove(customUITLSKeyStagePath())  // #nosec G104 -- best-effort cleanup
}

// completeUITLSTransition finishes a committed transition: the remaining
// renames (replace) or removals (delete), then the marker, then the
// directory sync. It is idempotent — a step already done is skipped — so a
// recovery can call it as often as needed. durable reports whether the
// final directory sync proved the result; err is a step that could not be
// done (the marker is left for the next recovery).
func completeUITLSTransition(tr uiTLSTransition) (durable bool, err error) {
	switch tr.Kind {
	case uiTLSTransitionReplace:
		if err := renameIfExists(customUITLSKeyStagePath(), customUITLSKeyPath()); err != nil {
			return false, fmt.Errorf("key: %w", err)
		}
		if err := renameIfExists(customUITLSCertStagePath(), customUITLSCertPath()); err != nil {
			return false, fmt.Errorf("cert: %w", err)
		}
	case uiTLSTransitionDelete:
		if err := removeIfExists(customUITLSKeyPath()); err != nil {
			return false, fmt.Errorf("key: %w", err)
		}
		if err := removeIfExists(customUITLSCertPath()); err != nil {
			return false, fmt.Errorf("cert: %w", err)
		}
		abandonUITLSStage()
	}
	if err := removeIfExists(customUITLSTransitionPath()); err != nil {
		return false, fmt.Errorf("marker: %w", err)
	}
	if err := fileutil.SyncParentDir(customUITLSCertPath()); err != nil {
		return false, nil
	}
	return true, nil
}

// uiTLSRecovery is what recoverUITLSTransition found and did.
type uiTLSRecovery struct {
	Kind        string // the completed transition's kind, "" when none
	OperationID string
	Completed   bool // a committed transition was finished by this call
	Abandoned   bool // staged files that never reached the commit point were removed
	Durable     bool // the completed transition's directory sync succeeded
	Err         error
}

// recoverUITLSTransition repairs an interrupted pair transition from its
// durable evidence: a marker is a committed transition and is COMPLETED; a
// staged file without a marker never committed and is ABANDONED (the live
// pair is untouched). A marker that cannot be read is left in place with
// the error (unavailable evidence is never treated as absent).
func recoverUITLSTransition() uiTLSRecovery {
	tr, err := readUITLSTransition()
	if err != nil {
		return uiTLSRecovery{Err: err}
	}
	if tr == nil {
		rec := uiTLSRecovery{}
		for _, p := range []string{customUITLSCertStagePath(), customUITLSKeyStagePath()} {
			if _, serr := os.Stat(p); serr == nil {
				rec.Abandoned = true
			}
		}
		if rec.Abandoned {
			abandonUITLSStage()
		}
		return rec
	}
	rec := uiTLSRecovery{Kind: tr.Kind, OperationID: tr.OperationID}
	durable, cerr := completeUITLSTransition(*tr)
	if cerr != nil {
		rec.Err = fmt.Errorf("%w: %w", errUITLSTransitionIncomplete, cerr)
		return rec
	}
	rec.Completed = true
	rec.Durable = durable
	return rec
}

// ── replace and delete ──────────────────────────────────────────────────────

// persistCustomUITLS durably replaces the persisted UI cert/key pair with
// the staged transition described in the file header. The key is written
// 0600 (private key material); the cert 0644 (public, and self-signed cert
// generation already treats it as non-sensitive).
//
// Returns nil when the pair is on disk and its durability proven;
// errUITLSDurabilityUnproven when the pair is on disk but a post-rename
// synchronisation failed; errUITLSTransitionIncomplete when the commit point
// was reached but a later step failed (the marker stays; the next recovery
// completes it); any other error when nothing at the live paths changed.
func persistCustomUITLS(certPEM, keyPEM []byte) error {
	return persistCustomUITLSOp(certPEM, keyPEM, "")
}

func persistCustomUITLSOp(certPEM, keyPEM []byte, opID string) error {
	var unproven error
	if err := fileutil.AtomicWrite(customUITLSCertStagePath(), certPEM, 0o644); err != nil {
		if !errors.Is(err, fileutil.ErrReplacedNotSynced) {
			abandonUITLSStage()
			return err
		}
		unproven = err
	}
	if err := uiTLSAtomicWrite(customUITLSKeyStagePath(), keyPEM, 0o600); err != nil {
		if !errors.Is(err, fileutil.ErrReplacedNotSynced) {
			abandonUITLSStage()
			return err
		}
		unproven = err
	}
	tr := uiTLSTransition{Kind: uiTLSTransitionReplace, OperationID: opID, CertDigest: hexDigest(certPEM)}
	if err := writeUITLSTransition(tr); err != nil {
		if !errors.Is(err, fileutil.ErrReplacedNotSynced) {
			abandonUITLSStage()
			return err
		}
		unproven = err
	}
	durable, err := completeUITLSTransition(tr)
	if err != nil {
		return fmt.Errorf("%w: %w", errUITLSTransitionIncomplete, err)
	}
	if !durable && unproven == nil {
		unproven = fileutil.ErrReplacedNotSynced
	}
	if unproven != nil {
		return fmt.Errorf("%w: %w", errUITLSDurabilityUnproven, unproven)
	}
	return nil
}

// deleteCustomUITLSOp removes the persisted pair through the same committed
// transition (marker first). The error vocabulary is persistCustomUITLS's:
// nil (removed, durable), errUITLSDurabilityUnproven, errUITLSTransitionIncomplete,
// or an ordinary error when the marker could not be written (nothing changed).
func deleteCustomUITLSOp(opID string) error {
	var unproven error
	tr := uiTLSTransition{Kind: uiTLSTransitionDelete, OperationID: opID}
	if err := writeUITLSTransition(tr); err != nil {
		if !errors.Is(err, fileutil.ErrReplacedNotSynced) {
			return err
		}
		unproven = err
	}
	durable, err := completeUITLSTransition(tr)
	if err != nil {
		return fmt.Errorf("%w: %w", errUITLSTransitionIncomplete, err)
	}
	if !durable && unproven == nil {
		unproven = fileutil.ErrReplacedNotSynced
	}
	if unproven != nil {
		return fmt.Errorf("%w: %w", errUITLSDurabilityUnproven, unproven)
	}
	return nil
}

// customUITLSPairValid reports whether the persisted cert/key pair on disk
// actually parses as a matching TLS key pair — the same check
// http.Server.ListenAndServeTLS performs internally via tls.LoadX509KeyPair.
// Existence alone proves nothing: a pair written by an older binary's two
// separate live-path writes, or altered out of band, can be individually
// well-formed and jointly mismatched. That pair must never reach
// ListenAndServeTLS, whose load failure is fatal (startUI calls logFatalf,
// which os.Exit(1)s the whole process) with no fallback — unlike the
// self-signed path right below it in startUI.
func customUITLSPairValid() bool {
	_, err := tls.LoadX509KeyPair(customUITLSCertPath(), customUITLSKeyPath())
	return err == nil
}

// resolveUITLSCertKey folds a persisted custom UI cert into startup cert/key
// resolution: an explicit -tls-cert/-tls-key (flag or YAML) always wins, and
// otherwise a GUI-uploaded cert (if any, and only if it still parses as a
// matching pair) is used before falling back to the auto self-signed
// certificate. Sets uiCustomTLSActive so the admin API can report whether the
// running server is actually using it. An interrupted pair transition is
// repaired FIRST (recoverUITLSTransition), so the pair examined is always a
// settled one.
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
	switch rec := recoverUITLSTransition(); {
	case rec.Err != nil:
		fmt.Printf("[Culvert] UITLS: an interrupted custom UI certificate transition could not be completed at boot (%s); the persisted pair is left as found\n", ca.PersistFailureClass(rec.Err))
	case rec.Completed:
		fmt.Printf("[Culvert] UITLS: completed an interrupted custom UI certificate %s at boot\n", rec.Kind)
	case rec.Abandoned:
		fmt.Printf("[Culvert] UITLS: abandoned an uncommitted custom UI certificate replacement found at boot (the previous pair is unchanged)\n")
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
