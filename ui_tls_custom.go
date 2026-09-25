package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

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

// uiCustomTLSActive records the BOOT-TIME SELECTION: resolveUITLSCertKey
// picked the persisted custom pair for the listener startUI is about to
// start. It is NOT activation evidence and is published nowhere (FE-6B.1
// correction round, B1): it never observes whether the listener bound or
// what it serves, and it stays true after the pair is replaced or deleted
// without a restart. What the running listener actually serves is recorded
// from the bind itself in ui_listener_evidence.go, and `uiCert.active` /
// `ui_custom_cert_active` are derived from that record (served == persisted).
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

// daysRemainingFloor differs from the shared daysUntil (cdr_ui.go) by
// FLOORING rather than truncating toward zero: daysUntil's int() truncation
// maps any duration in (-24h, 0) to 0, so a certificate that expired an
// hour ago would report "0 days remaining" — indistinguishable from "expires
// today" — for up to 24 hours after it actually expired (Codex review, PR
// #1381). The GET /api/settings/network contract for
// ui_tls_cert_days_remaining promises "negative once expired", and the
// Certificates panel switches to its EXPIRED banner on days < 0, so the
// value must go negative the instant NotAfter passes. Kept as a SEPARATE
// helper rather than changing daysUntil's rounding, which also feeds the
// already-shipped mTLS-client-cert and root-CA expiry displays.
func daysRemainingFloor(t time.Time) int {
	return int(math.Floor(time.Until(t).Hours() / 24))
}

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
	var certData, keyData []byte
	if ev.certPresent {
		data, err := os.ReadFile(customUITLSCertPath())
		if err != nil {
			return uiPairEvidence{class: uiPairUnavailable}
		}
		certData = data
		ev.certDigest = hexDigest(data)
	}
	// The key is READ, not merely stat-ed (round 4, B3): a present key that
	// cannot be read is unavailable evidence — never "an invalid pair".
	// Validity is then decided from the bytes actually read, so it means
	// readable-but-not-a-matching-pair and nothing else.
	if ev.keyPresent {
		data, err := os.ReadFile(customUITLSKeyPath())
		if err != nil {
			return uiPairEvidence{class: uiPairUnavailable}
		}
		keyData = data
	}
	switch {
	case !ev.certPresent && !ev.keyPresent:
		ev.class = uiPairAbsent
	case ev.certPresent && ev.keyPresent:
		ev.class = uiPairComplete
		_, perr := tls.X509KeyPair(certData, keyData)
		ev.valid = perr == nil
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

// removeIfExists removes path; did reports whether something was removed.
func removeIfExists(path string) (did bool, err error) {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// renameIfExists renames from over to when from exists; did reports whether
// a rename happened.
func renameIfExists(from, to string) (did bool, err error) {
	if _, err := os.Stat(from); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err := os.Rename(from, to); err != nil {
		return false, err
	}
	return true, nil
}

// abandonUITLSStage removes staged files that never reached the commit
// point. Best-effort: a leftover is abandoned again by the next recovery.
func abandonUITLSStage() {
	_ = os.Remove(customUITLSCertStagePath()) // #nosec G104 -- best-effort cleanup
	_ = os.Remove(customUITLSKeyStagePath())  // #nosec G104 -- best-effort cleanup
}

// completeUITLSTransition finishes a committed transition with TWO
// durability barriers (round 4, B2):
//
//	renames (replace) / removals (delete)
//	→ BARRIER 1: sync the directory — the completed pair (or its absence) is durable
//	→ remove the marker
//	→ BARRIER 2: sync the directory — the marker's removal is durable
//
// The marker is the recovery evidence, so it is deleted only once what it
// describes is durable: a crash after barrier 1 leaves a marker beside a
// complete pair (recovery re-completes idempotently and consumes it), and a
// crash between the renames and barrier 1 leaves the marker beside whatever
// landed (recovery finishes the renames) — never a marker-less half
// transition that recovery would abandon. Every step is idempotent.
//
// acted reports whether a rename/removal actually changed the live paths;
// durable whether BOTH barriers held (false ⇒ the marker is retained, or its
// removal is unproven — the next recovery re-runs the sequence); err is a
// rename/removal that could not be done (the marker stays for the next
// recovery).
func completeUITLSTransition(tr uiTLSTransition) (acted, durable bool, err error) {
	switch tr.Kind {
	case uiTLSTransitionReplace:
		for _, pair := range [][2]string{{customUITLSKeyStagePath(), customUITLSKeyPath()}, {customUITLSCertStagePath(), customUITLSCertPath()}} {
			did, rerr := renameIfExists(pair[0], pair[1])
			if rerr != nil {
				return acted, false, fmt.Errorf("%s: %w", filepath.Base(pair[1]), rerr)
			}
			acted = acted || did
		}
	case uiTLSTransitionDelete:
		for _, path := range []string{customUITLSKeyPath(), customUITLSCertPath()} {
			did, rerr := removeIfExists(path)
			if rerr != nil {
				return acted, false, fmt.Errorf("%s: %w", filepath.Base(path), rerr)
			}
			acted = acted || did
		}
		abandonUITLSStage()
	}
	if serr := fileutil.SyncParentDir(customUITLSCertPath()); serr != nil {
		return acted, false, nil // barrier 1 failed: the marker stays
	}
	if _, rerr := removeIfExists(customUITLSTransitionPath()); rerr != nil {
		return acted, false, nil // the marker could not be removed: retried by the next recovery
	}
	if serr := fileutil.SyncParentDir(customUITLSCertPath()); serr != nil {
		return acted, false, nil // barrier 2 failed: the removal is unproven (a reappeared marker is harmless)
	}
	return acted, true, nil
}

// uiTLSRecovery is what recoverUITLSTransition found and did.
type uiTLSRecovery struct {
	Kind        string // the completed transition's kind, "" when none
	OperationID string
	Completed   bool // a committed transition was finished durably by this call (marker consumed)
	Acted       bool // a rename or removal actually changed the live paths
	Abandoned   bool // staged files that never reached the commit point were removed
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
	acted, durable, cerr := completeUITLSTransition(*tr)
	rec.Acted = acted
	if cerr != nil {
		rec.Err = fmt.Errorf("%w: %w", errUITLSTransitionIncomplete, cerr)
		return rec
	}
	if !durable {
		rec.Err = fmt.Errorf("%w: a durability barrier failed; the marker is retained for the next recovery", errUITLSDurabilityUnproven)
		return rec
	}
	rec.Completed = true
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
	_, durable, err := completeUITLSTransition(tr)
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
	_, durable, err := completeUITLSTransition(tr)
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
	case errors.Is(rec.Err, errUITLSDurabilityUnproven):
		fmt.Printf("[Culvert] UITLS: an interrupted custom UI certificate transition was completed at boot but its durability could not be proven; the marker is retained and retried at the next settlement\n")
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
