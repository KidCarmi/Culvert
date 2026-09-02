package main

// cdr_lineage.go — per-instance credential LINEAGE + the lifecycle lock
// (2E-C trust-lifecycle correction, R7).
//
// Sluice.RenewCert does NOT retire the presented certificate: after a
// renewal BOTH the predecessor and the successor are trusted by Sluice
// until each expires or is revoked there. The appliance therefore keeps
// a bounded, durable list of every credential GENERATION it has ever
// been issued for an instance, each with its own state, so that:
//
//   - a still-valid predecessor stays identifiable (and revocable) after
//     a renewal, a restart, and a local delete;
//   - a renewal is a recoverable TRANSACTION: the intent (operation id)
//     is durable BEFORE the RPC, the issued fingerprint is durable BEFORE
//     any PEM is written, and activation is the last durable step — so
//     no crash or persistence failure can leave "new PEMs on disk + an
//     old durable fingerprint";
//   - renewal, revoke, delete and enroll for the SAME instance are
//     serialized on a per-instance lifecycle lock, and a renewal decided
//     before a removal re-validates the instance under that lock before
//     touching disk or registry.
//
// Generation states:
//
//	renewing   intent persisted; the RenewCert RPC is in flight or its
//	           outcome is unknown (resolved via EnrollStatus by the poller)
//	staged     Sluice issued it; fingerprint durable; PEMs not yet active
//	active     the credential the pool dials with (exactly one, or none
//	           for a legacy entry before normalisation)
//	superseded a former active credential still trusted by Sluice
//	orphaned   issued by Sluice, key material NOT held locally (lost
//	           response / lost PEM) — must be revoked, never dialed
//	revoked    a durable-deny proof was received from Sluice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/KidCarmi/Sluice/pkg/sluiceauth"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

const (
	cdrCredRenewing   = "renewing"
	cdrCredStaged     = "staged"
	cdrCredActive     = "active"
	cdrCredSuperseded = "superseded"
	cdrCredOrphaned   = "orphaned"
	cdrCredRevoked    = "revoked"

	// cdrMaxCredentialGenerations bounds the lineage. Only revoked or
	// expired generations are ever pruned; when the cap is reached with
	// live generations, renewal is REFUSED (the operator must revoke or
	// let predecessors expire) rather than forgetting a trusted credential.
	cdrMaxCredentialGenerations = 16
)

// CDRCredentialGeneration is one issued client credential in an
// instance's lineage. Non-secret: fingerprints, validity and state only.
type CDRCredentialGeneration struct {
	Seq          int       `json:"seq"`
	Fingerprint  string    `json:"fingerprint,omitempty"`
	NotAfterUnix int64     `json:"notAfterUnix,omitempty"`
	State        string    `json:"state"`
	IssuedAt     time.Time `json:"issuedAt,omitempty"`
	OperationID  string    `json:"operationId,omitempty"`
	Source       string    `json:"source"` // enroll | renewal | legacy
}

// Live reports whether Sluice may still trust this generation: not
// revoked, not expired, and actually issued (a "renewing" generation has
// no fingerprint yet — its outcome is unknown, so it counts as live for
// the purpose of "must be resolved before it is forgotten").
func (g CDRCredentialGeneration) Live(now time.Time) bool {
	if g.State == cdrCredRevoked {
		return false
	}
	if g.NotAfterUnix > 0 && now.Unix() >= g.NotAfterUnix {
		return false
	}
	return true
}

// cdrOperationIDRE mirrors Sluice's ValidOperationID grammar.
var cdrOperationIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{16,64}$`)

// mintCDROperationID returns a fresh 128-bit hex operation identity.
func mintCDROperationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable for a security identity.
		panic("cdr: crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// cdrLifecycle serializes renewal / revoke / delete / enroll for one
// instance name. Held for the whole ceremony, including the RPC, so a
// renewal that was DECIDED before a removal observes the removal when it
// re-validates the instance under the lock.
var cdrLifecycle = newKeyedMutex()

var (
	errCDRRenewalInProgress = errors.New("cdr lineage: a renewal is already in progress for this instance")
	errCDRLineageFull       = errors.New("cdr lineage: credential lineage is full (revoke or expire predecessors before renewing)")
	errCDRGenerationState   = errors.New("cdr lineage: generation is not in the expected state")
)

// normalizeLineageLocked synthesises the lineage for a pre-lineage entry
// (one recorded fingerprint, no generations) so every instance carries
// at least the credential it dials with. MUST be called under r.mu.
func normalizeLineageLocked(inst *CDREnrolledInstance) bool {
	if len(inst.Credentials) > 0 || inst.ClientCertFingerprint == "" {
		return false
	}
	var notAfter int64
	if exp, err := loadCertExpiry(inst.ClientCertPath); err == nil {
		notAfter = exp.Unix()
	}
	inst.Credentials = []CDRCredentialGeneration{{
		Seq: 1, Fingerprint: inst.ClientCertFingerprint, NotAfterUnix: notAfter,
		State: cdrCredActive, IssuedAt: inst.EnrolledAt, Source: "legacy",
	}}
	return true
}

// LiveFingerprints returns every fingerprint Sluice may still trust for
// this instance (all live, issued generations), active first. Falls back
// to the single recorded/derived fingerprint for a legacy entry.
func (i *CDREnrolledInstance) LiveFingerprints(now time.Time) []string {
	var out []string
	seen := map[string]bool{}
	add := func(fp string) {
		if fp != "" && !seen[fp] {
			seen[fp] = true
			out = append(out, fp)
		}
	}
	for _, g := range i.Credentials {
		if g.State == cdrCredActive && g.Live(now) {
			add(g.Fingerprint)
		}
	}
	for _, g := range i.Credentials {
		if g.Live(now) {
			add(g.Fingerprint)
		}
	}
	if len(i.Credentials) == 0 {
		add(i.ClientCertFingerprint)
	}
	return out
}

// findLocked returns the index of the named instance or -1. Under r.mu.
func (r *CDRInstanceRegistry) findLocked(name string) int {
	for i := range r.instances {
		if r.instances[i].Name == name {
			return i
		}
	}
	return -1
}

// mutateLineage applies fn to the named instance's generations under the
// write lock and persists durable-or-nothing: a failed write restores the
// previous generation slice and returns the error.
func (r *CDRInstanceRegistry) mutateLineage(name string, fn func(inst *CDREnrolledInstance) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.findLocked(name)
	if idx < 0 {
		return fmt.Errorf("cdr instances: %q not found", strings.ReplaceAll(strings.ReplaceAll(name, "\n", "_"), "\r", "_"))
	}
	inst := r.instances[idx]
	prevGens := append([]CDRCredentialGeneration(nil), inst.Credentials...)
	prevFP := inst.ClientCertFingerprint
	if err := fn(inst); err != nil {
		inst.Credentials = prevGens
		inst.ClientCertFingerprint = prevFP
		return err
	}
	if err := r.saveLocked(); err != nil {
		inst.Credentials = prevGens
		inst.ClientCertFingerprint = prevFP
		return err
	}
	r.bumpVersion()
	return nil
}

// pruneLineage drops generations that can no longer be trusted by Sluice
// (revoked or expired) beyond the cap, oldest first. Live generations are
// NEVER pruned.
func pruneLineage(gens []CDRCredentialGeneration, now time.Time) []CDRCredentialGeneration {
	if len(gens) < cdrMaxCredentialGenerations {
		return gens
	}
	out := make([]CDRCredentialGeneration, 0, len(gens))
	excess := len(gens) - (cdrMaxCredentialGenerations - 1)
	for _, g := range gens {
		if excess > 0 && !g.Live(now) {
			excess--
			continue
		}
		out = append(out, g)
	}
	return out
}

// StageRenewal records the INTENT to renew (a new "renewing" generation
// bound to operationID) durably BEFORE the RenewCert RPC. Returns the
// generation sequence. Refuses when an unresolved renewal exists or the
// lineage is full of live generations.
func (r *CDRInstanceRegistry) StageRenewal(name, operationID string) (int, error) {
	var seq int
	err := r.mutateLineage(name, func(inst *CDREnrolledInstance) error {
		normalizeLineageLocked(inst)
		now := time.Now()
		for _, g := range inst.Credentials {
			if g.State == cdrCredRenewing || g.State == cdrCredStaged {
				return errCDRRenewalInProgress
			}
		}
		inst.Credentials = pruneLineage(inst.Credentials, now)
		if len(inst.Credentials) >= cdrMaxCredentialGenerations {
			return errCDRLineageFull
		}
		seq = 1
		for _, g := range inst.Credentials {
			if g.Seq >= seq {
				seq = g.Seq + 1
			}
		}
		inst.Credentials = append(inst.Credentials, CDRCredentialGeneration{
			Seq: seq, State: cdrCredRenewing, IssuedAt: now.UTC(),
			OperationID: operationID, Source: "renewal",
		})
		return nil
	})
	return seq, err
}

// RecordIssuedCredential moves a "renewing" generation to `state` (staged
// or orphaned) with the fingerprint Sluice issued — durable BEFORE any
// PEM is written.
func (r *CDRInstanceRegistry) RecordIssuedCredential(name string, seq int, fp string, notAfterUnix int64, state string) error {
	return r.mutateLineage(name, func(inst *CDREnrolledInstance) error {
		for i := range inst.Credentials {
			if inst.Credentials[i].Seq != seq {
				continue
			}
			if inst.Credentials[i].State != cdrCredRenewing {
				return errCDRGenerationState
			}
			inst.Credentials[i].State = state
			inst.Credentials[i].Fingerprint = fp
			inst.Credentials[i].NotAfterUnix = notAfterUnix
			return nil
		}
		return errCDRGenerationState
	})
}

// ActivateCredential promotes a staged generation to active, demotes the
// previous active generation to superseded, and updates the dial
// fingerprint. Last durable step of a renewal.
func (r *CDRInstanceRegistry) ActivateCredential(name string, seq int) error {
	return r.mutateLineage(name, func(inst *CDREnrolledInstance) error {
		target := -1
		for i := range inst.Credentials {
			if inst.Credentials[i].Seq == seq {
				target = i
			}
		}
		if target < 0 || inst.Credentials[target].State != cdrCredStaged {
			return errCDRGenerationState
		}
		for i := range inst.Credentials {
			if i != target && inst.Credentials[i].State == cdrCredActive {
				inst.Credentials[i].State = cdrCredSuperseded
			}
		}
		inst.Credentials[target].State = cdrCredActive
		inst.ClientCertFingerprint = inst.Credentials[target].Fingerprint
		return nil
	})
}

// DropUnissuedRenewal removes a "renewing" generation whose outcome Sluice
// authoritatively reported as NOT issued.
func (r *CDRInstanceRegistry) DropUnissuedRenewal(name string, seq int) error {
	return r.mutateLineage(name, func(inst *CDREnrolledInstance) error {
		for i := range inst.Credentials {
			if inst.Credentials[i].Seq == seq && inst.Credentials[i].State == cdrCredRenewing {
				inst.Credentials = append(inst.Credentials[:i:i], inst.Credentials[i+1:]...)
				return nil
			}
		}
		return errCDRGenerationState
	})
}

// MarkCredentialRevoked records a PROVEN durable deny for one fingerprint.
// Idempotent. A fingerprint outside the recorded lineage (legacy entry)
// is appended as a revoked generation so the proof is not lost.
func (r *CDRInstanceRegistry) MarkCredentialRevoked(name, fp string) error {
	return r.mutateLineage(name, func(inst *CDREnrolledInstance) error {
		normalizeLineageLocked(inst)
		for i := range inst.Credentials {
			if inst.Credentials[i].Fingerprint == fp {
				inst.Credentials[i].State = cdrCredRevoked
				return nil
			}
		}
		seq := 1
		for _, g := range inst.Credentials {
			if g.Seq >= seq {
				seq = g.Seq + 1
			}
		}
		inst.Credentials = append(inst.Credentials, CDRCredentialGeneration{
			Seq: seq, Fingerprint: fp, State: cdrCredRevoked, IssuedAt: time.Now().UTC(), Source: "legacy",
		})
		return nil
	})
}

// reconcileCredentialLineage repairs every instance's lineage from the
// durable file + the on-disk PEMs after a restart — the crash-boundary
// half of the renewal transaction. Called from loadCDR after Load.
//
//   - a staged generation whose fingerprint is on disk (the cert rename
//     landed) is activated, finishing a pending key rename first;
//   - a staged generation NOT on disk with both tmp files present is
//     finished (rename cert then key) and activated;
//   - a staged generation whose material is gone is marked orphaned;
//   - a "renewing" generation is left for the poller to resolve via
//     EnrollStatus (needs a client);
//   - a legacy entry gets its synthesized lineage persisted.
func reconcileCredentialLineage() {
	for _, inst := range cdrInstances.SnapshotView() {
		inst := inst
		if len(inst.Credentials) == 0 {
			if inst.ClientCertFingerprint != "" {
				if err := cdrInstances.mutateLineage(inst.Name, func(i *CDREnrolledInstance) error {
					normalizeLineageLocked(i)
					return nil
				}); err != nil {
					logger.Printf("CDR: lineage: normalize %q: %v", sanitizeLog(inst.Name), err)
				}
			}
			continue
		}
		for _, g := range inst.Credentials {
			if g.State != cdrCredStaged {
				continue
			}
			finishStagedRenewal(inst, g)
		}
	}
}

// finishStagedRenewal completes (or abandons) one staged generation
// against the on-disk state. Under the instance's lifecycle lock.
func finishStagedRenewal(inst CDREnrolledInstance, g CDRCredentialGeneration) {
	unlock := cdrLifecycle.lock(inst.Name)
	defer unlock()
	certTmp, keyTmp := inst.ClientCertPath+".tmp", inst.ClientKeyPath+".tmp"
	diskFP, _ := loadCertFingerprint(inst.ClientCertPath)
	switch {
	case diskFP == g.Fingerprint:
		// Cert landed; the key rename may not have.
		if _, err := os.Stat(keyTmp); err == nil {
			if rerr := os.Rename(keyTmp, inst.ClientKeyPath); rerr != nil {
				logger.Printf("CDR: lineage: %q finish key swap: %v", sanitizeLog(inst.Name), rerr)
				return
			}
		}
	default:
		tmpFP, terr := loadCertFingerprint(certTmp)
		_, kerr := os.Stat(keyTmp)
		if terr != nil || tmpFP != g.Fingerprint || kerr != nil {
			logger.Printf("CDR: lineage: %q staged credential %s has no local material — marked orphaned (revoke it)",
				sanitizeLog(inst.Name), g.Fingerprint)
			if err := cdrInstances.mutateLineage(inst.Name, func(i *CDREnrolledInstance) error {
				for k := range i.Credentials {
					if i.Credentials[k].Seq == g.Seq {
						i.Credentials[k].State = cdrCredOrphaned
					}
				}
				return nil
			}); err != nil {
				logger.Printf("CDR: lineage: %q orphan: %v", sanitizeLog(inst.Name), err)
			}
			return
		}
		if err := os.Rename(certTmp, inst.ClientCertPath); err != nil {
			logger.Printf("CDR: lineage: %q finish cert swap: %v", sanitizeLog(inst.Name), err)
			return
		}
		if err := os.Rename(keyTmp, inst.ClientKeyPath); err != nil {
			logger.Printf("CDR: lineage: %q finish key swap: %v", sanitizeLog(inst.Name), err)
			return
		}
	}
	if err := cdrInstances.ActivateCredential(inst.Name, g.Seq); err != nil {
		logger.Printf("CDR: lineage: %q activate seq %d: %v", sanitizeLog(inst.Name), g.Seq, err)
		return
	}
	logger.Printf("CDR: lineage: %q completed interrupted renewal (seq %d, %s)", sanitizeLog(inst.Name), g.Seq, g.Fingerprint)
}

// certNotAfterUnix parses a PEM cert's NotAfter (0 when unparseable).
func certNotAfterUnix(certPEM []byte) int64 {
	if t, err := sluiceauth.NotAfter(certPEM); err == nil {
		return t.Unix()
	}
	return 0
}

// ─── R11: unresolved renewals block destructive lifecycle operations ────────

var (
	errCDRResolveUnavailable = errors.New("cdr lineage: an unresolved renewal operation could not be resolved against the engine")
	errCDRResolvePersist     = errors.New("cdr lineage: an unresolved renewal operation was resolved but its outcome could not be persisted")
)

// UnresolvedOperations lists the operation ids of every "renewing"
// generation — trust identities whose fingerprint is not yet known.
func (i *CDREnrolledInstance) UnresolvedOperations() []string {
	var out []string
	for _, g := range i.Credentials {
		if g.State == cdrCredRenewing && g.OperationID != "" {
			out = append(out, g.OperationID)
		}
	}
	return out
}

// cdrStatusViaBootstrap asks Sluice for an operation's outcome over the
// credential-less bootstrap channel (TOFU pin only) — usable with CDR
// disabled, with no pool, and right after a restart. A staged server-cert
// rotation window is honoured by retrying with the rotated pin.
func cdrStatusViaBootstrap(ctx context.Context, inst CDREnrolledInstance, opID string) (*pb.EnrollStatusResponse, error) {
	st, err := cdrEnrollStatusRPC(ctx, inst.Endpoint, inst.ServerFingerprint, opID)
	if err != nil && inst.RotatedFingerprint != "" &&
		(inst.RotatedFingerprintUntilUnix == 0 || time.Now().Unix() < inst.RotatedFingerprintUntilUnix) {
		st, err = cdrEnrollStatusRPC(ctx, inst.Endpoint, inst.RotatedFingerprint, opID)
	}
	return st, err
}

// resolveUnresolvedGenerations resolves EVERY "renewing" generation of the
// instance synchronously and authoritatively BEFORE a destructive
// lifecycle operation may proceed (caller holds the lifecycle lock):
//
//	NOT_ISSUED        the renewal intent is durably removed
//	ISSUED            the fingerprint is durably bound (orphaned — the key
//	                  material never landed here) before continuing
//	ISSUED + revoked  recorded as revoked
//	anything else     (unreachable, malformed, unspecified, unsupported, or
//	                  a persistence failure) ⇒ an error the caller maps to
//	                  503/409 with ZERO mutation and ZERO loss of the id
//
// Returns the refreshed instance copy.
func resolveUnresolvedGenerations(ctx context.Context, inst CDREnrolledInstance) (CDREnrolledInstance, error) {
	for _, g := range inst.Credentials {
		if g.State != cdrCredRenewing {
			continue
		}
		if g.OperationID == "" {
			// No identity exists to resolve or to lose: nothing Sluice could
			// have bound. Recorded as impossible by construction.
			return inst, fmt.Errorf("%w: generation %d has no operation id", errCDRResolvePersist, g.Seq)
		}
		st, err := cdrStatusViaBootstrap(ctx, inst, g.OperationID)
		if err != nil {
			return inst, fmt.Errorf("%w: operation %s: %v", errCDRResolveUnavailable, g.OperationID, err)
		}
		switch st.GetOutcome() {
		case pb.EnrollOutcome_ENROLL_NOT_ISSUED:
			if err := cdrInstances.DropUnissuedRenewal(inst.Name, g.Seq); err != nil {
				return inst, fmt.Errorf("%w: operation %s: %v", errCDRResolvePersist, g.OperationID, err)
			}
		case pb.EnrollOutcome_ENROLL_ISSUED:
			fp := st.GetClientCertFingerprint()
			if !cdrFingerprintRE.MatchString(fp) {
				return inst, fmt.Errorf("%w: operation %s: engine reported a malformed fingerprint", errCDRResolveUnavailable, g.OperationID)
			}
			state := cdrCredOrphaned
			if st.GetRevoked() {
				state = cdrCredRevoked
			}
			if err := cdrInstances.RecordIssuedCredential(inst.Name, g.Seq, fp, 0, state); err != nil {
				return inst, fmt.Errorf("%w: operation %s: %v", errCDRResolvePersist, g.OperationID, err)
			}
			logger.Printf("CDR: lineage: %q operation %s resolved as ISSUED (%s, %s) before a lifecycle mutation", sanitizeLog(inst.Name), g.OperationID, fp, state)
		default:
			return inst, fmt.Errorf("%w: operation %s: the engine reported an unspecified outcome (unsupported server)", errCDRResolveUnavailable, g.OperationID)
		}
	}
	cur, ok := cdrInstances.GetCopy(inst.Name)
	if !ok {
		return inst, fmt.Errorf("%w: instance vanished during resolution", errCDRResolvePersist)
	}
	return cur, nil
}

// resolveUnresolvedOrRefuse runs the resolution and writes the truthful
// refusal (503 unreachable / 409 persistence) when it cannot complete.
func resolveUnresolvedOrRefuse(w http.ResponseWriter, r *http.Request, inst CDREnrolledInstance) (CDREnrolledInstance, bool) {
	if len(inst.UnresolvedOperations()) == 0 {
		return inst, true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	cur, err := resolveUnresolvedGenerations(ctx, inst)
	if err == nil {
		return cur, true
	}
	code := http.StatusConflict
	if errors.Is(err, errCDRResolveUnavailable) {
		code = http.StatusServiceUnavailable
	}
	http.Error(w, fmt.Sprintf("%v — nothing was changed; the unresolved renewal operation(s) %v remain recorded", err, inst.UnresolvedOperations()), code)
	return inst, false
}
