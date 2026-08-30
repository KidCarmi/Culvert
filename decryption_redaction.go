package main

// decryption_redaction.go — the admin surface for the destination-privacy posture
// (ADR-0011 §4 → PR3 Option B). A single node-local toggle that, when ON, pseudonymizes
// the destination with a keyed HMAC (traffic_redaction.go) at the persistLogEntry
// chokepoint — the top-level Host/URI, the nested dec.host/dec.sni, AND the top-hosts
// ranking, across every sink — instead of recording the plaintext. OFF by default (the
// historical behavior), so upgrading changes nothing until an operator opts in.
//
// The flag is read at PROJECTION time (toBlock) on the decision/close path and at the
// persistLogEntry chokepoint, so it is a lock-free atomic read. It is DURABLE in
// admin_settings.json but node-local — off export/import, version-rollback, and CP→DP
// sync (AdminDurable-only config_surfaces rows for the flag AND the pseudonym key, like
// the auto-exclusion tunables): destination privacy is a per-appliance choice, not fleet
// policy (fleet-wide pseudonym correlation via a synced key is the deferred B3 follow-up).

import (
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// decRedactHostsFlag is the live redaction toggle. Default (false) = record plaintext host/SNI.
var decRedactHostsFlag atomic.Bool

// decRedactHosts reports whether host/SNI redaction is enabled. Called at every dec-block
// projection (toBlock) — a plain atomic load, safe on the proxy hot path.
func decRedactHosts() bool { return decRedactHostsFlag.Load() }

// setDecRedactHosts sets the redaction toggle (load-time restore + the admin PUT).
func setDecRedactHosts(v bool) { decRedactHostsFlag.Store(v) }

// trafficRotationReceipt is the durable, bounded, NON-SECRET record of ONE
// landed pseudonym-key rotation (2E-B correction, Blocker A): the caller's
// opaque operation id, the generation that rotation produced, the rotation
// sequence it advanced to, and an informational timestamp. NOTHING derivable
// from key material may ever enter a receipt — the allowlist is pinned by
// TestDec2EB2_RotationSurfacesCarryNoKeyMaterial.
type trafficRotationReceipt struct {
	OpID  string `json:"op_id"`
	KeyID string `json:"key_id"`
	Seq   int64  `json:"seq"`
	TS    string `json:"ts,omitempty"`
}

// maxTrafficRotationReceipts bounds the durable receipt window (FIFO —
// oldest evicted first). A client whose operation predates the retained
// window resolves as AMBIGUOUS, never as landed/not-landed.
const maxTrafficRotationReceipts = 32

// Rotation operation-identity state — guarded by adminSettingsMu (the
// destination-privacy writer domain): written only inside the redaction
// PUT's persist-before-apply transaction and the settings load, read by the
// coherent GET snapshot. trafficRotationSeq is the durable MONOTONIC
// key-generation sequence: EVERY new-key install (an explicit rotation, or
// the enable-path mint) advances it, so "sequence unchanged" proves no
// rotation landed in between; receipts exist only for client-identified
// rotations.
var (
	trafficRotationSeq      int64
	trafficRotationReceipts []trafficRotationReceipt
)

// findTrafficRotationReceiptLocked looks an operation id up in the retained
// window. Caller must hold adminSettingsMu.
func findTrafficRotationReceiptLocked(opID string) (trafficRotationReceipt, bool) {
	for _, r := range trafficRotationReceipts {
		if r.OpID == opID {
			return r, true
		}
	}
	return trafficRotationReceipt{}, false
}

// appendTrafficRotationReceipt returns a NEW slice (never mutating the
// input, which a published snapshot may alias) carrying the receipt, bounded
// FIFO to maxTrafficRotationReceipts.
func appendTrafficRotationReceipt(rs []trafficRotationReceipt, r trafficRotationReceipt) []trafficRotationReceipt {
	out := make([]trafficRotationReceipt, 0, len(rs)+1)
	out = append(out, rs...)
	out = append(out, r)
	if len(out) > maxTrafficRotationReceipts {
		out = out[len(out)-maxTrafficRotationReceipts:]
	}
	return out
}

// decRedactionTarget is the TARGET destination-privacy state a redaction PUT
// hands to saveAdminSettingsWithOverrides (2E-B persist-before-apply): the
// durable file records these values FIRST; only a successful write applies
// them to the live posture/key/rotation-metadata.
type decRedactionTarget struct {
	RedactHosts bool
	Key         []byte
	KeyID       string
	Seq         int64
	Receipts    []trafficRotationReceipt
}

// decRedactionState is one coherent read of the committed destination-privacy
// surface (posture, generation, rotation metadata).
type decRedactionState struct {
	Redact      bool
	KeyID       string
	Provisioned bool
	Seq         int64
	Receipts    []trafficRotationReceipt
}

// decRedactionSnapshot reads the committed destination-privacy state as ONE
// coherent snapshot under adminSettingsMu — the surface's writer domain (the
// PUT installs posture, key, and rotation metadata inside that mutex, so a
// lock-free multi-read could pair a new posture with an old generation id;
// 2E-A §1 doctrine).
func decRedactionSnapshot() decRedactionState {
	adminSettingsMu.Lock()
	defer adminSettingsMu.Unlock()
	return decRedactionState{
		Redact:      decRedactHosts(),
		KeyID:       getTrafficPseudonymKeyID(),
		Provisioned: len(getTrafficPseudonymKey()) == trafficKeyLen,
		Seq:         trafficRotationSeq,
		Receipts:    trafficRotationReceipts, // treated as immutable after publish
	}
}

// renderRotationReceipts maps the durable receipts to their API shape
// (operation_id / key_id / seq / ts — the pinned non-secret allowlist).
func renderRotationReceipts(rs []trafficRotationReceipt) []map[string]any {
	out := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		out = append(out, map[string]any{
			"operation_id": r.OpID,
			"key_id":       r.KeyID,
			"seq":          r.Seq,
			"ts":           r.TS,
		})
	}
	return out
}

// validRotationOperationID bounds the caller-supplied opaque operation id: it
// is persisted and echoed on read surfaces, so it must be short and from a
// tame alphabet (no control bytes, no separators the audit log would mangle).
func validRotationOperationID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// errRotationReplay marks a rotation whose operation id already has a
// durable receipt: the operation LANDED previously, so the save is aborted
// with no mutation and the handler answers from the receipt.
var errRotationReplay = errors.New("rotation operation already applied")

// decRedactionRevisionOf derives the destination-privacy revision from one
// committed snapshot — a pure function of (posture, generation id), so the
// fence covers BOTH the privacy toggle and the pseudonym-key rotation: any
// landed rotation changes the id, so a write (or retried rotation) asserting
// pre-rotation truth is a structured 409, never a silent overwrite or a
// silent second rotation.
func decRedactionRevisionOf(redact bool, keyID string) string {
	return contentSecRevision("dec-redaction", fmt.Sprintf("%t", redact), keyID)
}

// errPseudonymKeyMint marks an entropy failure while minting a key inside the
// redaction save's precondition (distinguishes a 500 from a fence 409).
var errPseudonymKeyMint = errors.New("pseudonym key mint failed")

// apiDecryptionRedaction is the ADR-0011 §4 admin surface for the host/SNI redaction
// posture. GET (viewer) reports the current setting; PUT (admin) sets it. The flag apply
// is an infallible atomic store, so it is set first and rolled back only if the durable
// write fails (the setting is node-local — off export/import, rollback, and CP→DP).
func apiDecryptionRedaction(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		// PR3 Option B (supersedes the B0 metadata-only interim): the posture is now a
		// GLOBAL destination-privacy posture. When on, the destination is pseudonymized
		// with a keyed HMAC at the persistLogEntry chokepoint across EVERY sink (feed,
		// JSONL/history, SIEM, drill-down) AND the nested dec.host/dec.sni. Node-local
		// key; fail-closed to a sentinel if the key is missing. key_provisioned reports
		// whether the node holds a pseudonym key (the value is NEVER exposed); key_id is
		// the NON-SECRET pseudonym generation (2E-B §B — changes iff a rotation landed).
		// One coherent snapshot under the writer domain; the revision fingerprints
		// exactly the returned state (2E-B §A).
		st := decRedactionSnapshot()
		jsonOK(w, map[string]any{
			"redact_hosts":      st.Redact,
			"scope":             "traffic_destination",
			"scope_fields":      []string{"host", "uri", "dec.host", "dec.sni", "top_hosts"},
			"key_provisioned":   st.Provisioned,
			"key_id":            st.KeyID,
			"rotation_seq":      st.Seq,
			"rotation_receipts": renderRotationReceipts(st.Receipts),
			"revision":          decRedactionRevisionOf(st.Redact, st.KeyID),
			"note":              "Global destination privacy: host, URI, dec.host/dec.sni, and the top-hosts ranking are pseudonymized with a node-local keyed HMAC across every sink (feed, JSONL/history, SIEM, drill-down, top-hosts). Fail-closed: a node with the posture on but no key emits a constant sentinel, never plaintext. Node-local (not exported/rolled-back/synced); fleet-wide correlation is a separate follow-up. Limitation: log search by host (?filter=) matches the stored token, not the plaintext, so plaintext host search does not resolve while the posture is on. Rotate the key via PUT {\"rotate_key\":true,\"operation_id\":\"...\",\"ifRevision\":\"...\"} — this breaks correlation with older records; key_id is the non-secret generation that changes with each rotation, rotation_seq is the durable monotonic key-generation sequence, and rotation_receipts are the bounded non-secret records that let a caller prove whether ITS OWN rotation landed.",
		})

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		// EXACTLY-ONE-ACTION command contract (2E-B correction, Blocker B).
		// RedactHosts is a POINTER so field ABSENCE is distinguishable from an
		// explicit false: PUT {} must never read as "disable the posture".
		var body struct {
			RedactHosts *bool `json:"redact_hosts"`
			// RotateKey, when true, mints a NEW node-local pseudonym key. All future
			// tokens change, so correlation with pre-rotation records breaks (the
			// mission's defined rotation behavior). Admin-only, audited. A rotation
			// is its own action: it must NOT be combined with a posture write, and
			// it REQUIRES operation_id + ifRevision.
			RotateKey bool `json:"rotate_key,omitempty"`
			// OperationID is the caller-generated OPAQUE identity of one rotation
			// operation (Blocker A): the appliance records a durable non-secret
			// receipt for it atomically with the rotation, a replay of the same id
			// never mints another key, and the caller resolves a transport-lost
			// rotation against the receipt — never by "key_id changed".
			OperationID string `json:"operation_id,omitempty"`
			// IfRevision is the stale-writer fence (2E-B §A): when present it must
			// equal the committed revision or the write is the ONE structured 409
			// with no mutation. Optional for posture writes (the legacy GUI's
			// last-writer-wins contract is preserved); REQUIRED for a rotation.
			IfRevision string `json:"ifRevision,omitempty"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		postureAction := body.RedactHosts != nil
		switch {
		case postureAction && body.RotateKey:
			// Ambiguous by construction (which action does the fence govern? is
			// the posture meant to apply before or after the new generation?):
			// refused rather than silently ignoring one of the two commands.
			http.Error(w, "exactly one action per request: send either redact_hosts or rotate_key:true, not both", http.StatusBadRequest)
			return
		case !postureAction && !body.RotateKey:
			// No command was supplied. Absence of redact_hosts is NOT a disable.
			http.Error(w, "no action supplied: send redact_hosts (posture) or rotate_key:true with operation_id and ifRevision (rotation)", http.StatusBadRequest)
			return
		}
		if body.RotateKey {
			if !validRotationOperationID(body.OperationID) {
				http.Error(w, "rotation requires operation_id: 1-64 characters of [A-Za-z0-9._-], generated by the caller per operation", http.StatusBadRequest)
				return
			}
			if body.IfRevision == "" {
				http.Error(w, "rotation requires ifRevision (the reviewed revision from GET)", http.StatusBadRequest)
				return
			}
		}
		// 2E-B §A/§B/§C: fence comparison, target construction (incl. any key
		// mint), durable write, and runtime apply all share ONE serialized
		// AdminSettings save domain — persist-before-apply, so a persist failure
		// leaves the RUNNING privacy posture untouched and a rotation is durable
		// before its success response. The target is built INSIDE the lock so a
		// concurrent PUT can never interleave between read-current and persist.
		var target decRedactionTarget
		var replay trafficRotationReceipt
		err := saveAdminSettingsWithOverrides(adminSaveOverrides{
			decRedaction: &target,
			precondition: func() error {
				curRedact := decRedactHosts()
				curKey := getTrafficPseudonymKey()
				curID := getTrafficPseudonymKeyID()
				// IDEMPOTENCY BEFORE THE FENCE (Blocker A): a retry of an
				// already-landed rotation necessarily asserts the PRE-rotation
				// revision, so the fence alone would answer it with a 409 the
				// caller cannot distinguish from a concurrent admin's change.
				// The receipt lookup runs first: a known operation id aborts the
				// save with NO mutation and the handler answers from the receipt.
				if body.RotateKey {
					if rcpt, ok := findTrafficRotationReceiptLocked(body.OperationID); ok {
						replay = rcpt
						return errRotationReplay
					}
				}
				if body.IfRevision != "" {
					if cur := decRedactionRevisionOf(curRedact, curID); cur != body.IfRevision {
						return errContentSecRevisionConflict{current: cur, asserted: body.IfRevision}
					}
				}
				switch {
				case body.RotateKey:
					// A NEW rotation operation: mint a fresh (key, generation)
					// pair, advance the durable sequence, and record the receipt
					// — all in ONE durable write with the key itself. Rotation
					// never changes the posture (exactly-one-action).
					target.RedactHosts = curRedact
					k, id, mintErr := mintTrafficPseudonymKeyPair()
					if mintErr != nil {
						return fmt.Errorf("%w: %v", errPseudonymKeyMint, mintErr)
					}
					target.Key, target.KeyID = k, id
					target.Seq = trafficRotationSeq + 1
					target.Receipts = appendTrafficRotationReceipt(trafficRotationReceipts, trafficRotationReceipt{
						OpID:  body.OperationID,
						KeyID: id,
						Seq:   target.Seq,
						TS:    time.Now().UTC().Format(time.RFC3339),
					})
				case *body.RedactHosts && len(curKey) != trafficKeyLen:
					// Enabling with no key: provision one in the SAME durable
					// transaction (no window where the posture is on but no key
					// exists ⇒ no accidental fail-closed sentinel run). A new key
					// is a key-generation event, so the sequence advances — but
					// no receipt exists (there is no client rotation operation),
					// keeping "sequence unchanged" a sound not-landed proof.
					target.RedactHosts = true
					k, id, mintErr := mintTrafficPseudonymKeyPair()
					if mintErr != nil {
						return fmt.Errorf("%w: %v", errPseudonymKeyMint, mintErr)
					}
					target.Key, target.KeyID = k, id
					target.Seq = trafficRotationSeq + 1
					target.Receipts = trafficRotationReceipts
				default:
					// Posture-only change: the key (and its generation, sequence,
					// receipts) is kept — disabling never destroys the pseudonym
					// key or the rotation history.
					target.RedactHosts = *body.RedactHosts
					target.Key, target.KeyID = curKey, curID
					target.Seq = trafficRotationSeq
					target.Receipts = trafficRotationReceipts
				}
				return nil
			},
			applyOnSuccess: func() {
				setDecRedactHosts(target.RedactHosts)
				setTrafficPseudonymKeyPair(target.Key, target.KeyID)
				// Runs inside the save's adminSettingsMu section — the guarded
				// rotation metadata moves atomically with the posture/key.
				trafficRotationSeq = target.Seq
				trafficRotationReceipts = target.Receipts
			},
		})
		var conflict errContentSecRevisionConflict
		switch {
		case errors.Is(err, errRotationReplay):
			// The operation already landed exactly once; answer from its durable
			// receipt (this operation's result) plus current truth. No mutation
			// occurred, and none may: a replay must NEVER mint another key.
			st := decRedactionSnapshot()
			auditEvent(r, "decryption.redaction.key-rotate-replay", "noop",
				"idempotent rotation replay (operation already applied); no key change")
			jsonOK(w, map[string]any{
				"redact_hosts":    st.Redact,
				"key_rotated":     true,
				"already_applied": true,
				"operation_id":    replay.OpID,
				"key_id":          replay.KeyID,
				"rotation_seq":    replay.Seq,
				"revision":        decRedactionRevisionOf(st.Redact, st.KeyID),
			})
			return
		case errors.As(err, &conflict):
			writeContentSecRevisionConflict(w, "destination privacy", conflict.current, conflict.asserted)
			return
		case errors.Is(err, errPseudonymKeyMint):
			logger.Printf("decryption redaction: %v", err)
			http.Error(w, "failed to provision pseudonym key", http.StatusInternalServerError)
			return
		case err != nil:
			logger.Printf("decryption redaction: persist failed, runtime unchanged: %v", err)
			http.Error(w, "failed to persist redaction setting", http.StatusInternalServerError)
			return
		}
		state := "disabled"
		if target.RedactHosts {
			state = "enabled"
		}
		if body.RotateKey {
			auditEvent(r, "decryption.redaction.key-rotated", state, "traffic-log destination pseudonym key rotated (breaks correlation with older records); operation "+body.OperationID)
		} else {
			auditEvent(r, "decryption.redaction", state, "traffic-log destination pseudonymization (host/URI/dec.*)")
		}
		// The response is the state THIS PUT installed (coherent by
		// construction), including the non-secret generation, the durable
		// rotation sequence, and — for a rotation — the operation identity.
		resp := map[string]any{
			"redact_hosts": target.RedactHosts,
			"key_rotated":  body.RotateKey,
			"key_id":       target.KeyID,
			"rotation_seq": target.Seq,
			"revision":     decRedactionRevisionOf(target.RedactHosts, target.KeyID),
		}
		if body.RotateKey {
			resp["already_applied"] = false
			resp["operation_id"] = body.OperationID
		}
		jsonOK(w, resp)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
