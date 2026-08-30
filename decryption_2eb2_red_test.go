package main

// decryption_2eb2_red_test.go — 2E-B FINAL CORRECTION: red-before proofs
// against 56c23e64 (the reviewed 2E-B candidate), written in final (green)
// form so each failure at the candidate IS the defect evidence. All
// assertions are HTTP-level plus pre-existing test seams, so the file
// compiles and runs meaningfully at the exact candidate.
//
// Defect families (each demonstrated RED at 56c23e64):
//
//	BLOCKER A — ROTATION OPERATION IDENTITY. The candidate resolves a
//	   transport-lost rotation by comparing the pre-rotation key_id against
//	   fresh truth, which cannot ATTRIBUTE a generation transition to the
//	   caller's own operation: if admin A's rotation never executed and
//	   admin B rotated meanwhile, A observes a changed key_id and would
//	   falsely conclude "my rotation landed". New contract: each rotation
//	   carries a client-generated opaque operation_id; the appliance records
//	   a bounded, durable, NON-SECRET receipt {operation_id, key_id, seq}
//	   atomically with the rotation and a durable monotonic rotation_seq;
//	   a replay of the same operation_id NEVER mints another key (the
//	   idempotency lookup runs BEFORE the stale fence); GET serves
//	   rotation_seq + rotation_receipts so a client proves its OWN
//	   operation landed / did not land / cannot yet be proven.
//
//	BLOCKER B — COMMAND PRESENCE. The candidate decodes redact_hosts into a
//	   plain bool, so PUT {} (or {"rotate_key":false}) is indistinguishable
//	   from an explicit disable and silently turns the posture off; and a
//	   combined posture+rotation body silently ignores the posture field.
//	   New contract: presence-aware decode, EXACTLY-ONE-ACTION — a posture
//	   write carries redact_hosts (alone), a rotation carries
//	   rotate_key:true + operation_id + ifRevision (alone); everything else
//	   is a 400 with no mutation.

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"encoding/json"
)

// dec2eb2Enable enables the posture (minting a key in the isolated state) and
// returns the fresh GET truth.
func dec2eb2Enable(t *testing.T) map[string]any {
	t.Helper()
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": true}); w.Code != 200 {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	return dec2eb2Get(t)
}

func dec2eb2Get(t *testing.T) map[string]any {
	t.Helper()
	w := dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)
	if w.Code != 200 {
		t.Fatalf("GET = %d: %s", w.Code, w.Body.String())
	}
	return dec2ebBody(t, w)
}

// dec2eb2Rotate issues a rotation in the FINAL contract shape: exactly one
// action (rotate_key), a client-generated operation identity, and the fence.
func dec2eb2Rotate(t *testing.T, opID, ifRev string) *httptest.ResponseRecorder {
	t.Helper()
	return dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"rotate_key": true, "operation_id": opID, "ifRevision": ifRev})
}

func dec2eb2Num(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("response is missing the numeric %q contract field: %v", key, m)
	}
	return v
}

// dec2eb2Receipts returns the REQUIRED rotation_receipts list from a GET body.
func dec2eb2Receipts(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	raw, ok := m["rotation_receipts"].([]any)
	if !ok {
		t.Fatalf("response is missing the rotation_receipts contract field: %v", m)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		em, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("rotation_receipts entry is not an object: %v", e)
		}
		out = append(out, em)
	}
	return out
}

// dec2eb2Receipt finds the receipt for one operation id ("" , false if absent).
func dec2eb2Receipt(rs []map[string]any, op string) (map[string]any, bool) {
	for _, r := range rs {
		if id, _ := r["operation_id"].(string); id == op {
			return r, true
		}
	}
	return nil, false
}

// ─── BLOCKER B: command presence ────────────────────────────────────────────

func TestDec2EB2_EmptyPutIsRefusedWithNoMutation(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	keyID := dec2ebStr(t, g, "key_id")

	// A body carrying NO action must be refused: absence of redact_hosts is
	// not a command to disable. (At the candidate this decodes
	// redact_hosts=false and silently disables the posture.)
	w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction", map[string]any{})
	if w.Code != 400 {
		t.Fatalf("PUT {} = %d, want 400 (no action supplied): %s", w.Code, w.Body.String())
	}
	after := dec2eb2Get(t)
	if on, _ := after["redact_hosts"].(bool); !on {
		t.Fatal("PUT {} disabled the destination-privacy posture (field absence read as explicit false)")
	}
	if got := dec2ebStr(t, after, "key_id"); got != keyID {
		t.Fatalf("PUT {} changed the pseudonym generation: %q → %q", keyID, got)
	}
}

func TestDec2EB2_RotateFalseAloneIsRefusedWithNoMutation(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	keyID := dec2ebStr(t, g, "key_id")

	// rotate_key:false supplies no action either — it must not decode as a
	// posture-disable command.
	w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"rotate_key": false})
	if w.Code != 400 {
		t.Fatalf("PUT {rotate_key:false} = %d, want 400 (no action): %s", w.Code, w.Body.String())
	}
	after := dec2eb2Get(t)
	if on, _ := after["redact_hosts"].(bool); !on {
		t.Fatal("PUT {rotate_key:false} disabled the posture")
	}
	if got := dec2ebStr(t, after, "key_id"); got != keyID {
		t.Fatalf("PUT {rotate_key:false} rotated the key: %q → %q", keyID, got)
	}
}

func TestDec2EB2_CombinedPostureAndRotationIsRefused(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	keyID := dec2ebStr(t, g, "key_id")
	rev := dec2ebStr(t, g, "revision")

	// A body carrying BOTH actions is ambiguous (the candidate silently
	// ignores the explicit redact_hosts:false and rotates): exactly-one-action
	// refuses it with no mutation of either axis.
	w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": false, "rotate_key": true, "ifRevision": rev})
	if w.Code != 400 {
		t.Fatalf("combined posture+rotation PUT = %d, want 400: %s", w.Code, w.Body.String())
	}
	after := dec2eb2Get(t)
	if on, _ := after["redact_hosts"].(bool); !on {
		t.Fatal("combined PUT changed the posture despite the refusal contract")
	}
	if got := dec2ebStr(t, after, "key_id"); got != keyID {
		t.Fatalf("combined PUT rotated the key: %q → %q", keyID, got)
	}
}

func TestDec2EB2_RotationRequiresOperationIdentity(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	keyID := dec2ebStr(t, g, "key_id")
	rev := dec2ebStr(t, g, "revision")

	// A rotation without a client operation id is unresolvable after a lost
	// response (the caller could never prove ITS operation landed), so the
	// contract requires one.
	w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"rotate_key": true, "ifRevision": rev})
	if w.Code != 400 {
		t.Fatalf("rotation without operation_id = %d, want 400: %s", w.Code, w.Body.String())
	}
	if got := dec2ebStr(t, dec2eb2Get(t), "key_id"); got != keyID {
		t.Fatalf("identity-less rotation still rotated: %q → %q", keyID, got)
	}
}

// Green control at BOTH trees: explicit posture values still work exactly.
func TestDec2EB2_ExplicitPostureValuesStillWork(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	if on, _ := g["redact_hosts"].(bool); !on {
		t.Fatal("explicit redact_hosts:true did not enable")
	}
	rev := dec2ebStr(t, g, "revision")
	if w := dec2ebDo(t, RoleAdmin, http.MethodPut, "/api/decryption/redaction",
		map[string]any{"redact_hosts": false, "ifRevision": rev}); w.Code != 200 {
		t.Fatalf("explicit disable = %d: %s", w.Code, w.Body.String())
	}
	if on, _ := dec2eb2Get(t)["redact_hosts"].(bool); on {
		t.Fatal("explicit redact_hosts:false did not disable")
	}
}

// ─── BLOCKER A: rotation operation identity ─────────────────────────────────

func TestDec2EB2_RotationCarriesOperationReceipt(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	seq0 := dec2eb2Num(t, g, "rotation_seq")
	rev := dec2ebStr(t, g, "revision")
	preKey := dec2ebStr(t, g, "key_id")

	w := dec2eb2Rotate(t, "op-2eb2-carry", rev)
	if w.Code != 200 {
		t.Fatalf("rotation = %d: %s", w.Code, w.Body.String())
	}
	res := dec2ebBody(t, w)
	if got := dec2ebStr(t, res, "operation_id"); got != "op-2eb2-carry" {
		t.Fatalf("rotation response does not echo the operation identity: %q", got)
	}
	if applied, _ := res["already_applied"].(bool); applied {
		t.Fatal("a first-time rotation reported already_applied")
	}
	if got := dec2eb2Num(t, res, "rotation_seq"); got != seq0+1 {
		t.Fatalf("rotation_seq did not advance by one: %v → %v", seq0, got)
	}
	newKey := dec2ebStr(t, res, "key_id")
	if newKey == preKey {
		t.Fatal("rotation did not change the pseudonym generation")
	}

	after := dec2eb2Get(t)
	if got := dec2eb2Num(t, after, "rotation_seq"); got != seq0+1 {
		t.Fatalf("GET rotation_seq = %v, want %v", got, seq0+1)
	}
	rcpt, ok := dec2eb2Receipt(dec2eb2Receipts(t, after), "op-2eb2-carry")
	if !ok {
		t.Fatal("GET carries no receipt for the landed operation")
	}
	if got, _ := rcpt["key_id"].(string); got != newKey {
		t.Fatalf("receipt names the wrong resulting generation: %q want %q", got, newKey)
	}
	if got, _ := rcpt["seq"].(float64); got != seq0+1 {
		t.Fatalf("receipt seq = %v, want %v", got, seq0+1)
	}
}

func TestDec2EB2_ReplaySameOperationNeverRotatesTwice(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	rev0 := dec2ebStr(t, g, "revision")

	first := dec2eb2Rotate(t, "op-2eb2-replay", rev0)
	if first.Code != 200 {
		t.Fatalf("first rotation = %d: %s", first.Code, first.Body.String())
	}
	fm := dec2ebBody(t, first)
	k1 := dec2ebStr(t, fm, "key_id")
	s1 := dec2eb2Num(t, fm, "rotation_seq")

	// A byte-identical replay (same operation_id, now-stale fence) is the
	// lost-response retry. It must be answered from the RECEIPT — never by a
	// second rotation, and never by a bare 409 the caller cannot distinguish
	// from "someone else changed the state".
	replay := dec2eb2Rotate(t, "op-2eb2-replay", rev0)
	if replay.Code != 200 {
		t.Fatalf("replay = %d, want 200 (idempotent receipt): %s", replay.Code, replay.Body.String())
	}
	rm := dec2ebBody(t, replay)
	if applied, _ := rm["already_applied"].(bool); !applied {
		t.Fatal("replay did not report already_applied")
	}
	if got := dec2ebStr(t, rm, "key_id"); got != k1 {
		t.Fatalf("replay minted a different generation: %q want %q", got, k1)
	}
	if got := dec2eb2Num(t, rm, "rotation_seq"); got != s1 {
		t.Fatalf("replay advanced rotation_seq: %v want %v", got, s1)
	}

	after := dec2eb2Get(t)
	if got := dec2ebStr(t, after, "key_id"); got != k1 {
		t.Fatalf("replay rotated the key again: %q → %q", k1, got)
	}
	if got := dec2eb2Num(t, after, "rotation_seq"); got != s1 {
		t.Fatalf("replay advanced the durable sequence: %v → %v", s1, got)
	}
	count := 0
	for _, r := range dec2eb2Receipts(t, after) {
		if id, _ := r["operation_id"].(string); id == "op-2eb2-replay" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("operation has %d receipts, want exactly 1", count)
	}
}

func TestDec2EB2_StaleFenceNewOperationConflictsWithoutRotating(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	rev0 := dec2ebStr(t, g, "revision")

	if w := dec2eb2Rotate(t, "op-2eb2-first", rev0); w.Code != 200 {
		t.Fatalf("first rotation = %d: %s", w.Code, w.Body.String())
	}
	mid := dec2eb2Get(t)
	k1 := dec2ebStr(t, mid, "key_id")
	s1 := dec2eb2Num(t, mid, "rotation_seq")

	// A DIFFERENT operation asserting the superseded revision is a stale
	// writer, not a retry: structured 409, no rotation, no receipt.
	w := dec2eb2Rotate(t, "op-2eb2-second", rev0)
	if w.Code != 409 {
		t.Fatalf("stale-fenced new operation = %d, want 409: %s", w.Code, w.Body.String())
	}
	var conflict struct {
		Error           string `json:"error"`
		CurrentRevision string `json:"currentRevision"`
		YourRevision    string `json:"yourRevision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil ||
		conflict.Error == "" || conflict.YourRevision != rev0 || conflict.CurrentRevision == "" {
		t.Fatalf("conflict is not the structured shape: %s", w.Body.String())
	}
	after := dec2eb2Get(t)
	if got := dec2ebStr(t, after, "key_id"); got != k1 {
		t.Fatalf("stale-fenced operation rotated anyway: %q → %q", k1, got)
	}
	if got := dec2eb2Num(t, after, "rotation_seq"); got != s1 {
		t.Fatalf("stale-fenced operation advanced the sequence: %v → %v", s1, got)
	}
	if _, ok := dec2eb2Receipt(dec2eb2Receipts(t, after), "op-2eb2-second"); ok {
		t.Fatal("a refused operation left a receipt")
	}
}

// TestDec2EB2_ConcurrentRotationTruthIsPerOperation is the review's
// counterexample, server side: admin A reviews G0/R0 and A's rotation NEVER
// executes; admin B rotates. Fresh truth must carry the facts that FORBID
// classifying A's operation as landed: the sequence advanced, B's receipt
// exists, and A's does not. It also proves the inverse: an operation that
// DID land stays provably landed via its own receipt after a later rotation
// by someone else.
func TestDec2EB2_ConcurrentRotationTruthIsPerOperation(t *testing.T) {
	dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	seq0 := dec2eb2Num(t, g, "rotation_seq")
	rev0 := dec2ebStr(t, g, "revision")

	// Admin A reviews (operation id chosen, nothing sent). Admin B rotates.
	if w := dec2eb2Rotate(t, "op-2eb2-admin-b", rev0); w.Code != 200 {
		t.Fatalf("admin B rotation = %d: %s", w.Code, w.Body.String())
	}

	fresh := dec2eb2Get(t)
	if got := dec2eb2Num(t, fresh, "rotation_seq"); got != seq0+1 {
		t.Fatalf("sequence after B = %v, want %v", got, seq0+1)
	}
	receipts := dec2eb2Receipts(t, fresh)
	if _, ok := dec2eb2Receipt(receipts, "op-2eb2-admin-b"); !ok {
		t.Fatal("B's landed rotation has no receipt")
	}
	if _, ok := dec2eb2Receipt(receipts, "op-2eb2-admin-a"); ok {
		t.Fatal("a never-sent operation has a receipt")
	}

	// A now lands a real rotation; B rotates again after it. A's receipt must
	// survive B's later rotation — landed stays provably landed.
	revA := dec2ebStr(t, fresh, "revision")
	if w := dec2eb2Rotate(t, "op-2eb2-admin-a", revA); w.Code != 200 {
		t.Fatalf("admin A rotation = %d: %s", w.Code, w.Body.String())
	}
	revB2 := dec2ebStr(t, dec2eb2Get(t), "revision")
	if w := dec2eb2Rotate(t, "op-2eb2-admin-b2", revB2); w.Code != 200 {
		t.Fatalf("admin B second rotation = %d: %s", w.Code, w.Body.String())
	}
	final := dec2eb2Receipts(t, dec2eb2Get(t))
	if _, ok := dec2eb2Receipt(final, "op-2eb2-admin-a"); !ok {
		t.Fatal("A's landed rotation lost its receipt after B rotated")
	}
	if _, ok := dec2eb2Receipt(final, "op-2eb2-admin-b2"); !ok {
		t.Fatal("B's second rotation has no receipt")
	}
}

func TestDec2EB2_RotationStateSurvivesRestart(t *testing.T) {
	path := dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	rev := dec2ebStr(t, g, "revision")
	if w := dec2eb2Rotate(t, "op-2eb2-restart", rev); w.Code != 200 {
		t.Fatalf("rotation = %d: %s", w.Code, w.Body.String())
	}
	mid := dec2eb2Get(t)
	k1 := dec2ebStr(t, mid, "key_id")
	s1 := dec2eb2Num(t, mid, "rotation_seq")

	// Durable BEFORE success: the file already carries seq + receipts.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var persisted map[string]any
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("settings decode: %v", err)
	}
	if _, ok := persisted["traffic_key_rotation_seq"]; !ok {
		t.Fatal("rotation sequence is not persisted")
	}
	if _, ok := persisted["traffic_key_rotation_receipts"]; !ok {
		t.Fatal("rotation receipts are not persisted")
	}

	// Advance the LIVE state past the snapshot (a second rotation), then load
	// the earlier file: load must restore the FILE's truth, not keep the
	// residue — proving restart-observability comes from the durable record.
	rev2 := dec2ebStr(t, mid, "revision")
	if w := dec2eb2Rotate(t, "op-2eb2-later", rev2); w.Code != 200 {
		t.Fatalf("second rotation = %d: %s", w.Code, w.Body.String())
	}
	snapPath := filepath.Join(t.TempDir(), "admin_settings.json")
	if err := os.WriteFile(snapPath, raw, 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	swapAdminSettingsPath(t, snapPath)
	setDecRedactHosts(false)
	setTrafficPseudonymKey(nil)
	LoadAdminSettings(snapPath)

	after := dec2eb2Get(t)
	if got := dec2ebStr(t, after, "key_id"); got != k1 {
		t.Fatalf("restart lost the rotated generation: %q want %q", got, k1)
	}
	if got := dec2eb2Num(t, after, "rotation_seq"); got != s1 {
		t.Fatalf("restart lost the rotation sequence: %v want %v", got, s1)
	}
	rcpts := dec2eb2Receipts(t, after)
	if _, ok := dec2eb2Receipt(rcpts, "op-2eb2-restart"); !ok {
		t.Fatal("restart lost the operation receipt")
	}
	if _, ok := dec2eb2Receipt(rcpts, "op-2eb2-later"); ok {
		t.Fatal("load kept live residue instead of restoring the file's truth")
	}
}

func TestDec2EB2_RotationSurfacesCarryNoKeyMaterial(t *testing.T) {
	path := dec2ebIsolate(t)
	g := dec2eb2Enable(t)
	rev := dec2ebStr(t, g, "revision")
	w := dec2eb2Rotate(t, "op-2eb2-secrets", rev)
	if w.Code != 200 {
		t.Fatalf("rotation = %d: %s", w.Code, w.Body.String())
	}
	rotateBody := w.Body.String()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var persisted struct {
		Key []byte `json:"traffic_pseudonym_key"`
	}
	if err := json.Unmarshal(raw, &persisted); err != nil || len(persisted.Key) == 0 {
		t.Fatalf("cannot recover the persisted key for the leak probe: %v", err)
	}
	encodings := []string{
		hex.EncodeToString(persisted.Key),
		base64.StdEncoding.EncodeToString(persisted.Key),
		base64.RawStdEncoding.EncodeToString(persisted.Key),
	}

	getW := dec2ebDo(t, RoleViewer, http.MethodGet, "/api/decryption/redaction", nil)
	for _, enc := range encodings {
		if strings.Contains(rotateBody, enc) || strings.Contains(getW.Body.String(), enc) {
			t.Fatal("a rotation surface carries pseudonym key material")
		}
	}

	// Receipts are a bounded allowlist of NON-SECRET facts — nothing else.
	for _, r := range dec2eb2Receipts(t, dec2ebBody(t, getW)) {
		for k := range r {
			switch k {
			case "operation_id", "key_id", "seq", "ts":
			default:
				t.Fatalf("receipt carries an out-of-contract field %q", k)
			}
		}
	}
}
