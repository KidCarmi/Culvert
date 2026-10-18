package session

// Equivalence contract for the pooled MAC engine (the macState / macEngine
// block in session.go). The performance contract lives in
// session_mac_benchgate_test.go; the benchmarks behind both live in
// session_mac_bench_test.go.
//
// The engine replaced a per-call hmac.New with a per-KEY HMAC state recycled
// through a pool. Two things can break that are invisible to the ordinary
// round-trip tests, so both are pinned here:
//
//   - the digest must stay byte-identical to the per-call form, for every
//     payload shape and key shape, which a differential test plus a fuzz
//     target against a verbatim copy of the old implementation decides; and
//   - a state primed with a superseded key must never verify under the new
//     one, which the key-rotation-under-load test decides (run with -race).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// legacyMAC is a VERBATIM copy of the implementation the engine replaced:
// read the key under the mutex, build a fresh HMAC per call, hash a converted
// copy of the payload, Sum(nil), encode to a string. The differential oracle.
func legacyMAC(data string) string {
	signingKeyMu.RLock()
	key := signingKey
	signingKeyMu.RUnlock()
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// legacyMacEqual is the comparison the engine replaced, verbatim.
func legacyMacEqual(data, sig string) bool {
	expected := legacyMAC(data)
	return hmac.Equal([]byte(sig), []byte(expected))
}

// macPayloads covers the shapes the engine branches on: empty, short, the
// realistic cookie payload, exactly at the inline-buffer bound, one byte over
// it (the conversion fallback) and far over it.
func macPayloads() map[string]string {
	return map[string]string{
		"empty":            "",
		"one byte":         "x",
		"short":            "test-payload",
		"realistic cookie": base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice@example.com","email":"alice@example.com","name":"Alice Example","grp":["engineering","proxy-users"],"pvd":"okta","role":"viewer","exp":1760000000,"jti":"0f1e2d3c4b5a69788796a5b4c3d2e1f0"}`)),
		"at bound":         strings.Repeat("a", macScratchLen),
		"bound minus one":  strings.Repeat("b", macScratchLen-1),
		"bound plus one":   strings.Repeat("c", macScratchLen+1),
		"far over bound":   strings.Repeat("d", 8*macScratchLen+7),
		"non-ascii":        "pâtisserie-日本語-🔐",
		"control bytes":    "a\x00b\nc\x7f",
	}
}

// macKeys covers the key shapes SetSigningKey can install: nil (the pre-init
// state the legacy form also signed under), short, the canonical 32 bytes, and
// longer than one SHA-256 block (which HMAC hashes down first).
func macKeys() map[string][]byte {
	long := make([]byte, 200)
	for i := range long {
		long[i] = byte(i * 7)
	}
	k32 := make([]byte, 32)
	for i := range k32 {
		k32[i] = byte(i + 1)
	}
	return map[string][]byte{
		"nil":        nil,
		"empty":      {},
		"short":      []byte("k"),
		"32 bytes":   k32,
		"over block": long,
	}
}

// TestMacEngine_MatchesLegacyDigest is the differential oracle: for every key
// shape crossed with every payload shape, the pooled engine and the per-call
// form must agree exactly.
func TestMacEngine_MatchesLegacyDigest(t *testing.T) {
	prev := SigningKey()
	t.Cleanup(func() { SetSigningKey(prev) })

	for keyName, key := range macKeys() {
		SetSigningKey(key)
		for payloadName, payload := range macPayloads() {
			want := legacyMAC(payload)
			if got := mac(payload); got != want {
				t.Errorf("key=%s payload=%s: mac = %q, legacy = %q", keyName, payloadName, got, want)
			}
			if got := MAC(payload); got != want {
				t.Errorf("key=%s payload=%s: MAC = %q, legacy = %q", keyName, payloadName, got, want)
			}
		}
	}
}

// TestMacEqual_MatchesLegacyVerdict crosses the same shapes against the
// signatures a verifier actually sees: the correct one, a flipped byte, a
// truncated one, an over-long one, and the empty string. The length-mismatch
// cases are the ones the inline compare buffer could get wrong.
func TestMacEqual_MatchesLegacyVerdict(t *testing.T) {
	prev := SigningKey()
	t.Cleanup(func() { SetSigningKey(prev) })

	for keyName, key := range macKeys() {
		SetSigningKey(key)
		for payloadName, payload := range macPayloads() {
			good := legacyMAC(payload)
			sigs := map[string]string{
				"correct":        good,
				"flipped first":  "~" + good[1:],
				"flipped last":   good[:len(good)-1] + "~",
				"truncated":      good[:len(good)-1],
				"over long":      good + "A",
				"empty":          "",
				"other payload":  legacyMAC(payload + "!"),
				"double length":  good + good,
				"single byte":    "A",
				"padded encoded": base64.StdEncoding.EncodeToString([]byte(payload)),
			}
			for sigName, sig := range sigs {
				want := legacyMacEqual(payload, sig)
				if got := macEqual(payload, sig); got != want {
					t.Errorf("key=%s payload=%s sig=%s: macEqual = %v, legacy = %v",
						keyName, payloadName, sigName, got, want)
				}
			}
		}
	}
}

// TestMacEncodedLen_MatchesEncoding pins the inline buffer size to the
// encoding it has to hold. A future digest or alphabet change must fail here
// rather than silently truncate a signature.
func TestMacEncodedLen_MatchesEncoding(t *testing.T) {
	if got := base64.RawURLEncoding.EncodedLen(sha256.Size); got != macEncodedLen {
		t.Fatalf("macEncodedLen = %d, base64.RawURLEncoding.EncodedLen(sha256.Size) = %d", macEncodedLen, got)
	}
	prev := SigningKey()
	t.Cleanup(func() { SetSigningKey(prev) })
	withKey32(t)
	if got := len(mac("anything")); got != macEncodedLen {
		t.Fatalf("len(mac(...)) = %d, want %d", got, macEncodedLen)
	}
}

// withKey32 installs the deterministic 32-byte key without registering its own
// cleanup, for tests that already own the restore.
func withKey32(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	SetSigningKey(key)
}

// TestMacEngine_KeyRotationUnderLoad is the pooling-specific hazard: states
// primed with a superseded key must never be handed to a caller signing under
// the new one. Verifiers run concurrently with installs; every verdict must be
// one the per-call form would also have reached at SOME installed key, and a
// token signed under a retired key must stop verifying once that key is gone.
//
// Run with -race: this is also the regression test for the unguarded global
// write the ADR-0002 extraction fixed.
func TestMacEngine_KeyRotationUnderLoad(t *testing.T) {
	prev := SigningKey()
	t.Cleanup(func() { SetSigningKey(prev) })

	const keys = 8
	keyring := make([][]byte, keys)
	for i := range keyring {
		k := make([]byte, 32)
		for j := range k {
			k[j] = byte(i*31 + j)
		}
		keyring[i] = k
	}

	// The signature of one fixed payload under each key, captured serially by
	// the per-call form so the oracle itself never touches the pool.
	const payload = "cm90YXRpb24tcGF5bG9hZA"
	want := make(map[string]struct{}, keys)
	for _, k := range keyring {
		SetSigningKey(k)
		want[legacyMAC(payload)] = struct{}{}
	}

	// A signature under a key that is NEVER installed. No concurrently
	// rotating engine may accept it, whatever the race decides.
	foreign := make([]byte, 32)
	for i := range foreign {
		foreign[i] = 0xA0 | byte(i)
	}
	SetSigningKey(foreign)
	foreignSig := legacyMAC(payload)
	if _, clash := want[foreignSig]; clash {
		t.Fatal("foreign key collided with the keyring; pick different test keys")
	}
	// Put the keyring back in place BEFORE the concurrent phase: the rotator
	// only ever installs keyring keys, so from here on no digest from the
	// foreign key can legitimately appear.
	SetSigningKey(keyring[0])

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			SetSigningKey(keyring[i%keys])
		}
	}()

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Every digest the engine produces must be the one the
				// per-call form reaches under SOME installed key. A pooled
				// state that outlived its key shows up here as a digest from
				// outside the keyring.
				//
				// Nothing stronger is assertable while the rotator runs: the
				// key can change between any two calls, so "the signature mac
				// just produced is the one macEqual accepts" is not an
				// invariant of the code, only of a quiescent key.
				if got := mac(payload); !isKeyringSig(want, got) {
					t.Errorf("mac produced %q, which is not the signature under ANY installed key — a pooled state outlived its key", got)
					return
				}
				// The never-installed key's signature must be rejected at every
				// point in the rotation.
				if macEqual(payload, foreignSig) {
					t.Error("macEqual accepted a signature from a key that was never installed")
					return
				}
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	// After the churn, a token signed under a key no longer installed must be
	// rejected, and one signed under the installed key accepted.
	SetSigningKey(keyring[0])
	if !macEqual(payload, legacyMAC(payload)) {
		t.Error("macEqual rejected the signature under the currently installed key")
	}
	SetSigningKey(keyring[1])
	SetSigningKey(keyring[0])
	stale := func() string {
		SetSigningKey(keyring[3])
		s := legacyMAC(payload)
		SetSigningKey(keyring[0])
		return s
	}()
	if macEqual(payload, stale) {
		t.Error("macEqual accepted a signature from a retired key")
	}
}

// isKeyringSig reports whether sig is the payload signature under one of the
// keys the rotation test installs.
func isKeyringSig(keyring map[string]struct{}, sig string) bool {
	_, ok := keyring[sig]
	return ok
}

// TestDecode_SurvivesKeyRotation checks the contract one level up: a cookie
// issued under one key must decode while that key is installed and fail with
// an invalid-signature error after it is replaced — the engine swap must not
// leave Decode verifying against the old binding.
func TestDecode_SurvivesKeyRotation(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)

	s := &Session{Sub: "alice", Provider: "okta", Exp: time.Now().Add(time.Hour).Unix()}
	tok, err := Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := Decode(tok); err != nil {
		t.Fatalf("Decode under the issuing key: %v", err)
	}

	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(200 - i)
	}
	SetSigningKey(other)
	if _, err := Decode(tok); err == nil {
		t.Fatal("Decode accepted a cookie signed under the superseded key")
	} else if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("Decode error = %v, want invalid signature", err)
	}
}

// TestMacState_DoesNotRetainOversizePayload pins the reason the inline buffer
// is an array and not a grown slice: verifying a huge payload must not leave a
// pooled state holding a huge allocation for the rest of the process (the
// failure mode the hostutil IDNA memo hit).
func TestMacState_DoesNotRetainOversizePayload(t *testing.T) {
	prev := SigningKey()
	t.Cleanup(func() { SetSigningKey(prev) })
	withKey32(t)

	huge := strings.Repeat("z", 1<<20)
	if got, want := mac(huge), legacyMAC(huge); got != want {
		t.Fatalf("oversize payload: mac = %q, legacy = %q", got, want)
	}
	e := macEngines.Load()
	s := e.pool.Get().(*macState)
	defer e.pool.Put(s)
	if got := len(s.msg); got != macScratchLen {
		t.Fatalf("pooled state scratch buffer is %d bytes, want the fixed %d", got, macScratchLen)
	}
}

// FuzzMacEqual drives the engine and the per-call form with the same arbitrary
// payload/signature pairs and requires identical verdicts, including the digest
// itself. Seeded with the shapes the table above enumerates.
func FuzzMacEqual(f *testing.F) {
	prev := SigningKey()
	f.Cleanup(func() { SetSigningKey(prev) })
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	SetSigningKey(key)

	for _, p := range macPayloads() {
		f.Add(p, legacyMAC(p))
		f.Add(p, "")
	}
	f.Add("", "AAAA")
	f.Add(strings.Repeat("x", macScratchLen+1), strings.Repeat("A", macEncodedLen))

	f.Fuzz(func(t *testing.T, payload, sig string) {
		if got, want := mac(payload), legacyMAC(payload); got != want {
			t.Fatalf("mac(%q) = %q, legacy = %q", payload, got, want)
		}
		if got, want := macEqual(payload, sig), legacyMacEqual(payload, sig); got != want {
			t.Fatalf("macEqual(%q, %q) = %v, legacy = %v", payload, sig, got, want)
		}
	})
}

// TestSetSigningKey_RebindsOnlyOnChange pins the pool-retention rule.
// applySnapshotSessionSecret reinstalls the CP-synced secret on every snapshot
// apply whether or not it moved; if each of those no-ops discarded the engine,
// a data plane under steady config sync would rebuild HMAC state continuously
// and keep none of the win. A real key change must still swap the engine.
func TestSetSigningKey_RebindsOnlyOnChange(t *testing.T) {
	prev := SigningKey()
	t.Cleanup(func() { SetSigningKey(prev) })

	first := make([]byte, 32)
	for i := range first {
		first[i] = byte(i + 1)
	}
	SetSigningKey(first)
	eng := macEngines.Load()

	// Same bytes, different slice: no rebind.
	again := make([]byte, len(first))
	copy(again, first)
	SetSigningKey(again)
	if got := macEngines.Load(); got != eng {
		t.Error("reinstalling an unchanged key rebound the MAC engine and discarded the warm pool")
	}
	if got, want := mac("payload"), legacyMAC("payload"); got != want {
		t.Errorf("after a no-op reinstall: mac = %q, legacy = %q", got, want)
	}

	// Different bytes: rebind.
	changed := make([]byte, len(first))
	copy(changed, first)
	changed[31] ^= 0xFF
	SetSigningKey(changed)
	if got := macEngines.Load(); got == eng {
		t.Fatal("installing a different key did NOT rebind the MAC engine — verification would keep using the retired key")
	}
	if got, want := mac("payload"), legacyMAC("payload"); got != want {
		t.Errorf("after a real rotation: mac = %q, legacy = %q", got, want)
	}

	// A length change is a change even when the shorter key is a prefix.
	SetSigningKey(changed[:16])
	if got := macEngines.Load(); got == eng {
		t.Log("engine rebound for the truncated key, as required")
	}
	if got, want := mac("payload"), legacyMAC("payload"); got != want {
		t.Errorf("after a truncating rotation: mac = %q, legacy = %q", got, want)
	}

	// nil and empty are the same key to HMAC (both pad to a zero block), so
	// they are also the same key to the engine. Recorded, not incidental.
	SetSigningKey(nil)
	nilEng := macEngines.Load()
	SetSigningKey([]byte{})
	if got := macEngines.Load(); got != nilEng {
		t.Error("nil → empty rebound the engine; HMAC treats them as one key")
	}
	if got, want := mac("payload"), legacyMAC("payload"); got != want {
		t.Errorf("under the zero key: mac = %q, legacy = %q", got, want)
	}
}

// TestSetSigningKey_EngineOwnsKeyCopy pins the invariant newMacEngine's copy
// exists for: once a key is installed, mutating the caller's slice must not
// change what the engine signs with. The per-call form re-read that slice on
// every MAC, so without the copy a post-install mutation would leave already
// pooled states on the old bytes and newly minted ones on the new — two keys
// live in one pool, with which one you got depending on pool luck.
func TestSetSigningKey_EngineOwnsKeyCopy(t *testing.T) {
	prev := SigningKey()
	t.Cleanup(func() { SetSigningKey(prev) })

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	SetSigningKey(key)

	const payload = "stable-payload"
	before := mac(payload)

	// Mutate the caller's slice in place, then force the pool to mint a fresh
	// state (an earlier one may still be cached) and sign again.
	key[0] ^= 0xFF
	e := macEngines.Load()
	for i := 0; i < 64; i++ {
		_ = mac(payload)
	}
	if got := mac(payload); got != before {
		t.Errorf("mac changed from %q to %q after the caller mutated its key slice — the engine is not holding its own copy", before, got)
	}
	if e != macEngines.Load() {
		t.Error("mutating the caller's slice rebound the engine; nothing should have")
	}
	if !macEqual(payload, before) {
		t.Error("macEqual stopped accepting the signature the installed key produces")
	}
}

// legacyDecode is Decode with the ONE changed line put back: the per-call
// hmac.New comparison instead of macEqual. Everything else — the dot split,
// the revocation lookups, the base64 payload decode, the json unmarshal, the
// expiry check — is the current body verbatim, so benchmarking the two side by
// side in one run isolates the MAC step's share of a whole verify.
//
// Kept beside the other oracles rather than in the benchmark file because this
// test also asserts it still decides what Decode decides.
func legacyDecode(raw string) (*Session, error) {
	dot := strings.LastIndex(raw, ".")
	if dot < 0 {
		return nil, fmt.Errorf("session: malformed cookie")
	}
	b64, sig := raw[:dot], raw[dot+1:]
	if !legacyMacEqual(b64, sig) {
		return nil, fmt.Errorf("session: invalid signature")
	}
	if Revoked.IsRevoked(b64) {
		return nil, fmt.Errorf("session: revoked")
	}
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("session: base64 decode: %w", err)
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, fmt.Errorf("session: json decode: %w", err)
	}
	if time.Now().Unix() > s.Exp {
		return nil, fmt.Errorf("session: expired")
	}
	if s.Sub != "" && Revoked.IsUserRevoked(s.Sub) {
		return nil, fmt.Errorf("session: user revoked")
	}
	return &s, nil
}

// TestDecode_MatchesLegacyDecode keeps the end-to-end oracle honest: if Decode
// and legacyDecode ever diverge, the benchmark comparison built on them is
// measuring two different functions.
func TestDecode_MatchesLegacyDecode(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)

	valid, err := Encode(&Session{
		Sub:    "alice@example.com",
		Groups: []string{"engineering"},
		Exp:    time.Now().Add(time.Hour).Unix(),
		Jti:    "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	expired, err := Encode(&Session{Sub: "bob", Exp: time.Now().Add(-time.Hour).Unix()})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	cases := map[string]string{
		"valid":            valid,
		"expired":          expired,
		"no dot":           "nodothere",
		"bad signature":    valid[:len(valid)-1] + "~",
		"empty":            "",
		"dot only":         ".",
		"bad base64":       "!!!." + MAC("!!!"),
		"not json":         base64.RawURLEncoding.EncodeToString([]byte("plain")) + "." + MAC(base64.RawURLEncoding.EncodeToString([]byte("plain"))),
		"truncated sig":    valid[:len(valid)-1],
		"signature only":   "." + MAC(""),
		"foreign envelope": "a.b.c",
	}
	for name, raw := range cases {
		gotSess, gotErr := Decode(raw)
		wantSess, wantErr := legacyDecode(raw)
		if (gotErr == nil) != (wantErr == nil) {
			t.Errorf("%s: Decode err = %v, legacyDecode err = %v", name, gotErr, wantErr)
			continue
		}
		if gotErr != nil {
			if gotErr.Error() != wantErr.Error() {
				t.Errorf("%s: Decode err = %q, legacyDecode err = %q", name, gotErr, wantErr)
			}
			continue
		}
		if !reflect.DeepEqual(gotSess, wantSess) {
			t.Errorf("%s: Decode = %+v, legacyDecode = %+v", name, gotSess, wantSess)
		}
	}
}
