package secret

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKEKHex is a deterministic 32-byte KEK in hex for env-provider tests.
const testKEKHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// envProviderWith returns an env-backed provider whose KEK is set for this test.
func envProviderWith(t *testing.T, keyHex string) *Provider {
	t.Helper()
	t.Setenv(EnvKEKName, keyHex)
	return EnvProvider(EnvKEKName)
}

func TestSealOpenRoundTrip(t *testing.T) {
	p := envProviderWith(t, testKEKHex)
	plaintext := []byte("cluster CA private key PEM")

	env, err := Seal(plaintext, p)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !IsEnvelope(env) {
		t.Fatal("Seal output is not a PSCA envelope")
	}
	if bytes.Contains(env, plaintext) {
		t.Fatal("envelope contains plaintext")
	}

	sealed, err := Open(env, p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var got []byte
	if err := sealed.WithPlaintext(func(b []byte) error {
		got = append(got[:0], b...) // copy out for assertion
		return nil
	}); err != nil {
		t.Fatalf("WithPlaintext: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestWithPlaintextZeroizesAndSingleUse(t *testing.T) {
	p := envProviderWith(t, testKEKHex)
	env, err := Seal([]byte("payload"), p)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed, err := Open(env, p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := sealed.WithPlaintext(func(b []byte) error { return nil }); err != nil {
		t.Fatalf("first WithPlaintext: %v", err)
	}
	// Buffer must be zeroized / consumed: a second call fails closed.
	if err := sealed.WithPlaintext(func(b []byte) error { return nil }); err == nil {
		t.Fatal("expected error on second WithPlaintext (single-use)")
	}
	// Destroy is idempotent.
	sealed.Destroy()
	sealed.Destroy()
}

func TestWithPlaintextPropagatesError(t *testing.T) {
	p := envProviderWith(t, testKEKHex)
	env, _ := Seal([]byte("x"), p)
	sealed, _ := Open(env, p)
	sentinel := errors.New("boom")
	if err := sealed.WithPlaintext(func(b []byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel, got %v", err)
	}
}

func TestWithPlaintextNilFn(t *testing.T) {
	p := envProviderWith(t, testKEKHex)
	env, _ := Seal([]byte("x"), p)
	sealed, _ := Open(env, p)
	if err := sealed.WithPlaintext(nil); err == nil {
		t.Fatal("expected error for nil fn")
	}
}

func TestOpenWrongKEKFailsClosed(t *testing.T) {
	pA := envProviderWith(t, testKEKHex)
	env, err := Seal([]byte("secret"), pA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Different KEK.
	otherHex := strings.Repeat("ab", KEKLen)
	pB := EnvProvider("OTHER_KEK")
	t.Setenv("OTHER_KEK", otherHex)
	if _, err := Open(env, pB); err == nil {
		t.Fatal("expected Open with wrong KEK to fail")
	}
}

func TestOpenCorruptFailsClosed(t *testing.T) {
	p := envProviderWith(t, testKEKHex)
	env, _ := Seal([]byte("secret"), p)
	env[len(env)-1] ^= 0xff // flip a tag/ciphertext byte
	if _, err := Open(env, p); err == nil {
		t.Fatal("expected Open of corrupted envelope to fail")
	}
}

func TestOpenNonEnvelopeFailsClosed(t *testing.T) {
	p := envProviderWith(t, testKEKHex)
	if IsEnvelope([]byte("-----BEGIN EC PRIVATE KEY-----")) {
		t.Fatal("plaintext PEM misdetected as envelope")
	}
	if _, err := Open([]byte("not an envelope"), p); err == nil {
		t.Fatal("expected Open of non-envelope to fail")
	}
}

func TestNilProvider(t *testing.T) {
	if _, err := Seal([]byte("x"), nil); err == nil {
		t.Fatal("Seal(nil provider) should error")
	}
	if _, err := Open([]byte("x"), nil); err == nil {
		t.Fatal("Open(nil provider) should error")
	}
	if err := ValidateProvider(nil); err == nil {
		t.Fatal("ValidateProvider(nil) should error")
	}
	if (&Provider{}).Name() != "" {
		t.Fatal("empty provider Name should be blank")
	}
}

func TestSealToFileOpenFile(t *testing.T) {
	dir := t.TempDir()
	p := envProviderWith(t, testKEKHex)
	path := filepath.Join(dir, "cluster-ca.key")
	plaintext := []byte("PEM DATA")

	if err := SealToFile(path, plaintext, p); err != nil {
		t.Fatalf("SealToFile: %v", err)
	}
	// On disk it must be an envelope with 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %#o, want 0600", perm)
	}
	raw, _ := os.ReadFile(path)
	if !IsEnvelope(raw) {
		t.Fatal("file is not an envelope")
	}

	sealed, err := OpenFile(path, p)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := sealed.WithPlaintext(func(b []byte) error {
		if !bytes.Equal(b, plaintext) {
			t.Fatalf("mismatch: %q", b)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPlaintext: %v", err)
	}

	if _, err := OpenFile(filepath.Join(dir, "missing"), p); err == nil {
		t.Fatal("OpenFile on missing path should error")
	}
}

func TestValidateProvider(t *testing.T) {
	p := envProviderWith(t, testKEKHex)
	if err := ValidateProvider(p); err != nil {
		t.Fatalf("ValidateProvider(valid) = %v", err)
	}
	// Missing env → ErrKEKMissing.
	missing := EnvProvider("DEFINITELY_UNSET_KEK")
	if err := ValidateProvider(missing); !errors.Is(err, ErrKEKMissing) {
		t.Fatalf("want ErrKEKMissing, got %v", err)
	}
}

func TestFileProviderGenerateThenLoadStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.kek")
	p := FileProvider(path)

	sealed, err := Open(mustSeal(t, p, []byte("k")), p) // forces generate on first KEK use
	if err != nil {
		t.Fatalf("round-trip after generate: %v", err)
	}
	_ = sealed.WithPlaintext(func(b []byte) error { return nil })

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("KEK file not created: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("KEK file perm = %#o, want 0600", perm)
	}

	// A second provider on the same path must load the same KEK (stable):
	// seal with one, open with the other.
	p2 := FileProvider(path)
	env := mustSeal(t, p, []byte("stable check"))
	s2, err := Open(env, p2)
	if err != nil {
		t.Fatalf("second provider cannot open first's ciphertext: %v", err)
	}
	_ = s2.WithPlaintext(func(b []byte) error {
		if string(b) != "stable check" {
			t.Fatalf("unstable KEK: %q", b)
		}
		return nil
	})
}

func TestFileProviderRejectsTooPermissive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loose.kek")
	// #nosec G306 -- deliberately 0644: this test verifies a too-permissive KEK file is REJECTED.
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, KEKLen), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Seal([]byte("x"), FileProvider(path)); err == nil {
		t.Fatal("expected rejection of 0644 KEK file")
	}
}

func TestFileProviderRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.kek")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Seal([]byte("x"), FileProvider(path)); err == nil {
		t.Fatal("expected rejection of wrong-size KEK file")
	}
}

func TestEnvProviderErrors(t *testing.T) {
	// Not valid hex.
	bad := EnvProvider("BAD_HEX_KEK")
	t.Setenv("BAD_HEX_KEK", "zzzz")
	if _, err := Seal([]byte("x"), bad); err == nil {
		t.Fatal("expected invalid-hex rejection")
	}
	// Wrong length.
	shortP := EnvProvider("SHORT_KEK")
	t.Setenv("SHORT_KEK", hex.EncodeToString([]byte("only16bytes.....")))
	if _, err := Seal([]byte("x"), shortP); err == nil {
		t.Fatal("expected wrong-length rejection")
	}
}

func TestResolveProviderPrecedence(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "resolve.kek")

	// Env set → env provider.
	t.Setenv(EnvKEKName, testKEKHex)
	if got := ResolveProvider("", filePath).Name(); got != "env" {
		t.Fatalf("with env set, provider = %q, want env", got)
	}

	// Env empty → file provider.
	t.Setenv(EnvKEKName, "")
	if got := ResolveProvider("", filePath).Name(); got != "file" {
		t.Fatalf("with env empty, provider = %q, want file", got)
	}
}

// TestSealedRedactsUnderAllVerbs is the fitness test for the fmt-reflection
// leak: no formatting verb may print the backing plaintext bytes of a Sealed,
// whether passed by pointer or by value. Guards against a future removal of the
// Format/String/GoString redaction.
func TestSealedRedactsUnderAllVerbs(t *testing.T) {
	p := envProviderWith(t, testKEKHex)
	const plaintext = "TOPSECRETKEYMATERIAL"
	env, err := Seal([]byte(plaintext), p)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed, err := Open(env, p) // NOT consumed: s.b still holds the plaintext
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Leak signatures: ASCII, hex ("54 4f 50…"), and decimal ("84 79 80…").
	hexLeak := hex.EncodeToString([]byte(plaintext)) // %x form
	decLeak := "84 79 80"                            // %v/%d byte-slice form of "TOP"
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d", "%q"} {
		for _, arg := range []any{sealed, *sealed, p, *p} {
			out := fmt.Sprintf(verb, arg)
			if strings.Contains(out, "TOPSECRET") ||
				strings.Contains(strings.ToLower(out), hexLeak) ||
				strings.Contains(out, decLeak) {
				t.Fatalf("verb %s on %T leaked secret bytes: %s", verb, arg, out)
			}
			if !strings.Contains(out, redactedMark) {
				t.Fatalf("verb %s on %T did not redact: %s", verb, arg, out)
			}
		}
	}
}

// mustSeal seals plaintext under p, failing the test on error.
func mustSeal(t *testing.T, p *Provider, plaintext []byte) []byte {
	t.Helper()
	env, err := Seal(plaintext, p)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return env
}
