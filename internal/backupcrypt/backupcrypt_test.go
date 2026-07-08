package backupcrypt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const testPassphrase = "correct-horse-battery-staple"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := bytes.Repeat([]byte("hello-backupcrypt "), 100)
	blob, err := EncryptBlob(plaintext, testPassphrase)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	if !IsEncryptedBlob(blob) {
		t.Fatal("encrypted blob does not carry the magic")
	}
	if len(blob) < 2 || (blob[0] == 0x1F && blob[1] == 0x8B) {
		t.Fatal("encrypted blob must not look like a gzip stream")
	}
	got, err := DecryptBlob(blob, testPassphrase)
	if err != nil {
		t.Fatalf("DecryptBlob: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("plaintext mismatch after round-trip")
	}
}

func TestDecryptOpaqueOnWrongKey(t *testing.T) {
	blob, err := EncryptBlob([]byte("payload"), testPassphrase)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	if _, err := DecryptBlob(blob, "wrong-passphrase"); !errors.Is(err, ErrDecryptOpaque) {
		t.Fatalf("expected ErrDecryptOpaque, got: %v", err)
	}
}

func TestDecryptOpaqueOnTamperedCiphertext(t *testing.T) {
	blob, err := EncryptBlob([]byte("payload-to-tamper"), testPassphrase)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	blob[HdrLen+1] ^= 0xFF // flip a ciphertext byte → GCM auth fails
	if _, err := DecryptBlob(blob, testPassphrase); !errors.Is(err, ErrDecryptOpaque) {
		t.Fatalf("expected ErrDecryptOpaque on tamper, got: %v", err)
	}
}

func TestHeaderTamperFailsAAD(t *testing.T) {
	blob, err := EncryptBlob([]byte("payload"), testPassphrase)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	blob[12] ^= 0x01 // flip an iters byte; stays above the floor → AAD path
	if _, err := DecryptBlob(blob, testPassphrase); !errors.Is(err, ErrDecryptOpaque) {
		t.Fatalf("expected ErrDecryptOpaque on header tamper (AAD), got: %v", err)
	}
}

func TestItersBelowFloorRejectedNonOpaque(t *testing.T) {
	blob, err := EncryptBlob([]byte("payload"), testPassphrase)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	// Drop iters to 1 (below the floor). Offsets 10..13 are iters BE.
	blob[10], blob[11], blob[12], blob[13] = 0, 0, 0, 1
	_, err = DecryptBlob(blob, testPassphrase)
	if err == nil || errors.Is(err, ErrDecryptOpaque) {
		t.Fatalf("expected a non-opaque below-floor rejection, got: %v", err)
	}
	if !strings.Contains(err.Error(), "below minimum") {
		t.Fatalf("expected 'below minimum', got: %v", err)
	}
}

func TestIsEncryptedBlobShortPrefix(t *testing.T) {
	if IsEncryptedBlob([]byte("CV")) {
		t.Fatal("a sub-MagicLen prefix must not be reported as encrypted")
	}
	if IsEncryptedBlob([]byte{0x1F, 0x8B}) {
		t.Fatal("a gzip prefix must not be reported as encrypted")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
}
