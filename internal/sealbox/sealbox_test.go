package sealbox

import (
	"bytes"
	"testing"
)

func TestSealOpen_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("the redacted support bundle bytes")
	blob, err := Seal(msg, pub, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !IsSealed(blob) {
		t.Fatal("sealed blob not recognised by IsSealed")
	}
	if bytes.Contains(blob, msg) {
		t.Fatal("plaintext present in the sealed blob")
	}
	got, err := Open(blob, pub, priv)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round-trip mismatch")
	}
}

func TestOpen_WrongKeyFails(t *testing.T) {
	pub, _, _ := GenerateKey()
	otherPub, otherPriv, _ := GenerateKey()
	blob, err := Seal([]byte("secret"), pub, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(blob, otherPub, otherPriv); err == nil {
		t.Fatal("open succeeded with the wrong key pair")
	}
}

func TestOpen_TamperFails(t *testing.T) {
	pub, priv, _ := GenerateKey()
	blob, _ := Seal([]byte("secret payload"), pub, nil)
	blob[len(blob)-1] ^= 0xff // flip a ciphertext/tag bit
	if _, err := Open(blob, pub, priv); err == nil {
		t.Fatal("open succeeded on tampered ciphertext")
	}
}

func TestOpen_HeaderErrors(t *testing.T) {
	pub, priv, _ := GenerateKey()
	if _, err := Open([]byte("short"), pub, priv); err == nil {
		t.Fatal("short blob accepted")
	}
	blob, _ := Seal([]byte("x"), pub, nil)
	bad := append([]byte(nil), blob...)
	bad[0] = 'X' // corrupt magic
	if _, err := Open(bad, pub, priv); err == nil {
		t.Fatal("bad magic accepted")
	}
	bad2 := append([]byte(nil), blob...)
	bad2[MagicLen] = 0x02 // unsupported version
	if _, err := Open(bad2, pub, priv); err == nil {
		t.Fatal("bad version accepted")
	}
}

func TestIsSealed(t *testing.T) {
	if IsSealed([]byte("CV")) {
		t.Fatal("short prefix should not match")
	}
	if IsSealed([]byte("CVRTBK01xxxx")) {
		t.Fatal("passphrase-envelope magic must not match sealbox")
	}
}
