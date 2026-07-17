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

func TestSeal_RejectsLowOrderKey(t *testing.T) {
	// The all-zero point is a canonical low-order Curve25519 point: sealing to it
	// derives an all-zero shared secret, so the box would be openable without the
	// recipient private key. Seal must refuse it rather than emit a "sealed" blob.
	var zero [KeyLen]byte
	if _, err := Seal([]byte("secret"), &zero, nil); err == nil {
		t.Fatal("Seal accepted a low-order (all-zero) recipient key")
	}
	if err := ValidateRecipientPublicKey(&zero); err == nil {
		t.Fatal("ValidateRecipientPublicKey accepted the all-zero point")
	}
	// The other small-order points must be rejected too.
	for _, lo := range lowOrderPoints() {
		p := lo
		if err := ValidateRecipientPublicKey(&p); err == nil {
			t.Fatalf("ValidateRecipientPublicKey accepted low-order point %x", p)
		}
	}
	// A genuine key pair still validates.
	pub, _, _ := GenerateKey()
	if err := ValidateRecipientPublicKey(pub); err != nil {
		t.Fatalf("ValidateRecipientPublicKey rejected a real key: %v", err)
	}
}

// lowOrderPoints returns the well-known small-order Curve25519 points that yield
// an all-zero shared secret (from RFC 7748 §5 / the curve25519 test vectors).
func lowOrderPoints() [][KeyLen]byte {
	return [][KeyLen]byte{
		{},  // 0
		{1}, // 1
		{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
		{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
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
