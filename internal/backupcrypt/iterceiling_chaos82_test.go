package backupcrypt

// CHAOS-82 / BKP-6a — the archive-declared PBKDF2 iteration count had a floor
// but no ceiling.
//
// parseEncHeader refused a WEAKENED header (iters below encMinIters) but
// accepted an arbitrarily large one, and DecryptBlob then fed it straight to
// pbkdf2.Key. A declared 0xFFFFFFFF bought roughly forty minutes of
// single-core work before the AAD binding failed the open anyway — so the cost
// landed on whoever pointed the restore CLI at the blob, and the attacker paid
// four bytes. The ceiling is checked beside the floor, in parseEncHeader,
// which runs before any key derivation.
//
// Mirrors TestItersBelowFloorRejectedNonOpaque: like the floor, the ceiling is
// a header-level rejection and must stay NON-opaque, because it cannot leak
// passphrase information and an operator needs to know what was wrong.

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestChaos82_ItersAboveCeilingRejectedNonOpaque(t *testing.T) {
	blob, err := EncryptBlob([]byte("payload"), testPassphrase)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	// Declare the maximum a uint32 can hold. Offsets 10..13 are iters BE.
	binary.BigEndian.PutUint32(blob[10:14], 0xFFFFFFFF)

	_, err = DecryptBlob(blob, testPassphrase)
	if err == nil {
		t.Fatal("a declared iteration count of 0xFFFFFFFF was accepted: " +
			"the restore burns CPU on an archive that cannot authenticate anyway")
	}
	if errors.Is(err, ErrDecryptOpaque) {
		t.Fatalf("ceiling rejection must be non-opaque like the floor, got: %v", err)
	}
	if !strings.Contains(err.Error(), "above maximum") {
		t.Fatalf("expected 'above maximum', got: %v", err)
	}
}

// Negative control: the count this version actually writes must still open, so
// the ceiling cannot be set below the shipped KDFIters by a later edit.
func TestChaos82_ShippedItersStillOpen(t *testing.T) {
	if KDFIters > encMaxIters {
		t.Fatalf("encMaxIters (%d) is below the shipped KDFIters (%d): every archive this version writes would be refused",
			encMaxIters, KDFIters)
	}
	blob, err := EncryptBlob([]byte("payload"), testPassphrase)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	if got := binary.BigEndian.Uint32(blob[10:14]); got != KDFIters {
		t.Fatalf("header declares %d iters, want the shipped %d", got, KDFIters)
	}
	if _, err := DecryptBlob(blob, testPassphrase); err != nil {
		t.Fatalf("an archive written by this version must still open: %v", err)
	}
}
