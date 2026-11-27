package filemagic

import "testing"

// CHAOS-129: the content-shape stage on the proxy response path sizes its
// buffer from PrefixWindow(), so a signature added at offset 0 that is LONGER
// than the window the callers read would be silently unreachable there — the
// detection would compile, ship, and never match. Both windows must therefore
// be derived from the table rather than written down, and this gate is what
// makes a hand-edited constant fail.
func TestDetectionWindows_DeriveFromTable(t *testing.T) {
	wantPrefix, wantMax := 0, 0
	for i := range knownMagicSigs {
		end := knownMagicSigs[i].Offset + len(knownMagicSigs[i].Magic)
		if end > wantMax {
			wantMax = end
		}
		if knownMagicSigs[i].Offset == 0 && end > wantPrefix {
			wantPrefix = end
		}
	}
	if got := PrefixWindow(); got != wantPrefix {
		t.Errorf("PrefixWindow() = %d, want %d (longest offset-0 signature in the table)", got, wantPrefix)
	}
	if got := MaxWindow(); got != wantMax {
		t.Errorf("MaxWindow() = %d, want %d (widest signature in the table)", got, wantMax)
	}
	if PrefixWindow() <= 0 || MaxWindow() < PrefixWindow() {
		t.Fatalf("degenerate windows: prefix=%d max=%d", PrefixWindow(), MaxWindow())
	}
}

// Every offset-0 signature must actually MATCH when Detect is handed exactly
// PrefixWindow() bytes — the property the shape stage depends on. The
// offset-0 set is the whole table except ISO9660, which needs MaxWindow();
// that exclusion is the recorded residue of CHAOS-129, pinned here as a
// negative control so a future change cannot quietly claim ISO coverage on
// the prefix window.
func TestPrefixWindow_MatchesEveryOffsetZeroSignature(t *testing.T) {
	window := PrefixWindow()
	for i := range knownMagicSigs {
		sig := &knownMagicSigs[i]
		if sig.Offset != 0 {
			continue
		}
		data := make([]byte, window)
		copy(data, sig.Magic)
		got := Detect(data)
		if got == nil || got.Type != sig.Type {
			// A later entry may legitimately shadow an earlier one only if the
			// magic bytes are a prefix of each other; none in this table are.
			t.Errorf("Detect(%d bytes of %s magic) = %v, want %s", window, sig.Type, got, sig.Type)
		}
	}
	iso := 0
	for i := range knownMagicSigs {
		if knownMagicSigs[i].Offset != 0 {
			iso++
			data := make([]byte, window)
			copy(data[0:], knownMagicSigs[i].Magic)
			if got := Detect(data); got != nil && got.Type == knownMagicSigs[i].Type {
				t.Errorf("%s has offset %d but matched inside the %d-byte prefix window",
					knownMagicSigs[i].Type, knownMagicSigs[i].Offset, window)
			}
		}
	}
	if iso == 0 {
		t.Log("note: every signature now sits at offset 0; the prefix window covers the whole table")
	}
}
