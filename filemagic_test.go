package main

import "testing"

func TestDetectMagic_PE(t *testing.T) {
	data := []byte("MZ\x90\x00\x03\x00\x00\x00")
	sig := DetectMagic(data)
	if sig == nil || sig.Type != "PE" {
		t.Errorf("DetectMagic PE = %v, want PE", sig)
	}
}

func TestDetectMagic_ZIP(t *testing.T) {
	data := []byte("PK\x03\x04rest of zip")
	sig := DetectMagic(data)
	if sig == nil || sig.Type != "ZIP" {
		t.Errorf("DetectMagic ZIP = %v, want ZIP", sig)
	}
	if !sig.Archive {
		t.Error("ZIP should be marked as archive")
	}
}

func TestDetectMagic_GZIP(t *testing.T) {
	data := []byte{0x1f, 0x8b, 0x08, 0x00}
	sig := DetectMagic(data)
	if sig == nil || sig.Type != "GZIP" {
		t.Errorf("DetectMagic GZIP = %v, want GZIP", sig)
	}
}

func TestDetectMagic_ELF(t *testing.T) {
	data := []byte{0x7f, 'E', 'L', 'F', 0x02}
	sig := DetectMagic(data)
	if sig == nil || sig.Type != "ELF" {
		t.Errorf("DetectMagic ELF = %v, want ELF", sig)
	}
}

func TestDetectMagic_Unknown(t *testing.T) {
	data := []byte("just plain text")
	sig := DetectMagic(data)
	if sig != nil {
		t.Errorf("DetectMagic unknown = %v, want nil", sig)
	}
}

func TestDetectMagic_TooShort(t *testing.T) {
	sig := DetectMagic([]byte{0x7f})
	if sig != nil {
		t.Errorf("DetectMagic short = %v, want nil", sig)
	}
}

func TestCheckMagicVsContentType_Match(t *testing.T) {
	// PE exe served as octet-stream — no mismatch.
	data := []byte("MZ\x90\x00\x03\x00\x00\x00")
	if reason := CheckMagicVsContentType(data, "application/octet-stream"); reason != "" {
		t.Errorf("expected no mismatch, got %q", reason)
	}
}

func TestCheckMagicVsContentType_Polyglot(t *testing.T) {
	// PE exe served as image/png — polyglot.
	data := []byte("MZ\x90\x00\x03\x00\x00\x00")
	reason := CheckMagicVsContentType(data, "image/png")
	if reason == "" {
		t.Error("expected polyglot detection for PE served as image/png")
	}
	if reason != "magic:PE disguised as image/png" {
		t.Errorf("reason = %q", reason)
	}
}

func TestCheckMagicVsContentType_ZIPasImage(t *testing.T) {
	data := []byte("PK\x03\x04rest")
	reason := CheckMagicVsContentType(data, "image/jpeg")
	if reason == "" {
		t.Error("expected polyglot detection for ZIP served as image/jpeg")
	}
}

func TestCheckMagicVsContentType_UnknownContent(t *testing.T) {
	data := []byte("just text")
	reason := CheckMagicVsContentType(data, "text/html")
	if reason != "" {
		t.Errorf("expected no detection for unknown magic, got %q", reason)
	}
}

// Regression test: ZSTD-compressed HTML (Content-Encoding: zstd) must NOT
// be flagged as polyglot. SourceForge and other CDNs serve text/html with
// zstd compression; the raw bytes start with the ZSTD magic signature.
func TestCheckMagicVsContentType_ZSTDCompressedHTML(t *testing.T) {
	// ZSTD magic bytes followed by compressed content
	data := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 64)...)
	reason := CheckMagicVsContentType(data, "text/html; charset=utf-8")
	if reason != "" {
		t.Errorf("ZSTD + text/html should NOT be polyglot, got %q", reason)
	}
}

func TestCheckMagicVsContentType_GZIPCompressedJS(t *testing.T) {
	data := append([]byte{0x1f, 0x8b}, make([]byte, 64)...)
	reason := CheckMagicVsContentType(data, "application/javascript")
	if reason != "" {
		t.Errorf("GZIP + application/javascript should NOT be polyglot, got %q", reason)
	}
}

func TestCheckMagicVsContentType_ZSTDAsImage_StillPolyglot(t *testing.T) {
	// ZSTD magic served as image/jpeg — this IS suspicious (not a web content type)
	data := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 64)...)
	reason := CheckMagicVsContentType(data, "image/jpeg")
	if reason == "" {
		t.Error("ZSTD + image/jpeg SHOULD be flagged as polyglot")
	}
}

func TestCheckMagicVsContentType_Script(t *testing.T) {
	data := []byte("#!/bin/bash\necho hello")
	// Script served as text/plain — expected match, no polyglot.
	if reason := CheckMagicVsContentType(data, "text/plain"); reason != "" {
		t.Errorf("expected no mismatch for script as text/plain, got %q", reason)
	}
	// Script served as image — polyglot.
	if reason := CheckMagicVsContentType(data, "image/png"); reason == "" {
		t.Error("expected polyglot detection for script served as image/png")
	}
}

// Q13: Additional scan pipeline integration tests.

func TestDetectMagic_MachO(t *testing.T) {
	tests := []struct {
		data     []byte
		wantType string
	}{
		{[]byte{0xFE, 0xED, 0xFA, 0xCE, 0, 0, 0, 0}, "MachO32"},
		{[]byte{0xFE, 0xED, 0xFA, 0xCF, 0, 0, 0, 0}, "MachO64"},
		{[]byte{0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0}, "MachO64r"},
	}
	for _, tc := range tests {
		sig := DetectMagic(tc.data)
		if sig == nil || sig.Type != tc.wantType {
			t.Errorf("DetectMagic(%x) = %v, want %s", tc.data[:4], sig, tc.wantType)
		}
	}
}

func TestDetectMagic_RAR(t *testing.T) {
	data := make([]byte, 16)
	copy(data, []byte("Rar!\x1a\x07\x00"))
	sig := DetectMagic(data)
	if sig == nil || sig.Type != "RAR" {
		t.Errorf("DetectMagic RAR = %v, want RAR", sig)
	}
	if sig != nil && !sig.Archive {
		t.Error("RAR should be flagged as archive")
	}
}

func TestDetectMagic_7Z(t *testing.T) {
	data := make([]byte, 16)
	copy(data, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C})
	sig := DetectMagic(data)
	if sig == nil || sig.Type != "7Z" {
		t.Errorf("DetectMagic 7Z = %v, want 7Z", sig)
	}
}

func TestIsBlockedArchive_AllTypes(t *testing.T) {
	// Add .zip to file blocker so IsBlockedArchive can detect archives.
	fileBlocker.Add(".zip")
	defer fileBlocker.Remove(".zip")

	tests := []struct {
		name     string
		data     []byte
		wantType string
	}{
		{"ZIP", append([]byte("PK\x03\x04"), make([]byte, 4)...), "ZIP"},
		{"GZIP", append([]byte{0x1f, 0x8b}, make([]byte, 8)...), "GZIP"},
		{"RAR", append([]byte("Rar!\x1a\x07\x00"), make([]byte, 8)...), "RAR"},
		{"7Z", append([]byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, make([]byte, 8)...), "7Z"},
		{"XZ", append([]byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, make([]byte, 8)...), "XZ"},
		{"BZIP2", append([]byte("BZh"), make([]byte, 8)...), "BZIP2"},
		{"ZSTD", append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 8)...), "ZSTD"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsBlockedArchive(tc.data)
			if result != tc.wantType {
				t.Errorf("IsBlockedArchive = %q, want %q", result, tc.wantType)
			}
		})
	}
}

func TestIsBlockedArchive_NonArchive(t *testing.T) {
	// PE is NOT an archive — should return empty even with .zip blocked.
	fileBlocker.Add(".zip")
	defer fileBlocker.Remove(".zip")
	data := []byte("MZ\x90\x00\x03\x00\x00\x00")
	if result := IsBlockedArchive(data); result != "" {
		t.Errorf("IsBlockedArchive(PE) = %q, want empty", result)
	}
}

func TestCheckMagicVsContentType_ELFasImage(t *testing.T) {
	data := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 8)...)
	reason := CheckMagicVsContentType(data, "image/jpeg")
	if reason == "" {
		t.Error("expected polyglot detection for ELF served as image/jpeg")
	}
}

func TestCheckMagicVsContentType_ELFasOctetStream(t *testing.T) {
	data := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 8)...)
	reason := CheckMagicVsContentType(data, "application/octet-stream")
	if reason != "" {
		t.Errorf("ELF as octet-stream should not be flagged, got %q", reason)
	}
}

func TestCheckMagicVsContentType_OctetStream(t *testing.T) {
	// application/octet-stream is always considered a valid match.
	data := []byte("MZ\x90\x00\x03\x00\x00\x00")
	reason := CheckMagicVsContentType(data, "application/octet-stream")
	if reason != "" {
		t.Errorf("octet-stream should not trigger polyglot, got %q", reason)
	}
}

func TestDetectMagic_ISO9660(t *testing.T) {
	data := make([]byte, 0x8001+5) // offset 0x8001 + 5 bytes for "CD001"
	copy(data[0x8001:], []byte("CD001"))
	sig := DetectMagic(data)
	if sig == nil || sig.Type != "ISO9660" {
		t.Errorf("DetectMagic ISO9660 = %v, want ISO9660", sig)
	}
}
