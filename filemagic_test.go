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
