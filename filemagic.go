package main

// filemagic.go — package-main glue for magic-byte detection. The detection
// engine (signatures, Detect, CheckVsContentType) moved to internal/filemagic
// (ADR-0002); IsBlockedArchive stays here because it consults the fileBlocker
// singleton. The two shim vars keep proxy.go and the test suite unqualified.

import "github.com/KidCarmi/Culvert/internal/filemagic"

// DetectMagic / CheckMagicVsContentType are re-exposed unqualified for the test
// suite and proxy.go (the engine funcs are filemagic.Detect / .CheckVsContentType).
var (
	DetectMagic             = filemagic.Detect
	CheckMagicVsContentType = filemagic.CheckVsContentType
)

// IsBlockedArchive checks whether data starts with archive magic bytes that the
// file blocker should block. Returns the archive type name if blocked. It stays
// in package main because it consults the fileBlocker singleton.
func IsBlockedArchive(data []byte) string {
	sig := filemagic.Detect(data)
	if sig == nil {
		return ""
	}

	// Block if the detected extension is in the file blocker.
	if ext := fileBlocker.CheckExt(sig.Ext); ext != "" {
		return sig.Type
	}

	// Also block any archive when .zip is blocked.
	if sig.Archive {
		if ext := fileBlocker.CheckExt(".zip"); ext != "" {
			return sig.Type
		}
	}

	return ""
}
