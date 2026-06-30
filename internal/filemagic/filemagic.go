// Package filemagic does magic-byte detection for archive identification and
// polyglot detection — examining the first bytes of a response body to catch
// archives disguised as safe types and Content-Type/content mismatches. It is a
// self-contained leaf (stdlib only) extracted from package main per ADR-0002.
//
// This complements extension-based blocking — magic bytes can't be faked by
// renaming a file or manipulating the URL path. (The glue that consults the
// file blocker, IsBlockedArchive, stays in package main since it needs the
// fileBlocker singleton.)
package filemagic

import "strings"

// isHTTPCompressedWebContent returns true if the Content-Type is a normal web
// content type commonly served with HTTP Content-Encoding compression (gzip,
// br, zstd). When the body hasn't been decompressed, the raw bytes start with
// the compression format's magic — expected, NOT a polyglot disguise. Without
// this, any zstd/gzip/brotli-compressed HTML/CSS/JS would be false-positive
// flagged as "archive disguised as text/html".
func isHTTPCompressedWebContent(ct string) bool {
	return strings.Contains(ct, "text/") ||
		strings.Contains(ct, "application/javascript") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/xml") ||
		strings.Contains(ct, "application/xhtml") ||
		strings.Contains(ct, "application/wasm") ||
		strings.Contains(ct, "image/svg")
}

// Sig describes a file type signature (magic bytes).
type Sig struct {
	Offset  int    // byte offset where the magic starts
	Magic   []byte // expected bytes at that offset
	Type    string // detected file type (e.g., "PE", "ZIP")
	Ext     string // canonical extension (e.g., ".exe", ".zip")
	Archive bool   // true if this is an archive/container format
}

// knownMagicSigs lists well-known file signatures for dangerous file types.
// Order matters: first match wins.
var knownMagicSigs = []Sig{
	// Executables
	{0, []byte("MZ"), "PE", ".exe", false},                           // DOS/PE executable
	{0, []byte{0x7f, 'E', 'L', 'F'}, "ELF", ".elf", false},           // Linux ELF
	{0, []byte{0xfe, 0xed, 0xfa, 0xce}, "MachO32", ".macho", false},  // macOS Mach-O 32
	{0, []byte{0xfe, 0xed, 0xfa, 0xcf}, "MachO64", ".macho", false},  // macOS Mach-O 64
	{0, []byte{0xcf, 0xfa, 0xed, 0xfe}, "MachO64r", ".macho", false}, // macOS Mach-O 64 reversed

	// Archives (F4)
	{0, []byte("PK\x03\x04"), "ZIP", ".zip", true},                 // ZIP / DOCX / XLSX / JAR
	{0, []byte("PK\x05\x06"), "ZIP-empty", ".zip", true},           // Empty ZIP
	{0, []byte{0x1f, 0x8b}, "GZIP", ".gz", true},                   // gzip
	{0, []byte("Rar!\x1a\x07"), "RAR", ".rar", true},               // RAR v4+
	{0, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, "XZ", ".xz", true}, // XZ
	{0, []byte("7z\xbc\xaf\x27\x1c"), "7Z", ".7z", true},           // 7-Zip
	{0, []byte("BZh"), "BZIP2", ".bz2", true},                      // bzip2
	{0, []byte{0x1f, 0x9d}, "Z-LZW", ".Z", true},                   // compress (LZW)
	{0, []byte{0x28, 0xb5, 0x2f, 0xfd}, "ZSTD", ".zst", true},      // Zstandard

	// ISO / disk images
	{0x8001, []byte("CD001"), "ISO9660", ".iso", true}, // ISO at sector 16

	// Scripts/macros
	{0, []byte("#!"), "Script", ".sh", false}, // shell script
}

// Detect examines the first bytes of data and returns the detected file
// signature, or nil if no known signature matches.
func Detect(data []byte) *Sig {
	for i := range knownMagicSigs {
		sig := &knownMagicSigs[i]
		end := sig.Offset + len(sig.Magic)
		if len(data) < end {
			continue
		}
		match := true
		for j, b := range sig.Magic {
			if data[sig.Offset+j] != b {
				match = false
				break
			}
		}
		if match {
			return sig
		}
	}
	return nil
}

// expectedCTForMagic maps magic signature types to Content-Type substrings that
// are considered legitimate (not a polyglot disguise).
var expectedCTForMagic = map[string][]string{
	"PE":        {"application/x-dosexec", "application/x-msdownload", "application/octet-stream"},
	"ELF":       {"application/x-executable", "application/x-elf", "application/octet-stream"},
	"ZIP":       {"application/zip", "application/x-zip", "application/java-archive", "application/vnd.openxmlformats", "application/octet-stream"},
	"ZIP-empty": {"application/zip", "application/x-zip", "application/java-archive", "application/vnd.openxmlformats", "application/octet-stream"},
	"RAR":       {"application/x-rar", "application/vnd.rar", "application/octet-stream"},
	"7Z":        {"application/x-7z", "application/octet-stream"},
	"Script":    {"text/", "application/x-sh", "application/octet-stream"},
	"MachO32":   {"application/octet-stream"},
	"MachO64":   {"application/octet-stream"},
	"MachO64r":  {"application/octet-stream"},
	"XZ":        {"application/x-xz", "application/octet-stream"},
	"Z-LZW":     {"application/x-compress", "application/octet-stream"},
	"ISO9660":   {"application/x-iso9660-image", "application/octet-stream"},
}

// compressionMagicTypes are signature types that double as HTTP Content-Encoding
// formats. When the body hasn't been decompressed, their magic bytes are
// expected and should not trigger polyglot detection for web content types.
var compressionMagicTypes = map[string][]string{
	"GZIP":  {"application/gzip", "application/x-gzip", "application/octet-stream"},
	"ZSTD":  {"application/zstd", "application/octet-stream"},
	"BZIP2": {"application/x-bzip2", "application/octet-stream"},
}

// CheckVsContentType detects polyglot files by comparing the Content-Type
// header against the actual content's magic bytes. Returns a non-empty reason
// when a mismatch indicates a potentially disguised file (e.g., a PE served as
// image/png).
func CheckVsContentType(data []byte, contentType string) string {
	sig := Detect(data)
	if sig == nil {
		return ""
	}

	ct := strings.ToLower(contentType)

	// Check compression types (also exempt web content for HTTP Content-Encoding).
	if accepted, ok := compressionMagicTypes[sig.Type]; ok {
		for _, a := range accepted {
			if strings.Contains(ct, a) {
				return ""
			}
		}
		if isHTTPCompressedWebContent(ct) {
			return ""
		}
	}

	// Check known magic-to-CT mappings.
	if accepted, ok := expectedCTForMagic[sig.Type]; ok {
		for _, a := range accepted {
			if strings.Contains(ct, a) {
				return ""
			}
		}
	} else if strings.Contains(ct, "application/octet-stream") {
		return "" // unknown type + octet-stream = legitimate
	}

	return "magic:" + sig.Type + " disguised as " + ct
}
