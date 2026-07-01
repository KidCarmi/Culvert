package filemagic

import "testing"

func TestDetect(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string // "" means expect nil
	}{
		{"PE", []byte("MZ\x90\x00"), "PE"},
		{"ZIP", []byte("PK\x03\x04rest"), "ZIP"},
		{"GZIP", []byte{0x1f, 0x8b, 0x08}, "GZIP"},
		{"ELF", []byte{0x7f, 'E', 'L', 'F', 0x01}, "ELF"},
		{"ZSTD", []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00}, "ZSTD"},
		{"unknown", []byte("hello world"), ""},
		{"too short", []byte{0x7f}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sig := Detect(c.data)
			if c.want == "" {
				if sig != nil {
					t.Errorf("Detect = %v, want nil", sig)
				}
				return
			}
			if sig == nil || sig.Type != c.want {
				t.Errorf("Detect type = %v, want %q", sig, c.want)
			}
		})
	}
}

func TestCheckVsContentType(t *testing.T) {
	pe := []byte("MZ\x90\x00")
	if r := CheckVsContentType(pe, "application/octet-stream"); r != "" {
		t.Errorf("PE as octet-stream should be legitimate, got %q", r)
	}
	if r := CheckVsContentType(pe, "image/png"); r == "" {
		t.Error("PE disguised as image/png should be flagged")
	}
	// A zstd-compressed HTML page (body not decompressed) is expected, not a disguise.
	zstd := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00}
	if r := CheckVsContentType(zstd, "text/html"); r != "" {
		t.Errorf("zstd-compressed text/html should not be flagged, got %q", r)
	}
	// But zstd magic served as an image is still a polyglot.
	if r := CheckVsContentType(zstd, "image/jpeg"); r == "" {
		t.Error("zstd disguised as image/jpeg should be flagged")
	}
	// No known signature → no finding.
	if r := CheckVsContentType([]byte("plain text"), "text/plain"); r != "" {
		t.Errorf("unknown content should not be flagged, got %q", r)
	}
}
