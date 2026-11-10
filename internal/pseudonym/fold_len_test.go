package pseudonym

import (
	"strings"
	"testing"
)

// ReplaceHostFold must not drift when lowercasing changes byte length before
// the host: U+023A (2 bytes) lowercases to U+2C65 (3 bytes), and each invalid
// UTF-8 byte becomes U+FFFD (3 bytes). The host must still be replaced and
// nothing may panic.
func TestReplaceHostFold_LengthChangingPrefixStillRedacts(t *testing.T) {
	cases := map[string]string{
		"U+023A before host": "/aȺ/x?h=Secret.Example.com&z=1",
		"invalid UTF-8":      "/a\xff\xfe/x?h=secret.example.com&z=1",
		"many expanders":     strings.Repeat("Ⱥ", 8) + "?secret.example.com",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			out := ReplaceHostFold(in, "secret.example.com", "TOKEN")
			if strings.Contains(strings.ToLower(out), "secret.example.com") {
				t.Fatalf("plaintext host left in %q", out)
			}
			if !strings.Contains(out, "TOKEN") {
				t.Fatalf("host not replaced in %q", out)
			}
		})
	}
}
