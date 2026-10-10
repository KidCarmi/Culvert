package applianceaccess

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func fixturePublicKey(t *testing.T) []byte {
	t.Helper()
	key, err := ssh.NewPublicKey(ed25519.PublicKey(bytes.Repeat([]byte{7}, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(key)
}

func TestCanonicalKeysDropsCommentsNotRestrictions(t *testing.T) {
	key := fixturePublicKey(t)
	source := append([]byte("# fixture only\n\n"), bytes.TrimSpace(key)...)
	source = append(source, []byte(" a comment that must not be published\r\n")...)
	got, err := CanonicalKeys(source)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("ordinary imported public key did not canonicalize")
	}
	for _, prefix := range []string{"restrict ", "no-pty ", "command=\"status\" ", "environment=\"BASH_ENV=/tmp/payload\" ", "from=\"192.0.2.1\" "} {
		if got, err := CanonicalKeys(append([]byte(prefix), key...)); err == nil || got != nil {
			t.Fatal("key options were stripped or accepted")
		}
	}
}

func TestCanonicalKeysRejectsMalformedAndOversizedImportAtomically(t *testing.T) {
	key := fixturePublicKey(t)
	for _, data := range [][]byte{
		[]byte("not a public key"), append(append([]byte{}, key...), []byte("bad final line")...),
		bytes.Repeat(key, MaxKeys+1), []byte(strings.Repeat("#", MaxKeyBytes+1)),
	} {
		if got, err := CanonicalKeys(data); err == nil || got != nil {
			t.Fatal("invalid import returned publishable key material")
		}
	}
	for _, data := range [][]byte{nil, []byte("# comment only\n\r\n")} {
		if got, err := CanonicalKeys(data); err != nil || len(got) != 0 {
			t.Fatal("missing keys should produce empty authorization")
		}
	}
	if got, err := CanonicalKeys(bytes.Repeat(key, MaxKeys)); err != nil || len(got) == 0 {
		t.Fatal("maximum allowed key count rejected")
	}
}
