package applianceaccess

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/ssh"
)

// MaxKeyBytes bounds the entire imported authorized-key file.
const MaxKeyBytes = 64 * 1024

// MaxKeys bounds noncomment key entries in one import.
const MaxKeys = 64

// CanonicalKeys refuses options rather than weakening an imported key's
// restrictions. Comments never enter the root-owned authorization file or logs.
func CanonicalKeys(data []byte) ([]byte, error) {
	if len(data) > MaxKeyBytes {
		return nil, errors.New("key import exceeds bound")
	}
	var out bytes.Buffer
	count := 0
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		count++
		if count > MaxKeys {
			return nil, errors.New("too many imported keys")
		}
		key, _, options, rest, err := ssh.ParseAuthorizedKey(line)
		if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("invalid or restricted imported key")
		}
		out.Write(ssh.MarshalAuthorizedKey(key))
	}
	return out.Bytes(), nil
}
