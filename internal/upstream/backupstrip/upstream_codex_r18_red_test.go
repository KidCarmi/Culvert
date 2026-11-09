package backupstrip

import (
	"bytes"
	"testing"
)

// PR-C28 RED matrix — the eighteenth Codex round on the Batch 2 PR head
// (466a16d0), written against that tree BEFORE any correction.
//
//   R18-A  (P2) Strip decoded the settings
//          body into a map[string]any, and the JSON literal `null` decodes
//          into a NIL map without error — so the duplicate-key walk, the
//          trailing-data check, the legacy gate and the v2 strip all saw an
//          empty document and the zero-strip branch handed the original
//          `null` back to be archived, though the function's contract is
//          that a body which is not a JSON object is refused. A restore of
//          such an archive silently boots zero-valued settings. A null root
//          is not a settings object and must fail the backup CLOSED.

func TestUpstreamR18_BackupStripRefusesNullRoot(t *testing.T) {
	for name, body := range map[string]string{
		"bare null":         `null`,
		"null with newline": "null\n",
		"padded null":       "  null  ",
	} {
		out, n, err := Strip([]byte(body))
		if err == nil {
			t.Errorf("%s: a null settings root was accepted for archiving (n=%d out=%q)", name, n, out)
		}
		if bytes.Equal(bytes.TrimSpace(out), []byte("null")) {
			t.Errorf("%s: the null body was handed back as a sound settings file", name)
		}
	}
	// Controls: the other non-object roots stay refused, and an EMPTY
	// object stays a sound (credential-free) settings file.
	for name, body := range map[string]string{
		"array root":  `[]`,
		"string root": `"settings"`,
		"number root": `1`,
		"bool root":   `true`,
	} {
		if _, _, err := Strip([]byte(body)); err == nil {
			t.Errorf("control %s: a non-object root was accepted", name)
		}
	}
	out, n, err := Strip([]byte(`{}`))
	if err != nil || n != 0 || string(out) != `{}` {
		t.Errorf("control empty object: got n=%d out=%q err=%v, want unchanged", n, out, err)
	}
}
