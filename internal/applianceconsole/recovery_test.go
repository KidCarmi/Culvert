package applianceconsole

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryRequiresSchemaAndSanitizesDisplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	for _, raw := range []string{"{}", "null", `{"version":9}`, "{"} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if readRecovery(path).Available {
			t.Fatal("invalid history became available")
		}
	}
	raw := `{"version":1,"records":[{"id":"operation","action":"reboot","phase":"intent","boot":"old-boot","machine":"stable","observation":"bad\u001b[2J"}]}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	r := readRecovery(path)
	if !r.Available || len(r.Records) != 1 || r.Records[0].ID != "operation" {
		t.Fatal("history missing")
	}
	v := NewView(false)
	v.open("report")
	for _, row := range v.Frame(Snapshot{Recovery: r}, 25, 80) {
		if strings.Contains(row.Text, "\x1b") {
			t.Fatal("history injected terminal control")
		}
	}
}
