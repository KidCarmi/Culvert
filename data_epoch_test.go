package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/dataepoch"
)

// The image labels are what the maintenance agent reads to decide whether an
// image may be put back on this data. They must name exactly the range this
// build reads.
func TestDockerfile_DataEpochLabelsMatchTheBuild(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	final := s[strings.LastIndex(s, "\nFROM "):]
	want := map[string]int{dataepoch.LabelMin: dataepoch.OldestReadable, dataepoch.LabelMax: dataepoch.Current}
	for key, v := range want {
		re := regexp.MustCompile(regexp.QuoteMeta(key) + `="(\d+)"`)
		m := re.FindAllStringSubmatch(final, -1)
		if len(m) != 1 {
			t.Fatalf("the final image stage must set %s exactly once, found %d", key, len(m))
		}
		got, _ := strconv.Atoi(m[0][1])
		if got != v {
			t.Fatalf("Dockerfile %s=%d, the build reads %d", key, got, v)
		}
	}
	if strings.Contains(s[:strings.LastIndex(s, "\nFROM ")], "io.culvert.data-epoch") {
		t.Fatal("a data-epoch label outside the final stage does not reach the image")
	}
}

// Tripwire (docs/engineering/data-epoch.md): raising dataepoch.Current is safe
// only once backup carries the marker and restore can never lower it. Neither
// is implemented, because at epoch 1 there is nothing to carry: no build
// writes the marker. Raising the epoch must come with both, and this test
// with them.
func TestDataEpoch_BumpObligationsTripwire(t *testing.T) {
	if dataepoch.Current != 1 {
		t.Fatalf("dataepoch.Current is %d: before raising it, backup must include %s and restore must keep the higher of the restored and the current marker (docs/engineering/data-epoch.md), then update this test",
			dataepoch.Current, dataepoch.MarkerName)
	}
}

func withDataDir(t *testing.T, dir string) {
	t.Helper()
	prev := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = prev })
}

func TestPrintDataEpoch(t *testing.T) {
	dir := t.TempDir()
	withDataDir(t, dir)
	var out bytes.Buffer
	if err := runPrintDataEpoch(&out); err != nil {
		t.Fatal(err)
	}
	var r dataepoch.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("not JSON: %q", out.String())
	}
	if r.Epoch != 1 || r.MarkerPresent || r.BuildMin != dataepoch.OldestReadable || r.BuildMax != dataepoch.Current {
		t.Fatalf("report = %+v", r)
	}
	if err := os.WriteFile(filepath.Join(dir, dataepoch.MarkerName), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runPrintDataEpoch(&out); err == nil {
		t.Fatal("an unreadable marker was reported")
	}
}

// A boot at epoch 1 writes nothing, and a boot on newer data leaves the marker.
func TestCheckDataEpochAtBoot_NeverLowersOrInvents(t *testing.T) {
	dir := t.TempDir()
	withDataDir(t, dir)
	checkDataEpochAtBoot()
	if _, err := os.Stat(filepath.Join(dir, dataepoch.MarkerName)); !os.IsNotExist(err) {
		t.Fatalf("a boot at the implicit epoch wrote a marker: %v", err)
	}
	newer := `{"schema":1,"epoch":7}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, dataepoch.MarkerName), []byte(newer), 0o600); err != nil {
		t.Fatal(err)
	}
	checkDataEpochAtBoot()
	if b, _ := os.ReadFile(filepath.Join(dir, dataepoch.MarkerName)); string(b) != newer {
		t.Fatalf("a boot lowered or rewrote a newer marker: %q", b)
	}
}
