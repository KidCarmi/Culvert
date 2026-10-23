package config

import (
	"strings"
	"testing"
)

// compose_no_build / local_only_images (Workstream C): both default off; the
// image list is refused unless compose_no_build is on (elsewhere Compose can
// still build a missing image, so the list would silently mean nothing), and
// every entry must be a plain local repo:tag — never a digest, registry
// host:port or anything that could reach a sudo argv as more than one token.
func TestLoad_ComposeNoBuild(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalValid))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ComposeNoBuild || len(cfg.LocalOnlyImages) != 0 {
		t.Fatalf("defaults must be off/empty: no_build=%v images=%q", cfg.ComposeNoBuild, cfg.LocalOnlyImages)
	}

	ok := minimalValid + "\ncompose_no_build = true\nlocal_only_images = [\"culvert/clamav:1.5.4-culvert.2\"]"
	cfg, err = Load(writeConfig(t, ok))
	if err != nil {
		t.Fatalf("Load (valid): %v", err)
	}
	if !cfg.ComposeNoBuild || len(cfg.LocalOnlyImages) != 1 || cfg.LocalOnlyImages[0] != "culvert/clamav:1.5.4-culvert.2" {
		t.Fatalf("got no_build=%v images=%q", cfg.ComposeNoBuild, cfg.LocalOnlyImages)
	}

	// compose_no_build alone is valid (the preflight then checks nothing).
	if _, err := Load(writeConfig(t, minimalValid+"\ncompose_no_build = true")); err != nil {
		t.Fatalf("compose_no_build without images: %v", err)
	}
}

func TestLoad_LocalOnlyImagesRefused(t *testing.T) {
	if _, err := Load(writeConfig(t, minimalValid+"\nlocal_only_images = [\"culvert/clamav:1.5.4-culvert.2\"]")); err == nil ||
		!strings.Contains(err.Error(), "requires compose_no_build") {
		t.Fatalf("a list without compose_no_build must be refused, got %v", err)
	}

	rejected := map[string]string{
		"digest":           "culvert/clamav@sha256:" + strings.Repeat("a", 64),
		"no tag":           "culvert/clamav",
		"registry port":    "localhost:5000/culvert/clamav:1",
		"uppercase repo":   "Culvert/clamav:1",
		"whitespace":       "culvert/clamav:1 x",
		"shell metachar":   "culvert/clamav:$(id)",
		"leading dash tag": "culvert/clamav:-x",
		"empty":            "",
	}
	for name, ref := range rejected {
		body := minimalValid + "\ncompose_no_build = true\nlocal_only_images = [\"" + ref + "\"]"
		if _, err := Load(writeConfig(t, body)); err == nil {
			t.Errorf("%s (%q): expected rejection", name, ref)
		}
	}

	var many []string
	for i := 0; i <= maxLocalOnlyImages; i++ {
		many = append(many, "\"culvert/x:"+strings.Repeat("a", i+1)+"\"")
	}
	body := minimalValid + "\ncompose_no_build = true\nlocal_only_images = [" + strings.Join(many, ",") + "]"
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatalf("more than %d entries must be refused", maxLocalOnlyImages)
	}
}
