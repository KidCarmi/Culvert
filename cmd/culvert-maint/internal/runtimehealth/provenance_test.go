package runtimehealth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dig(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func installedRec() Installed {
	return Installed{OpID: "01HZX", Kind: "upgrades.apply",
		ImageID: dig("1"), Ref: "ghcr.io/kidcarmi/culvert@" + dig("a"), Digest: dig("a"),
		ReplacedImageID: dig("2"), ReplacedRef: "ghcr.io/kidcarmi/culvert@" + dig("b"),
		InstalledAt: time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)}
}

func TestInstalled_RoundTripAndAbsent(t *testing.T) {
	st := openTemp(t)
	if in, err := st.ReadInstalled(); in != nil || err != nil {
		t.Fatalf("absent = %+v, %v", in, err)
	}
	if err := st.WriteInstalled(installedRec()); err != nil {
		t.Fatal(err)
	}
	in, err := st.ReadInstalled()
	if err != nil || in == nil || in.ImageID != dig("1") || in.ReplacedImageID != dig("2") || in.Schema != SchemaVersion {
		t.Fatalf("ReadInstalled = %+v, %v", in, err)
	}
	// A replaced image without a validated reference is still provenance (the
	// recovery then has nothing it may restore).
	noRef := installedRec()
	noRef.ReplacedRef = ""
	if err := st.WriteInstalled(noRef); err != nil {
		t.Fatalf("empty replaced_ref refused: %v", err)
	}
}

func TestInstalled_Refusals(t *testing.T) {
	st := openTemp(t)
	for name, mut := range map[string]func(*Installed){
		"rollback kind":         func(i *Installed) { i.Kind = "rollbacks.create" },
		"no op":                 func(i *Installed) { i.OpID = "" },
		"op with a slash":       func(i *Installed) { i.OpID = "a/b" },
		"bad image":             func(i *Installed) { i.ImageID = "x" },
		"ref without digest":    func(i *Installed) { i.Ref = "ghcr.io/kidcarmi/culvert:latest" },
		"replaced itself":       func(i *Installed) { i.ReplacedImageID = i.ImageID },
		"bad replaced":          func(i *Installed) { i.ReplacedImageID = "" },
		"replaced ref is a tag": func(i *Installed) { i.ReplacedRef = "ghcr.io/kidcarmi/culvert:v1" },
		"no time":               func(i *Installed) { i.InstalledAt = time.Time{} },
	} {
		in := installedRec()
		mut(&in)
		if err := st.WriteInstalled(in); err == nil {
			t.Errorf("%s: accepted %+v", name, in)
		}
	}
}

func gated(c string, at time.Time) GatedEntry {
	return GatedEntry{ImageID: dig(c), Ref: "ghcr.io/kidcarmi/culvert@" + dig("d"), Digest: dig("d"), GatedAt: at}
}

func TestNoteGated_KeepsTwoDistinctNewestFirst(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	ids := func() []string {
		h, err := st.ReadGated()
		if err != nil || h == nil {
			t.Fatalf("ReadGated = %+v, %v", h, err)
		}
		var out []string
		for _, e := range h.Entries {
			out = append(out, e.ImageID[len(e.ImageID)-1:])
		}
		return out
	}
	steps := []struct {
		img  string
		want string
	}{
		{"1", "1"}, {"1", "1"}, {"2", "2,1"}, {"2", "2,1"}, {"3", "3,2"}, {"2", "2,3"}, {"1", "1,2"},
	}
	for i, s := range steps {
		if err := st.NoteGated(gated(s.img, t0.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(ids(), ","); got != s.want {
			t.Fatalf("after gating %s: history %s, want %s", s.img, got, s.want)
		}
	}
	h, _ := st.ReadGated()
	if !h.Contains(dig("2")) || h.Contains(dig("3")) {
		t.Fatalf("Contains wrong for %+v", h)
	}
}

func TestReadGated_Refusals(t *testing.T) {
	e1 := `{"image_id":"` + dig("1") + `","ref":"r@` + dig("d") + `","digest":"` + dig("d") + `","gated_at":"2026-11-28T09:00:00Z"}`
	e2 := `{"image_id":"` + dig("2") + `","ref":"r@` + dig("d") + `","digest":"` + dig("d") + `","gated_at":"2026-11-28T09:00:00Z"}`
	for name, body := range map[string]string{
		"empty":        `{"schema":1,"entries":[]}`,
		"three":        `{"schema":1,"entries":[` + e1 + `,` + e2 + `,` + e1 + `]}`,
		"repeat":       `{"schema":1,"entries":[` + e1 + `,` + e1 + `]}`,
		"schema 2":     `{"schema":2,"entries":[` + e1 + `]}`,
		"unknown keys": `{"schema":1,"entries":[` + e1 + `],"x":1}`,
	} {
		st := openTemp(t)
		if err := os.WriteFile(filepath.Join(st.Dir(), gatedName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if h, err := st.ReadGated(); err == nil {
			t.Errorf("%s: ReadGated = %+v, want an error", name, h)
		}
	}
}

// An unreadable history is replaced by one holding the new entry alone: it is
// evidence only of what this observer gated, never merged with garbage.
func TestNoteGated_ReplacesAnUnreadableHistory(t *testing.T) {
	st := openTemp(t)
	if err := os.WriteFile(filepath.Join(st.Dir(), gatedName), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.NoteGated(gated("1", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if h, err := st.ReadGated(); err != nil || len(h.Entries) != 1 {
		t.Fatalf("history = %+v, %v", h, err)
	}
}
