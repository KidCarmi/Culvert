package fileblock

import (
	"mime"
	"path"
	"strings"
	"sync"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Correctness spine: the per-transaction gate got cheaper, not different.
//
// Both halves of this change are cost changes, so both are pinned against a
// verbatim copy of the code they replaced rather than against hand-written
// expectations. checkContentTypeLegacy and checkExtLegacy below ARE the pre-fix
// bodies; do not "tidy" them to match the new ones.
// ─────────────────────────────────────────────────────────────────────────────

// checkContentTypeLegacy is the verbatim pre-fix CheckContentType body, kept as
// the differential oracle. It reads the authoritative map under the lock, so it
// is also independent of the view machinery.
func checkContentTypeLegacy(fb *FileBlocker, contentType string) string {
	if contentType == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	ext, ok := blockedMIMETypes[mediaType]
	if !ok {
		return ""
	}
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	if fb.extensions[ext] {
		return ext
	}
	return ""
}

// checkPathLegacy is the verbatim pre-fix CheckPath body.
func checkPathLegacy(fb *FileBlocker, urlPath string) string {
	ext := strings.ToLower(path.Ext(urlPath))
	if ext == "" {
		return ""
	}
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	if fb.extensions[ext] {
		return ext
	}
	return ""
}

// gateFB returns a blocker seeded with the shipped default extension set plus
// the two MIME-only extensions the default list does not carry, so the
// differential covers both the "extension blocked" and "extension not blocked"
// arms of every dangerous MIME type.
func gateFB(t *testing.T) *FileBlocker {
	t.Helper()
	fb := NewBlocker()
	for _, e := range DefaultBlockedExts {
		fb.Add(e)
	}
	return fb
}

// contentTypeCorpus carries the shapes where a cheap prefix split and
// mime.ParseMediaType could plausibly disagree: parameters, whitespace, case,
// malformed parameters, duplicate parameters, empty and bare separators, and
// media types that are not dangerous at all.
var contentTypeCorpus = []string{
	"",
	"text/html",
	"text/html; charset=utf-8",
	"application/json",
	"application/octet-stream",
	"image/png",
	"application/x-msdownload",
	"application/x-msdownload; charset=utf-8",
	"  application/x-msdownload  ",
	"  application/x-msdownload  ; charset=utf-8",
	"APPLICATION/X-MSDOWNLOAD",
	"Application/X-MsDownload; Charset=UTF-8",
	"application/x-msdownload;",
	"application/x-msdownload; ",
	"application/x-msdownload; bogus",
	"application/x-msdownload; charset",
	"application/x-msdownload; charset=",
	`application/x-msdownload; charset="utf-8`,
	"application/x-msdownload; a=1; a=2",
	"application/x-msdownload; a=1; a=1",
	"application/x-msi",
	"application/x-ms-installer;name=setup",
	"application/x-bat",
	"application/x-powershell; version=5",
	"application/x-vbs",
	"application/x-dosexec",
	"application/x-executable",
	"application/vnd.microsoft.portable-executable",
	"application/x-msdos-program",
	";",
	";charset=utf-8",
	"/",
	"text",
	"text/",
	"/html",
	"application/x-msdownload extra",
	"application/x-msdownload\t; charset=utf-8",
	"\napplication/x-msdownload",
	"application/x-msdownload; filename*=utf-8''a.exe",
}

func TestCheckContentType_MatchesPreFilterBehaviour(t *testing.T) {
	// Both postures: extension on the block list, and extension removed so the
	// dangerous MIME type resolves to an allowed extension.
	full := gateFB(t)
	empty := NewBlocker()

	for _, fb := range []*FileBlocker{full, empty} {
		for _, ct := range contentTypeCorpus {
			got := fb.CheckContentType(ct)
			want := checkContentTypeLegacy(fb, ct)
			if got != want {
				t.Errorf("CheckContentType(%q) = %q, pre-fix body = %q", ct, got, want)
			}
		}
	}
}

// TestMediaTypeOf_MatchesParseMediaType is the narrower half: whenever
// mime.ParseMediaType SUCCEEDS, the pre-filter's media type must equal the one
// the stdlib reports. This is the property the negative pre-filter rests on, so
// an upstream x/mime change fails here with a precise message rather than
// showing up as a mysterious differential mismatch.
func TestMediaTypeOf_MatchesParseMediaType(t *testing.T) {
	for _, ct := range contentTypeCorpus {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil {
			continue
		}
		if got := mediaTypeOf(ct); got != mt {
			t.Errorf("mediaTypeOf(%q) = %q, mime.ParseMediaType = %q", ct, got, mt)
		}
	}
}

func FuzzCheckContentType(f *testing.F) {
	for _, ct := range contentTypeCorpus {
		f.Add(ct)
	}
	fb := NewBlocker()
	for _, e := range DefaultBlockedExts {
		fb.Add(e)
	}
	f.Fuzz(func(t *testing.T, ct string) {
		if got, want := fb.CheckContentType(ct), checkContentTypeLegacy(fb, ct); got != want {
			t.Fatalf("CheckContentType(%q) = %q, pre-fix body = %q", ct, got, want)
		}
		// The property the pre-filter rests on, fuzzed directly.
		if mt, _, err := mime.ParseMediaType(ct); err == nil {
			if got := mediaTypeOf(ct); got != mt {
				t.Fatalf("mediaTypeOf(%q) = %q, mime.ParseMediaType = %q", ct, got, mt)
			}
		}
	})
}

func FuzzCheckPath(f *testing.F) {
	for _, p := range []string{"", "/", "/a.exe", "/a.EXE", "/x/y/z.tar.gz", "/no-ext", "/.exe", "/a.exe?q=1", "/a."} {
		f.Add(p)
	}
	fb := NewBlocker()
	for _, e := range DefaultBlockedExts {
		fb.Add(e)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if got, want := fb.CheckPath(p), checkPathLegacy(fb, p); got != want {
			t.Fatalf("CheckPath(%q) = %q, pre-fix body = %q", p, got, want)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// The view contract.
// ─────────────────────────────────────────────────────────────────────────────

// TestBlockerView_EveryMutatorRepublishes is the security half of the lock-free
// read path: a mutator that forgets publishLocked() does not slow anything
// down, it makes the store LIE — a newly-blocked extension that never blocks,
// or a removed one that keeps blocking. Every mutator gets its own arm; adding
// a mutator without an arm here is the drift this test exists to catch.
func TestBlockerView_EveryMutatorRepublishes(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		fb := NewBlocker()
		fb.Add(".exe")
		if fb.CheckExt(".exe") != ".exe" {
			t.Fatal("Add did not republish: .exe is not blocked through the view")
		}
	})
	t.Run("Remove", func(t *testing.T) {
		fb := NewBlocker()
		fb.Add(".exe")
		fb.Remove(".exe")
		if fb.CheckExt(".exe") != "" {
			t.Fatal("Remove did not republish: .exe still blocked through the view")
		}
	})
	t.Run("ReplaceAll", func(t *testing.T) {
		fb := NewBlocker()
		fb.Add(".exe")
		fb.ReplaceAll([]string{".dll"})
		if fb.CheckExt(".exe") != "" {
			t.Fatal("ReplaceAll did not republish: stale .exe still blocked")
		}
		if fb.CheckExt(".dll") != ".dll" {
			t.Fatal("ReplaceAll did not republish: new .dll not blocked")
		}
	})
	t.Run("ClearAll", func(t *testing.T) {
		fb := NewBlocker()
		fb.Add(".exe")
		fb.ClearAll()
		if fb.CheckExt(".exe") != "" {
			t.Fatal("ClearAll did not republish: .exe still blocked through the view")
		}
	})
	t.Run("SetPath", func(t *testing.T) {
		dir := t.TempDir()
		seed := NewBlocker()
		seed.SetPath(path.Join(dir, "fileblock.json"))
		seed.Add(".exe")

		loaded := NewBlocker()
		loaded.SetPath(path.Join(dir, "fileblock.json"))
		if loaded.CheckExt(".exe") != ".exe" {
			t.Fatal("SetPath did not republish: loaded .exe is not blocked through the view")
		}
	})
}

// TestBlockerView_NeverPublishedReadsEmpty pins the nil-view posture: the
// in-package tests construct &FileBlocker{extensions: …} directly, and a
// FileBlocker that has never published must read exactly like an empty one
// rather than panicking.
func TestBlockerView_NeverPublishedReadsEmpty(t *testing.T) {
	fb := &FileBlocker{extensions: map[string]bool{".exe": true}}
	if got := fb.CheckExt(".exe"); got != "" {
		t.Fatalf("unpublished blocker returned %q, want \"\"", got)
	}
	if got := fb.CheckPath("/a.exe"); got != "" {
		t.Fatalf("unpublished blocker returned %q, want \"\"", got)
	}
	if got := fb.CheckContentType("application/x-msdownload"); got != "" {
		t.Fatalf("unpublished blocker returned %q, want \"\"", got)
	}
	// One mutator brings it live.
	fb.Add(".exe")
	if got := fb.CheckExt(".exe"); got != ".exe" {
		t.Fatalf("after Add: %q, want %q", got, ".exe")
	}
}

// TestBlockerView_ConcurrentReadersAndWriters is the no-in-place-mutation half:
// it has no assertions of its own, it exists to hand the race detector a
// reader/writer overlap. A published map mutated in place fails under -race.
func TestBlockerView_ConcurrentReadersAndWriters(t *testing.T) {
	fb := NewBlocker()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = fb.CheckPath("/a.exe")
				_ = fb.CheckExt(".dll")
				_ = fb.CheckContentType("text/html; charset=utf-8")
				_ = fb.CheckContentDisposition(`attachment; filename="a.exe"`)
			}
		}()
	}
	for i := 0; i < 200; i++ {
		fb.Add(".exe")
		fb.Add(".dll")
		fb.Remove(".exe")
		fb.ReplaceAll([]string{".exe", ".msi"})
		fb.ClearAll()
	}
	close(stop)
	wg.Wait()
}
