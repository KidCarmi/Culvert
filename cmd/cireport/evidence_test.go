package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, b := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The reporter reads ONLY allowlisted member names. The binary sitting next to
// them in the archive is never returned, and so never written or executed.
func TestZipMembers_ReadsOnlyTheAllowlist(t *testing.T) {
	data := makeZip(t, map[string][]byte{
		"verdict.json":     []byte(`{"ok":true}`),
		"sub/results.json": []byte(`{}`),
		"root.test":        []byte("\x7fELF binary"),
		"rootshard":        []byte("\x7fELF tool"),
		"merged.cover.out": []byte("mode: atomic\n"),
	})
	got, err := zipMembers(data, readableMembers("qa-race-verdict"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["verdict.json"] == nil || got["results.json"] == nil {
		t.Fatalf("members %v, want exactly verdict.json and results.json", keys(got))
	}
	dup := makeZip(t, map[string][]byte{"verdict.json": []byte(`{}`), "nested/verdict.json": []byte(`{}`)})
	if _, err := zipMembers(dup, readableMembers("qa-race-verdict")); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("an archive carrying one member base name twice must be refused as ambiguous, got %v", err)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The prebuilt test binary's artifact is never readable, and no allowlisted
// member is anything but a JSON document.
func TestReadableArtifacts_ExcludeTheBinary(t *testing.T) {
	if readableMembers("qa-race-build") != nil {
		t.Fatal("qa-race-build carries the prebuilt test binary and must never be read")
	}
	for _, name := range []string{"qa-audit-reference", "fast-audit-reference", "qa-coverage", "fast-gate-coverage", "qa-race-lane"} {
		if readableMembers(name) != nil {
			t.Errorf("%s is not needed and must not be read", name)
		}
	}
	for art, members := range readableArtifacts {
		for m := range members {
			if !strings.HasSuffix(m, ".json") {
				t.Errorf("artifact %s allowlists non-JSON member %s", art, m)
			}
		}
	}
	if m := readableMembers("qa-race-shard-3"); len(m) != 1 || !m["meta.json"] {
		t.Errorf("shard artifacts expose only meta.json, got %v", m)
	}
}

// Every JSON field this reporter reads from rootshard's documents must exist,
// spelled identically, in rootshard's source. A renamed field then fails here
// instead of silently decoding as zero.
func TestEvidenceFields_MatchRootshard(t *testing.T) {
	var src strings.Builder
	files, _ := filepath.Glob("../rootshard/*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	tagRE := regexp.MustCompile(`json:"([^",]+)`)
	var walk func(reflect.Type)
	seen := map[reflect.Type]bool{}
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if m := tagRE.FindStringSubmatch(string(f.Tag)); m != nil {
				if !strings.Contains(src.String(), `json:"`+m[1]+`"`) && !strings.Contains(src.String(), `json:"`+m[1]+`,`) {
					t.Errorf("%s.%s reads json field %q, which cmd/rootshard does not write", rt.Name(), f.Name, m[1])
				}
			}
			walk(f.Type)
		}
	}
	for _, v := range []any{evVerdict{}, evPkgResult{}, evShardMeta{}, evComparison{}, evTimings{}} {
		walk(reflect.TypeOf(v))
	}
}

func TestEvidence_IngestRecordsUndecodable(t *testing.T) {
	var ev runEvidence
	ev.ingest("qa-race-verdict", map[string][]byte{"verdict.json": []byte("{not json")})
	ev.ingest("qa-race-shard-1", map[string][]byte{})
	if ev.Verdict != nil || len(ev.ShardMetas) != 0 || len(ev.Notes) != 2 {
		t.Errorf("undecodable evidence must stay absent and be noted: verdict=%v metas=%v notes=%v", ev.Verdict, ev.ShardMetas, ev.Notes)
	}
}

func TestGHClient_PlainHTTPOnlyOnLoopback(t *testing.T) {
	for base, ok := range map[string]bool{
		"https://api.github.com":  true,
		"http://127.0.0.1:1234":   true,
		"http://localhost:9":      true,
		"http://api.github.com":   false,
		"http://10.0.0.1":         false,
		"ftp://api.github.com":    false,
		"file:///etc/passwd":      false,
		"https://ghe.example/api": true,
	} {
		_, err := newGHClient(base, "")
		if (err == nil) != ok {
			t.Errorf("newGHClient(%q) err=%v, want ok=%v", base, err, ok)
		}
	}
}

// A transport error on the storage redirect must not carry the presigned
// query into a report: that query is the credential.
func TestRedactURLError_DropsPresignedQuery(t *testing.T) {
	in := &url.Error{Op: "Get", URL: "https://blob.example/x.zip?sv=1&sig=SECRET&se=2026", Err: errors.New("403")}
	got := redactURLError(fmt.Errorf("wrap: %w", in)).Error()
	if strings.Contains(got, "SECRET") || strings.Contains(got, "sig=") || !strings.Contains(got, "https://blob.example/x.zip") {
		t.Errorf("redacted error %q", got)
	}
	if plain := errors.New("plain"); redactURLError(plain) != plain {
		t.Error("a non-URL error must pass through unchanged")
	}
}
