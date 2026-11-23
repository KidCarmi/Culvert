//go:build policy_pathdiff

package pathdiffgen

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIndependence: standard library only, so no production code can leak in.
func TestIndependence(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			if p := strings.Trim(im.Path.Value, `"`); strings.Contains(p, ".") {
				t.Errorf("%s imports %s: this package must use the standard library only", f, p)
			}
		}
	}
}

func TestDeterministic(t *testing.T) {
	a, _ := json.Marshal(Generate("d", 0.05))
	b, _ := json.Marshal(Generate("d", 0.05))
	if string(a) != string(b) {
		t.Fatal("generator is not deterministic for a fixed seed")
	}
	if c, _ := json.Marshal(Generate("e", 0.05)); string(a) == string(c) {
		t.Fatal("different seeds produced identical cases")
	}
}

func TestReference(t *testing.T) {
	same := [][2]string{
		{"a.example", "A.Example"}, {"a.example", "a.example."}, {"a.example", "a.example:443"}, {"a.example:80", "a.example:"},
		{"[2001:db8::1]", "[2001:DB8:0:0:0:0:0:1]:443"}, {"192.0.2.7", "192.0.2.7:8080"},
	}
	for _, p := range same {
		if Relate(p[0], p[1]) != Same {
			t.Errorf("Relate(%q,%q) should be Same", p[0], p[1])
		}
	}
	unspec := [][2]string{
		{"192.0.2.7", "[::ffff:192.0.2.7]"}, {"192.0.2.7", "0xc0.0.2.7"}, {"192.0.2.7", "192.0.2.007"}, {"a.example", "a.example.."},
		{"a.example", "b.example"}, {"a.example", "a.example:65536"}, {"a.example", "user@a.example"}, {"a.example", "a%2eexample"},
		{"xn--bcher-kva.example", "XN--BCHER-KVA.example"}, {"a.example", ""}, {"192.0.2.7", "192.0.2.7."},
	}
	for _, p := range unspec {
		if Relate(p[0], p[1]) != Unspecified {
			t.Errorf("Relate(%q,%q) should be Unspecified", p[0], p[1])
		}
	}
	rules := []Rule{{Priority: 2, Name: "b", DestFQDN: "*"}, {Priority: 1, Name: "a", DestFQDN: "x.example", Disabled: true}, {Priority: 3, Name: "c", DestFQDN: "x.example"}}
	if n, ok := DecidePlain(rules, "x.example:443"); !ok || n != "b" {
		t.Errorf("DecidePlain = %q,%v want b,true", n, ok)
	}
	if n, ok := DecidePlain(ApplyOps(rules, []Op{{Kind: "delete", Name: "b"}}), "x.example"); !ok || n != "c" {
		t.Errorf("after delete: %q,%v want c,true", n, ok)
	}
	if n, ok := DecidePlain([]Rule{{Priority: 1, Name: "a", DestFQDN: "x.example"}}, "sub.x.example:443"); !ok || n != "a" {
		t.Errorf("bare name must cover a subdomain: %q,%v", n, ok)
	}
	if n, ok := DecidePlain([]Rule{{Priority: 1, Name: "a", DestFQDN: "x.example"}}, "evilx.example"); !ok || n != "" {
		t.Errorf("bare name must not cover a glued prefix: %q,%v", n, ok)
	}
	if _, ok := DecidePlain([]Rule{{Priority: 1, Name: "a", DestFQDN: "*.x.example"}}, "x.example"); ok {
		t.Error("wildcard rule must be outside the plain fragment")
	}
}
