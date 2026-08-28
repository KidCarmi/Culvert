package main

// objects_enum_lockstep_test.go — 2D-A §15: the v2 frontend's decryption-enum
// vocabulary (frontend/src/api/objects.ts) is mechanically pinned to the
// backend runtime contract, in both directions, the same way the legacy-GUI
// lockstep (decryptprofile_cert_contract_test.go) pins static/index.html:
// every value the frontend offers must be runtime-accepted, every
// runtime-accepted value must be offered, "permissive" must never resurface,
// and the stall-timeout bounds must equal the engine clamp constants.
// (The frontend additionally pins the same arrays against the generated
// OpenAPI union types at compile time.)

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// frontendObjectsTS reads the v2 objects API module source.
func frontendObjectsTS(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("frontend", "src", "api", "objects.ts"))
	if err != nil {
		t.Fatalf("read frontend objects.ts: %v", err)
	}
	return string(data)
}

// extractConstArray pulls the string values of `export const NAME = [ ... ]`.
func extractConstArray(t *testing.T, src, name string) []string {
	t.Helper()
	re := regexp.MustCompile(`export const ` + name + ` = \[([^\]]*)\]`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("constant %s not found in objects.ts", name)
	}
	var out []string
	for _, q := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(m[1], -1) {
		out = append(out, q[1])
	}
	if len(out) == 0 {
		t.Fatalf("constant %s parsed empty", name)
	}
	return out
}

func TestObjectsEnumLockstep_FrontendMatchesRuntime(t *testing.T) {
	src := frontendObjectsTS(t)
	probe := func(mutate func(p *DecryptionProfile)) error {
		p := DecryptionProfile{Name: "probe"}
		mutate(&p)
		return decryptprofile.Validate(&p)
	}
	cases := []struct {
		constName string
		set       func(p *DecryptionProfile, v string)
		runtime   []string // the full runtime-accepted vocabulary (reverse parity)
	}{
		{"CERT_VERIFICATION_VALUES", func(p *DecryptionProfile, v string) { p.CertVerification = v }, []string{"", "strict", "skip"}},
		{"ON_UNSUPPORTED_VALUES", func(p *DecryptionProfile, v string) { p.OnUnsupported = v }, []string{"", "fail-close", "fail-open"}},
		{"ON_INSPECT_ERROR_VALUES", func(p *DecryptionProfile, v string) { p.OnInspectError = v }, []string{"", "fail-close", "fail-open"}},
		{"TLS_VERSION_VALUES", func(p *DecryptionProfile, v string) { p.MinTLSVersion = v }, []string{"", "1.2", "1.3"}},
	}
	for _, c := range cases {
		values := extractConstArray(t, src, c.constName)
		got := map[string]bool{}
		// Forward parity: every frontend value is runtime-accepted.
		for _, v := range values {
			got[v] = true
			if err := probe(func(p *DecryptionProfile) { c.set(p, v) }); err != nil {
				t.Errorf("%s offers %q but the runtime rejects it: %v", c.constName, v, err)
			}
		}
		// Reverse parity: every runtime-accepted value is offered.
		for _, v := range c.runtime {
			if !got[v] {
				t.Errorf("runtime accepts %q but %s does not offer it", v, c.constName)
			}
			if err := probe(func(p *DecryptionProfile) { c.set(p, v) }); err != nil {
				t.Errorf("runtime vocabulary drifted: %q now rejected: %v (update this test AND the frontend)", v, err)
			}
		}
		// And nothing beyond the runtime vocabulary.
		for _, v := range values {
			found := false
			for _, rv := range c.runtime {
				if v == rv {
					found = true
				}
			}
			if !found {
				t.Errorf("%s offers %q which is not in the runtime vocabulary", c.constName, v)
			}
		}
	}
	// The retired value must never resurface anywhere in the module.
	if strings.Contains(src, `"permissive"`) {
		t.Error("objects.ts must not carry the retired certVerification=permissive value")
	}
	if decryptprofile.Validate(&DecryptionProfile{Name: "probe", CertVerification: "permissive"}) == nil {
		t.Error("runtime must reject permissive")
	}
}

func TestObjectsEnumLockstep_StallBounds(t *testing.T) {
	src := frontendObjectsTS(t)
	extract := func(name string) int {
		re := regexp.MustCompile(`export const ` + name + ` = (\d+);`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("constant %s not found", name)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := extract("STALL_TIMEOUT_MIN_SECS"); got != decryptprofile.MinStallSecs {
		t.Errorf("frontend STALL_TIMEOUT_MIN_SECS = %d, engine MinStallSecs = %d", got, decryptprofile.MinStallSecs)
	}
	if got := extract("STALL_TIMEOUT_MAX_SECS"); got != decryptprofile.MaxStallSecs {
		t.Errorf("frontend STALL_TIMEOUT_MAX_SECS = %d, engine MaxStallSecs = %d", got, decryptprofile.MaxStallSecs)
	}
}
