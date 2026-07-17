package redaction

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// fixture mirrors a collected section struct with one field of every class,
// including planted secret values that must never survive redaction.
type fixture struct {
	Version   string `json:"version" redact:"public"`
	Host      string `json:"host" redact:"internal"`
	User      string `json:"user" redact:"sensitive"`
	Password  string `json:"password" redact:"secret"`
	CAKey     string `json:"ca_key" redact:"never_export"`
	Untagged  string `json:"untagged"` // no redact tag → fail-closed SENSITIVE
	Nested    inner  `json:"nested" redact:"internal"`
	Anonymous string `json:"-" redact:"public"` // json:"-" → omitted entirely
}

type inner struct {
	Rule   string `json:"rule" redact:"internal"`
	Client string `json:"client" redact:"sensitive"`
	Token  string `json:"token" redact:"secret"`
}

const (
	plantedPassword = "hunter2-BCRYPT-$2a$10$plantedsecret" // #nosec G101 -- test fixture, not a real credential
	plantedCAKey    = "-----BEGIN PRIVATE KEY-----AAAA-----END PRIVATE KEY-----"
	plantedToken    = "eyJ-planted-bearer-token" // #nosec G101 -- test fixture, not a real credential
	plantedUser     = "alice@example.com"
)

func redactToJSON(t *testing.T, v any) (string, Result) {
	t.Helper()
	r := NewWithSalt([]byte("fixed-test-salt"))
	res := r.Classify(v)
	b, err := json.Marshal(res.Value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b), res
}

func sampleFixture() fixture {
	return fixture{
		Version: "v1.2.3", Host: "proxy-1.internal", User: plantedUser,
		Password: plantedPassword, CAKey: plantedCAKey, Untagged: "also-secret-ish",
		Nested:    inner{Rule: "allow-github", Client: "203.0.113.7", Token: plantedToken},
		Anonymous: "should-not-appear",
	}
}

func TestSecretAndNeverExportDropped(t *testing.T) {
	js, res := redactToJSON(t, sampleFixture())
	for _, planted := range []string{plantedPassword, plantedCAKey, plantedToken} {
		if strings.Contains(js, planted) {
			t.Fatalf("planted secret survived redaction: %q in %s", planted, js)
		}
	}
	// The secret field keys are dropped entirely (not masked-and-kept).
	for _, key := range []string{"password", "ca_key", "token"} {
		if strings.Contains(js, `"`+key+`"`) {
			t.Fatalf("dropped-class key %q present in output: %s", key, js)
		}
	}
	if res.Dropped != 3 { // password, ca_key, nested.token
		t.Fatalf("Dropped=%d want 3", res.Dropped)
	}
}

func TestUnclassifiedFieldIsMasked(t *testing.T) {
	js, _ := redactToJSON(t, sampleFixture())
	if strings.Contains(js, "also-secret-ish") {
		t.Fatalf("untagged field passed through raw (should be masked): %s", js)
	}
	if !strings.Contains(js, `"untagged":"mask_`) {
		t.Fatalf("untagged field not masked to a token: %s", js)
	}
}

func TestSensitiveMaskedNotRaw(t *testing.T) {
	js, _ := redactToJSON(t, sampleFixture())
	if strings.Contains(js, plantedUser) || strings.Contains(js, "203.0.113.7") {
		t.Fatalf("SENSITIVE value leaked raw: %s", js)
	}
	if !strings.Contains(js, `"user":"mask_`) || !strings.Contains(js, `"client":"mask_`) {
		t.Fatalf("SENSITIVE fields not masked: %s", js)
	}
}

func TestPublicInternalKept(t *testing.T) {
	js, _ := redactToJSON(t, sampleFixture())
	for _, keep := range []string{"v1.2.3", "proxy-1.internal", "allow-github"} {
		if !strings.Contains(js, keep) {
			t.Fatalf("PUBLIC/INTERNAL value dropped: %q missing from %s", keep, js)
		}
	}
	if strings.Contains(js, "should-not-appear") {
		t.Fatalf(`json:"-" field was emitted: %s`, js)
	}
}

func TestClassMaxNeverExceedsInternal(t *testing.T) {
	_, res := redactToJSON(t, sampleFixture())
	if res.ClassMax > ShareableCeiling {
		t.Fatalf("ClassMax=%s exceeds shareable ceiling %s", res.ClassMax, ShareableCeiling)
	}
	if res.ClassMax != ClassInternal { // fixture has internal + masked-sensitive fields
		t.Fatalf("ClassMax=%s want INTERNAL", res.ClassMax)
	}
}

func TestDeterministicSameSalt(t *testing.T) {
	a := NewWithSalt([]byte("s")).Struct(sampleFixture())
	b := NewWithSalt([]byte("s")).Struct(sampleFixture())
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatalf("redaction not deterministic under a fixed salt:\n%s\n%s", ja, jb)
	}
}

func TestParseClassFailsClosed(t *testing.T) {
	if c, ok := ParseClass("bogus"); ok || c != DefaultClass {
		t.Fatalf("unknown tag should fail closed to SENSITIVE, got %s ok=%v", c, ok)
	}
	if DefaultClass != ClassSensitive {
		t.Fatalf("fail-closed default must be SENSITIVE, got %s", DefaultClass)
	}
}
