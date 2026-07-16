package redaction

import (
	"encoding/json"
	"strings"
	"testing"
)

// live-secret seed corpus: one real-shaped fixture per pattern. Each must be
// redacted (the raw secret gone) and carry the correct [redacted:<name>] token.
func liveSecretFixtures() []struct{ name, in, secret string } {
	rep := strings.Repeat
	return []struct{ name, in, secret string }{
		{"github_token", "err: ghp_" + rep("a", 36) + " rejected", "ghp_" + rep("a", 36)},
		{"github_pat", "tok github_pat_" + rep("b", 30), "github_pat_" + rep("b", 30)},
		{"gitlab_pat", "glpat-" + rep("c", 24), "glpat-" + rep("c", 24)},
		{"gcp_api_key", "key AIza" + rep("D", 35), "AIza" + rep("D", 35)},
		{"slack_token", "xoxb-" + rep("1", 12), "xoxb-" + rep("1", 12)},
		{"slack_app_token", "xapp-1-" + rep("E", 12), "xapp-1-" + rep("E", 12)},
		{"slack_webhook", "hooks.slack.com/services/T00000000/B00000000/" + rep("z", 24), "hooks.slack.com/services/T00000000/B00000000/" + rep("z", 24)},
		{"sendgrid_key", "SG." + rep("a", 22) + "." + rep("b", 43), "SG." + rep("a", 22) + "." + rep("b", 43)},
		{"openai_key", "OPENAI=sk-" + rep("A", 48), "sk-" + rep("A", 48)},
		{"stripe_key", "sk_live_" + rep("9", 20), "sk_live_" + rep("9", 20)},
		{"stripe_webhook_secret", "whsec_" + rep("Z", 28), "whsec_" + rep("Z", 28)},
		{"npm_token", "npm_" + rep("x", 36), "npm_" + rep("x", 36)},
		{"databricks_pat", "dapi" + rep("a", 32), "dapi" + rep("a", 32)},
		{"vault_token", "hvs." + rep("V", 28), "hvs." + rep("V", 28)},
		{"twilio_key", "SK" + rep("f", 32), "SK" + rep("f", 32)},
		{"aws_access_key_id", "id=AKIAIOSFODNN7EXAMPLE end", "AKIAIOSFODNN7EXAMPLE"},
		{"jwt", "auth eyJhbGciOiJIUzI.eyJzdWIiOiIx.SflKxwRJSMeK end", "eyJhbGciOiJIUzI.eyJzdWIiOiIx.SflKxwRJSMeK"},
		{"pem_private_key", "cfg:\n-----BEGIN RSA PRIVATE KEY-----\nMIIBaddrighthere\nabcd/efgh+\n-----END RSA PRIVATE KEY-----\ndone", "MIIBaddrighthere"},
		{"basic_auth_url", "dial mongodb+srv://admin:s3cr3tPW@cluster.example.com/db", "admin:s3cr3tPW"},
		{"aws_secret", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"credential_assignment_pwd", "conn Password=hunter2secret;Server=x", "hunter2secret"},
		{"credential_assignment_quoted", `{"api_key":"hunter2secretval"}`, "hunter2secretval"},
		{"credential_assignment_env_quoted", `PASSWORD="hunter2secretval"`, "hunter2secretval"},
		{"bearer_token", "authorization: bearer abc123def456ghi789", "abc123def456ghi789"},
		{"basic_auth_slash_pw", "dial https://admin:s3cr/3tPWvalue@host", "s3cr/3tPWvalue"},
	}
}

func TestScrub_LiveSecretsRedacted(t *testing.T) {
	sc := defaultScrubber
	for _, f := range liveSecretFixtures() {
		t.Run(f.name, func(t *testing.T) {
			out, n := sc.Scrub(f.in)
			if n == 0 {
				t.Fatalf("no redaction for %s: %q", f.name, out)
			}
			if strings.Contains(out, f.secret) {
				t.Fatalf("%s: secret %q survived in %q", f.name, f.secret, out)
			}
			if !strings.Contains(out, "[redacted:") {
				t.Fatalf("%s: no redaction token in %q", f.name, out)
			}
		})
	}
}

// false-positive corpus: legitimate INTERNAL data that MUST pass through verbatim
// (the precision-over-recall contract that keeps bundles useful).
func TestScrub_FalsePositivesPassThrough(t *testing.T) {
	sc := defaultScrubber
	rep := strings.Repeat
	clean := []string{
		"0a1b2c3d4e5f60718293a4b5c6d7e8f901234567", // git SHA-1 (40 hex)
		rep("a", 64),                               // SHA-256 (64 hex)
		"01ARZ3NDEKTSV4RRFFQ69G5FAV",               // ULID
		"550e8400-e29b-41d4-a716-446655440000",     // UUID
		"proxy-1.internal",                         // hostname
		"allow-github-egress",                      // rule name
		"region=us-east-1",                         // config assignment, not a credential word
		"cache_key=abc123def",                      // bare 'key' is not a trigger
		"routing_key=orders.created",               // ditto
		"rule=allow-github",                        // ditto
		"culvert 1.4.0+g0a1b2c3d4e5f",              // semver + build id
		"sk-egress-allow-eu",                       // hyphenated name, openai body excludes '-'
		"sk-prod_us_east_replica_0001",             // sk- internal name (< 40-char body floor)
		"content-type: application/json",           // header, no credential word
		"x-request-id: 9f8e7d6c5b4a3210",           // request id
		"use_api_key=true",                         // credential-word key, boolean toggle value
		"is_secret=false",                          // ditto
		"PWD=/home/user/culvert",                   // working-dir env var (bare pwd dropped)
		"OLDPWD=/srv/culvert",                      // ditto
		"rejected: bearer authentication required", // 'bearer' followed by a prose word
	}
	for _, s := range clean {
		out, n := sc.Scrub(s)
		if n != 0 || out != s {
			t.Errorf("false positive: %q -> %q (n=%d)", s, out, n)
		}
	}
}

func TestScrub_Idempotent(t *testing.T) {
	sc := defaultScrubber
	for _, f := range liveSecretFixtures() {
		once, _ := sc.Scrub(f.in)
		twice, n := sc.Scrub(once)
		if twice != once || n != 0 {
			t.Errorf("%s not idempotent: once=%q twice=%q n=%d", f.name, once, twice, n)
		}
	}
}

func TestScrub_Bounds(t *testing.T) {
	sc := defaultScrubber
	// oversized: a leaf larger than the scan cap is replaced whole (fail-closed).
	big := strings.Repeat("a", maxScanBytes+1) + "ghp_" + strings.Repeat("z", 36)
	if out, n := sc.Scrub(big); out != "[redacted:oversized]" || n != 1 {
		t.Fatalf("oversized: out=%q n=%d", out[:min(40, len(out))], n)
	}
	// clean-but-oversized: a >cap leaf with NO secret is STILL replaced whole
	// (the cap is enforced before the clean-path return — fail-closed contract).
	cleanBig := strings.Repeat("a", maxScanBytes+1)
	if out, n := sc.Scrub(cleanBig); out != "[redacted:oversized]" || n != 1 {
		t.Fatalf("clean oversized: out=%q n=%d", out[:min(40, len(out))], n)
	}
	// overflow: more matches than the cap → replaced whole.
	many := strings.Repeat("AKIAIOSFODNN7EXAMPLE ", maxReplacements+5)
	if out, n := sc.Scrub(many); out != "[redacted:overflow]" || n != 1 {
		t.Fatalf("overflow: out=%q n=%d", out[:min(40, len(out))], n)
	}
	if out, n := sc.Scrub(""); out != "" || n != 0 {
		t.Fatalf("empty: out=%q n=%d", out, n)
	}
}

func TestScrub_ZeroWidthEvasion(t *testing.T) {
	sc := defaultScrubber
	// Splice a variety of format/zero-width runes into the AKIA key id \u2014 all must
	// be stripped so the underlying shape is caught (Cf category + variation sel).
	for _, zwr := range []string{"\u200b", "\u2060", "\u200e", "\ufeff", "\u00ad", "\ufe0f"} {
		evaded := "AKIA" + zwr + "IOSFODNN7EXAMPLE"
		out, n := sc.Scrub(evaded)
		if n == 0 || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
			t.Fatalf("zero-width evasion survived (%U): %q (n=%d)", []rune(zwr)[0], out, n)
		}
	}
}

// ── Integration: the scrubber runs on KEPT strings via the redactor walk ──────

type embeddedSecretSection struct {
	Message string            `json:"message" redact:"internal"` // free text with an embedded secret
	Labels  map[string]string `json:"labels" redact:"internal"`  // secret hidden in a map key
	Raw     []byte            `json:"raw" redact:"internal"`     // secret in a []byte
	Masked  string            `json:"masked" redact:"sensitive"` // already masked; scrubber must not double-handle
}

func TestScrub_IntegrationViaRedactor(t *testing.T) {
	rd := NewWithSalt([]byte("salt"))
	sec := embeddedSecretSection{
		Message: "dial failed, sent ghp_" + strings.Repeat("q", 36),
		Labels:  map[string]string{"token-ghp_" + strings.Repeat("w", 36): "v"},
		Raw:     []byte("password=hunter2secretvalue"),
		Masked:  "alice@corp.example",
	}
	res := rd.Classify(sec)
	js, _ := json.Marshal(res.Value)
	s := string(js)
	if strings.Contains(s, "ghp_"+strings.Repeat("q", 36)) {
		t.Fatalf("embedded secret in INTERNAL message leaked: %s", s)
	}
	if strings.Contains(s, "ghp_"+strings.Repeat("w", 36)) {
		t.Fatalf("secret in map key leaked: %s", s)
	}
	if strings.Contains(s, "hunter2secretvalue") {
		t.Fatalf("secret in []byte leaked: %s", s)
	}
	if res.Scrubbed < 3 {
		t.Fatalf("expected >=3 scrubs, got %d", res.Scrubbed)
	}
	// The []byte must render as a scrubbed string, not a JSON array of ints.
	if strings.Contains(s, "[104,101") {
		t.Fatalf("[]byte exploded into ints instead of scrubbed string: %s", s)
	}
	// class_max must not exceed INTERNAL — a scrubbed value never raises class.
	if res.ClassMax > ClassInternal {
		t.Fatalf("scrubbing raised class_max to %v", res.ClassMax)
	}
}

// TestScrub_ByteSliceRaisesClassMax proves a kept []byte leaf raises ClassMax to
// its context (the []byte walk path calls scrubString directly, bypassing leaf's
// own bump) — so a PUBLIC-ceiling collector emitting byte content is still caught.
func TestScrub_ByteSliceRaisesClassMax(t *testing.T) {
	rd := NewWithSalt([]byte("s"))
	// A top-level []byte is walked with the default INTERNAL context; ClassMax
	// must reflect INTERNAL, not fall through to PUBLIC.
	if res := rd.Classify([]byte("plain byte content")); res.ClassMax != ClassInternal {
		t.Fatalf("top-level []byte class_max=%v want INTERNAL", res.ClassMax)
	}
	// A []byte value inside a kept map likewise.
	if res := rd.Classify(map[string][]byte{"k": []byte("v")}); res.ClassMax != ClassInternal {
		t.Fatalf("map []byte class_max=%v want INTERNAL", res.ClassMax)
	}
}

// FuzzScrub asserts the scrubber never panics, always terminates, and is
// idempotent on every input.
func FuzzScrub(f *testing.F) {
	for _, fx := range liveSecretFixtures() {
		f.Add(fx.in)
	}
	f.Add("")
	f.Add(strings.Repeat("a", 20000))
	f.Add("password=x; api_key=y; bearer z")
	sc := defaultScrubber
	f.Fuzz(func(t *testing.T, s string) {
		once, _ := sc.Scrub(s)
		twice, n := sc.Scrub(once)
		if twice != once || n != 0 {
			t.Fatalf("not idempotent: in=%q once=%q twice=%q n=%d", s, once, twice, n)
		}
	})
}
