package bootstrap

// hostsafety_test.go — SEC-BOOTSTRAP-HOST-1 regression suite.
//
// The defect these gates pin: `r.Host` (and `X-Forwarded-Host` on a
// trustForwardedHeaders deployment) was interpolated into a shell script the
// product documents as `curl … | sudo bash`, inside a DOUBLE-quoted word:
//
//	CP_BASE="{{.CPBase}}"
//
// Go's own Host-header validation is not a mitigation — it accepts every byte
// `$( … )` needs — so a request with `Host: cp.example.com$(…)` produced a
// root-executed script that ran the attacker's command first.
//
// Every defect gate below was verified FAILING against the pre-fix tree
// (unvalidated BaseURL/EnrollmentAddr + the double-quoted template) and passing
// after. The CONTROLS exist because the cheapest way to pass every defect gate
// is to refuse everything, which would take one-click DP enrolment away
// entirely — a worse outcome than the defect.

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── The empirical wall ─────────────────────────────────────────────────────

// TestSafeAuthority_RejectsEveryByteGoAcceptsInAHostHeader measures which bytes
// net/http will actually put into r.Host and requires SafeAuthority to refuse
// every one of them that is not part of a host[:port].
//
// It is EMPIRICAL on purpose. The pre-fix reasoning that made this defect
// survive review was "net/http validates the Host header", which is true and
// irrelevant: httpguts rejects `"`, a backtick, `{` and space but ACCEPTS
// `$`, `(`, `)`, `'` and `;`. Asserting that against the real server means a
// future Go release that widens the accepted set fails this build instead of
// silently re-opening the injection sink.
func TestSafeAuthority_RejectsEveryByteGoAcceptsInAHostHeader(t *testing.T) {
	accepted := bytesGoAcceptsInHostHeader(t)
	if len(accepted) < 40 {
		t.Fatalf("probe is not exercising net/http: only %d bytes accepted", len(accepted))
	}

	// The only bytes a host[:port] may carry. Everything else Go lets through
	// must die at SafeAuthority. The underscore is here for the reason
	// validDNSName records: inert in every sink, and present in real Docker
	// Compose service names.
	const hostAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:[]"

	var leaked []string
	for _, b := range accepted {
		if strings.IndexByte(hostAlphabet, b) >= 0 {
			continue
		}
		probe := "cp.example.com" + string(rune(b)) + "x"
		if got, ok := SafeAuthority(probe); ok {
			leaked = append(leaked, string(rune(b))+" → "+got)
		}
	}
	if len(leaked) > 0 {
		t.Fatalf("SafeAuthority admitted bytes net/http allows in a Host header: %v", leaked)
	}

	// Not vacuous: the bytes that make the injection work must be present in
	// what Go accepts, or this gate is proving nothing.
	for _, need := range []byte{'$', '(', ')', '\'', ';'} {
		if strings.IndexByte(string(accepted), need) < 0 {
			t.Fatalf("probe did not observe %q in an accepted Host header — the gate would be vacuous", string(need))
		}
	}
}

// bytesGoAcceptsInHostHeader returns every printable ASCII byte that a real
// net/http server will carry through into r.Host.
func bytesGoAcceptsInHostHeader(t *testing.T) []byte {
	t.Helper()

	seen := make(chan string, 1)
	srv := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case seen <- r.Host:
			default:
			}
			io.WriteString(w, "ok") //nolint:errcheck // probe response body is not read
		}),
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln) //nolint:errcheck // Serve always returns on Close
	t.Cleanup(func() { _ = srv.Close() })

	var accepted []byte
	for b := 0x20; b < 0x7f; b++ {
		host := "a" + string(rune(b)) + "b"
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(conn, "GET /probe HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
			_ = conn.Close()
			continue
		}
		_, _ = bufio.NewReader(conn).ReadString('\n')
		select {
		case <-seen:
			accepted = append(accepted, byte(b))
		case <-time.After(500 * time.Millisecond):
		}
		_ = conn.Close()
	}
	return accepted
}

// ── Validator tables ───────────────────────────────────────────────────────

func TestSafeAuthority_Accepts(t *testing.T) {
	// CONTROL: every authority a real Control Plane can legitimately present.
	// A validator that refused these would pass every defect gate below while
	// breaking one-click DP enrolment on every deployment.
	tests := []struct{ in, want string }{
		{"cp.example.com", "cp.example.com"},
		{"cp.example.com:9090", "cp.example.com:9090"},
		{"cp.example.com.", "cp.example.com."},
		{"localhost", "localhost"},
		{"localhost:1", "localhost:1"},
		{"cp-1.eu-west-2.internal:65535", "cp-1.eu-west-2.internal:65535"},
		{"culvert_cp:50051", "culvert_cp:50051"},         // Docker Compose service name
		{"[fe80::1%eth0]:50051", "[fe80::1%eth0]:50051"}, // RFC 4007 zone id (Codex review)
		{"[fe80::1%eth0]", "[fe80::1%eth0]"},
		{"[fe80::1%2]:50051", "[fe80::1%2]:50051"}, // numeric scope id
		{"10.0.0.7", "10.0.0.7"},
		{"10.0.0.7:9090", "10.0.0.7:9090"},
		{"[::1]", "[::1]"},
		{"[::1]:9090", "[::1]:9090"},
		{"[2001:db8::1]:50051", "[2001:db8::1]:50051"},
		{"x", "x"},
		{strings.Repeat("a", 63) + ".example.com", strings.Repeat("a", 63) + ".example.com"},
	}
	for _, tt := range tests {
		got, ok := SafeAuthority(tt.in)
		if !ok {
			t.Errorf("SafeAuthority(%q) refused a legitimate authority", tt.in)
			continue
		}
		if got != tt.want {
			t.Errorf("SafeAuthority(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSafeAuthority_Refuses(t *testing.T) {
	tests := []string{
		"",
		"cp.example.com$(id)",                    // the shipped exploit shape
		"cp.example.com$(curl$IFS-sf/x;sh)",      // no space, no pipe — still RCE
		"cp.example.com'",                        // would close a single-quoted word
		`cp.example.com"`,                        // would close a double-quoted word
		"cp.example.com`id`",                     // backtick substitution
		"cp.example.com;id",                      // command separator
		"cp.example.com x",                       // whitespace
		"cp.example.com\tx",                      // tab
		"cp.example.com\nid",                     // newline (header split / YAML)
		"cp.example.com/../evil",                 // path fragment
		"user:pass@cp.example.com",               // userinfo
		"cp.example.com:",                        // empty port
		"cp.example.com:0",                       // port 0
		"cp.example.com:65536",                   // port out of range
		"cp.example.com:9090x",                   // non-numeric port
		"cp.example.com:-1",                      // signed port
		"::1",                                    // bare (unbracketed) IPv6
		"2001:db8::1",                            // bare IPv6
		"[::1",                                   // unterminated bracket
		"-cp.example.com",                        // leading hyphen label
		"cp-.example.com",                        // trailing hyphen label
		"cp..example.com",                        // empty label
		".example.com",                           // empty first label
		strings.Repeat("a", 64) + ".example.com", // label over 63
		strings.Repeat("a.", 130) + "com",        // name over 253
		strings.Repeat("a", 300),                 // over the byte bound
		"cp.example.com%00",                      // encoded NUL
		"café.example.com",                       // non-ASCII (must be punycode)
		"[fe80::1%]",                             // empty zone
		"[fe80::1%et$(id)]",                      // injected zone
		"[fe80::1%eth 0]",                        // whitespace in the zone
		"[fe80::1%" + strings.Repeat("a", 33) + "]", // zone over the bound
		"10.0.0.7%eth0",          // a zone is meaningless on IPv4
		"[::ffff:10.0.0.7%eth0]", // …and on a 4-in-6 address
		"cp.example.com%eth0",    // a zone is not a DNS-name byte
	}
	for _, in := range tests {
		if got, ok := SafeAuthority(in); ok {
			t.Errorf("SafeAuthority(%q) ACCEPTED and returned %q — must fail closed", in, got)
		}
	}
}

func TestSafeToken(t *testing.T) {
	good := []string{"tok123", "AbC-_019", strings.Repeat("a", 128)}
	for _, g := range good {
		if !SafeToken(g) {
			t.Errorf("SafeToken(%q) = false, want true", g)
		}
	}
	bad := []string{"", "tok/123", "tok'123", "tok$(id)", "tok 123", "tok\n", "tok=", strings.Repeat("a", 129)}
	for _, b := range bad {
		if SafeToken(b) {
			t.Errorf("SafeToken(%q) = true, want false", b)
		}
	}
}

func TestSafeImageRef(t *testing.T) {
	good := []string{
		"ghcr.io/kidcarmi/culvert:latest",
		"registry.corp:5000/culvert:1.2.3",
		"ghcr.io/x/y@sha256:" + strings.Repeat("a", 64),
	}
	for _, g := range good {
		if !SafeImageRef(g) {
			t.Errorf("SafeImageRef(%q) = false, want true", g)
		}
	}
	bad := []string{
		"",
		"img:1\nservices:", // YAML injection
		"img:1 # comment",  // whitespace
		"img:1\"",          // quote
		"img$(id):1",       // substitution
		strings.Repeat("a", 513),
	}
	for _, b := range bad {
		if SafeImageRef(b) {
			t.Errorf("SafeImageRef(%q) = true, want false", b)
		}
	}
}

func TestSafeEnrollURL(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	if !SafeEnrollURL("culvert://enroll/cp.example.com:50051/tok123?ca-fp=sha256:" + fp) {
		t.Fatal("SafeEnrollURL refused the shape this appliance builds")
	}
	bad := []string{
		"",
		"https://cp.example.com/", // wrong scheme
		"culvert://enroll/cp.example.com:50051/tok123",               // no fingerprint
		"culvert://enroll/cp.example.com:50051/tok123?ca-fp=sha256:", // empty fingerprint (CA not ready)
		"culvert://enroll/cp$(id):50051/tok123?ca-fp=sha256:" + fp,   // injected authority
		"culvert://enroll/cp.example.com:50051/tok'?ca-fp=sha256:" + fp,
		"culvert://enroll/cp.example.com:50051/tok123?ca-fp=sha256:" + strings.ToUpper(fp),
		"culvert://enroll/cp.example.com:50051/tok123?ca-fp=sha256:" + fp[:63],
	}
	for _, b := range bad {
		if SafeEnrollURL(b) {
			t.Errorf("SafeEnrollURL(%q) = true, want false", b)
		}
	}
}

// ── Derivation helpers fail closed ─────────────────────────────────────────

func TestBaseURL_FailsClosedOnInjectedHost(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cp/x", http.NoBody)
	req.Host = "cp.example.com$(id)"
	if got, ok := BaseURL(req, false); ok {
		t.Fatalf("BaseURL accepted an injected Host and returned %q", got)
	}
}

func TestBaseURL_FailsClosedOnInjectedForwardedHost(t *testing.T) {
	// X-Forwarded-Host is an ordinary header: net/http applies no host-shaped
	// validation to it at all, so on a trustForwardedHeaders deployment the
	// injection is unconstrained (quotes and backticks included).
	for _, evil := range []string{`evil.example.com";id;"`, "evil.example.com`id`", "evil.example.com$(id)"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cp/x", http.NoBody)
		req.Host = "cp.example.com"
		req.Header.Set("X-Forwarded-Host", evil)
		if got, ok := BaseURL(req, true); ok {
			t.Errorf("BaseURL accepted X-Forwarded-Host %q and returned %q", evil, got)
		}
		// CONTROL: the same request with forwarded headers untrusted must still
		// succeed on its own Host — the fix must not disable the endpoint.
		if got, ok := BaseURL(req, false); !ok || got != "https://cp.example.com" {
			t.Errorf("BaseURL(untrusted) = %q, %v; want https://cp.example.com, true", got, ok)
		}
	}
}

func TestEnrollmentAddr_FailsClosedOnInjection(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cp/x", http.NoBody)
	req.Host = "cp.example.com$(id):9090"
	if got, ok := EnrollmentAddr(req, ":50051", false); ok {
		t.Fatalf("EnrollmentAddr accepted an injected Host and returned %q", got)
	}

	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cp/x", http.NoBody)
	req2.Host = "cp.example.com:9090"
	req2.Header.Set("X-Forwarded-Host", `evil";id;"`)
	if got, ok := EnrollmentAddr(req2, ":50051", true); ok {
		t.Fatalf("EnrollmentAddr accepted an injected X-Forwarded-Host and returned %q", got)
	}
}

// ── The sink refuses too ───────────────────────────────────────────────────

func TestRenderScript_RefusesUnsafeValuesAndWritesNothing(t *testing.T) {
	fp := "https://cp.example.com:9090"
	cases := []struct {
		name            string
		host, base, tok string
	}{
		{"injected host", "cp.example.com$(id)", fp, "tok123"},
		{"injected base", "cp.example.com:9090", "https://cp.example.com$(id)", "tok123"},
		{"base is not a URL", "cp.example.com:9090", "cp.example.com:9090", "tok123"},
		{"base has a path", "cp.example.com:9090", "https://cp.example.com/x", "tok123"},
		{"injected token", "cp.example.com:9090", fp, "tok'123"},
		{"empty token", "cp.example.com:9090", fp, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sb strings.Builder
			err := RenderScript(&sb, tc.host, tc.base, tc.tok)
			if err == nil {
				t.Fatalf("RenderScript accepted an unsafe value; output:\n%s", sb.String())
			}
			if sb.Len() != 0 {
				t.Fatalf("RenderScript wrote %d bytes on refusal — a half-written root-executed artifact", sb.Len())
			}
		})
	}
}

func TestRenderCompose_RefusesUnsafeValuesAndWritesNothing(t *testing.T) {
	good := "culvert://enroll/cp.example.com:50051/tok123?ca-fp=sha256:" + strings.Repeat("ab", 32)
	cases := []struct{ name, image, url string }{
		{"injected image", "img:1\nservices:", good},
		{"injected enroll url", "img:1", "culvert://enroll/cp$(id):50051/tok123?ca-fp=sha256:" + strings.Repeat("ab", 32)},
		{"unpinned enroll url", "img:1", "culvert://enroll/cp.example.com:50051/tok123?ca-fp=sha256:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sb strings.Builder
			if err := RenderCompose(&sb, tc.image, tc.url); err == nil {
				t.Fatalf("RenderCompose accepted an unsafe value; output:\n%s", sb.String())
			} else if sb.Len() != 0 {
				t.Fatalf("RenderCompose wrote %d bytes on refusal", sb.Len())
			}
		})
	}
}

func TestImage_UnsafeRegistryOverrideFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/registry_settings.json"
	if err := writeFile(path, `{"registry_url":"registry.corp/culvert\nservices:"}`); err != nil {
		t.Fatal(err)
	}
	if got := Image(path, "1.2.3"); got != DefaultImage+":1.2.3" {
		t.Fatalf("Image(unsafe override) = %q, want the built-in default", got)
	}
}

// ── Structural wall on the template ────────────────────────────────────────

// TestScriptTemplate_NoInterpolationInsideADoubleQuotedWord is the wall that
// would have caught the original defect by reading the template rather than its
// output: a `{{.X}}` inside a double-quoted shell word is a command-substitution
// sink, whatever the value happens to be today.
func TestScriptTemplate_NoInterpolationInsideADoubleQuotedWord(t *testing.T) {
	src := scriptTmpl.Root.String()
	if bad := doubleQuotedInterpolations(src); len(bad) > 0 {
		t.Fatalf("script template interpolates inside a double-quoted shell word (command substitution applies there): %v", bad)
	}

	// CONTROL: the detector must reject the pre-fix form, or it is a selector
	// that matches nothing and would pass forever.
	prefix := "CP_BASE=\"{{.CPBase}}\"\n"
	if bad := doubleQuotedInterpolations(prefix); len(bad) == 0 {
		t.Fatal("detector failed to flag the pre-fix template form — the wall is vacuous")
	}
}

// doubleQuotedInterpolations returns each `{{…}}` action in src that appears
// inside a double-quoted region of its own line.
func doubleQuotedInterpolations(src string) []string {
	var bad []string
	for _, line := range strings.Split(src, "\n") {
		idx := strings.Index(line, "{{")
		if idx < 0 || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		// Odd number of unescaped double quotes before the action ⇒ open word.
		if strings.Count(line[:idx], `"`)%2 == 1 {
			bad = append(bad, strings.TrimSpace(line))
		}
	}
	return bad
}

// TestDefect_DoubleQuotedWordExpandsCommandSubstitution is the DEFECT PROOF: it
// runs the real shell to show that the pre-fix template form executes an
// injected `$( … )` and the shipped single-quoted form does not. Without it a
// future "simplification" back to double quotes reads as a style change.
func TestDefect_DoubleQuotedWordExpandsCommandSubstitution(t *testing.T) {
	sh, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	// The marker must be produced BY the substitution, never present in the
	// payload text, or the assertions below would pass on a literal echo.
	const injected = `cp.example.com$(echo PWNED)`
	const expanded = `cp.example.comPWNED`

	// CommandContext, not Command: the harness must die with the test (noctx).
	// #nosec G204 -- fixed argv; `injected` is this test's own literal above.
	out, err := exec.CommandContext(t.Context(), sh, "-c", `CP_BASE="`+injected+`"; printf %s "$CP_BASE"`).Output()
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	if string(out) != expanded {
		t.Fatalf("double-quoted word did not expand $( ) — this gate no longer proves the defect (got %q)", out)
	}

	// #nosec G204 -- same fixed payload, single-quoted; see above.
	out, err = exec.CommandContext(t.Context(), sh, "-c", `CP_BASE='`+injected+`'; printf %s "$CP_BASE"`).Output()
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	if string(out) != injected {
		t.Fatalf("single-quoted word did not stay literal — the defence is not sound (got %q)", out)
	}
}

// ── Concurrency ────────────────────────────────────────────────────────────

// TestRenderers_ConcurrentSafeAndUnsafe runs both renderers from many
// goroutines, mixing accepted and refused inputs, so -race covers the shared
// template globals and the validators alongside them.
func TestRenderers_ConcurrentSafeAndUnsafe(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	good := "culvert://enroll/cp.example.com:50051/tok123?ca-fp=sha256:" + fp

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var sb strings.Builder
			if i%2 == 0 {
				if err := RenderScript(&sb, "cp.example.com:9090", "https://cp.example.com:9090", "tok123"); err != nil {
					t.Errorf("RenderScript(safe): %v", err)
				}
				if err := RenderCompose(&sb, "img:1", good); err != nil {
					t.Errorf("RenderCompose(safe): %v", err)
				}
				return
			}
			if err := RenderScript(&sb, "cp$(id)", "https://cp$(id)", "tok'"); err == nil {
				t.Error("RenderScript accepted an unsafe value under concurrency")
			}
			if err := RenderCompose(&sb, "img\n:1", "culvert://x"); err == nil {
				t.Error("RenderCompose accepted an unsafe value under concurrency")
			}
		}(i)
	}
	wg.Wait()
}

// writeFile is a tiny helper so the table tests above stay readable.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
