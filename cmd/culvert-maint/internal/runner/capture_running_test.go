package runner

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	testImageID  = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testRepoRef  = "ghcr.io/kidcarmi/culvert@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRepoRef2 = "ghcr.io/kidcarmi/culvert@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// captureRig wires a Runner whose fake exec routes canned stdout per
// command (ps / container-inspect / image-inspect) so the three-step
// CaptureRunningProxyImage chain runs without docker.
type captureRig struct {
	psOut        []byte
	containerOut []byte
	imageOut     []byte
	failContains string // if non-empty, any command whose joined argv contains this exits non-zero
}

func newCaptureRunner(t *testing.T, rig *captureRig) *Runner {
	t.Helper()
	r, err := New(Options{
		ComposeProjectDir: "/srv/culvert",
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      5 * time.Second,
		EnvAllow:          []string{EnvCulvertBackupPassphrase},
		DockerBinary:      "/usr/bin/docker",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.execStartFn = func(cmd *exec.Cmd) error {
		if out := rig.cannedFor(cmd.Args); out != nil {
			_, _ = cmd.Stdout.Write(out)
		}
		return nil
	}
	r.execWaitFn = func(cmd *exec.Cmd) error {
		if rig.failContains != "" && strings.Contains(strings.Join(cmd.Args, " "), rig.failContains) {
			return errors.New("simulated non-zero exit")
		}
		return nil
	}
	return r
}

func (rig *captureRig) cannedFor(args []string) []byte {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "{{json .Image}}"):
		return rig.containerOut
	case hasToken(args, "ps"):
		return rig.psOut
	case hasToken(args, "image") && hasToken(args, "inspect"):
		return rig.imageOut
	}
	return nil
}

func hasToken(args []string, tok string) bool {
	for _, a := range args {
		if a == tok {
			return true
		}
	}
	return false
}

// ─── happy paths ────────────────────────────────────────────────────

func TestCaptureRunningProxyImage_NDJSON(t *testing.T) {
	rig := &captureRig{
		psOut: []byte(`{"Service":"clamav","State":"running","ID":"111111111111"}
{"Service":"proxy","State":"running","ID":"abcdef012345"}`),
		containerOut: []byte(`"` + testImageID + `"` + "\n"),
		imageOut:     []byte(`[{"Id":"` + testImageID + `","RepoDigests":["` + testRepoRef + `"]}]`),
	}
	got, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background())
	if err != nil {
		t.Fatalf("CaptureRunningProxyImage: %v", err)
	}
	if got.ContainerID != "abcdef012345" {
		t.Errorf("ContainerID: got %q want abcdef012345", got.ContainerID)
	}
	if got.RunningImageID != testImageID {
		t.Errorf("RunningImageID: got %q want %q", got.RunningImageID, testImageID)
	}
	if len(got.RepoDigests) != 1 || got.RepoDigests[0] != testRepoRef {
		t.Errorf("RepoDigests: got %v want [%s]", got.RepoDigests, testRepoRef)
	}
	if got.PriorRef() != testRepoRef {
		t.Errorf("PriorRef: got %q want %q", got.PriorRef(), testRepoRef)
	}
}

func TestCaptureRunningProxyImage_ArrayForm(t *testing.T) {
	rig := &captureRig{
		psOut:        []byte(`[{"Service":"proxy","State":"running","ID":"deadbeef0123"}]`),
		containerOut: []byte(`"` + testImageID + `"`),
		imageOut:     []byte(`[{"RepoDigests":["` + testRepoRef2 + `","` + testRepoRef + `"]}]`),
	}
	got, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background())
	if err != nil {
		t.Fatalf("CaptureRunningProxyImage: %v", err)
	}
	if got.ContainerID != "deadbeef0123" {
		t.Errorf("ContainerID: got %q", got.ContainerID)
	}
	// RepoDigests are sorted + de-duplicated.
	if len(got.RepoDigests) != 2 || got.RepoDigests[0] != testRepoRef || got.RepoDigests[1] != testRepoRef2 {
		t.Errorf("RepoDigests not sorted/deduped as expected: %v", got.RepoDigests)
	}
}

// ─── #351 hygiene: parsed identifiers only, never raw inspect JSON ──

func TestCaptureRunningProxyImage_NoRawMetadataLeak(t *testing.T) {
	// The image-inspect record carries metadata beyond digests
	// (Config.Env with a secret, labels). The capture must surface ONLY
	// the parsed identifiers — none of that metadata may appear anywhere
	// in the returned struct.
	rig := &captureRig{
		psOut:        []byte(`{"Service":"proxy","State":"running","ID":"abcdef012345"}`),
		containerOut: []byte(`"` + testImageID + `"`),
		imageOut: []byte(`[{"Id":"` + testImageID + `","RepoDigests":["` + testRepoRef + `"],` +
			`"Config":{"Env":["SUPER_SECRET=leakme","PATH=/usr/bin"],"Labels":{"build":"private-meta"}}}]`),
	}
	got, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background())
	if err != nil {
		t.Fatalf("CaptureRunningProxyImage: %v", err)
	}
	blob := got.ContainerID + " " + got.RunningImageID + " " + strings.Join(got.RepoDigests, " ")
	for _, leaked := range []string{"SUPER_SECRET", "leakme", "private-meta", "Config", "Env", "Labels"} {
		if strings.Contains(blob, leaked) {
			t.Errorf("captured result leaked raw inspect metadata %q: %q", leaked, blob)
		}
	}
}

// ─── failure / edge cases ───────────────────────────────────────────

func TestCaptureRunningProxyImage_ProxyAbsent(t *testing.T) {
	rig := &captureRig{
		psOut: []byte(`{"Service":"clamav","State":"running","ID":"111111111111"}`),
	}
	if _, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background()); err == nil {
		t.Fatal("expected error when no proxy container is present")
	}
}

func TestCaptureRunningProxyImage_MultipleProxy(t *testing.T) {
	rig := &captureRig{
		psOut: []byte(`{"Service":"proxy","State":"running","ID":"aaaaaaaaaaaa"}
{"Service":"proxy","State":"running","ID":"bbbbbbbbbbbb"}`),
	}
	_, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exactly one proxy") {
		t.Fatalf("expected multiple-proxy error, got %v", err)
	}
}

func TestCaptureRunningProxyImage_ProxyNoContainerID(t *testing.T) {
	rig := &captureRig{
		psOut: []byte(`{"Service":"proxy","State":"running","ID":""}`),
	}
	if _, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background()); err == nil {
		t.Fatal("expected error when proxy has no container id")
	}
}

// A best-effort image-inspect failure (registry/daemon hiccup, or a
// locally-built image) must NOT fail the capture — the running image id
// is already authoritative; RepoDigests is simply left empty.
func TestCaptureRunningProxyImage_ImageInspectFailure_BestEffort(t *testing.T) {
	rig := &captureRig{
		psOut:        []byte(`{"Service":"proxy","State":"running","ID":"abcdef012345"}`),
		containerOut: []byte(`"` + testImageID + `"`),
		failContains: "image inspect", // make `docker image inspect` exit non-zero
	}
	got, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background())
	if err != nil {
		t.Fatalf("image-inspect failure must be best-effort, not fatal; got %v", err)
	}
	if got.RunningImageID != testImageID {
		t.Errorf("RunningImageID: got %q", got.RunningImageID)
	}
	if len(got.RepoDigests) != 0 {
		t.Errorf("RepoDigests must be empty on image-inspect failure; got %v", got.RepoDigests)
	}
	if got.PriorRef() != "" {
		t.Errorf("PriorRef must be empty when no repo digest captured; got %q", got.PriorRef())
	}
}

// A locally-built image with no RepoDigests is a legitimate state, not a
// failure: capture succeeds with an empty RepoDigests set.
func TestCaptureRunningProxyImage_NoRepoDigests(t *testing.T) {
	rig := &captureRig{
		psOut:        []byte(`{"Service":"proxy","State":"running","ID":"abcdef012345"}`),
		containerOut: []byte(`"` + testImageID + `"`),
		imageOut:     []byte(`[{"Id":"` + testImageID + `","RepoDigests":[]}]`),
	}
	got, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background())
	if err != nil {
		t.Fatalf("CaptureRunningProxyImage: %v", err)
	}
	if len(got.RepoDigests) != 0 {
		t.Errorf("expected no repo digests; got %v", got.RepoDigests)
	}
}

// A `.Image` value that is not a sha256 image id is a hard error — and
// the error must NOT echo the raw payload (hygiene).
func TestCaptureRunningProxyImage_MalformedImageID_NoLeak(t *testing.T) {
	rig := &captureRig{
		psOut:        []byte(`{"Service":"proxy","State":"running","ID":"abcdef012345"}`),
		containerOut: []byte(`"not-a-digest-but-secret-looking-value"`),
	}
	_, err := newCaptureRunner(t, rig).CaptureRunningProxyImage(context.Background())
	if err == nil {
		t.Fatal("expected error for a non-sha256 .Image value")
	}
	if strings.Contains(err.Error(), "secret-looking-value") {
		t.Errorf("error must not echo the raw .Image payload: %v", err)
	}
}

// ─── direct parser unit tests ───────────────────────────────────────

func TestParseContainerImageID(t *testing.T) {
	if id, err := parseContainerImageID([]byte(`"` + testImageID + `"` + "\n")); err != nil || id != testImageID {
		t.Errorf("valid: got (%q,%v) want (%q,nil)", id, err, testImageID)
	}
	for _, bad := range [][]byte{
		[]byte(``),
		[]byte(`   `),
		[]byte(`sha256:short`),
		[]byte(`"sha256:nothex` + strings.Repeat("z", 58) + `"`),
		[]byte(`{"Image":"x"}`), // object, not a JSON string
		[]byte(`not json`),
	} {
		if _, err := parseContainerImageID(bad); err == nil {
			t.Errorf("parseContainerImageID(%q) should have errored", bad)
		}
	}
}

func TestRepoDigestsFromImageInspect(t *testing.T) {
	out := repoDigestsFromImageInspect([]byte(`[{"RepoDigests":["` + testRepoRef2 + `","` + testRepoRef + `","garbage","` + testRepoRef + `"]}]`))
	if len(out) != 2 || out[0] != testRepoRef || out[1] != testRepoRef2 {
		t.Errorf("expected sorted/deduped/filtered [%s %s]; got %v", testRepoRef, testRepoRef2, out)
	}
	if got := repoDigestsFromImageInspect([]byte(`not json`)); got != nil {
		t.Errorf("malformed input must yield nil; got %v", got)
	}
}
