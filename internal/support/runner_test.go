package support

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

type fakeCollector struct {
	meta CollectorMeta
	fn   func(ctx context.Context, in CollectInput, sink SectionSink) Result
}

func (f *fakeCollector) Meta() CollectorMeta { return f.meta }
func (f *fakeCollector) Collect(ctx context.Context, in CollectInput, sink SectionSink) Result {
	return f.fn(ctx, in, sink)
}

func baseMeta(id string, min DebugLevel, maxClass redaction.DataClass) CollectorMeta {
	return CollectorMeta{
		ID: id, Path: "sections/" + id + ".json", Owner: "test", SchemaVersion: 1,
		Timeout: time.Second, ByteBudget: 64 << 10, Mandatory: true, MinLevel: min,
		MaxClass: maxClass, Sensitivity: maxClass,
	}
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func buildWith(t *testing.T, collectors ...Collector) *BuildResult {
	t.Helper()
	restore := resetRegistryForTest()
	defer restore()
	for _, c := range collectors {
		Register(c)
	}
	res, err := NewRunner().Build(context.Background(), BuildOptions{
		Version: "v1.2.3", GoVersion: "go1.25.12",
		Runtime: RuntimeInfo{NodeID: "node-a", Role: "standalone", Runtime: "compose"},
		Level:   L1, Nonce: "nonce-1", Clock: fixedClock(), Salt: []byte("fixed-salt"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return res
}

func tarFiles(t *testing.T, tgz []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	var order []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = b
		order = append(order, h.Name)
	}
	if len(order) == 0 || order[0] != ManifestName {
		t.Fatalf("manifest.json must be the first tar entry, got order=%v", order)
	}
	return out
}

func okCollector(id string, class redaction.DataClass, payload any) *fakeCollector {
	return &fakeCollector{
		meta: baseMeta(id, L0, class),
		fn: func(ctx context.Context, in CollectInput, sink SectionSink) Result {
			r := in.Redactor.Classify(payload)
			if err := sink.WriteJSON(r.Value); err != nil {
				return Result{Status: StatusFailed}
			}
			return Result{Status: StatusOK, ClassMax: r.ClassMax}
		},
	}
}

func TestRunner_TwoSectionsBundle(t *testing.T) {
	type pub struct {
		V string `json:"v" redact:"public"`
	}
	type internalSec struct {
		Rule string `json:"rule" redact:"internal"`
	}
	res := buildWith(t,
		okCollector("product", redaction.ClassPublic, pub{V: "v1.2.3"}),
		okCollector("diagnostics", redaction.ClassInternal, internalSec{Rule: "allow-x"}),
	)
	if res.Manifest.Format != BundleFormat {
		t.Fatalf("format=%s", res.Manifest.Format)
	}
	if res.Manifest.Collection.OK != 2 || res.Manifest.Collection.TotalCollectors != 2 {
		t.Fatalf("collection stats: %+v", res.Manifest.Collection)
	}
	files := tarFiles(t, res.TarGz)
	for _, want := range []string{ManifestName, RedactionReportName, CollectionErrorName, "sections/product.json", "sections/diagnostics.json"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("bundle missing %s", want)
		}
	}
	if !strings.HasPrefix(res.BundleID, "csb_") {
		t.Fatalf("bundle_id=%s", res.BundleID)
	}
}

func TestRunner_PanicIsolated(t *testing.T) {
	type pub struct {
		V string `json:"v" redact:"public"`
	}
	panicker := &fakeCollector{
		meta: baseMeta("boom", L0, redaction.ClassInternal),
		fn: func(ctx context.Context, in CollectInput, sink SectionSink) Result {
			panic("collector exploded")
		},
	}
	res := buildWith(t, okCollector("product", redaction.ClassPublic, pub{V: "ok"}), panicker)
	if res.Manifest.Collection.Failed != 1 || res.Manifest.Collection.OK != 1 {
		t.Fatalf("panic not isolated: %+v", res.Manifest.Collection)
	}
	if res.Manifest.Collection.ErrorCount != 1 {
		t.Fatalf("expected 1 collection error, got %d", res.Manifest.Collection.ErrorCount)
	}
}

func TestRunner_SkipByLevel(t *testing.T) {
	type sec struct {
		X string `json:"x" redact:"internal"`
	}
	high := okCollector("l2only", redaction.ClassInternal, sec{X: "y"})
	high.meta.MinLevel = L2 // build runs at L1
	res := buildWith(t, high)
	if res.Manifest.Collection.Skipped != 1 {
		t.Fatalf("expected skipped, got %+v", res.Manifest.Collection)
	}
	if res.Manifest.Sections[0].Status != StatusSkipped {
		t.Fatalf("status=%s want skipped", res.Manifest.Sections[0].Status)
	}
}

func TestRunner_ClassCeilingDropsSection(t *testing.T) {
	// Payload contains an INTERNAL field but the collector declares MaxClass=PUBLIC.
	type sec struct {
		Host string `json:"host" redact:"internal"`
	}
	over := okCollector("greedy", redaction.ClassPublic, sec{Host: "proxy-1"})
	res := buildWith(t, over)
	if res.Manifest.Collection.Failed != 1 {
		t.Fatalf("over-ceiling section should fail: %+v", res.Manifest.Collection)
	}
	files := tarFiles(t, res.TarGz)
	if _, ok := files["sections/greedy.json"]; ok {
		t.Fatal("over-ceiling section must not be emitted")
	}
}

func TestRunner_Deterministic(t *testing.T) {
	type pub struct {
		V string `json:"v" redact:"public"`
	}
	mk := func() []byte {
		return buildWith(t, okCollector("product", redaction.ClassPublic, pub{V: "v1"})).TarGz
	}
	if !bytes.Equal(mk(), mk()) {
		t.Fatal("bundle bytes not deterministic under fixed clock+salt+nonce")
	}
}

func TestRunner_SecretFieldNeverInBundle(t *testing.T) {
	const planted = "PLANTED-bcrypt-$2a$secret"
	type sec struct {
		Pub  string `json:"pub" redact:"public"`
		Hash string `json:"hash" redact:"secret"`
	}
	res := buildWith(t, okCollector("auth", redaction.ClassInternal, sec{Pub: "n", Hash: planted}))
	if bytes.Contains(res.TarGz, []byte(planted)) {
		t.Fatal("planted secret survived into the bundle bytes")
	}
}
