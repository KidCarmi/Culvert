package alerts

// store_maxwebhooks_test.go — MaxWebhooks grandfathering at load. The limit is
// enforced by the write ingresses (the admin API create arm and config import,
// both in package main); the store itself must never drop or refuse a file that
// is already over it, because losing a configured webhook silently loses alerts.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// captureObs routes the package log sink into a buffer for one test. obs has
// no getter for the previous sink, so the cleanup restores the package default
// (stderr), as the other obs-capturing tests do.
func captureObs(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var b strings.Builder
	obs.SetSink(func(line string) {
		mu.Lock()
		defer mu.Unlock()
		b.WriteString(line + "\n")
	})
	t.Cleanup(func() { obs.SetSink(func(line string) { fmt.Fprintln(os.Stderr, line) }) })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return b.String()
	}
}

func writeHooksFile(t *testing.T, n int) string {
	t.Helper()
	// Plain maps, not Webhook: the on-disk shape is what Init reads, and the
	// fixture carries no secret.
	hooks := make([]map[string]any, n)
	for i := range hooks {
		hooks[i] = map[string]any{
			"id":      fmt.Sprintf("overcap-%03d", i),
			"name":    fmt.Sprintf("overcap-hook-%03d", i),
			"url":     fmt.Sprintf("https://siem.example.invalid/overcap/%03d", i),
			"events":  []string{"threat_detected"},
			"enabled": true,
		}
	}
	data, err := json.Marshal(hooks)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "alert_webhooks.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("seed store file: %v", err)
	}
	return path
}

func TestStore_Init_OverMaxWebhooksIsGrandfathered(t *testing.T) {
	logged := captureObs(t)
	const n = MaxWebhooks + 5
	path := writeHooksFile(t, n)

	as := &Store{}
	as.Init(path)

	if got := as.Len(); got != n {
		t.Fatalf("Init loaded %d webhooks from an over-cap file, want all %d — an over-cap store is grandfathered, never truncated", got, n)
	}
	for _, id := range []string{"overcap-000", fmt.Sprintf("overcap-%03d", n-1)} {
		if _, ok := as.GetByID(id); !ok {
			t.Errorf("webhook %s missing after an over-cap load", id)
		}
	}
	out := logged()
	if !strings.Contains(out, "WARN") || !strings.Contains(out, fmt.Sprintf("over the limit of %d", MaxWebhooks)) {
		t.Errorf("an over-cap load must warn through the package log sink; logged %q", out)
	}

	// Updates and deletes of the existing webhooks keep working over the cap.
	if !as.Update("overcap-001", Webhook{Name: "overcap-renamed-001", Events: []string{"policy_block"}, Enabled: true}) {
		t.Fatal("Update of an existing webhook failed while the store is over the cap")
	}
	if h, _ := as.GetByID("overcap-001"); h.Name != "overcap-renamed-001" {
		t.Errorf("Update did not apply over the cap: name %q", h.Name)
	}
	if !as.Delete("overcap-002") {
		t.Fatal("Delete of an existing webhook failed while the store is over the cap")
	}
	if _, ok := as.GetByID("overcap-002"); ok {
		t.Error("deleted webhook still present")
	}
	if got := as.Len(); got != n-1 {
		t.Errorf("Len after one delete = %d, want %d", got, n-1)
	}

	// The delete persisted the remaining hooks (no truncation on the way out).
	again := &Store{}
	again.Init(path)
	if got := again.Len(); got != n-1 {
		t.Errorf("reloaded %d webhooks after the delete, want %d", got, n-1)
	}
	if _, ok := again.GetByID("overcap-002"); ok {
		t.Error("deleted webhook came back after a reload")
	}
}

// TestStore_Init_AtMaxWebhooksDoesNotWarn is the negative control: a store at
// exactly the limit is not over it, so loading it must not warn.
func TestStore_Init_AtMaxWebhooksDoesNotWarn(t *testing.T) {
	logged := captureObs(t)
	as := &Store{}
	as.Init(writeHooksFile(t, MaxWebhooks))
	if got := as.Len(); got != MaxWebhooks {
		t.Fatalf("loaded %d webhooks, want %d", got, MaxWebhooks)
	}
	if out := logged(); strings.Contains(out, "over the limit") {
		t.Errorf("a store at exactly the limit warned as over it: %q", out)
	}
}
