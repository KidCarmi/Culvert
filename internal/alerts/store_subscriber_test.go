package alerts

// store_subscriber_test.go — HasSubscriber, the cheap "will anyone receive
// this?" check that lets a fault-driven producer skip firing (and, crucially,
// skip spawning a delivery goroutine) when no webhook is listening.

import "testing"

func TestHasSubscriber(t *testing.T) {
	tests := []struct {
		name  string
		hooks []Webhook
		event string
		want  bool
	}{
		{"empty store", nil, "storage_write_failed", false},
		{"exact match, enabled", []Webhook{{Enabled: true, Events: []string{"storage_write_failed"}}}, "storage_write_failed", true},
		{"exact match, DISABLED", []Webhook{{Enabled: false, Events: []string{"storage_write_failed"}}}, "storage_write_failed", false},
		{"catch-all", []Webhook{{Enabled: true, Events: []string{"*"}}}, "storage_write_failed", true},
		{"different event only", []Webhook{{Enabled: true, Events: []string{"policy_block"}}}, "storage_write_failed", false},
		{"one of several matches", []Webhook{
			{Enabled: true, Events: []string{"policy_block"}},
			{Enabled: false, Events: []string{"*"}},
			{Enabled: true, Events: []string{"threat_detected", "storage_write_failed"}},
		}, "storage_write_failed", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			as := &Store{hooks: tc.hooks}
			if got := as.HasSubscriber(tc.event); got != tc.want {
				t.Errorf("HasSubscriber(%q) = %v, want %v", tc.event, got, tc.want)
			}
		})
	}
}
