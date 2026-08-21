package main

import "testing"

// The omnibus SaveAdminSettings rebuild must preserve the new durable feed fields
// via their holder — otherwise an unrelated admin mutation drops an explicit
// disable and resets the schema marker, re-triggering the migration (+ a fresh
// backup) on the next restart (Codex P1).
func TestSnapshotSaaSFeedDurable_PreservesFields(t *testing.T) {
	prev := getSaaSFeedDurable()
	defer setSaaSFeedDurable(prev) // isolate the global holder from other tests

	setSaaSFeedDurable(saasFeedDurable{
		Managed:        true,
		Enabled:        false, // explicit durable disable
		Protocol:       saasFeedProtocolV1,
		RefreshSeconds: 7200,
		SchemaVersion:  saasStoreSchemaVersion,
	})

	var s AdminSettings
	snapshotSaaSFeedDurable(&s)

	if !s.SaaSFeedManaged {
		t.Error("SaaSFeedManaged dropped by the omnibus snapshot")
	}
	if s.SaaSFeedEnabled {
		t.Error("explicit disable (SaaSFeedEnabled=false) not preserved")
	}
	if s.SaaSFeedProtocol != saasFeedProtocolV1 {
		t.Errorf("SaaSFeedProtocol dropped; got %q", s.SaaSFeedProtocol)
	}
	if s.SaaSFeedRefreshSeconds != 7200 {
		t.Errorf("SaaSFeedRefreshSeconds dropped; got %d", s.SaaSFeedRefreshSeconds)
	}
	if s.SaaSStoreSchemaVersion != saasStoreSchemaVersion {
		t.Errorf("schema marker dropped ⇒ migration would repeat + re-backup; got %d", s.SaaSStoreSchemaVersion)
	}
}
