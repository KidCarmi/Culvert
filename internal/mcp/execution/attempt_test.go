package execution

import "testing"

// TestNewAttemptID_ShapeAndUniqueness pins the minted identity contract (§5):
// bounded, self-describing, and collision-resistant.
func TestNewAttemptID_ShapeAndUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 1024)
	for i := 0; i < 1024; i++ {
		id, err := newAttemptID()
		if err != nil {
			t.Fatalf("newAttemptID: %v", err)
		}
		if !validAttemptID(id) {
			t.Fatalf("minted id %q fails its own validator", id)
		}
		if len(id) != len(attemptIDPrefix)+2*attemptIDBytes {
			t.Fatalf("unbounded id: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("attempt id collision at iteration %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

// TestValidAttemptID_RejectsForeignIdentifiers pins that identifiers which are NOT
// minted attempt ids cannot enter the reconciliation set — in particular the
// identifiers §5 says an attempt id is not (wire id, server id, execution id).
func TestValidAttemptID_RejectsForeignIdentifiers(t *testing.T) {
	for _, bad := range []string{
		"", "att_", "u-server1", "exec-1234", "att_zzzz",
		"att_00112233445566778899aabbccddeeff00", // too long
		"att_00112233445566778899aabbccddee",     // too short
		"ATT_00112233445566778899aabbccddeeff",   // wrong prefix case
		"00112233445566778899aabbccddeeff",       // no prefix
	} {
		if validAttemptID(bad) {
			t.Errorf("validAttemptID(%q) must be false", bad)
		}
	}
}
