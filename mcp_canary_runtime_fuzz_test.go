package main

import (
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// FuzzCanaryRuntimeStateRestore fuzzes the ONE decoder that turns untrusted bytes on disk into an
// execution authority: the canary runtime-state record. Blocker #7 added a field to it
// (HealthSnapshot) and made restore ACT on the decoded content — it can now latch window_expired or
// budget_exhausted synchronously — so the decoder is no longer merely a reader.
//
// The invariant is one sentence and it does not depend on the bytes being valid: whatever is on
// disk, a restore must never produce an activation that can reserve execution, and must never
// report granted execution authority. A corrupt record is quarantined and treated as absent; a
// well-formed record for a spent or expired activation restores already latched. Neither can grant.
//
// The seeds are the shapes most likely to reach a grant if the fail-closed handling were wrong: a
// truncated record, a schema/capability mismatch, a record with trailing junk, and a plausible
// active record with a zero abort snapshot.
func FuzzCanaryRuntimeStateRestore(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"generation":`))
	f.Add([]byte(`{"schema_version":1,"capability":"gateway","active":true}`))
	f.Add([]byte(`{"schema_version":99,"capability":"gateway","active":true}`))
	f.Add([]byte(`{"schema_version":1,"capability":"management","active":true}{}`))
	f.Add([]byte(`{"schema_version":1,"capability":"gateway","active":true,"generation":7,` +
		`"budget":{"max_total_executions":3},"budget_snapshot":{},"abort_snapshot":{},"health_snapshot":{}}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
		capb := rollout.CapabilityGateway
		if err := os.WriteFile(canaryRuntimeStatePath(capb), raw, 0o600); err != nil {
			t.Fatalf("write state: %v", err)
		}
		fresh := &canaryRuntime{}
		globalCanaryRuntime = fresh
		fresh.restore()

		if o, _ := fresh.reserveCanaryExecution(capb, canaryRuntimeTestNow, rtIdent); o == canary.BudgetGranted {
			t.Fatalf("SECURITY: untrusted persisted bytes restored into an activation that granted execution: %q", raw)
		}
		if st := canaryAbortStatusFor(capb); st.ExecutionAuthority == "granted" {
			t.Fatalf("SECURITY: untrusted persisted bytes restored into granted execution authority: %q", raw)
		}
		_ = rt
	})
}
