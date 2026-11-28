package status

import (
	"encoding/json"
	"strings"
	"testing"

	"culvert-maint/internal/server"
)

func TestRuntimeRecovery_AbsentWhenOff(t *testing.T) {
	var st server.Status
	(&Provider{}).addRuntimeRecovery(&st)
	b, _ := json.Marshal(st)
	if st.RuntimeRecovery != nil || strings.Contains(string(b), "runtime_recovery") {
		t.Fatalf("runtime_recovery reported with it off: %s", b)
	}
}

func TestRuntimeRecovery_ReportsTheTracker(t *testing.T) {
	var st server.Status
	(&Provider{}).WithRuntimeRecovery(server.NewRuntimeRecoveryTracker(), "restore_last_gated").addRuntimeRecovery(&st)
	rr := st.RuntimeRecovery
	if rr == nil || rr.Policy != "restore_last_gated" || rr.Threshold != server.RuntimeRecoveryStreak || rr.Last != nil {
		t.Fatalf("runtime_recovery = %+v", rr)
	}
}
