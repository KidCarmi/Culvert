package main

// ha_publish_gate.go — ADR-0064 part D. Placeholder predicate until the gate
// lands in the next commit: publishing is authorized.

func haPublishAuthorized() (ok bool, reason string) { return true, "" }

func addPublishGateStatus(map[string]any) {}
