package pac

// inventory_diff.go — PAC Exception Intelligence P3-a: the DIRECT bypass
// change-diff. Given two config-derived DIRECT inventories (a "before" and an
// "after" — e.g. the active config vs a candidate an operator is about to
// publish), it reports which full-security-path bypasses the change ADDS,
// REMOVES, or BROADENS, per profile.
//
// This is a pure diff over two DirectInventory read-models — same Observable,
// config-only evidence class as the inventory itself. It never claims a bypass
// was used; it reports how the configuration's reachable DIRECT surface would
// change. It is INTENTIONALLY order-insensitive: rule reordering does not change
// the SET of DIRECT paths a profile can emit (that is capability, not
// per-request routing — the latter is what /api/pac/analyze's simulate covers).

import "fmt"

// Change kinds (stable API strings) for one DIRECT-surface delta.
const (
	// ChangeProfileGainedDirect: a profile that is newly DIRECT-capable.
	ChangeProfileGainedDirect = "profile_gained_direct"
	// ChangeProfileLostDirect: a profile that is no longer DIRECT-capable.
	ChangeProfileLostDirect = "profile_lost_direct"
	// ChangePathAdded: a new DIRECT source on an existing profile.
	ChangePathAdded = "path_added"
	// ChangePathRemoved: a DIRECT source removed from an existing profile.
	ChangePathRemoved = "path_removed"
)

// DirectPathDelta is one change to the DIRECT bypass surface.
type DirectPathDelta struct {
	ProfileID string           `json:"profileId"`
	Name      string           `json:"name"`
	Change    string           `json:"change"`
	Kind      DirectBypassKind `json:"kind,omitempty"`
	Detail    string           `json:"detail,omitempty"`
	Pattern   string           `json:"pattern,omitempty"`
	Broad     bool             `json:"broad,omitempty"`
	// RiskIncreasing is true when the change widens the full-bypass surface (a
	// newly DIRECT-capable profile, or an added DIRECT path). Removals are not
	// risk-increasing. A broadened rule shows as a removed narrow path + an
	// added broad path, so the add carries the risk signal.
	RiskIncreasing bool `json:"riskIncreasing"`
}

// DirectInventoryDiff is the full before→after change to the DIRECT surface.
type DirectInventoryDiff struct {
	// EvidenceClass is always "config" — Observable configuration delta, never
	// observed usage.
	EvidenceClass        string            `json:"evidenceClass"`
	Deltas               []DirectPathDelta `json:"deltas"`
	ProfilesGainedDirect int               `json:"profilesGainedDirect"`
	ProfilesLostDirect   int               `json:"profilesLostDirect"`
	PathsAdded           int               `json:"pathsAdded"`
	PathsRemoved         int               `json:"pathsRemoved"`
	// BroadPathsAdded counts added DIRECT paths flagged broad (wildcard, broad
	// CIDR, or an all-destination mode/private/fail-open bypass) — the highest-
	// signal risk-increasing changes.
	BroadPathsAdded int `json:"broadPathsAdded"`
	// RiskIncreased is true when the change adds any DIRECT surface (a gained
	// profile or an added path). A pure narrowing/removal leaves it false.
	RiskIncreased bool `json:"riskIncreased"`
}

// pathKey identifies a DIRECT source for set-diffing. Singleton kinds
// (plain_host / private_networks / availability_mode / fail_open) have no
// pattern, so their kind alone is the key; rule paths key on kind+pattern+
// scheme+port so a pattern change reads as remove+add (which surfaces a
// broadening as an added broad path).
func pathKey(e DirectEntry) string {
	return e.Kind + "|" + e.Pattern + "|" + e.Scheme + "|" + fmt.Sprintf("%d", e.Port)
}

// DiffDirectInventory computes the before→after DIRECT-surface change. Pure and
// deterministic (deltas are emitted in a stable order).
func DiffDirectInventory(before, after DirectInventory) DirectInventoryDiff {
	diff := DirectInventoryDiff{EvidenceClass: "config"}
	beforeByID := indexInventory(before)
	afterByID := indexInventory(after)

	// Stable profile-id order over the union.
	for _, id := range unionSortedIDs(beforeByID, afterByID) {
		b, bok := beforeByID[id]
		a, aok := afterByID[id]
		switch {
		case aok && !bok:
			if a.DirectCapable {
				diff.ProfilesGainedDirect++
				diff.RiskIncreased = true
				diff.Deltas = append(diff.Deltas, DirectPathDelta{
					ProfileID: id, Name: a.Name, Change: ChangeProfileGainedDirect, RiskIncreasing: true,
				})
			}
			diff.addPathDeltas(id, a.Name, nil, a.DirectPaths)
		case bok && !aok:
			if b.DirectCapable {
				diff.ProfilesLostDirect++
				diff.Deltas = append(diff.Deltas, DirectPathDelta{
					ProfileID: id, Name: b.Name, Change: ChangeProfileLostDirect,
				})
			}
			diff.addPathDeltas(id, b.Name, b.DirectPaths, nil)
		default:
			diff.addPathDeltas(id, a.Name, b.DirectPaths, a.DirectPaths)
		}
	}
	return diff
}

// addPathDeltas emits path_added / path_removed deltas for the set difference
// between a profile's before and after DIRECT paths.
func (diff *DirectInventoryDiff) addPathDeltas(id, name string, before, after []DirectEntry) {
	beforeSet := make(map[string]DirectEntry, len(before))
	for _, e := range before {
		beforeSet[pathKey(e)] = e
	}
	afterSet := make(map[string]DirectEntry, len(after))
	for _, e := range after {
		afterSet[pathKey(e)] = e
	}
	for _, e := range after {
		if _, ok := beforeSet[pathKey(e)]; ok {
			continue
		}
		diff.PathsAdded++
		if e.Broad {
			diff.BroadPathsAdded++
		}
		diff.RiskIncreased = true
		diff.Deltas = append(diff.Deltas, DirectPathDelta{
			ProfileID: id, Name: name, Change: ChangePathAdded,
			Kind: e.Kind, Detail: e.Detail, Pattern: e.Pattern, Broad: e.Broad, RiskIncreasing: true,
		})
	}
	for _, e := range before {
		if _, ok := afterSet[pathKey(e)]; ok {
			continue
		}
		diff.PathsRemoved++
		diff.Deltas = append(diff.Deltas, DirectPathDelta{
			ProfileID: id, Name: name, Change: ChangePathRemoved,
			Kind: e.Kind, Detail: e.Detail, Pattern: e.Pattern, Broad: e.Broad,
		})
	}
}

func indexInventory(inv DirectInventory) map[string]ProfileDirectInventory {
	m := make(map[string]ProfileDirectInventory, len(inv.Profiles))
	for i := range inv.Profiles {
		m[inv.Profiles[i].ProfileID] = inv.Profiles[i]
	}
	return m
}

// unionSortedIDs returns the sorted union of the two maps' keys (deterministic
// delta ordering) — a tiny insertion sort to avoid importing sort for one use.
func unionSortedIDs(a, b map[string]ProfileDirectInventory) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var ids []string
	for id := range a {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for id := range b {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
	return ids
}
