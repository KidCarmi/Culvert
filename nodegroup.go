package main

// nodegroup.go — package-main glue for node groups, moved to
// internal/nodegroup (ADR-0002). The alias shim keeps ConfigSnapshot, the
// startup slice, and the test suite using the original unqualified names; the
// admin API handlers, the EnrolledNode-typed membership filter, and the
// globalNodeGroups singleton stay here (requireRole/auditEvent/jsonOK and the
// cluster-store read are main-owned).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/KidCarmi/Culvert/internal/nodegroup"
)

// NodeGroup / NodeGroupStore re-exposed unqualified (engine types are
// nodegroup.Group / .Store).
type (
	NodeGroup      = nodegroup.Group
	NodeGroupStore = nodegroup.Store
)

// NewNodeGroupStore / labelsMatch re-exposed for the startup slice, the
// handlers below, and the test suite.
var (
	NewNodeGroupStore = nodegroup.NewStore
	labelsMatch       = nodegroup.LabelsMatch
)

// NodeGroupInfo extends NodeGroup with runtime membership info for the API.
type NodeGroupInfo struct {
	NodeGroup
	NodeCount int      `json:"node_count"`
	NodeIDs   []string `json:"node_ids"`
}

// globalNodeGroups is the singleton node-group store.
var globalNodeGroups *NodeGroupStore

// nodesInGroup filters the provided nodes, returning only those whose labels
// satisfy the named group's selector. Stays in main because EnrolledNode is
// the enrollment hub's type (the engine is EnrolledNode-free by design).
func nodesInGroup(s *NodeGroupStore, name string, nodes []EnrolledNode) []EnrolledNode {
	g, ok := s.Get(name)
	if !ok {
		return nil
	}
	var out []EnrolledNode
	for i := range nodes {
		if labelsMatch(g.LabelSelector, nodes[i].Labels) {
			out = append(out, nodes[i])
		}
	}
	return out
}

// ─── Admin API ──────────────────────────────────────────────────────────────

// apiNodeGroups handles CRUD for node groups.
//
//	GET    /api/node-groups          — list all groups with membership (viewer)
//	POST   /api/node-groups          — create a group (admin)
//	DELETE /api/node-groups?name=X   — delete a group (admin)
func apiNodeGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		listNodeGroupsAPI(w)
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		createNodeGroupAPI(w, r)
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		deleteNodeGroupAPI(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func listNodeGroupsAPI(w http.ResponseWriter) {
	groups := globalNodeGroups.List()
	var nodes []EnrolledNode
	if globalClusterStore != nil {
		nodes = globalClusterStore.ListNodes()
	}
	infos := make([]NodeGroupInfo, len(groups))
	for i, g := range groups {
		var ids []string
		for j := range nodes {
			if labelsMatch(g.LabelSelector, nodes[j].Labels) {
				ids = append(ids, nodes[j].NodeID)
			}
		}
		if ids == nil {
			ids = []string{}
		}
		sort.Strings(ids)
		infos[i] = NodeGroupInfo{
			NodeGroup: g,
			NodeCount: len(ids),
			NodeIDs:   ids,
		}
	}
	jsonOK(w, map[string]any{"groups": infos})
}

func createNodeGroupAPI(w http.ResponseWriter, r *http.Request) {
	var g NodeGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	created, err := globalNodeGroups.Add(g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	auditEvent(r, "nodegroup.create", sanitizeLog(created.Name), fmt.Sprintf("label_selector=%v", created.LabelSelector))
	jsonOK(w, map[string]any{"ok": true, "group": created})
}

func deleteNodeGroupAPI(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name query parameter is required", http.StatusBadRequest)
		return
	}
	if !globalNodeGroups.Delete(name) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	auditEvent(r, "nodegroup.delete", sanitizeLog(name), "deleted")
	jsonOK(w, map[string]any{"ok": true})
}

// apiNodeGroupMembership returns detailed membership info for a specific group (F9).
// GET /api/node-groups/membership?name=GroupName
func apiNodeGroupMembership(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name query parameter is required", http.StatusBadRequest)
		return
	}
	group, ok := globalNodeGroups.Get(name)
	if !ok {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	var nodes []EnrolledNode
	if globalClusterStore != nil {
		nodes = globalClusterStore.ListNodes()
	}

	type memberInfo struct {
		NodeID    string            `json:"node_id"`
		IPAddress string            `json:"ip_address"`
		Status    string            `json:"status"`
		Labels    map[string]string `json:"labels"`
		Version   string            `json:"version"`
	}
	var members []memberInfo
	for i := range nodes {
		if labelsMatch(group.LabelSelector, nodes[i].Labels) {
			members = append(members, memberInfo{
				NodeID:    nodes[i].NodeID,
				IPAddress: nodes[i].IPAddress,
				Status:    nodes[i].Status,
				Labels:    nodes[i].Labels,
				Version:   nodes[i].Version,
			})
		}
	}
	if members == nil {
		members = []memberInfo{}
	}
	jsonOK(w, map[string]any{
		"group":   group,
		"members": members,
		"count":   len(members),
	})
}
