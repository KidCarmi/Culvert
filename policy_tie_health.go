package main

import (
	"fmt"
	"strings"
)

// policy_tie_health.go — observability for rules that share a priority.
//
// Rules with equal priority evaluate in stored order (POL-001 amended,
// policy_tie_order.go). New ties are refused at the API, import and draft
// commit (POL-006), but Load, config-version rollback and CP→DP sync restore
// faithfully and may carry one in. Nothing renumbers them, and a move cannot
// touch a tied rule (PermutePriorities refuses an ambiguous priority), so the
// operator needs to see them: a /metrics gauge and one /api/diagnostics row.
// Both read the running store only and change no enforcement.

// policyPriorityTiesWritePrometheus emits culvert_policy_priority_ties: the
// number of rules that share their priority with at least one other rule
// (two rules at priority 5 and three at priority 9 read 5). 0 means every rule
// has a unique priority. Always emitted, so an alert on > 0 has a series.
func policyPriorityTiesWritePrometheus(w *strings.Builder) {
	fmt.Fprintf(w, "\n# HELP culvert_policy_priority_ties Policy rules that share their priority with at least one other rule; such rules evaluate in stored order (0 = every priority is unique)\n"+
		"# TYPE culvert_policy_priority_ties gauge\n"+
		"culvert_policy_priority_ties %d\n", policyStore.priorityTiedRuleCount())
}

func checkPolicyPriorityTies() OperatorContractCheck {
	return policyPriorityTiesRow(policyPriorityTies(policyStore.List()))
}

func policyPriorityTiesRow(ties []policyPriorityTie) OperatorContractCheck {
	if len(ties) == 0 {
		return OperatorContractCheck{
			Code:    "policy_priority_ties",
			Status:  diagOK,
			Message: "every policy rule has a unique priority",
		}
	}
	return OperatorContractCheck{
		Code:   "policy_priority_ties",
		Status: diagWarn,
		Message: fmt.Sprintf("%d policy rule(s) share a priority with another rule (%d shared priorit(ies)); rules that share a priority are evaluated in stored order: %s",
			tiedRuleCount(ties), len(ties), describePolicyPriorityTies(ties, 5)),
		OperatorAction: "Give each listed rule its own priority. A move cannot reorder rules that share a priority, and nothing is renumbered automatically. " +
			"Either edit one rule of each group through the API (PUT /api/policy?priority=<shared priority> with an unused priority in the body; it edits the first rule stored at that priority), " +
			"or export the configuration, give every rule a unique priority and import it in replace mode.",
	}
}
