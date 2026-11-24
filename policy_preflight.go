package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// `culvert policy-check <file>...` — the upgrade preflight for POL-005.
//
// This version refuses, whole, a ruleset that holds a rule it cannot enforce: at
// startup that is a fatal error naming the FIRST such rule. An operator about to
// upgrade needs the opposite view, before anything is stopped: every offending
// rule in every file, with nothing started and nothing changed. That is this
// command. It reads files only; it opens no listener, touches no state and
// needs no configuration.
//
// It understands the shapes policy rules are stored in:
//
//   - a policy file: a JSON array of rules (the -policy file);
//   - a config backup (an exported configuration): an object with "policyRules";
//   - a stored config version (a file under config_versions): {"meta", "config"};
//   - a pending policy draft: an object with "state" and "rules";
//   - a control-plane snapshot, which is also a data plane's last-known-good
//     file (dp_last_config_snapshot.json): an object with "policy_rules".
//
// Every door applies this same gate, so one verdict holds for startup, import,
// rollback and a control-plane snapshot built from the same rules.
//
// Exit status: 0 every file would be accepted (a backup with no policy section
// counts: it holds zero rules); 1 at least one file would be refused; 2 a file
// could not be read or is not one of those shapes.

// maybeRunPolicyPreflight intercepts `culvert policy-check ...` at the top of
// main(), before the global flag set is defined, runs it and exits. Any other
// invocation returns and normal startup proceeds.
func maybeRunPolicyPreflight(argv []string) {
	if len(argv) < 2 || argv[1] != "policy-check" {
		return
	}
	os.Exit(runPolicyPreflight(argv[2:], os.Stdout, os.Stderr))
}

// preflightPrintf writes one line of the report. A failed write to the
// operator's terminal has nowhere better to be reported.
func preflightPrintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// preflightFinding is one rule a file holds that this version would refuse.
type preflightFinding struct {
	Index  int
	Name   string
	Reason string
}

func runPolicyPreflight(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		preflightPrintf(stderr, "%s\n", "usage: culvert policy-check <policy.json | config-backup.json | config-version.json | policy_draft.json | dp_last_config_snapshot.json>...")
		preflightPrintf(stderr, "%s\n", "Lists every rule this version would refuse. Reads files only; changes nothing.")
	}
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	status := 0
	for _, path := range fs.Args() {
		rules, shape, err := readPreflightRules(path)
		if err != nil {
			preflightPrintf(stderr, "%s: %v\n", path, err)
			status = 2
			continue
		}
		findings := preflightFindings(rules)
		if len(findings) == 0 {
			preflightPrintf(stdout, "%s: OK — %d rule(s) in a %s, all enforceable by this version\n", path, len(rules), shape)
			continue
		}
		if status == 0 {
			status = 1
		}
		preflightPrintf(stdout, "%s: REFUSED — %d of %d rule(s) in a %s cannot be enforced by this version; the whole ruleset would be refused\n",
			path, len(findings), len(rules), shape)
		for _, f := range findings {
			preflightPrintf(stdout, "  rule #%d %q: %s\n", f.Index+1, sanitizeLog(f.Name), sanitizeLog(f.Reason))
		}
	}
	return status
}

// preflightDoc is every place a stored JSON object keeps policy rules.
type preflightDoc struct {
	Version     *json.RawMessage `json:"version"`     // a config backup always carries one
	PolicyRules *[]*PolicyRule   `json:"policyRules"` // config backup
	State       *json.RawMessage `json:"state"`       // a policy draft always carries one
	Rules       *[]*PolicyRule   `json:"rules"`       // policy draft
	Config      *preflightDoc    `json:"config"`      // stored config version: {"meta":…, "config":{backup}}; HA bundle: {"config":{snapshot}}
	// SnapshotRules is the control-plane snapshot shape, which is also the data
	// plane's last-known-good file (dp_last_config_snapshot.json). It carries a
	// "version" too, so without this key it read as a backup holding no rules.
	SnapshotRules *[]*PolicyRule `json:"policy_rules"`
}

// rules returns every rule the document holds and what kind of document it is.
func (doc *preflightDoc) rules() (rules []*PolicyRule, shape string) {
	shape = "config backup"
	if doc.PolicyRules != nil {
		rules = append(rules, *doc.PolicyRules...)
	}
	if doc.SnapshotRules != nil {
		rules = append(rules, *doc.SnapshotRules...)
		if doc.PolicyRules == nil {
			shape = "control-plane snapshot"
		}
	}
	if doc.Rules != nil {
		rules = append(rules, *doc.Rules...)
		if doc.PolicyRules == nil && doc.SnapshotRules == nil {
			shape = "policy draft"
		}
	}
	return rules, shape
}

// readPreflightRules decodes one of the stored shapes. Rules are decoded as
// pointers so a null array entry is reported instead of becoming a zero rule.
// An object that is recognisably a backup, a stored version or a draft but
// holds no rules is a valid file with zero rules, not an error: a backup need
// not carry a policy section.
func readPreflightRules(path string) (rules []*PolicyRule, shape string, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- an operator-named file, read-only, on the operator's own host
	if err != nil {
		return nil, "", err
	}
	if json.Unmarshal(data, &rules) == nil {
		return rules, "policy file", nil
	}
	var doc preflightDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("not valid JSON for a policy file, config backup, stored config version or policy draft: %w", err)
	}
	stored := doc.Config != nil
	if stored {
		doc = *doc.Config
	}
	recognised := doc.Version != nil || doc.PolicyRules != nil || doc.State != nil || doc.Rules != nil || doc.SnapshotRules != nil
	if !recognised {
		return nil, "", fmt.Errorf("no policy rules found: expected a JSON array of rules, a config backup, a stored config version, a policy draft or a control-plane snapshot")
	}
	rules, shape = doc.rules()
	if stored {
		shape = "stored config version"
	}
	return rules, shape, nil
}

// preflightFindings applies the same per-rule decisions as the POL-005 gate
// (knownRuleType, ruleEnforceable) and reports EVERY rule that fails,
// where the gate itself stops at naming the first.
func preflightFindings(rules []*PolicyRule) []preflightFinding {
	var out []preflightFinding
	for i, r := range rules {
		switch {
		case r == nil:
			out = append(out, preflightFinding{Index: i, Reason: "null entry"})
		case !knownRuleType(r.RuleType):
			out = append(out, preflightFinding{Index: i, Name: r.Name,
				Reason: fmt.Sprintf("ruleType %q is not recognised (known: %q, %q, or absent)", r.RuleType, ruleTypeAccess, ruleTypeAuth)})
		default:
			if ok, reason := ruleEnforceable(r); !ok {
				out = append(out, preflightFinding{Index: i, Name: r.Name, Reason: reason})
			}
		}
	}
	return out
}
