package policy

import "strings"

// This file defines the CLOSED policy-field vocabulary and the pure accessors that
// extract a typed value from the immutable input. A field not listed here is
// rejected at compile time. An OPTIONAL field that is absent from the input
// reports present=false, so a condition on a missing field never matches (no
// "missing-field-as-empty-string" behavior) — with default-deny that fails closed.

// fieldKinds maps every scalar field to its value kind (for op compatibility).
var fieldKinds = map[string]fieldKind{
	"capability":                        kindString,
	"principal.kind":                    kindString,
	"principal.subject":                 kindString,
	"principal.tenant":                  kindString,
	"principal.issuer":                  kindString,
	"principal.groups":                  kindSet,
	"principal.assurance":               kindAssurance,
	"principal.sender_binding":          kindString,
	"principal.sender_bound":            kindBool,
	"agent.id":                          kindString,
	"agent.owner":                       kindString,
	"agent.version":                     kindString,
	"agent.managed":                     kindString,
	"agent.trust":                       kindString,
	"client.id":                         kindString,
	"client.app":                        kindString,
	"client.trust":                      kindString,
	"server.id":                         kindString,
	"server.owner":                      kindString,
	"server.environment":                kindString,
	"server.enabled":                    kindBool,
	"server.verification":               kindString,
	"tool.name":                         kindString,
	"tool.fingerprint":                  kindString,
	"tool.disposition":                  kindString,
	"tool.drift":                        kindString,
	"tool.destination":                  kindString,
	"tool.credential_power":             kindPower,
	"tool.reversibility":                kindString,
	"tool.risk":                         kindSet,
	"operation.method":                  kindString,
	"operation.operand":                 kindString,
	"operation.point":                   kindString,
	"operation.class":                   kindString,
	"operation.namespace":               kindString,
	"resource.type":                     kindString,
	"resource.id":                       kindString,
	"resource.tenant":                   kindString,
	"destination.class":                 kindString,
	"destination.environment":           kindString,
	"destination.approved_breadth":      kindString,
	"credential.profile":                kindString,
	"credential.kind":                   kindString,
	"credential.power_ceiling":          kindPower,
	"session.assurance":                 kindAssurance,
	"session.sender_binding":            kindString,
	"session.prior_confirmation":        kindBool,
	"session.prior_approval":            kindBool,
	"session.prior_grant":               kindBool,
	"inspection.dlp_available":          kindBool,
	"inspection.redaction_available":    kindBool,
	"inspection.dest_inspect_available": kindBool,
	"inspection.secret_scan_available":  kindBool,
	"inspection.secret_found":           kindBool,
	"inspection.pii_found":              kindBool,
	"inspection.injection_suspected":    kindBool,
	"inspection.schema_invalid":         kindBool,
	"time":                              kindTime,
}

// stringFields maps a scalar string/enum field to its accessor. Enum values are
// returned via String() so a rule author matches "write", "privilege_expansion", etc.
var stringFields = map[string]func(*DecisionInput) (string, bool){
	"capability":        func(in *DecisionInput) (string, bool) { return in.Capability.String(), true },
	"principal.kind":    func(in *DecisionInput) (string, bool) { return in.Principal.Kind.String(), true },
	"principal.subject": func(in *DecisionInput) (string, bool) { return present(in.Principal.SubjectID) },
	"principal.tenant":  func(in *DecisionInput) (string, bool) { return present(in.Principal.Tenant) },
	"principal.issuer":  func(in *DecisionInput) (string, bool) { return present(in.Principal.Issuer) },
	"principal.sender_binding": func(in *DecisionInput) (string, bool) {
		return in.Principal.SenderBinding.String(), true
	},
	"session.sender_binding": func(in *DecisionInput) (string, bool) {
		return in.Session.SenderBinding.String(), true
	},
	"agent.id": func(in *DecisionInput) (string, bool) {
		return agentStr(in, func(a *Agent) string { return a.AgentID })
	},
	"agent.owner": func(in *DecisionInput) (string, bool) { return agentStr(in, func(a *Agent) string { return a.Owner }) },
	"agent.version": func(in *DecisionInput) (string, bool) {
		return agentStr(in, func(a *Agent) string { return a.Version })
	},
	"agent.managed": func(in *DecisionInput) (string, bool) {
		return agentStr(in, func(a *Agent) string { return a.Managed.String() })
	},
	"agent.trust": func(in *DecisionInput) (string, bool) {
		return agentStr(in, func(a *Agent) string { return a.Trust.String() })
	},
	"client.id":    func(in *DecisionInput) (string, bool) { return present(in.Client.ClientID) },
	"client.app":   func(in *DecisionInput) (string, bool) { return present(in.Client.AppID) },
	"client.trust": func(in *DecisionInput) (string, bool) { return in.Client.Trust.String(), true },
	"server.id": func(in *DecisionInput) (string, bool) {
		return serverStr(in, func(s *Server) string { return s.ServerID })
	},
	"server.owner": func(in *DecisionInput) (string, bool) {
		return serverStr(in, func(s *Server) string { return s.Owner })
	},
	"server.environment": func(in *DecisionInput) (string, bool) {
		return serverStr(in, func(s *Server) string { return s.Environment })
	},
	"server.verification": func(in *DecisionInput) (string, bool) {
		return serverStr(in, func(s *Server) string { return s.Verification.String() })
	},
	"tool.name": func(in *DecisionInput) (string, bool) { return toolStr(in, func(t *Tool) string { return t.Name }) },
	"tool.fingerprint": func(in *DecisionInput) (string, bool) {
		return toolStr(in, func(t *Tool) string { return t.FingerprintHash })
	},
	"tool.disposition": func(in *DecisionInput) (string, bool) {
		return toolStr(in, func(t *Tool) string { return t.Disposition.String() })
	},
	"tool.drift": func(in *DecisionInput) (string, bool) {
		return toolStr(in, func(t *Tool) string { return t.Drift.String() })
	},
	"tool.destination": func(in *DecisionInput) (string, bool) {
		return toolStr(in, func(t *Tool) string { return t.Destination.String() })
	},
	"tool.reversibility": func(in *DecisionInput) (string, bool) {
		return toolStr(in, func(t *Tool) string { return t.Reversibility.String() })
	},
	"operation.method":    func(in *DecisionInput) (string, bool) { return present(in.Operation.Method) },
	"operation.operand":   func(in *DecisionInput) (string, bool) { return present(in.Operation.Operand) },
	"operation.point":     func(in *DecisionInput) (string, bool) { return present(in.Operation.DecisionPoint) },
	"operation.class":     func(in *DecisionInput) (string, bool) { return in.Operation.Class.String(), true },
	"operation.namespace": func(in *DecisionInput) (string, bool) { return in.Operation.Namespace.String(), true },
	"resource.type": func(in *DecisionInput) (string, bool) {
		return resourceStr(in, func(r *Resource) string { return r.Type })
	},
	"resource.id": func(in *DecisionInput) (string, bool) {
		return resourceStr(in, func(r *Resource) string { return r.ID })
	},
	"resource.tenant": func(in *DecisionInput) (string, bool) {
		return resourceStr(in, func(r *Resource) string { return r.Tenant })
	},
	"destination.class":            func(in *DecisionInput) (string, bool) { return in.Destination.Class.String(), true },
	"destination.environment":      func(in *DecisionInput) (string, bool) { return present(in.Destination.Environment) },
	"destination.approved_breadth": func(in *DecisionInput) (string, bool) { return in.Destination.ApprovedBreadth.String(), true },
	"credential.profile": func(in *DecisionInput) (string, bool) {
		return credStr(in, func(c *CredentialMeta) string { return c.ProfileRef })
	},
	"credential.kind": func(in *DecisionInput) (string, bool) {
		return credStr(in, func(c *CredentialMeta) string { return c.Kind })
	},
}

// setFields maps a set field to its accessor.
var setFields = map[string]func(*DecisionInput) []string{
	"principal.groups": func(in *DecisionInput) []string { return in.Principal.Groups },
	"tool.risk": func(in *DecisionInput) []string {
		if in.Tool == nil {
			return nil
		}
		return in.Tool.RiskSignals
	},
}

// boolFields maps a bool field to its accessor.
var boolFields = map[string]func(*DecisionInput) bool{
	"server.enabled":                    func(in *DecisionInput) bool { return in.Server != nil && in.Server.Enabled },
	"principal.sender_bound":            func(in *DecisionInput) bool { return in.Principal.SenderBinding.Bound() },
	"session.prior_confirmation":        func(in *DecisionInput) bool { return in.Session.PriorConfirmation },
	"session.prior_approval":            func(in *DecisionInput) bool { return in.Session.PriorApproval },
	"session.prior_grant":               func(in *DecisionInput) bool { return in.Session.PriorGrant },
	"inspection.dlp_available":          func(in *DecisionInput) bool { return in.Inspection.DLPAvailable },
	"inspection.redaction_available":    func(in *DecisionInput) bool { return in.Inspection.RedactionAvailable },
	"inspection.dest_inspect_available": func(in *DecisionInput) bool { return in.Inspection.DestInspectAvailable },
	"inspection.secret_scan_available":  func(in *DecisionInput) bool { return in.Inspection.SecretScanAvailable },
	// secret_found only "matches true" meaningfully when a scan actually ran, so an
	// absent scan reports false (fail closed — a rule keyed on secret_found=false
	// must also assert the scan is available).
	"inspection.secret_found": func(in *DecisionInput) bool { return in.Inspection.SecretScanAvailable && in.Inspection.SecretFound },
	// PR-7 summary facts. pii_found/schema_invalid gate on scan/inspection availability
	// so an absent inspector reports false (fail closed — a rule keyed on the negative
	// must also assert availability); injection_suspected likewise requires DLP.
	"inspection.pii_found":           func(in *DecisionInput) bool { return in.Inspection.DLPAvailable && in.Inspection.PIIFound },
	"inspection.injection_suspected": func(in *DecisionInput) bool { return in.Inspection.DLPAvailable && in.Inspection.InjectionSuspected },
	"inspection.schema_invalid":      func(in *DecisionInput) bool { return in.Inspection.DestInspectAvailable && in.Inspection.SchemaInvalid },
}

// assuranceFields maps an assurance field to its accessor.
var assuranceFields = map[string]func(*DecisionInput) Assurance{
	"principal.assurance": func(in *DecisionInput) Assurance { return in.Principal.Assurance },
	"session.assurance":   func(in *DecisionInput) Assurance { return in.Session.Assurance },
}

// powerFields maps a credential-power field to its accessor.
var powerFields = map[string]func(*DecisionInput) CredentialPower{
	"tool.credential_power": func(in *DecisionInput) CredentialPower {
		if in.Tool == nil {
			return PowerUnset
		}
		return in.Tool.CredentialPower
	},
	"credential.power_ceiling": func(in *DecisionInput) CredentialPower {
		if in.Credential == nil {
			return PowerUnset
		}
		return in.Credential.PowerCeiling
	},
}

// --- accessor helpers ------------------------------------------------------

func present(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	return s, true
}

func agentStr(in *DecisionInput, f func(*Agent) string) (string, bool) {
	if in.Agent == nil {
		return "", false
	}
	return present(f(in.Agent))
}

func serverStr(in *DecisionInput, f func(*Server) string) (string, bool) {
	if in.Server == nil {
		return "", false
	}
	return present(f(in.Server))
}

func toolStr(in *DecisionInput, f func(*Tool) string) (string, bool) {
	if in.Tool == nil {
		return "", false
	}
	return present(f(in.Tool))
}

func resourceStr(in *DecisionInput, f func(*Resource) string) (string, bool) {
	if in.Resource == nil {
		return "", false
	}
	return present(f(in.Resource))
}

func credStr(in *DecisionInput, f func(*CredentialMeta) string) (string, bool) {
	if in.Credential == nil {
		return "", false
	}
	return present(f(in.Credential))
}

// resourceAttrField recognises the "resource.attr:<key>" parameterized field and
// returns its <key>. Every attribute is a string-kind field, so the caller assumes
// kindString on a match.
func resourceAttrField(field string) (string, bool) {
	const p = "resource.attr:"
	if strings.HasPrefix(field, p) {
		key := field[len(p):]
		if key != "" {
			return key, true
		}
	}
	return "", false
}

// resourceAttr reads a bounded resource scope attribute (absent → not present).
func resourceAttr(in *DecisionInput, key string) (string, bool) {
	if in.Resource == nil || in.Resource.Attrs == nil {
		return "", false
	}
	v, ok := in.Resource.Attrs[key]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// parseAssurance parses an assurance label to its enum (exact, case-sensitive).
func parseAssurance(s string) (Assurance, bool) {
	switch s {
	case "unknown":
		return AssuranceUnknown, true
	case "low":
		return AssuranceLow, true
	case "medium":
		return AssuranceMedium, true
	case "high":
		return AssuranceHigh, true
	default:
		return AssuranceUnknown, false
	}
}

// parsePower parses a credential-power label to its enum (exact, case-sensitive).
func parsePower(s string) (CredentialPower, bool) {
	switch s {
	case "read_only":
		return PowerReadOnly, true
	case "write":
		return PowerWrite, true
	case "admin":
		return PowerAdmin, true
	default:
		return PowerUnset, false
	}
}
