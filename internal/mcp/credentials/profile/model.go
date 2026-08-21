package profile

// CredentialKind enumerates the shape of the upstream credential. The broker's
// scoped materialization callback receives the kind plus a lifetime-bounded view
// of only the secret fields the kind requires. PR-4 never constructs an HTTP
// header or upstream request from any kind.
type CredentialKind uint8

const (
	// KindUnset is the invalid zero value (fails closed).
	KindUnset CredentialKind = iota
	// KindBearerToken — a bearer token secret field.
	KindBearerToken
	// KindAPIKey — an API-key secret field.
	KindAPIKey
	// KindUsernamePassword — a username (non-secret) + password (secret) pair.
	KindUsernamePassword
	// KindClientCertificate — a client certificate + private-key material.
	KindClientCertificate
	// KindWorkloadIdentity — a short-lived workload-identity assertion (no long-lived
	// static secret); modelled through the same lease/scope/rotation contracts.
	KindWorkloadIdentity
	// KindOpaque — provider-defined opaque material.
	KindOpaque
)

// Valid reports whether the kind is a defined non-zero kind.
func (k CredentialKind) Valid() bool { return k >= KindBearerToken && k <= KindOpaque }

// String returns the stable kind label.
func (k CredentialKind) String() string {
	switch k {
	case KindBearerToken:
		return "bearer_token"
	case KindAPIKey:
		return "api_key"
	case KindUsernamePassword:
		return "username_password"
	case KindClientCertificate:
		return "client_certificate"
	case KindWorkloadIdentity:
		return "workload_identity"
	case KindOpaque:
		return "opaque"
	default:
		return "unset"
	}
}

// CredentialPower is the privilege ceiling of a credential, ordered from least to
// most powerful. It is the ceiling dimension of scope validation: a provider's
// effective power must never exceed the plan's power ceiling.
type CredentialPower uint8

const (
	// PowerUnset is the invalid zero value.
	PowerUnset CredentialPower = iota
	// PowerReadOnly — read-only access.
	PowerReadOnly
	// PowerWrite — write / mutate access.
	PowerWrite
	// PowerAdmin — administrative access.
	PowerAdmin
	// PowerDestructive — destructive access (delete/purge).
	PowerDestructive
)

// Valid reports whether the power is a defined non-zero level.
func (p CredentialPower) Valid() bool { return p >= PowerReadOnly && p <= PowerDestructive }

// String returns the stable power label.
func (p CredentialPower) String() string {
	switch p {
	case PowerReadOnly:
		return "read_only"
	case PowerWrite:
		return "write"
	case PowerAdmin:
		return "admin"
	case PowerDestructive:
		return "destructive"
	default:
		return "unset"
	}
}

// OperationClass is the class of upstream operation a plan is for. It determines
// the risk class and the least-privilege power ceiling for that plan.
type OperationClass uint8

const (
	// OpUnset is the invalid zero value.
	OpUnset OperationClass = iota
	// OpRead — a read / low-risk operation.
	OpRead
	// OpWrite — a write / mutate operation (high risk).
	OpWrite
	// OpAdmin — an administrative operation (high risk).
	OpAdmin
	// OpDestructive — a destructive operation (high risk).
	OpDestructive
)

// Valid reports whether the operation class is a defined non-zero class.
func (o OperationClass) Valid() bool { return o >= OpRead && o <= OpDestructive }

// String returns the stable operation-class label.
func (o OperationClass) String() string {
	switch o {
	case OpRead:
		return "read"
	case OpWrite:
		return "write"
	case OpAdmin:
		return "admin"
	case OpDestructive:
		return "destructive"
	default:
		return "unset"
	}
}

// RiskClass is the coarse risk of an operation. Only OpRead is low risk; every
// mutating class is high risk and fails closed on any provider/cache uncertainty.
type RiskClass uint8

const (
	// RiskLow — cached low-risk fallback MAY apply when the profile explicitly
	// enables it and the entry is still valid/fresh.
	RiskLow RiskClass = iota
	// RiskHigh — always fail closed; no stale fallback.
	RiskHigh
)

// String returns the stable risk label.
func (r RiskClass) String() string {
	if r == RiskLow {
		return "low"
	}
	return "high"
}

// Risk returns the risk class of an operation. Only reads are low risk.
func (o OperationClass) Risk() RiskClass {
	if o == OpRead {
		return RiskLow
	}
	return RiskHigh
}

// CeilingPower is the least-privilege power ceiling implied by an operation class:
// a read plan may carry at most read-only power, a write plan at most write power,
// and so on. The plan's effective ceiling is min(profile ceiling, this).
func (o OperationClass) CeilingPower() CredentialPower {
	switch o {
	case OpRead:
		return PowerReadOnly
	case OpWrite:
		return PowerWrite
	case OpAdmin:
		return PowerAdmin
	case OpDestructive:
		return PowerDestructive
	default:
		return PowerUnset
	}
}

// MinPower returns the lower of two powers (used to compute a plan's least-privilege
// power ceiling from the profile ceiling and the operation ceiling).
func MinPower(a, b CredentialPower) CredentialPower {
	if a < b {
		return a
	}
	return b
}
