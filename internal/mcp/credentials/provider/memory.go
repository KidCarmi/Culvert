package provider

import (
	"context"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
)

// InMemoryProvider is a deterministic, in-memory test/reference provider. It holds
// template secret fields and returns a FRESH sealed handle on every Fetch/Rotate
// (a Sealed is single-use). It is used by the broker's tests, fuzz targets and
// benchmarks. It performs no network I/O and no randomness. Configure it via the
// exported setters; it is safe for concurrent use.
type InMemoryProvider struct {
	id   profile.ProviderID
	caps Capabilities

	mu           sync.Mutex
	kind         profile.CredentialKind
	fields       map[FieldName][]byte // template; cloned per Fetch
	lease        Lease
	fetchErr     error
	rotateFields map[FieldName][]byte
	rotateLease  Lease
	rotateErr    error
	revokeErr    error
	fetchCalls   int
	rotateCalls  int
	revokeCalls  int
}

// NewInMemory returns a provider with the given id and capabilities.
func NewInMemory(id profile.ProviderID, caps Capabilities) *InMemoryProvider {
	return &InMemoryProvider{id: id, caps: caps}
}

// SetMaterial configures the fetch material (kind, fields, lease). The field bytes
// are copied.
func (p *InMemoryProvider) SetMaterial(kind profile.CredentialKind, fields map[FieldName][]byte, lease Lease) *InMemoryProvider {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.kind = kind
	p.fields = cloneFields(fields)
	p.lease = lease
	return p
}

// SetRotateMaterial configures the successor material returned by Rotate.
func (p *InMemoryProvider) SetRotateMaterial(fields map[FieldName][]byte, lease Lease) *InMemoryProvider {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rotateFields = cloneFields(fields)
	p.rotateLease = lease
	return p
}

// SetFetchError makes Fetch return err (verbatim — used to test broker sanitization
// of untrusted, possibly canary-bearing provider errors).
func (p *InMemoryProvider) SetFetchError(err error) *InMemoryProvider {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetchErr = err
	return p
}

// SetRotateError makes Rotate return err.
func (p *InMemoryProvider) SetRotateError(err error) *InMemoryProvider {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rotateErr = err
	return p
}

// SetRevokeError makes Revoke return err.
func (p *InMemoryProvider) SetRevokeError(err error) *InMemoryProvider {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revokeErr = err
	return p
}

// Calls returns the fetch/rotate/revoke call counts (for asserting a gate failure
// left the provider untouched).
func (p *InMemoryProvider) Calls() (fetch, rotate, revoke int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fetchCalls, p.rotateCalls, p.revokeCalls
}

// ID returns the provider id.
func (p *InMemoryProvider) ID() profile.ProviderID { return p.id }

// Capabilities returns the declared capabilities.
func (p *InMemoryProvider) Capabilities() Capabilities { return p.caps }

// Fetch returns a fresh sealed handle from the configured template, or the
// configured error. It honors context cancellation (fail as retryable-unavailable).
func (p *InMemoryProvider) Fetch(ctx context.Context, _ Request) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, NewError(reasonUnavailable, true)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetchCalls++
	if p.fetchErr != nil {
		return nil, p.fetchErr
	}
	return &Result{Handle: SealFields(fieldsFromMap(p.fields)), Kind: p.kind, Lease: p.lease}, nil
}

// Rotate returns a fresh successor handle, or unsupported/error.
func (p *InMemoryProvider) Rotate(ctx context.Context, _ Request) (*Result, error) {
	if !p.caps.CanRotate {
		return nil, NewError(reasonUnsupported, false)
	}
	if err := ctx.Err(); err != nil {
		return nil, NewError(reasonUnavailable, true)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rotateCalls++
	if p.rotateErr != nil {
		return nil, p.rotateErr
	}
	return &Result{Handle: SealFields(fieldsFromMap(p.rotateFields)), Kind: p.kind, Lease: p.rotateLease}, nil
}

// Revoke revokes a version, or returns unsupported/error.
func (p *InMemoryProvider) Revoke(_ context.Context, _ RevokeRequest) error {
	if !p.caps.CanRevoke {
		return NewError(reasonUnsupported, false)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revokeCalls++
	return p.revokeErr
}

// Inspect returns the configured lease metadata, or unsupported.
func (p *InMemoryProvider) Inspect(_ context.Context, _ Request) (Lease, error) {
	if !p.caps.CanInspect {
		return Lease{}, NewError(reasonUnsupported, false)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lease, nil
}

func cloneFields(m map[FieldName][]byte) map[FieldName][]byte {
	if m == nil {
		return nil
	}
	out := make(map[FieldName][]byte, len(m))
	for k, v := range m {
		b := make([]byte, len(v))
		copy(b, v)
		out[k] = b
	}
	return out
}

// fieldsFromMap materializes a fresh []Field (with copied values) from a template
// map, so SealFields can take ownership and zeroize without touching the template.
func fieldsFromMap(m map[FieldName][]byte) []Field {
	out := make([]Field, 0, len(m))
	for k, v := range m {
		b := make([]byte, len(v))
		copy(b, v)
		out = append(out, Field{Name: k, Value: b})
	}
	return out
}
