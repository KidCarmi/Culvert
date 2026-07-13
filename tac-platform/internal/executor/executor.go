// Package executor is the ONLY component that mutates infrastructure. All provider
// mutations flow through Mutate; nothing else in the system calls a provider Adapter
// mutation method. It never replans: it applies exactly the given (already approved)
// plan and returns the provider receipt.
package executor

import (
	"context"

	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/provider"
)

type Executor struct {
	Prov provider.Adapter
	Name string
}

func New(p provider.Adapter, name string) *Executor { return &Executor{Prov: p, Name: name} }

// Mutate applies the plan's intended change via the provider. Same code path for
// L2 restart and L3 deploy — the single mutation spine.
func (e *Executor) Mutate(ctx context.Context, op domain.Operation, p domain.Plan) (provider.Receipt, error) {
	if op.Kind == domain.KindDeploy {
		return e.Prov.Deploy(ctx, op.Scope, op.WorkerID, p.TargetImageDigest)
	}
	return e.Prov.Restart(ctx, op.Scope, op.WorkerID)
}

// MutateReverse applies a reverse-deploy to a target digest (rollback path).
func (e *Executor) MutateReverse(ctx context.Context, op domain.Operation, targetDigest string) (provider.Receipt, error) {
	return e.Prov.Deploy(ctx, op.Scope, op.WorkerID, targetDigest)
}

func (e *Executor) Inspect(ctx context.Context, op domain.Operation) (provider.Truth, error) {
	return e.Prov.Inspect(ctx, op.Scope, op.WorkerID)
}
