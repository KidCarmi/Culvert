package ops

import "context"

type opIDKey struct{}

// WithOpID returns a context that names the operation the work is done for.
// Run sets it for every stage; the startup reconcile sets it to the op_id of
// the record it is acting on, because that is the operation its docker
// commands complete.
func WithOpID(ctx context.Context, opID string) context.Context {
	return context.WithValue(ctx, opIDKey{}, opID)
}

// OpIDFrom returns the operation named by WithOpID, or "".
func OpIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(opIDKey{}).(string)
	return id
}
