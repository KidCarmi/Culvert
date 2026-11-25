package ops

import "context"

type opIDKey struct{}

// WithOpID returns a context that names the operation the work is done for.
// Run sets it for every stage, so a docker command run by a stage can be
// attributed to the operation's own journal record.
func WithOpID(ctx context.Context, opID string) context.Context {
	return context.WithValue(ctx, opIDKey{}, opID)
}

// OpIDFrom returns the operation named by WithOpID, or "".
func OpIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(opIDKey{}).(string)
	return id
}
