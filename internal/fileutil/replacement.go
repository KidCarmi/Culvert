package fileutil

import "errors"

// ErrReplacementBlocked means rename(2) would refuse to replace the target
// itself — it is immutable or append-only, a mount point, or in an immutable
// or append-only directory — so no save can land there. Returned by
// ReplacementBlocked, which detects it only on Linux.
var ErrReplacementBlocked = errors.New("the target cannot be replaced by any save")
