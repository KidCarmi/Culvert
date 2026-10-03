package server

import (
	"context"
	"fmt"
)

// spaceHeadroomBytes is added to the pull's own estimate: container state,
// json logs and the proxy's /data writes share the disk with the image
// store, and a full root disk took the RUNNING proxy down with it (Deep
// gate runs on 3e5384a…b0b7c9c: the predecessor crashed and Docker could
// not even restart it, because writing container state needed space).
const spaceHeadroomBytes = 256 << 20

// spaceNeeded is the conservative requirement for pulling an image whose
// registry layers total compressed bytes: the compressed content lands in
// the content store and is unpacked into snapshots (~2x for gzip layers).
// Already-present layers are not credited — refusing on a tight disk is a
// no-op, filling it is not.
func spaceNeeded(compressed int64) uint64 {
	return uint64(3*compressed) + spaceHeadroomBytes //nolint:gosec // compressed is a non-negative registry size
}

// preflightSpace refuses an upgrade before the pull when the Docker data
// root cannot hold the target. Best-effort in the other direction: an
// unknown target size or an unreadable free-space figure proceeds as
// before, saying so in the op log.
func (s *Server) preflightSpace(acc *upgradeApplyAccumulator) stageRun {
	return func(_ context.Context) ([]byte, []byte, error) {
		if acc.targetCompressed <= 0 {
			return []byte("preflight_space: target size unknown; proceeding"), nil, nil
		}
		free := s.opts.FreeBytes
		if free == nil {
			free = statfsFreeBytes
		}
		root := s.opts.Cfg.DockerRoot
		avail, err := free(root)
		if err != nil {
			return []byte("preflight_space: free space on " + root + " unknown (" + err.Error() + "); proceeding"), nil, nil
		}
		need := spaceNeeded(acc.targetCompressed)
		if avail < need {
			msg := fmt.Sprintf("preflight_space: REFUSED — %s has %d MiB free; pulling the target (%d MiB compressed) needs about %d MiB. Nothing was pulled or changed. Free space (e.g. `docker image prune`, or grow the disk), then retry",
				root, avail>>20, acc.targetCompressed>>20, need>>20)
			return []byte(msg), nil, fmt.Errorf("insufficient_space: %d MiB free, %d MiB needed on %s", avail>>20, need>>20, root)
		}
		return []byte(fmt.Sprintf("preflight_space: %d MiB free on %s, about %d MiB needed", avail>>20, root, need>>20)), nil, nil
	}
}
