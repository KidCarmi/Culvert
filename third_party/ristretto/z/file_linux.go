/*
 * SPDX-FileCopyrightText: © Hypermode Inc. <hello@hypermode.com>
 * SPDX-License-Identifier: Apache-2.0
 */

package z

import (
	"fmt"
)

// Truncate would truncate the mmapped file to the given size. On Linux, we truncate
// the underlying file and then call mremap, but on other systems, we unmap first,
// then truncate, then re-map.
func (m *MmapFile) Truncate(maxSz int64) error {
	if err := m.Sync(); err != nil {
		return fmt.Errorf("while sync file: %s, error: %v\n", m.Fd.Name(), err)
	}
	oldSz := int64(len(m.Data))
	if err := m.Fd.Truncate(maxSz); err != nil {
		return fmt.Errorf("while truncate file: %s, error: %v\n", m.Fd.Name(), err)
	}
	// CULVERT PATCH (F-DISK-1, CULVERT-PATCH.md): growing the mapping reserves
	// the new range before it can be stored into; on a shortage the file goes
	// back to its old size and the existing mapping is left as it was.
	if maxSz > oldSz {
		if err := preallocate(m.Fd, oldSz, maxSz-oldSz); err != nil {
			_ = m.Fd.Truncate(oldSz)
			return fmt.Errorf("while reserving %d bytes for %s: %w", maxSz-oldSz, m.Fd.Name(), err)
		}
	}

	var err error
	m.Data, err = mremap(m.Data, int(maxSz)) // Mmap up to max size.
	return err
}
