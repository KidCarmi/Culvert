//go:build !unix

package fileutil

import "os"

// holdInode makes no duplicate here: a file open across a rename can block
// the rename on Windows, so WriteResult.Landed is the last fstat before it.
func holdInode(*os.File) *os.File { return nil }
