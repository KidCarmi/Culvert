//go:build !unix

package fileutil

import "os"

// preserveOwner is a no-op where file ownership is not a uid/gid pair.
func preserveOwner(*os.File, os.FileInfo) {}
