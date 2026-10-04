//go:build !linux

package applianceconsole

import "os"

// Used by portable domain tests; the appliance runtime is Linux only.
func openPublicFile(path string) (*os.File, error) { return os.Open(path) }
