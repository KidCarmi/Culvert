package server

import "io"

// copyStream isolates io.Copy so the server file's import list stays
// minimal and so tests can override it later if needed.
func copyStream(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
