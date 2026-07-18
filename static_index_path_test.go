package main

import (
	"path/filepath"
	"runtime"
)

// staticIndexHTMLPath returns the ABSOLUTE path to static/index.html, anchored to
// this package's source directory via runtime.Caller — NOT the process working
// directory. Many tests read the SPA file to assert on its content; a plain
// os.ReadFile("static/index.html") is CWD-RELATIVE, so it intermittently reads the
// wrong file when a CONCURRENT test changes the working directory (os.Chdir to a
// scratch dir that carries its own static/index.html stub). The determinism and
// -race gates catch that as a flaky "static/index.html missing …" failure even
// though the real file is intact. Anchoring the read to the source dir makes it
// CWD-independent and deterministic.
func staticIndexHTMLPath() string {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("static", "index.html") // fall back to the CWD-relative path
	}
	return filepath.Join(filepath.Dir(self), "static", "index.html")
}
