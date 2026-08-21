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
	return filepath.Join(pkgSourceDir(), "static", "index.html")
}

// pkgSourceDir returns the ABSOLUTE path to this package's source directory,
// anchored via runtime.Caller — NOT the process working directory. Test file/asset
// reads (static/index.html, the source-scanning parity walls) must resolve through
// here so a CONCURRENT test's os.Chdir cannot flake them (the CWD-race class the
// determinism/-race gates catch). Falls back to "." only if runtime.Caller fails.
func pkgSourceDir() string {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(self)
}
