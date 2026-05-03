package runner

import "os"

// syscallGetenv is the production env source. Wrapped so tests can
// override `lookupEnv` if needed without monkey-patching os.Getenv.
func syscallGetenv(name string) (string, bool) {
	return os.LookupEnv(name)
}
