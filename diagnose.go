package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Diagnostic command framework (M3). Product-level, typed operations — NEVER a
// shell (DIAGNOSTIC-COMMAND-FRAMEWORK §Absolute rule). No verb takes free-form OS
// input, runs sh -c, or reaches a host binary; the verb set is a FIXED in-binary
// registry, so allowlisting is structural. Every verb returns a typed, versioned
// JSON contract (schema_version) that the API, CLI, and GUI all render identically.
//
// This file ships the first verb — `diagnose storage` — a purely LOCAL, read-only
// health probe (writability + free space + data-dir stat). Network verbs
// (dns/tls/upstream), which require SSRF guards, and cluster fan-out are deferred.

// diagnoseSchemaVersion is bumped when any diagnose output contract changes shape.
const diagnoseSchemaVersion = 1

// storageMinFreeWarnBytes is the free-space floor below which storage is flagged
// (not fatal — the bundle path has its own preflight; this is an advisory signal).
const storageMinFreeWarnBytes = 256 << 20 // 256 MiB

type storageCheck struct {
	Name   string `json:"name"`
	Path   string `json:"path"` // server-side path (INTERNAL; a live admin read, never bundled)
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type storageDiagnosis struct {
	SchemaVersion int            `json:"schema_version"`
	GeneratedAt   string         `json:"generated_at"`
	OK            bool           `json:"ok"` // all checks passed
	DataDir       string         `json:"data_dir"`
	FreeBytes     uint64         `json:"free_bytes"`
	TotalBytes    uint64         `json:"total_bytes"`
	UsedPct       float64        `json:"used_pct"`
	Checks        []storageCheck `json:"checks"`
}

// probeWritable creates and removes a uniquely-named temp file in an EXISTING dir
// to prove the process can actually write there — a stat/permission bit can lie
// (read-only mount, full disk, SELinux). The probe file is always removed
// (create+remove is the whole test); a failure to create is the diagnostic signal.
// It deliberately does NOT create dir: the diagnostic must not mutate storage or
// pre-create the support tree (which the bundle path owns, at 0700). Callers stat
// first and only probe dirs that already exist.
func probeWritable(dir string) (ok bool, detail string) {
	f, err := os.CreateTemp(dir, ".diag-write-*")
	if err != nil {
		return false, "create: " + err.Error()
	}
	name := f.Name()
	_, wErr := f.Write([]byte("culvert-storage-probe"))
	cErr := f.Close()
	rmErr := os.Remove(name)
	switch {
	case wErr != nil:
		return false, "write: " + wErr.Error()
	case cErr != nil:
		return false, "close: " + cErr.Error()
	case rmErr != nil:
		return false, "cleanup: " + rmErr.Error()
	}
	return true, ""
}

// diagnoseStorage runs the local storage probe. now is injected for deterministic
// timestamps in tests.
func diagnoseStorage(now time.Time) storageDiagnosis {
	d := storageDiagnosis{
		SchemaVersion: diagnoseSchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		DataDir:       dataDir,
	}

	if usedPct, free, total, err := diskUsage(dataDir); err == nil {
		d.FreeBytes, d.TotalBytes, d.UsedPct = free, total, usedPct
		free64 := free
		d.Checks = append(d.Checks, storageCheck{
			Name: "free_space", Path: dataDir, OK: free64 >= storageMinFreeWarnBytes,
			Detail: byteCountDetail(free64, storageMinFreeWarnBytes),
		})
	} else {
		d.Checks = append(d.Checks, storageCheck{
			Name: "free_space", Path: dataDir, OK: false, Detail: "statfs: " + err.Error(),
		})
	}

	// Writability of the data dir and the two critical support subdirs. A subdir
	// that does not yet exist is NOT created here — the diagnostic must not mutate
	// storage or pre-seed the support tree (the bundle path owns that, at 0700). An
	// absent subdir is fine as long as its parent is writable, which the
	// data_dir_writable check establishes.
	for _, c := range []struct{ name, path string }{
		{"data_dir_writable", dataDir},
		{"support_dir_writable", filepath.Join(dataDir, "support")},
		{"bundles_dir_writable", supportBundlesDir()},
	} {
		fi, err := os.Stat(c.path)
		switch {
		case err == nil && fi.IsDir():
			ok, detail := probeWritable(c.path)
			d.Checks = append(d.Checks, storageCheck{Name: c.name, Path: c.path, OK: ok, Detail: detail})
		case err == nil: // exists but is not a directory
			d.Checks = append(d.Checks, storageCheck{Name: c.name, Path: c.path, OK: false, Detail: "not a directory"})
		case os.IsNotExist(err):
			d.Checks = append(d.Checks, storageCheck{Name: c.name, Path: c.path, OK: true, Detail: "absent (created on first bundle)"})
		default:
			d.Checks = append(d.Checks, storageCheck{Name: c.name, Path: c.path, OK: false, Detail: "stat: " + err.Error()})
		}
	}

	d.OK = true
	for i := range d.Checks {
		if !d.Checks[i].OK {
			d.OK = false
			break
		}
	}
	return d
}

// byteCountDetail renders a compact "have X, want ≥ Y MiB" advisory for the check.
func byteCountDetail(have, want uint64) string {
	return "free=" + mib(have) + "MiB floor=" + mib(want) + "MiB"
}

func mib(n uint64) string { return strconv.FormatUint(n/(1<<20), 10) }

// apiDiagnoseStorage runs the local storage diagnosis (POST, operator). It is
// read-only except for a create+remove writability probe, and touches no network.
func apiDiagnoseStorage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	d := diagnoseStorage(time.Now())
	auditEvent(r, "diagnose.storage", "storage", boolResult(d.OK))
	jsonOK(w, d)
}

func boolResult(ok bool) string {
	if ok {
		return "ok"
	}
	return "degraded"
}

// registerDiagnoseRoutes wires the diagnose verb surface.
func registerDiagnoseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/diagnose/storage", apiDiagnoseStorage)
}
