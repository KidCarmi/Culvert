//go:build linux

package appliancehost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
)

// Netplan is restricted to one managed file. Run is a bounded fixed-command adapter.
type Netplan struct {
	Target      string
	Directories []string
	Run         func(context.Context) error
}

func (n Netplan) inputs() ([]string, error) {
	var paths []string
	for _, dir := range n.Directories {
		matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		paths = append(paths, matches...)
		if len(paths) > 16 {
			return nil, errors.New("too many Netplan files for guided management")
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func (n Netplan) Read() (File, string, error) {
	paths, err := n.inputs()
	if err != nil {
		return File{}, "", err
	}
	original := File{}
	h := sha256.New()
	for _, path := range paths {
		data, mode, err := readRegular(path, 65536, false)
		if err != nil {
			return File{}, "", err
		}
		if path == n.Target {
			original = File{data, true, uint32(mode)}
			continue
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00%d\x00", path, mode, len(data))
		_, _ = h.Write(data)
	}
	return original, hex.EncodeToString(h.Sum(nil)), nil
}

// Preflight runs before queuing. Existing privileged external writers cannot be
// serialized by our lock; a digest fence detects their persistent file changes.
func (n Netplan) Preflight(iface string) error {
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	paths, err := n.inputs()
	if err != nil {
		return err
	}
	baseCount := 0
	for _, path := range paths {
		data, _, err := readRegular(path, 65536, false)
		if err != nil {
			return err
		}
		base := path != n.Target
		if err := ValidateInput(data, iface, base); err != nil {
			return err
		}
		if err := ValidateHardware(data, iface, device.HardwareAddr.String()); err != nil {
			return err
		}
		if base {
			baseCount++
		}
	}
	if baseCount != 1 {
		return errors.New("guided network changes require one unambiguous DHCP base file")
	}
	return nil
}

func (n Netplan) Write(file File) error {
	if err := secureDirectory(filepath.Dir(n.Target), 0o755); err != nil {
		return err
	}
	if file.Exists {
		return atomicFile(n.Target, file.Data, os.FileMode(file.Mode))
	}
	if err := os.Remove(n.Target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(n.Target))
}

// Apply delegates to the fixed, bounded netplan generate/apply adapter.
func (n Netplan) Apply(ctx context.Context) error { return n.Run(ctx) }
