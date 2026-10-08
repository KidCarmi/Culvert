// pclnfuncs counts the Go functions in a binary whose names start with PREFIX
// (a package path plus ".", e.g. "golang.org/x/crypto/ssh.").
// It reads .gopclntab, which a stripped (-s -w) binary still carries, so it
// answers "is this package linked?" on the exact shipped bytes where `go tool
// nm` and `go tool objdump` see nothing.
//
//	pclnfuncs BINARY PREFIX...      →  one "PREFIX<TAB>COUNT<TAB>TOTAL" line each
//	pclnfuncs BINARY -inventory     →  "PACKAGE<TAB>COUNT" for every package with
//	                                   at least one function, sorted by package
package main

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: pclnfuncs BINARY PREFIX...")
		os.Exit(2)
	}
	f, err := elf.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pcln, text := f.Section(".gopclntab"), f.Section(".text")
	if pcln == nil || text == nil {
		fmt.Fprintln(os.Stderr, "no .gopclntab/.text: not a Go ELF binary")
		os.Exit(1)
	}
	data, err := pcln.Data()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	t, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if os.Args[2] == "-inventory" {
		inv := map[string]int{}
		for i := range t.Funcs {
			inv[pkgOf(t.Funcs[i].Name)]++
		}
		pkgs := make([]string, 0, len(inv))
		for p := range inv {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		for _, p := range pkgs {
			fmt.Printf("%s\t%d\n", p, inv[p])
		}
		return
	}
	for _, p := range os.Args[2:] {
		n := 0
		for i := range t.Funcs {
			if strings.HasPrefix(t.Funcs[i].Name, p) {
				n++
			}
		}
		fmt.Printf("%s\t%d\t%d\n", p, n, len(t.Funcs))
	}
}

// pkgOf returns the import path of a Go function symbol name: everything up to
// the first "." after the last "/" ("golang.org/x/crypto/ssh.(*Client).Dial"
// → "golang.org/x/crypto/ssh"), ignoring generic type arguments. Names without
// a package dot are returned whole.
func pkgOf(name string) string {
	if b := strings.IndexByte(name, '['); b >= 0 { // generic type arguments carry paths too
		name = name[:b]
	}
	slash := strings.LastIndex(name, "/")
	if dot := strings.Index(name[slash+1:], "."); dot >= 0 {
		return name[:slash+1+dot]
	}
	return name
}
