package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// blockKey identifies one coverage block: source path + block coordinates.
type blockKey struct {
	File                                 string
	StartLine, StartCol, EndLine, EndCol int
}

type blockVal struct {
	NumStmt int
	Count   int64
}

// Profile is a parsed Go coverage profile (the text format -coverprofile
// writes).
type Profile struct {
	Mode   string
	Blocks map[blockKey]*blockVal
}

// parseProfile reads a text coverage profile. Unlike a line concatenation,
// every block is decoded, so a truncated line, a missing mode header or two
// different statement counts for the same block are errors, not silently
// different arithmetic.
func parseProfile(r io.Reader) (*Profile, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read profile: %w", err)
		}
		return nil, errors.New("empty profile — no mode line")
	}
	mode, ok := strings.CutPrefix(sc.Text(), "mode: ")
	if !ok || (mode != "set" && mode != "count" && mode != "atomic") {
		return nil, fmt.Errorf("first line %q is not a coverage mode line", sc.Text())
	}
	p := &Profile{Mode: mode, Blocks: map[blockKey]*blockVal{}}
	for line := 2; sc.Scan(); line++ {
		txt := sc.Text()
		if txt == "" {
			continue
		}
		k, v, err := parseBlock(txt)
		if err != nil {
			return nil, fmt.Errorf("profile line %d: %w", line, err)
		}
		if err := p.add(k, v); err != nil {
			return nil, fmt.Errorf("profile line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	return p, nil
}

// parseBlock decodes "file:sl.sc,el.ec numStmt count".
func parseBlock(s string) (blockKey, blockVal, error) {
	fields := strings.Fields(s)
	if len(fields) != 3 {
		return blockKey{}, blockVal{}, fmt.Errorf("malformed block %q", s)
	}
	colon := strings.LastIndexByte(fields[0], ':')
	if colon <= 0 {
		return blockKey{}, blockVal{}, fmt.Errorf("malformed block position %q", fields[0])
	}
	var k blockKey
	k.File = fields[0][:colon]
	var err error
	n, err := fmt.Sscanf(fields[0][colon+1:], "%d.%d,%d.%d", &k.StartLine, &k.StartCol, &k.EndLine, &k.EndCol)
	if err != nil || n != 4 {
		return blockKey{}, blockVal{}, fmt.Errorf("malformed block coordinates %q", fields[0])
	}
	var v blockVal
	if v.NumStmt, err = strconv.Atoi(fields[1]); err != nil || v.NumStmt < 0 {
		return blockKey{}, blockVal{}, fmt.Errorf("malformed statement count %q", fields[1])
	}
	if v.Count, err = strconv.ParseInt(fields[2], 10, 64); err != nil || v.Count < 0 {
		return blockKey{}, blockVal{}, fmt.Errorf("malformed hit count %q", fields[2])
	}
	return k, v, nil
}

// add combines one block into p. A block already present must agree on its
// statement count (a disagreement means two different builds of the source);
// counters combine by the mode's rule — set ORs, count/atomic SUM — so a block
// covered by any process is covered, and a zero-covered block is still counted
// ONCE in the denominator.
func (p *Profile) add(k blockKey, v blockVal) error {
	cur, ok := p.Blocks[k]
	if !ok {
		c := v
		p.Blocks[k] = &c
		return nil
	}
	if cur.NumStmt != v.NumStmt {
		return fmt.Errorf("block %s: %d statements vs %d — profiles from different builds", k, cur.NumStmt, v.NumStmt)
	}
	if p.Mode == "set" {
		if v.Count > 0 {
			cur.Count = 1
		}
		return nil
	}
	cur.Count += v.Count
	return nil
}

// mergeProfile folds src into dst; modes must match.
func mergeProfile(dst, src *Profile) error {
	if dst.Mode != src.Mode {
		return fmt.Errorf("coverage mode %q cannot merge with %q", src.Mode, dst.Mode)
	}
	for _, k := range src.sortedKeys() {
		if err := dst.add(k, *src.Blocks[k]); err != nil {
			return err
		}
	}
	return nil
}

func (k blockKey) String() string {
	return fmt.Sprintf("%s:%d.%d,%d.%d", k.File, k.StartLine, k.StartCol, k.EndLine, k.EndCol)
}

func (p *Profile) sortedKeys() []blockKey {
	keys := make([]blockKey, 0, len(p.Blocks))
	for k := range p.Blocks {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		if a.StartCol != b.StartCol {
			return a.StartCol < b.StartCol
		}
		if a.EndLine != b.EndLine {
			return a.EndLine < b.EndLine
		}
		return a.EndCol < b.EndCol
	})
	return keys
}

// write emits p in the text format, blocks in a stable order.
func (p *Profile) write(w io.Writer) error {
	// bufio.Writer errors are sticky: the first write failure is returned by
	// Flush, so the per-line results carry nothing Flush does not.
	bw := bufio.NewWriter(w)
	_, _ = fmt.Fprintf(bw, "mode: %s\n", p.Mode)
	for _, k := range p.sortedKeys() {
		v := p.Blocks[k]
		_, _ = fmt.Fprintf(bw, "%s %d %d\n", k, v.NumStmt, v.Count)
	}
	return bw.Flush()
}

// sameUniverse reports the first difference between the block universes of a
// and b (keys + statement counts), or "" when they match.
func sameUniverse(a, b *Profile) string {
	for _, k := range a.sortedKeys() {
		bv, ok := b.Blocks[k]
		if !ok {
			return fmt.Sprintf("block %s missing from the second profile", k)
		}
		if bv.NumStmt != a.Blocks[k].NumStmt {
			return fmt.Sprintf("block %s: %d vs %d statements", k, a.Blocks[k].NumStmt, bv.NumStmt)
		}
	}
	if len(b.Blocks) != len(a.Blocks) {
		for _, k := range b.sortedKeys() {
			if _, ok := a.Blocks[k]; !ok {
				return fmt.Sprintf("block %s missing from the first profile", k)
			}
		}
	}
	return ""
}

// coverageStats is statement-weighted coverage, the way `go tool cover`
// computes its total line.
type coverageStats struct {
	Blocks            int     `json:"blocks"`
	CoveredBlocks     int     `json:"coveredBlocks"`
	Statements        int     `json:"statements"`
	CoveredStatements int     `json:"coveredStatements"`
	Percent           float64 `json:"percent"`
}

func (p *Profile) stats(filter func(file string) bool) coverageStats {
	var s coverageStats
	for k, v := range p.Blocks {
		if filter != nil && !filter(k.File) {
			continue
		}
		s.Blocks++
		s.Statements += v.NumStmt
		if v.Count > 0 {
			s.CoveredBlocks++
			s.CoveredStatements += v.NumStmt
		}
	}
	if s.Statements > 0 {
		s.Percent = float64(int(float64(s.CoveredStatements)/float64(s.Statements)*1000+0.5)) / 10
	}
	return s
}

func readProfile(path string) (*Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open profile: %w", err)
	}
	defer f.Close()
	p, err := parseProfile(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

func writeProfile(path string, p *Profile) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := p.write(f); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// rootFile reports whether a profile path belongs to the package pkg itself
// (not a subpackage): "<pkg>/<file>.go" with no further separator.
func rootFile(pkg, file string) bool {
	rest, ok := strings.CutPrefix(file, pkg+"/")
	return ok && !strings.Contains(rest, "/")
}
