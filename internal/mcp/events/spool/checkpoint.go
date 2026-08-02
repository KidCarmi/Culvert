package spool

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// The checkpoint is the crash-consistent committed-position metadata for one
// partition. It is written via the Backend's AtomicReplace (temp + fsync +
// rename + dir-sync), so a crash during a checkpoint update leaves either the old
// or the new file intact — never a torn one. A record is COMMITTED if and only if
// the checkpoint's per-segment CommittedLen covers it; anything on disk beyond
// CommittedLen is an uncommitted tail that recovery truncates. The checkpoint
// carries a self-digest so metadata corruption is DETECTABLE and never silently
// replaced with a fresh "normal" file (EVENT-MODEL.md §4b.7 / MCP-OPS-005).

const checkpointVersion = 1

var errCheckpointCorrupt = errors.New("spool: checkpoint integrity check failed")

// segMeta is the durable metadata for one segment.
type segMeta struct {
	ID           uint32 `json:"id"`
	FirstSeq     uint64 `json:"first_seq"`
	LastSeq      uint64 `json:"last_seq"`
	CommittedLen int64  `json:"committed_len"`
	Records      int    `json:"records"`
	Sealed       bool   `json:"sealed"`
	Exported     bool   `json:"exported"`
	CreatedNano  int64  `json:"created_nano"`
}

// checkpoint is one partition's durable committed state.
type checkpoint struct {
	Version      int       `json:"version"`
	Partition    uint8     `json:"partition"`
	NextSeq      uint64    `json:"next_seq"`
	NextSegID    uint32    `json:"next_seg_id"`
	LastChainHex string    `json:"last_chain_hex"`
	TotalBytes   int64     `json:"total_bytes"`
	Segments     []segMeta `json:"segments"`
	Digest       string    `json:"digest"`
}

// encode renders the checkpoint with a fresh self-digest.
func (c checkpoint) encode() ([]byte, error) {
	c.Digest = ""
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	c.Digest = hex.EncodeToString(sum[:])
	return json.Marshal(c)
}

// decodeCheckpoint parses and integrity-checks a checkpoint. A digest mismatch or
// unknown version is errCheckpointCorrupt (fail toward the narrow critical state).
func decodeCheckpoint(b []byte) (checkpoint, error) {
	var c checkpoint
	if err := json.Unmarshal(b, &c); err != nil {
		return checkpoint{}, errCheckpointCorrupt
	}
	if c.Version != checkpointVersion {
		return checkpoint{}, errCheckpointCorrupt
	}
	want := c.Digest
	c.Digest = ""
	body, err := json.Marshal(c)
	if err != nil {
		return checkpoint{}, errCheckpointCorrupt
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != want {
		return checkpoint{}, errCheckpointCorrupt
	}
	c.Digest = want
	return c, nil
}
