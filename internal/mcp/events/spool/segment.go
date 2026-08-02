package spool

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// The on-disk segment format is versioned, append-only, and self-describing. A
// segment file begins with a fixed segment header (segMagic … keyID) and is
// followed by a sequence of length-framed, authenticated records. Every record
// header field is authenticated as GCM additional-authenticated-data (AAD), so a
// mutated partition byte, sequence number, prior-chain digest or length is
// detected as a decrypt failure — not a silently accepted record. A bounded
// per-partition hash chain (priorChain) links records so a removed, reordered or
// inserted record inside the retained committed sequence is detectable
// (EVENT-MODEL.md §4b integrity rule).

const (
	segFormatVersion = 1
	recFormatVersion = 1
	segAlgAES256GCM  = 1
)

var (
	segMagic = [4]byte{'M', 'C', 'P', 'S'} // segment file magic
	recMagic = [4]byte{'M', 'C', 'P', 'R'} // record frame magic
)

const (
	// segHeaderLen is the fixed segment-header size for keyIDLen=8.
	segHeaderLen = 4 + 1 + 1 + 1 + 4 + 8 + 8 + 1 + keyIDLen
	// recFixedPrefixLen is the record-header size before the variable ciphertext:
	// magic(4)+ver(1)+partition(1)+seq(8)+priorChain(32)+nonceLen(1)+nonce(12)+ctLen(4).
	recFixedPrefixLen = 4 + 1 + 1 + 8 + 32 + 1 + spoolNonceLen + 4
)

var (
	errBadSegHeader = errors.New("spool: malformed segment header")
	errBadRecord    = errors.New("spool: malformed record frame")
	errChainBreak   = errors.New("spool: hash-chain break (reorder/removal/insertion)")
)

// segHeader is the parsed segment header.
type segHeader struct {
	partition   model.Partition
	capability  model.Capability
	segID       uint32
	firstSeq    uint64
	createdNano int64
	keyID       [keyIDLen]byte
}

// encodeSegHeader renders a segment header.
func encodeSegHeader(h segHeader) []byte {
	b := make([]byte, segHeaderLen)
	copy(b[0:4], segMagic[:])
	b[4] = segFormatVersion
	b[5] = byte(h.capability)
	b[6] = byte(h.partition)
	binary.BigEndian.PutUint32(b[7:11], h.segID)
	binary.BigEndian.PutUint64(b[11:19], h.firstSeq)
	binary.BigEndian.PutUint64(b[19:27], uint64(h.createdNano))
	b[27] = keyIDLen
	copy(b[28:28+keyIDLen], h.keyID[:])
	return b
}

// decodeSegHeader parses a segment header, rejecting a bad magic/version.
func decodeSegHeader(b []byte) (segHeader, error) {
	if len(b) < segHeaderLen {
		return segHeader{}, errBadSegHeader
	}
	if [4]byte{b[0], b[1], b[2], b[3]} != segMagic {
		return segHeader{}, errBadSegHeader
	}
	if b[4] != segFormatVersion {
		return segHeader{}, errBadSegHeader
	}
	if b[27] != keyIDLen {
		return segHeader{}, errBadSegHeader
	}
	h := segHeader{
		capability:  model.Capability(b[5]),
		partition:   model.Partition(b[6]),
		segID:       binary.BigEndian.Uint32(b[7:11]),
		firstSeq:    binary.BigEndian.Uint64(b[11:19]),
		createdNano: int64(binary.BigEndian.Uint64(b[19:27])),
	}
	copy(h.keyID[:], b[28:28+keyIDLen])
	if !h.partition.Valid() || !h.capability.Valid() {
		return segHeader{}, errBadSegHeader
	}
	return h, nil
}

// recordFrame holds a decoded record's header fields and payload boundaries.
type recordFrame struct {
	partition  model.Partition
	seq        uint64
	priorChain [32]byte
	nonce      []byte
	ciphertext []byte
	total      int // total on-disk bytes of this frame
}

// encodeRecord seals plaintext and renders a complete record frame. It returns
// the frame bytes and the NEW chain value (C_i) for the next record. The prior
// chain (C_{i-1}) is authenticated in the frame, so the linkage is tamper-evident.
func encodeRecord(cr *cryptor, part model.Partition, seq uint64, prior [32]byte, plaintext []byte) (frame []byte, next [32]byte, err error) {
	// Build the header prefix first (it is the AAD, minus the ciphertext which the
	// tag already covers).
	hdr := make([]byte, recFixedPrefixLen)
	copy(hdr[0:4], recMagic[:])
	hdr[4] = recFormatVersion
	hdr[5] = byte(part)
	binary.BigEndian.PutUint64(hdr[6:14], seq)
	copy(hdr[14:46], prior[:])
	hdr[46] = spoolNonceLen
	// nonce (47:47+12) and ctLen (59:63) are filled after sealing.
	nonce, ct, serr := cr.seal(hdr, plaintext) // AAD is the header prefix as built
	if serr != nil {
		return nil, next, serr
	}
	copy(hdr[47:47+spoolNonceLen], nonce)
	binary.BigEndian.PutUint32(hdr[47+spoolNonceLen:recFixedPrefixLen], uint32(len(ct)))
	// The AAD used at Seal time was the header BEFORE nonce/ctLen were written; to
	// make verification reproduce the exact AAD, re-seal is avoided by defining the
	// AAD as the header prefix with nonce+ctLen zeroed. See sealAAD/verifyAAD.
	frame = make([]byte, 0, recFixedPrefixLen+len(ct))
	frame = append(frame, hdr...)
	frame = append(frame, ct...)
	rd := sha256.Sum256(plaintext)
	next = chainNext(prior, rd)
	return frame, next, nil
}

// chainNext computes C_i = sha256(C_{i-1} || recordDigest_i).
func chainNext(prior [32]byte, recordDigest [32]byte) [32]byte {
	h := sha256.New()
	h.Write(prior[:])
	h.Write(recordDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// sealAAD returns the additional-authenticated-data for a record: the fixed
// header prefix with the nonce and ctLen fields zeroed, so the value is identical
// at seal and verify time regardless of the concrete nonce/length. The magic,
// version, partition, sequence and prior-chain are all covered.
func sealAAD(part model.Partition, seq uint64, prior [32]byte) []byte {
	aad := make([]byte, recFixedPrefixLen)
	copy(aad[0:4], recMagic[:])
	aad[4] = recFormatVersion
	aad[5] = byte(part)
	binary.BigEndian.PutUint64(aad[6:14], seq)
	copy(aad[14:46], prior[:])
	aad[46] = spoolNonceLen
	// nonce + ctLen left zero.
	return aad
}

// decodeRecordAt parses a record frame starting at buf[0], returning the frame
// and its total length. It does NOT decrypt; verifyRecord does.
func decodeRecordAt(buf []byte) (recordFrame, error) {
	if len(buf) < recFixedPrefixLen {
		return recordFrame{}, errBadRecord
	}
	if [4]byte{buf[0], buf[1], buf[2], buf[3]} != recMagic {
		return recordFrame{}, errBadRecord
	}
	if buf[4] != recFormatVersion {
		return recordFrame{}, errBadRecord
	}
	part := model.Partition(buf[5])
	seq := binary.BigEndian.Uint64(buf[6:14])
	var prior [32]byte
	copy(prior[:], buf[14:46])
	if buf[46] != spoolNonceLen {
		return recordFrame{}, errBadRecord
	}
	nonce := buf[47 : 47+spoolNonceLen]
	ctLen := binary.BigEndian.Uint32(buf[47+spoolNonceLen : recFixedPrefixLen])
	total := recFixedPrefixLen + int(ctLen)
	if ctLen == 0 || int(ctLen) > maxCiphertextLen || len(buf) < total {
		return recordFrame{}, errBadRecord
	}
	return recordFrame{
		partition:  part,
		seq:        seq,
		priorChain: prior,
		nonce:      nonce,
		ciphertext: buf[recFixedPrefixLen:total],
		total:      total,
	}, nil
}

// verifyRecord decrypts a decoded frame and returns the canonical event bytes and
// the next chain value. A decrypt failure (wrong key or any header/ciphertext
// tamper) is the opaque errDecryptOpaque.
func verifyRecord(cr *cryptor, f recordFrame) (plaintext []byte, next [32]byte, err error) {
	aad := sealAAD(f.partition, f.seq, f.priorChain)
	pt, oerr := cr.open(aad, f.nonce, f.ciphertext)
	if oerr != nil {
		return nil, next, oerr
	}
	rd := sha256.Sum256(pt)
	return pt, chainNext(f.priorChain, rd), nil
}

// maxCiphertextLen bounds a record's ciphertext (one max event plus GCM overhead
// and canonical-encoding slack). It is a hard structural guard used while parsing
// untrusted on-disk bytes, independent of the configured per-event bound.
const maxCiphertextLen = (1 << 20) + 4096
