// Package grant: hand-written CBOR codec for the grant wire format. No
// external CBOR dependency. Map with integer keys 0–6, Core Deterministic
// (keys in order; preferred serialization for lengths and integers).
//
// Two forms share the keys. The payload form (keys 1–6) is what the owner
// signs and what the commitment covers. The response form (keys 0–6) is the
// payload form with the assigned idtimestamp at key 0. The normative
// definition is forestrie/protocol, spec/log-authority-and-grants.md §2.1;
// the conformance vectors are that repository's vectors/fixtures/.
package grant

import (
	"encoding/binary"
	"fmt"
)

// CBOR map key assignments for the grant wire format. Other implementations
// must use the same keys for interoperability. Keys 7 (signer) and 8 (kind)
// are retired and rejected on decode; see ErrGrantObsoleteKey.
const (
	CborKeyIDTimestamp = 0
	CborKeyLogId       = 1
	CborKeyOwnerLogId  = 2
	CborKeyGrantFlags  = 3
	CborKeyMaxHeight   = 4
	CborKeyMinGrowth   = 5
	CborKeyGrantData   = 6

	cborKeyObsoleteSigner = 7
	cborKeyObsoleteKind   = 8
)

// Map sizes of the two wire forms.
const (
	cborResponseMapPairs = 7 // keys 0–6
	cborPayloadMapPairs  = 6 // keys 1–6
)

// CBOR initial bytes for byte-string length (major type 2, additional = length).
// Part of the formal serialization interface.
const (
	CborBstrLen8  = 0x48 // 8-byte byte string (single byte)
	CborBstrLen16 = 0x50 // 16-byte byte string (single byte)
)

// CborFixedLogIdLen and CborFixedGrantFlagsLen are the fixed wire lengths.
// LogId and OwnerLogId are always 32 bytes on the wire; GrantFlags always 8.
// This guarantees decode→LeafCommitment pad paths are no-ops and CheckSizes
// always passes for wire-decoded grants.
const (
	CborFixedLogIdOwnerLogIdLen = InnerLogIDBytes // 32
	CborFixedGrantFlagsLen      = GrantFlagsBytes // 8
)

// 32-byte bstr encoding: first byte 0x58 (major 2, additional 24), then byte(32).
const CborBstrLen32Lead = 0x58 // lead byte for "bstr length in next byte"; next byte is CborFixedLogIdOwnerLogIdLen

// Max length for the variable-length GrantData field. Decode rejects larger
// values for safety.
const (
	CborMaxGrantData = 64 * 1024 // 64 KiB
)

// MarshalGrant encodes g in the response form: one map with keys 0–6 in
// order, Core Deterministic, key 0 the idtimestamp. LogId, OwnerLogId, and
// GrantFlags have fixed wire lengths (CborFixedLogIdOwnerLogIdLen,
// CborFixedGrantFlagsLen); we left-pad to those lengths on encode so decode
// always yields the same size and LeafCommitment pad paths are no-ops.
// GrantData is variable-length. Returns ErrGrantFieldSize if logId,
// grantFlags, or ownerLogId exceed their max (CheckSizes).
func MarshalGrant(g *Grant) ([]byte, error) {
	if g == nil {
		return nil, fmt.Errorf("grant: MarshalGrant: nil grant")
	}
	b := make([]byte, 0, 64)
	b = append(b, 0xa0|cborResponseMapPairs)
	// Key 0: IDTimestamp always 8 bytes
	b = append(b, 0x00, CborBstrLen8)
	b = append(b, g.IDTimestamp[:]...)
	return appendGrantPayloadPairs(b, g)
}

// MarshalGrantPayload encodes g in the payload form: one map with keys 1–6
// in order, Core Deterministic, with no idtimestamp. This is the form the
// owner signs and the form the commitment covers; g.IDTimestamp is ignored.
func MarshalGrantPayload(g *Grant) ([]byte, error) {
	if g == nil {
		return nil, fmt.Errorf("grant: MarshalGrantPayload: nil grant")
	}
	b := make([]byte, 0, 64)
	b = append(b, 0xa0|cborPayloadMapPairs)
	return appendGrantPayloadPairs(b, g)
}

// appendGrantPayloadPairs appends the key 1–6 pairs shared by both forms.
func appendGrantPayloadPairs(b []byte, g *Grant) ([]byte, error) {
	if err := CheckSizes(g.LogId, g.GrantFlags, g.OwnerLogId); err != nil {
		return nil, err
	}
	// Key 1: LogId, fixed 32 bytes on wire (left-pad)
	logId32, err := cborPadTo(g.LogId, CborFixedLogIdOwnerLogIdLen)
	if err != nil {
		return nil, err
	}
	b = append(b, 0x01, CborBstrLen32Lead, byte(CborFixedLogIdOwnerLogIdLen))
	b = append(b, logId32...)
	// Key 2: OwnerLogId, fixed 32 bytes on wire (left-pad)
	owner32, err := cborPadTo(g.OwnerLogId, CborFixedLogIdOwnerLogIdLen)
	if err != nil {
		return nil, err
	}
	b = append(b, 0x02, CborBstrLen32Lead, byte(CborFixedLogIdOwnerLogIdLen))
	b = append(b, owner32...)
	// Key 3: GrantFlags, fixed 8 bytes on wire (left-pad)
	flags8, err := cborPadTo(g.GrantFlags, CborFixedGrantFlagsLen)
	if err != nil {
		return nil, err
	}
	b = append(b, 0x03, CborBstrLen8)
	b = append(b, flags8...)
	// Key 4, 5: uints
	b = append(b, 0x04)
	b = appendCborUint(b, g.MaxHeight)
	b = append(b, 0x05)
	b = appendCborUint(b, g.MinGrowth)
	// Key 6: GrantData (variable)
	b = append(b, 0x06)
	b = appendCborBstr(b, g.GrantData)
	return b, nil
}

// cborPadTo left-pads s to size bytes. Returns ErrGrantFieldSize if len(s) > size.
func cborPadTo(s []byte, size int) ([]byte, error) {
	if s == nil {
		s = []byte{}
	}
	if len(s) > size {
		return nil, fmt.Errorf("grant: field length %d exceeds limit %d: %w", len(s), size, ErrGrantFieldSize)
	}
	if len(s) == size {
		return s, nil
	}
	out := make([]byte, size)
	copy(out[size-len(s):], s)
	return out, nil
}

// appendCborBstr appends a CBOR byte string for the variable-length
// GrantData field. No size check; used only where length is unbounded.
func appendCborBstr(b []byte, s []byte) []byte {
	if s == nil {
		s = []byte{}
	}
	n := len(s)
	if n < 24 {
		b = append(b, 0x40|byte(n))
	} else if n <= 0xff {
		b = append(b, 0x58, byte(n))
	} else if n <= 0xffff {
		b = append(b, 0x59)
		b = append(b, byte(n>>8), byte(n))
	} else {
		b = append(b, 0x5a)
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(n))
		b = append(b, buf[:]...)
	}
	return append(b, s...)
}

func appendCborUint(b []byte, v uint64) []byte {
	if v < 24 {
		return append(b, byte(v))
	}
	if v <= 0xff {
		return append(b, 0x18, byte(v))
	}
	if v <= 0xffff {
		b = append(b, 0x19)
		return append(b, byte(v>>8), byte(v))
	}
	if v <= 0xffffffff {
		b = append(b, 0x1a)
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(v))
		return append(b, buf[:]...)
	}
	b = append(b, 0x1b)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}

// UnmarshalGrant decodes either wire form into g: the response form (keys
// 0–6) sets g.IDTimestamp; the payload form (keys 1–6) leaves it zero. g must
// be non-nil. Enforces max sizes on byte-string fields. Returns
// ErrGrantObsoleteKey if the map carries key 7 or 8, and an error on any other
// malformed or unexpected structure.
func UnmarshalGrant(data []byte, g *Grant) error {
	if g == nil {
		return fmt.Errorf("grant: UnmarshalGrant: nil grant")
	}
	d := cborDecoder{data: data}
	if err := d.decodeGrant(g); err != nil {
		return err
	}
	if d.off != len(data) {
		return fmt.Errorf("grant: UnmarshalGrant: %d trailing bytes", len(data)-d.off)
	}
	return nil
}

type cborDecoder struct {
	data []byte
	off  int
}

func (d *cborDecoder) need(n int) bool {
	return d.off+n <= len(d.data)
}

func (d *cborDecoder) readByte() (byte, error) {
	if !d.need(1) {
		return 0, fmt.Errorf("grant: CBOR truncated at byte %d", d.off)
	}
	b := d.data[d.off]
	d.off++
	return b, nil
}

func (d *cborDecoder) readBytes(n int) ([]byte, error) {
	if !d.need(n) {
		return nil, fmt.Errorf("grant: CBOR truncated at byte %d", d.off)
	}
	out := make([]byte, n)
	copy(out, d.data[d.off:d.off+n])
	d.off += n
	return out, nil
}

func (d *cborDecoder) decodeGrant(g *Grant) error {
	b, err := d.readByte()
	if err != nil {
		return err
	}
	major := b >> 5
	aux := b & 0x1f
	if major != 5 {
		return fmt.Errorf("grant: expected CBOR map, got major type %d", major)
	}
	n, err := d.decodeAuxCount(aux)
	if err != nil {
		return err
	}
	firstKey := CborKeyIDTimestamp
	switch n {
	case cborResponseMapPairs:
	case cborPayloadMapPairs:
		firstKey = CborKeyLogId
	default:
		// A wrong pair count is most likely the retired 9-pair form; name
		// that error specifically when key 7 or 8 is present.
		if err := d.scanForObsoleteKeys(n); err != nil {
			return err
		}
		return fmt.Errorf("grant: expected map of %d (response form) or %d (payload form) pairs, got %d", cborResponseMapPairs, cborPayloadMapPairs, n)
	}
	// Decode the pairs in order; keys must run firstKey..6 in sequence.
	for key := firstKey; key <= CborKeyGrantData; key++ {
		gotKey, err := d.decodeUint()
		if err != nil {
			return err
		}
		if gotKey == cborKeyObsoleteSigner || gotKey == cborKeyObsoleteKind {
			return fmt.Errorf("grant: map key %d: %w", gotKey, ErrGrantObsoleteKey)
		}
		if gotKey != uint64(key) {
			return fmt.Errorf("grant: expected map key %d, got %d", key, gotKey)
		}
		switch key {
		case CborKeyIDTimestamp:
			raw, err := d.decodeBstr(IDTimestampBytes, true)
			if err != nil {
				return err
			}
			copy(g.IDTimestamp[:], raw)
		case CborKeyLogId:
			g.LogId, err = d.decodeBstr(CborFixedLogIdOwnerLogIdLen, true)
			if err != nil {
				return err
			}
		case CborKeyOwnerLogId:
			g.OwnerLogId, err = d.decodeBstr(CborFixedLogIdOwnerLogIdLen, true)
			if err != nil {
				return err
			}
		case CborKeyGrantFlags:
			g.GrantFlags, err = d.decodeBstr(CborFixedGrantFlagsLen, true)
			if err != nil {
				return err
			}
		case CborKeyMaxHeight:
			g.MaxHeight, err = d.decodeUint()
			if err != nil {
				return err
			}
		case CborKeyMinGrowth:
			g.MinGrowth, err = d.decodeUint()
			if err != nil {
				return err
			}
		case CborKeyGrantData:
			g.GrantData, err = d.decodeBstr(CborMaxGrantData, false) // variable
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// scanForObsoleteKeys walks n pairs without interpreting the values and
// returns ErrGrantObsoleteKey if any key is 7 or 8. Any structural error
// during the walk is returned as-is; the caller reports the count mismatch
// when the walk finds nothing.
func (d *cborDecoder) scanForObsoleteKeys(n int) error {
	scan := cborDecoder{data: d.data, off: d.off}
	for i := 0; i < n; i++ {
		key, err := scan.decodeUint()
		if err != nil {
			return nil
		}
		if key == cborKeyObsoleteSigner || key == cborKeyObsoleteKind {
			return fmt.Errorf("grant: map key %d: %w", key, ErrGrantObsoleteKey)
		}
		if err := scan.skipValue(); err != nil {
			return nil
		}
	}
	return nil
}

// skipValue advances past one unsigned integer or byte string value.
func (d *cborDecoder) skipValue() error {
	if !d.need(1) {
		return fmt.Errorf("grant: CBOR truncated at byte %d", d.off)
	}
	switch d.data[d.off] >> 5 {
	case 0:
		_, err := d.decodeUint()
		return err
	case 2:
		_, err := d.decodeBstr(len(d.data), false)
		return err
	default:
		return fmt.Errorf("grant: unsupported value major type %d", d.data[d.off]>>5)
	}
}

func (d *cborDecoder) decodeAuxCount(aux byte) (int, error) {
	if aux < 24 {
		return int(aux), nil
	}
	if aux == 24 {
		b, err := d.readByte()
		if err != nil {
			return 0, err
		}
		return int(b), nil
	}
	if aux == 25 {
		if !d.need(2) {
			return 0, fmt.Errorf("grant: CBOR truncated")
		}
		v := binary.BigEndian.Uint16(d.data[d.off : d.off+2])
		d.off += 2
		if v > 0x7fff {
			return 0, fmt.Errorf("grant: count too large")
		}
		return int(v), nil
	}
	return 0, fmt.Errorf("grant: unsupported CBOR count encoding (aux=%d)", aux)
}

func (d *cborDecoder) decodeUint() (uint64, error) {
	b, err := d.readByte()
	if err != nil {
		return 0, err
	}
	major := b >> 5
	aux := b & 0x1f
	if major != 0 {
		return 0, fmt.Errorf("grant: expected unsigned int, got major %d", major)
	}
	if aux < 24 {
		return uint64(aux), nil
	}
	if aux == 24 {
		b2, err := d.readByte()
		if err != nil {
			return 0, err
		}
		return uint64(b2), nil
	}
	if aux == 25 {
		if !d.need(2) {
			return 0, fmt.Errorf("grant: CBOR truncated")
		}
		v := binary.BigEndian.Uint16(d.data[d.off : d.off+2])
		d.off += 2
		return uint64(v), nil
	}
	if aux == 26 {
		if !d.need(4) {
			return 0, fmt.Errorf("grant: CBOR truncated")
		}
		v := binary.BigEndian.Uint32(d.data[d.off : d.off+4])
		d.off += 4
		return uint64(v), nil
	}
	if aux == 27 {
		if !d.need(8) {
			return 0, fmt.Errorf("grant: CBOR truncated")
		}
		v := binary.BigEndian.Uint64(d.data[d.off : d.off+8])
		d.off += 8
		return v, nil
	}
	return 0, fmt.Errorf("grant: unsupported uint encoding (aux=%d)", aux)
}

// decodeBstr reads a CBOR byte string. If exactLen >= 0, length must equal exactLen.
// If maxLen > 0 and exactLen < 0, length must be <= maxLen. Returns nil slice for length 0.
func (d *cborDecoder) decodeBstr(maxLen int, exactLen bool) ([]byte, error) {
	b, err := d.readByte()
	if err != nil {
		return nil, err
	}
	major := b >> 5
	aux := b & 0x1f
	if major != 2 {
		return nil, fmt.Errorf("grant: expected byte string, got major %d", major)
	}
	var n int
	if aux < 24 {
		n = int(aux)
	} else if aux == 24 {
		b2, err := d.readByte()
		if err != nil {
			return nil, err
		}
		n = int(b2)
	} else if aux == 25 {
		if !d.need(2) {
			return nil, fmt.Errorf("grant: CBOR truncated")
		}
		n = int(binary.BigEndian.Uint16(d.data[d.off : d.off+2]))
		d.off += 2
	} else if aux == 26 {
		if !d.need(4) {
			return nil, fmt.Errorf("grant: CBOR truncated")
		}
		n = int(binary.BigEndian.Uint32(d.data[d.off : d.off+4]))
		d.off += 4
	} else {
		return nil, fmt.Errorf("grant: unsupported bstr length encoding (aux=%d)", aux)
	}
	if exactLen && n != maxLen {
		return nil, fmt.Errorf("grant: byte string length %d, want %d: %w", n, maxLen, ErrGrantFieldSize)
	}
	if n > maxLen {
		return nil, fmt.Errorf("grant: byte string length %d exceeds max %d: %w", n, maxLen, ErrGrantFieldSize)
	}
	if n == 0 {
		return nil, nil
	}
	return d.readBytes(n)
}
