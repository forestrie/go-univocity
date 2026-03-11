// Package grant: hand-written CBOR codec for the grant wire format. No
// external CBOR dependency. Map with integer keys 0–8, Core Deterministic
// (keys in order; preferred serialization for lengths and integers).
package grant

import (
	"encoding/binary"
	"fmt"
)

// CBOR map key assignments for the grant wire format. Other implementations
// must use the same keys for interoperability.
const (
	CborKeyIDTimestamp = 0
	CborKeyLogId       = 1
	CborKeyOwnerLogId  = 2
	CborKeyGrantFlags  = 3
	CborKeyMaxHeight   = 4
	CborKeyMinGrowth   = 5
	CborKeyGrantData   = 6
	CborKeySigner      = 7
	CborKeyKind        = 8
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

// Max lengths for variable-length CBOR fields (GrantData, Signer). Decode
// rejects larger values for safety.
const (
	CborMaxGrantData = 64 * 1024 // 64 KiB
	CborMaxSigner    = 1024      // 1 KiB
)

// MarshalGrant encodes g to CBOR: one map with keys 0–8 in order, Core
// Deterministic. LogId, OwnerLogId, and GrantFlags have fixed wire lengths
// (CborFixedLogIdOwnerLogIdLen, CborFixedGrantFlagsLen); we left-pad to
// those lengths on encode so decode always yields the same size and
// LeafCommitment pad paths are no-ops. GrantData and Signer are
// variable-length. Returns ErrGrantFieldSize if logId, grantFlags, or
// ownerLogId exceed their max (CheckSizes).
func MarshalGrant(g *Grant) ([]byte, error) {
	if g == nil {
		return nil, fmt.Errorf("grant: MarshalGrant: nil grant")
	}
	if err := CheckSizes(g.LogId, g.GrantFlags, g.OwnerLogId); err != nil {
		return nil, err
	}
	b := make([]byte, 0, 64)
	b = append(b, 0xa9)
	// Key 0: IDTimestamp always 8 bytes
	b = append(b, 0x00, CborBstrLen8)
	b = append(b, g.IDTimestamp[:]...)
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
	// Key 7: Signer (variable)
	b = append(b, 0x07)
	b = appendCborBstr(b, g.Signer)
	// Key 8: Kind
	b = append(b, 0x08)
	b = appendCborUint(b, uint64(g.Kind))
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

// appendCborBstr appends a CBOR byte string for variable-length fields
// (GrantData, Signer). No size check; used only where length is unbounded.
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

// UnmarshalGrant decodes CBOR produced by MarshalGrant into g. g must be
// non-nil. Enforces max sizes on byte-string fields. Returns an error on
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
	if n != 9 {
		return fmt.Errorf("grant: expected map of 9 pairs, got %d", n)
	}
	// Decode 9 pairs in order; we accept only key 0,1,...,8 in sequence.
	for key := 0; key < 9; key++ {
		gotKey, err := d.decodeUint()
		if err != nil {
			return err
		}
		if gotKey != uint64(key) {
			return fmt.Errorf("grant: expected map key %d, got %d", key, gotKey)
		}
		switch key {
		case 0:
			raw, err := d.decodeBstr(IDTimestampBytes, true)
			if err != nil {
				return err
			}
			copy(g.IDTimestamp[:], raw)
		case 1:
			g.LogId, err = d.decodeBstr(CborFixedLogIdOwnerLogIdLen, true)
			if err != nil {
				return err
			}
		case 2:
			g.OwnerLogId, err = d.decodeBstr(CborFixedLogIdOwnerLogIdLen, true)
			if err != nil {
				return err
			}
		case 3:
			g.GrantFlags, err = d.decodeBstr(CborFixedGrantFlagsLen, true)
			if err != nil {
				return err
			}
		case 4:
			g.MaxHeight, err = d.decodeUint()
			if err != nil {
				return err
			}
		case 5:
			g.MinGrowth, err = d.decodeUint()
			if err != nil {
				return err
			}
		case 6:
			g.GrantData, err = d.decodeBstr(CborMaxGrantData, false) // variable
			if err != nil {
				return err
			}
		case 7:
			g.Signer, err = d.decodeBstr(CborMaxSigner, false) // variable
			if err != nil {
				return err
			}
		case 8:
			k, err := d.decodeUint()
			if err != nil {
				return err
			}
			if k > 0xff {
				return fmt.Errorf("grant: kind %d exceeds 255", k)
			}
			g.Kind = byte(k)
		}
	}
	return nil
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
