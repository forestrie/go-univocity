package grant

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// grantWire matches the CBOR map shape (keyasint 0-8) for verification with
// fxamacker/cbor in tests only.
type grantWire struct {
	IDTimestamp []byte `cbor:"0,keyasint"`
	LogId       []byte `cbor:"1,keyasint"`
	OwnerLogId  []byte `cbor:"2,keyasint"`
	GrantFlags  []byte `cbor:"3,keyasint"`
	MaxHeight   uint64 `cbor:"4,keyasint"`
	MinGrowth   uint64 `cbor:"5,keyasint"`
	GrantData   []byte `cbor:"6,keyasint"`
	Signer      []byte `cbor:"7,keyasint"`
	Kind        byte   `cbor:"8,keyasint"`
}

func TestMarshalGrant_UnmarshalGrant_RoundTrip(t *testing.T) {
	g := &Grant{
		IDTimestamp: [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1},
		LogId:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		OwnerLogId:  []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		GrantFlags:  []byte{0, 0, 0, 0, 0, 0, 0, 1},
		MaxHeight:   1000,
		MinGrowth:   1,
		GrantData:   []byte{0xab, 0xcd},
		Signer:      []byte{0x01, 0x02},
		Kind:        1,
	}
	data, err := MarshalGrant(g)
	if err != nil {
		t.Fatalf("MarshalGrant: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("MarshalGrant: empty output")
	}
	var dec Grant
	if err := UnmarshalGrant(data, &dec); err != nil {
		t.Fatalf("UnmarshalGrant: %v", err)
	}
	if dec.IDTimestamp != g.IDTimestamp {
		t.Errorf("IDTimestamp: got %x, want %x", dec.IDTimestamp[:], g.IDTimestamp[:])
	}
	// Wire format is fixed 32, 32, 8; decode yields left-padded bytes.
	wantLogId := leftPad32(g.LogId)
	wantOwner := leftPad32(g.OwnerLogId)
	wantFlags := leftPad8(g.GrantFlags)
	if !bytes.Equal(dec.LogId, wantLogId) {
		t.Errorf("LogId: got %x, want %x", dec.LogId, wantLogId)
	}
	if !bytes.Equal(dec.OwnerLogId, wantOwner) {
		t.Errorf("OwnerLogId: got %x, want %x", dec.OwnerLogId, wantOwner)
	}
	if !bytes.Equal(dec.GrantFlags, wantFlags) {
		t.Errorf("GrantFlags: got %x, want %x", dec.GrantFlags, wantFlags)
	}
	if dec.MaxHeight != g.MaxHeight || dec.MinGrowth != g.MinGrowth {
		t.Errorf("MaxHeight=%d MinGrowth=%d, want %d %d", dec.MaxHeight, dec.MinGrowth, g.MaxHeight, g.MinGrowth)
	}
	if !bytes.Equal(dec.GrantData, g.GrantData) {
		t.Errorf("GrantData: got %x, want %x", dec.GrantData, g.GrantData)
	}
	if !bytes.Equal(dec.Signer, g.Signer) {
		t.Errorf("Signer: got %x, want %x", dec.Signer, g.Signer)
	}
	if dec.Kind != g.Kind {
		t.Errorf("Kind: got %d, want %d", dec.Kind, g.Kind)
	}
	// Second round-trip: encoded bytes should be identical (deterministic).
	data2, err := MarshalGrant(&dec)
	if err != nil {
		t.Fatalf("MarshalGrant round 2: %v", err)
	}
	if !bytes.Equal(data, data2) {
		t.Error("second MarshalGrant produced different bytes (encoding should be deterministic)")
	}
}

func leftPad32(b []byte) []byte {
	if len(b) >= CborFixedLogIdOwnerLogIdLen {
		return b[:CborFixedLogIdOwnerLogIdLen]
	}
	out := make([]byte, CborFixedLogIdOwnerLogIdLen)
	copy(out[CborFixedLogIdOwnerLogIdLen-len(b):], b)
	return out
}

func leftPad8(b []byte) []byte {
	if len(b) >= CborFixedGrantFlagsLen {
		return b[:CborFixedGrantFlagsLen]
	}
	out := make([]byte, CborFixedGrantFlagsLen)
	copy(out[CborFixedGrantFlagsLen-len(b):], b)
	return out
}

func TestMarshalGrant_ErrGrantFieldSizeWhenOversized(t *testing.T) {
	valid := &Grant{
		IDTimestamp: [IDTimestampBytes]byte{},
		LogId:       make([]byte, LogIDBytes),
		GrantFlags:  make([]byte, GrantFlagsBytes),
		OwnerLogId:  make([]byte, LogIDBytes),
	}
	_, err := MarshalGrant(valid)
	if err != nil {
		t.Fatalf("MarshalGrant(valid): %v", err)
	}
	overLogId := &Grant{
		IDTimestamp: [IDTimestampBytes]byte{},
		LogId:       make([]byte, InnerLogIDBytes+1),
		GrantFlags:  make([]byte, GrantFlagsBytes),
		OwnerLogId:  make([]byte, LogIDBytes),
	}
	_, err = MarshalGrant(overLogId)
	if err == nil {
		t.Fatal("MarshalGrant(oversized LogId): want error")
	}
	if !errors.Is(err, ErrGrantFieldSize) {
		t.Errorf("MarshalGrant(oversized): want ErrGrantFieldSize, got %v", err)
	}
}

func TestMarshalGrant_NilGrant(t *testing.T) {
	_, err := MarshalGrant(nil)
	if err == nil {
		t.Fatal("MarshalGrant(nil): want error")
	}
}

func TestUnmarshalGrant_NilGrant(t *testing.T) {
	err := UnmarshalGrant([]byte{0xa0}, nil)
	if err == nil {
		t.Fatal("UnmarshalGrant(_, nil): want error")
	}
}

func TestMarshalGrant_EmptyGrant(t *testing.T) {
	g := &Grant{}
	data, err := MarshalGrant(g)
	if err != nil {
		t.Fatalf("MarshalGrant empty: %v", err)
	}
	var dec Grant
	if err := UnmarshalGrant(data, &dec); err != nil {
		t.Fatalf("UnmarshalGrant: %v", err)
	}
	if dec.IDTimestamp != [IDTimestampBytes]byte{} {
		t.Errorf("empty grant IDTimestamp should decode to zero")
	}
	if dec.MaxHeight != 0 || dec.MinGrowth != 0 || dec.Kind != 0 {
		t.Errorf("empty grant numeric fields should decode to zero")
	}
}

// TestMarshalGrant_ValidCBOR verifies that our hand-written encoder produces
// CBOR that fxamacker/cbor can decode into the expected map shape.
func TestMarshalGrant_ValidCBOR(t *testing.T) {
	g := &Grant{
		IDTimestamp: [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1},
		LogId:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		OwnerLogId:  []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		GrantFlags:  []byte{0, 0, 0, 0, 0, 0, 0, 1},
		MaxHeight:   1000,
		MinGrowth:   1,
		GrantData:   []byte{0xab, 0xcd},
		Signer:      []byte{0x01, 0x02},
		Kind:        1,
	}
	data, err := MarshalGrant(g)
	if err != nil {
		t.Fatalf("MarshalGrant: %v", err)
	}
	var w grantWire
	if err := cbor.Unmarshal(data, &w); err != nil {
		t.Fatalf("fxamacker/cbor could not decode our CBOR: %v", err)
	}
	if !bytes.Equal(w.IDTimestamp, g.IDTimestamp[:]) {
		t.Errorf("IDTimestamp: library decoded %x, want %x", w.IDTimestamp, g.IDTimestamp[:])
	}
	// We encode fixed 32, 32, 8 (left-padded)
	wantLogId := leftPad32(g.LogId)
	wantOwner := leftPad32(g.OwnerLogId)
	wantFlags := leftPad8(g.GrantFlags)
	if !bytes.Equal(w.LogId, wantLogId) || !bytes.Equal(w.OwnerLogId, wantOwner) || !bytes.Equal(w.GrantFlags, wantFlags) {
		t.Error("LogId, OwnerLogId, or GrantFlags mismatch after library decode (expected fixed-length padded)")
	}
	if w.MaxHeight != g.MaxHeight || w.MinGrowth != g.MinGrowth || w.Kind != g.Kind {
		t.Errorf("MaxHeight=%d MinGrowth=%d Kind=%d, want %d %d %d", w.MaxHeight, w.MinGrowth, w.Kind, g.MaxHeight, g.MinGrowth, g.Kind)
	}
}

// TestUnmarshalGrant_FromLibrary verifies we can decode CBOR produced by
// fxamacker/cbor when the library encodes fixed-length fields (32, 32, 8).
func TestUnmarshalGrant_FromLibrary(t *testing.T) {
	logId32 := make([]byte, CborFixedLogIdOwnerLogIdLen)
	logId32[30], logId32[31] = 0xaa, 0xbb
	owner32 := make([]byte, CborFixedLogIdOwnerLogIdLen)
	owner32[30], owner32[31] = 0xcc, 0xdd
	flags8 := make([]byte, CborFixedGrantFlagsLen)
	flags8[7] = 1
	w := grantWire{
		IDTimestamp: []byte{0, 0, 0, 0, 0, 0, 0, 2},
		LogId:       logId32,
		OwnerLogId:  owner32,
		GrantFlags:  flags8,
		MaxHeight:   2000,
		MinGrowth:   2,
		GrantData:   []byte{0xde, 0xad},
		Signer:      []byte{0x03},
		Kind:        2,
	}
	data, err := cbor.Marshal(w)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	var g Grant
	if err := UnmarshalGrant(data, &g); err != nil {
		t.Fatalf("UnmarshalGrant(library bytes): %v", err)
	}
	if g.IDTimestamp != [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 2} {
		t.Errorf("IDTimestamp mismatch")
	}
	if !bytes.Equal(g.LogId, w.LogId) || !bytes.Equal(g.GrantData, w.GrantData) {
		t.Error("LogId or GrantData mismatch")
	}
	if g.MaxHeight != w.MaxHeight || g.MinGrowth != w.MinGrowth || g.Kind != w.Kind {
		t.Errorf("MaxHeight=%d MinGrowth=%d Kind=%d", g.MaxHeight, g.MinGrowth, g.Kind)
	}
}

func TestUnmarshalGrant_Truncated(t *testing.T) {
	data, _ := MarshalGrant(&Grant{IDTimestamp: [IDTimestampBytes]byte{}})
	var g Grant
	err := UnmarshalGrant(data[:len(data)-2], &g)
	if err == nil {
		t.Fatal("UnmarshalGrant(truncated): want error")
	}
}

func TestUnmarshalGrant_OversizedBstrRejected(t *testing.T) {
	// Claim GrantData length 66560 (over cborMaxGrantData 64K); codec rejects before reading.
	data, _ := MarshalGrant(&Grant{IDTimestamp: [IDTimestampBytes]byte{}})
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0x06 && data[i+1] == 0x40 {
			// Replace 0x40 with 0x5a 0x00 0x01 0x04 0x00 (length 66560)
			bad := append(append([]byte{}, data[:i+1]...), 0x5a, 0x00, 0x01, 0x04, 0x00)
			bad = append(bad, data[i+2:]...)
			var g Grant
			err := UnmarshalGrant(bad, &g)
			if err == nil {
				t.Fatal("UnmarshalGrant(oversized GrantData): want error")
			}
			if !errors.Is(err, ErrGrantFieldSize) {
				t.Errorf("UnmarshalGrant(oversized): want ErrGrantFieldSize, got %v", err)
			}
			return
		}
	}
	t.Skip("could not find key 6 in encoded empty grant")
}

func TestMarshalGrant_LeafCommitmentPreserved(t *testing.T) {
	g := &Grant{
		IDTimestamp: [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1},
		LogId:       make([]byte, LogIDBytes),
		OwnerLogId:  make([]byte, LogIDBytes),
		GrantFlags:  make([]byte, GrantFlagsBytes),
		MaxHeight:   1000,
		MinGrowth:   1,
		GrantData:   []byte{0xab, 0xcd},
	}
	for i := range g.LogId {
		g.LogId[i] = byte(i)
	}
	for i := range g.OwnerLogId {
		g.OwnerLogId[i] = byte(i + 16)
	}
	g.GrantFlags[7] = 1

	leafBefore := LeafCommitmentFromGrant(g)
	data, err := MarshalGrant(g)
	if err != nil {
		t.Fatalf("MarshalGrant: %v", err)
	}
	var dec Grant
	if err := UnmarshalGrant(data, &dec); err != nil {
		t.Fatalf("UnmarshalGrant: %v", err)
	}
	leafAfter := LeafCommitmentFromGrant(&dec)
	if leafBefore != leafAfter {
		t.Error("leaf commitment must be preserved across MarshalGrant/UnmarshalGrant round-trip")
	}
}
