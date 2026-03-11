package grant

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLeafCommitmentDeterministic(t *testing.T) {
	idTs := [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logId := make([]byte, LogIDBytes)
	for i := range logId {
		logId[i] = byte(i)
	}
	flags := make([]byte, GrantFlagsBytes)
	flags[7] = 1
	ownerLogId := make([]byte, LogIDBytes)
	for i := range ownerLogId {
		ownerLogId[i] = byte(i + 16)
	}
	grantData := []byte{0xab, 0xcd}

	leaf1 := LeafCommitment(idTs, logId, flags, 1000, 1, ownerLogId, grantData)
	leaf2 := LeafCommitment(idTs, logId, flags, 1000, 1, ownerLogId, grantData)
	if leaf1 != leaf2 {
		t.Error("LeafCommitment must be deterministic")
	}
	if leaf1 == [32]byte{} {
		t.Error("LeafCommitment must be non-zero")
	}
	t.Logf("leaf hash (hex): %s", hex.EncodeToString(leaf1[:]))
}

func TestLeafCommitmentFromGrant(t *testing.T) {
	g := &Grant{
		IDTimestamp: [8]byte{0, 0, 0, 0, 0, 0, 0, 2},
		LogId:       make([]byte, 16),
		OwnerLogId:  make([]byte, 16),
		GrantFlags:  make([]byte, 8),
		MaxHeight:   2000,
		MinGrowth:   2,
		GrantData:   []byte{0xde, 0xad},
		Signer:      []byte{0x01, 0x02}, // not in commitment
		Kind:        0,
	}
	for i := range g.LogId {
		g.LogId[i] = byte(i)
	}
	for i := range g.OwnerLogId {
		g.OwnerLogId[i] = byte(i + 8)
	}

	leaf := LeafCommitmentFromGrant(g)
	if leaf == [32]byte{} {
		t.Error("leaf must be non-zero")
	}

	// Same inputs via LeafCommitment
	direct := LeafCommitment(g.IDTimestamp, g.LogId, g.GrantFlags, g.MaxHeight, g.MinGrowth, g.OwnerLogId, g.GrantData)
	if direct != leaf {
		t.Error("LeafCommitmentFromGrant must match LeafCommitment")
	}
}

// leafVector is one entry from tests/fixtures/leaf_vectors.json (from gen_testvectors.py).
type leafVector struct {
	IDTimestampHex  string `json:"idtimestamp_hex"`
	LogIDHex        string `json:"log_id_hex"`
	GrantFlagsHex   string `json:"grant_flags_hex"`
	MaxHeight       uint64 `json:"max_height"`
	MinGrowth       uint64 `json:"min_growth"`
	OwnerLogIDHex   string `json:"owner_log_id_hex"`
	GrantDataHex    string `json:"grant_data_hex"`
	ExpectedLeafHex string `json:"expected_leaf_hex"`
}

// TestLeafCommitmentFromFixture loads tests/fixtures/leaf_vectors.json if present
// and checks that our LeafCommitment matches the expected hash for each vector.
func TestLeafCommitmentFromFixture(t *testing.T) {
	candidates := []string{
		filepath.Join("tests", "fixtures", "leaf_vectors.json"),
		filepath.Join("..", "tests", "fixtures", "leaf_vectors.json"),
	}
	var data []byte
	var err error
	for _, path := range candidates {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}
	if data == nil {
		t.Skipf("fixture not found (run gen_testvectors.py): %v", err)
		return
	}
	var vectors []leafVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	for i, v := range vectors {
		idTs, _ := hex.DecodeString(v.IDTimestampHex)
		logId, _ := hex.DecodeString(v.LogIDHex)
		flags, _ := hex.DecodeString(v.GrantFlagsHex)
		ownerLogId, _ := hex.DecodeString(v.OwnerLogIDHex)
		grantData, _ := hex.DecodeString(v.GrantDataHex)
		expected, _ := hex.DecodeString(v.ExpectedLeafHex)
		var idTsArr [IDTimestampBytes]byte
		copy(idTsArr[:], idTs)
		leaf := LeafCommitment(idTsArr, logId, flags, v.MaxHeight, v.MinGrowth, ownerLogId, grantData)
		if hex.EncodeToString(leaf[:]) != v.ExpectedLeafHex {
			t.Errorf("vector %d: got leaf %s, want %s", i, hex.EncodeToString(leaf[:]), v.ExpectedLeafHex)
		}
		if len(expected) == 32 && leaf != [32]byte{} {
			for j := 0; j < 32; j++ {
				if leaf[j] != expected[j] {
					t.Errorf("vector %d: byte %d: got %02x want %02x", i, j, leaf[j], expected[j])
					break
				}
			}
		}
	}
}

// --- CheckSizes tests ---

func TestCheckSizes_AllValid(t *testing.T) {
	logId := make([]byte, LogIDBytes)
	flags := make([]byte, GrantFlagsBytes)
	ownerLogId := make([]byte, LogIDBytes)
	if err := CheckSizes(logId, flags, ownerLogId); err != nil {
		t.Errorf("CheckSizes with valid sizes: got %v", err)
	}
}

func TestCheckSizes_AtLimits(t *testing.T) {
	logId := make([]byte, InnerLogIDBytes)
	flags := make([]byte, GrantFlagsBytes)
	ownerLogId := make([]byte, InnerOwnerLogIDBytes)
	if err := CheckSizes(logId, flags, ownerLogId); err != nil {
		t.Errorf("CheckSizes at limits: got %v", err)
	}
}

func TestCheckSizes_LogIdTooLong(t *testing.T) {
	logId := make([]byte, InnerLogIDBytes+1)
	flags := make([]byte, GrantFlagsBytes)
	ownerLogId := make([]byte, LogIDBytes)
	err := CheckSizes(logId, flags, ownerLogId)
	if err == nil {
		t.Fatal("CheckSizes with oversized logId: want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "logId") {
		t.Errorf("error message should mention logId: %q", msg)
	}
	if !strings.Contains(msg, "33") || !strings.Contains(msg, "32") {
		t.Errorf("error message should mention length and limit: %q", msg)
	}
}

func TestCheckSizes_GrantFlagsTooLong(t *testing.T) {
	logId := make([]byte, LogIDBytes)
	flags := make([]byte, GrantFlagsBytes+1)
	ownerLogId := make([]byte, LogIDBytes)
	err := CheckSizes(logId, flags, ownerLogId)
	if err == nil {
		t.Fatal("CheckSizes with oversized grantFlags: want error")
	}
}

func TestCheckSizes_OwnerLogIdTooLong(t *testing.T) {
	logId := make([]byte, LogIDBytes)
	flags := make([]byte, GrantFlagsBytes)
	ownerLogId := make([]byte, InnerOwnerLogIDBytes+1)
	err := CheckSizes(logId, flags, ownerLogId)
	if err == nil {
		t.Fatal("CheckSizes with oversized ownerLogId: want error")
	}
}

func TestCheckSizes_ThenLeafCommitment_Valid(t *testing.T) {
	idTs := [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logId := make([]byte, LogIDBytes)
	for i := range logId {
		logId[i] = byte(i)
	}
	flags := make([]byte, GrantFlagsBytes)
	flags[7] = 1
	ownerLogId := make([]byte, LogIDBytes)
	for i := range ownerLogId {
		ownerLogId[i] = byte(i + 16)
	}
	grantData := []byte{0xab, 0xcd}

	if err := CheckSizes(logId, flags, ownerLogId); err != nil {
		t.Fatalf("CheckSizes: %v", err)
	}
	leaf := LeafCommitment(idTs, logId, flags, 1000, 1, ownerLogId, grantData)
	if leaf == [32]byte{} {
		t.Error("leaf must be non-zero")
	}
}

func TestCheckSizes_ThenLeafCommitment_InvalidStillComputes(t *testing.T) {
	// LeafCommitment does not call CheckSizes; oversized inputs are truncated.
	// So even if CheckSizes would error, LeafCommitment still produces a hash.
	idTs := [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logIdOversized := make([]byte, InnerLogIDBytes+5)
	for i := range logIdOversized {
		logIdOversized[i] = byte(i)
	}
	flags := make([]byte, GrantFlagsBytes)
	ownerLogId := make([]byte, LogIDBytes)
	grantData := []byte("x")

	if err := CheckSizes(logIdOversized, flags, ownerLogId); err == nil {
		t.Fatal("CheckSizes must error on oversized logId")
	}
	// LeafCommitment truncates: first 32 bytes of logId are used
	leaf := LeafCommitment(idTs, logIdOversized, flags, 0, 0, ownerLogId, grantData)
	if leaf == [32]byte{} {
		t.Error("leaf must be non-zero")
	}
	// Same hash as if we had passed only the first 32 bytes
	logIdTruncated := logIdOversized[:InnerLogIDBytes]
	leafTruncated := LeafCommitment(idTs, logIdTruncated, flags, 0, 0, ownerLogId, grantData)
	if leaf != leafTruncated {
		t.Error("oversized logId should truncate to first 32 bytes; leaf should match")
	}
}

// --- padLeft behavior via LeafCommitment (len == limit returns same slice, no copy) ---

func TestLeafCommitment_LogIdExactly32_NoExtraCopy(t *testing.T) {
	idTs := [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logId := make([]byte, InnerLogIDBytes)
	for i := range logId {
		logId[i] = byte(i + 10)
	}
	flags := make([]byte, GrantFlagsBytes)
	ownerLogId := make([]byte, LogIDBytes)
	grantData := []byte("a")

	leaf1 := LeafCommitment(idTs, logId, flags, 0, 0, ownerLogId, grantData)
	leaf2 := LeafCommitment(idTs, logId, flags, 0, 0, ownerLogId, grantData)
	if leaf1 != leaf2 {
		t.Error("LeafCommitment with 32-byte logId must be deterministic")
	}
}

func TestLeafCommitment_LogIdLongerThan32_TruncatesToFirst32(t *testing.T) {
	idTs := [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logId33 := make([]byte, InnerLogIDBytes+1)
	for i := range logId33 {
		logId33[i] = byte(i)
	}
	logId32 := logId33[:InnerLogIDBytes]
	flags := make([]byte, GrantFlagsBytes)
	ownerLogId := make([]byte, LogIDBytes)
	grantData := []byte("x")

	leaf33 := LeafCommitment(idTs, logId33, flags, 0, 0, ownerLogId, grantData)
	leaf32 := LeafCommitment(idTs, logId32, flags, 0, 0, ownerLogId, grantData)
	if leaf33 != leaf32 {
		t.Error("33-byte logId should produce same leaf as first 32 bytes")
	}
}

func TestLeafCommitment_EmptyVariableLengthFields(t *testing.T) {
	idTs := [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logId := []byte{}
	flags := []byte{}
	ownerLogId := []byte{}
	grantData := []byte{}

	if err := CheckSizes(logId, flags, ownerLogId); err != nil {
		t.Fatalf("CheckSizes with empty slices (within limits): %v", err)
	}
	leaf := LeafCommitment(idTs, logId, flags, 0, 0, ownerLogId, grantData)
	if leaf == [32]byte{} {
		t.Error("leaf must be non-zero even with empty variable-length fields")
	}
}

func TestLeafCommitment_OwnerLogId32Vs16_Differ(t *testing.T) {
	// Left-pad: 16-byte owner becomes 16 zeros + 16 bytes. 32-byte owner is used as-is.
	// So 32-byte owner and 16-byte owner (different content) must produce different leaves.
	idTs := [IDTimestampBytes]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logId := make([]byte, LogIDBytes)
	flags := make([]byte, GrantFlagsBytes)
	owner32 := make([]byte, InnerOwnerLogIDBytes)
	for i := range owner32 {
		owner32[i] = byte(i + 20)
	}
	owner16 := make([]byte, LogIDBytes) // different content: all 0x20
	for i := range owner16 {
		owner16[i] = 0x20
	}
	grantData := []byte("y")

	leaf32 := LeafCommitment(idTs, logId, flags, 1, 1, owner32, grantData)
	leaf16 := LeafCommitment(idTs, logId, flags, 1, 1, owner16, grantData)
	if leaf32 == leaf16 {
		t.Error("different ownerLogId content should produce different leaves")
	}
}

func TestCheckSizes_ErrorMessages(t *testing.T) {
	tests := []struct {
		name       string
		logId      []byte
		grantFlags []byte
		ownerLogId []byte
		wantSub    string
	}{
		{"logId", make([]byte, InnerLogIDBytes+1), make([]byte, GrantFlagsBytes), make([]byte, LogIDBytes), "logId"},
		{"grantFlags", make([]byte, LogIDBytes), make([]byte, GrantFlagsBytes+1), make([]byte, LogIDBytes), "grantFlags"},
		{"ownerLogId", make([]byte, LogIDBytes), make([]byte, GrantFlagsBytes), make([]byte, InnerOwnerLogIDBytes+1), "ownerLogId"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSizes(tt.logId, tt.grantFlags, tt.ownerLogId)
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantSub)
			}
			if !errors.Is(err, ErrGrantFieldSize) {
				t.Errorf("error should wrap ErrGrantFieldSize so callers can use errors.Is")
			}
		})
	}
}
