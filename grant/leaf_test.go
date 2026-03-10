package grant

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
	path := filepath.Join("..", "..", "tests", "fixtures", "leaf_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
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
