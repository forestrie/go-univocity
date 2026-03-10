// Package grant provides leaf commitment and grant encoding aligned with
// univocity Solidity (LibLogState._leafCommitment) and canopy grant format.
package grant

import (
	"crypto/sha256"
	"encoding/binary"
)

// Sizes for leaf commitment (align with univocity and canopy).
const (
	IDTimestampBytes = 8
	LogIDBytes       = 16
	GrantFlagsBytes  = 8
	BoundsBytes      = 8 // maxHeight, minGrowth as uint64
)

// LeafCommitment computes the authority log leaf hash as in univocity:
//
//	leafCommitment = sha256(grantIDTimestampBe || sha256(logId || grant || maxHeight || minGrowth || ownerLogId || grantData))
//
// All multi-byte numeric fields are big-endian. Variable-length fields (logId, ownerLogId, grantData) are
// concatenated without length prefix (abi.encodePacked style).
func LeafCommitment(
	grantIDTimestampBe [IDTimestampBytes]byte,
	logId []byte,
	grantFlags []byte,
	maxHeight, minGrowth uint64,
	ownerLogId []byte,
	grantData []byte,
) [32]byte {
	inner := sha256.Sum256(concat(
		logId,
		grantFlags,
		u64BE(maxHeight),
		u64BE(minGrowth),
		ownerLogId,
		grantData,
	))
	return sha256.Sum256(concat(grantIDTimestampBe[:], inner[:]))
}

func concat(chunks ...[]byte) []byte {
	var n int
	for _, c := range chunks {
		n += len(c)
	}
	out := make([]byte, 0, n)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func u64BE(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
