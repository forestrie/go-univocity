package grant

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// CheckSizes validates that variable-length parameters do not exceed their
// fixed maximum lengths. Parameters are in the same order as LeafCommitment:
// logId, grantFlags, ownerLogId. Returns an error if any single parameter
// exceeds its limit (logId and ownerLogId <= InnerLogIDBytes; grantFlags <= GrantFlagsBytes).
// The error wraps ErrGrantFieldSize so callers can match it with errors.Is.
func CheckSizes(logId, grantFlags, ownerLogId []byte) error {
	if len(logId) > InnerLogIDBytes {
		return fmt.Errorf("logId: length %d exceeds limit %d: %w", len(logId), InnerLogIDBytes, ErrGrantFieldSize)
	}
	if len(grantFlags) > GrantFlagsBytes {
		return fmt.Errorf("grantFlags: length %d exceeds limit %d: %w", len(grantFlags), GrantFlagsBytes, ErrGrantFieldSize)
	}
	if len(ownerLogId) > InnerOwnerLogIDBytes {
		return fmt.Errorf("ownerLogId: length %d exceeds limit %d: %w", len(ownerLogId), InnerOwnerLogIDBytes, ErrGrantFieldSize)
	}
	return nil
}

// InnerHash returns the 32-byte SHA-256 of the inner preimage (logId(32)||grant(32)||maxHeight(8)||minGrowth(8)||ownerLogId(32)||grantData).
// This is the value used as ContentHash when enqueueing a grant for sequencing (Plan 0004 subplan 03): ranger
// computes leafHash = H(idTimestampBE || ContentHash), so ContentHash must be the inner hash.
// Call CheckSizes before InnerHash if you need to reject oversized inputs.
func InnerHash(
	logId []byte,
	grantFlags []byte,
	maxHeight, minGrowth uint64,
	ownerLogId []byte,
	grantData []byte,
) [32]byte {
	return sha256.Sum256(concat(
		padLeft(logId, InnerLogIDBytes),
		padGrant32(grantFlags),
		u64BE(maxHeight),
		u64BE(minGrowth),
		padLeft(ownerLogId, InnerOwnerLogIDBytes),
		grantData,
	))
}

// InnerHashFromGrant returns the inner hash for a Grant (the ContentHash for grant-sequencing).
// Uses only the fields that are part of the univocity leaf inner preimage (idtimestamp is not included).
func InnerHashFromGrant(g *Grant) [32]byte {
	return InnerHash(
		g.LogId,
		g.GrantFlags,
		g.MaxHeight,
		g.MinGrowth,
		g.OwnerLogId,
		g.GrantData,
	)
}

// LeafCommitment computes the authority log leaf hash as in univocity:
//
//	leafCommitment = sha256(grantIDTimestampBe || sha256(inner))
//	inner          = logId(32) || grant(32) || maxHeight(8) || minGrowth(8) || ownerLogId(32) || grantData
//
// Padding: logId and ownerLogId are left-padded to 32 bytes (see padLeft).
// grantFlags (8 bytes) are placed in the low 8 bytes of a 32-byte grant field (high 24 zero).
// All multi-byte numeric fields are big-endian. grantData is variable length, no length prefix.
// Call CheckSizes before LeafCommitment if you need to reject oversized inputs.
func LeafCommitment(
	grantIDTimestampBe [IDTimestampBytes]byte,
	logId []byte,
	grantFlags []byte,
	maxHeight, minGrowth uint64,
	ownerLogId []byte,
	grantData []byte,
) [32]byte {
	inner := InnerHash(logId, grantFlags, maxHeight, minGrowth, ownerLogId, grantData)
	return sha256.Sum256(concat(grantIDTimestampBe[:], inner[:]))
}

// LeafCommitmentFromGrant computes the leaf hash from a Grant using only
// the fields that are part of the univocity leaf commitment (idtimestamp,
// logId, grant flags, maxHeight, minGrowth, ownerLogId, grantData).
func LeafCommitmentFromGrant(g *Grant) [32]byte {
	return LeafCommitment(
		g.IDTimestamp,
		g.LogId,
		g.GrantFlags,
		g.MaxHeight,
		g.MinGrowth,
		g.OwnerLogId,
		g.GrantData,
	)
}

// padLeft returns b left-padded to limit bytes (leading zeros). The original bytes
// occupy the least-significant (right) positions, consistent with big-endian
// layout for fixed-size fields. If len(b) >= limit, returns immediately without
// allocating: when len(b) == limit the same slice is returned; when len(b) > limit
// returns b[:limit]. Callers should use CheckSizes to reject oversized inputs
// when strict validation is required.
func padLeft(b []byte, limit int) []byte {
	if len(b) >= limit {
		if len(b) == limit {
			return b
		}
		return b[:limit]
	}
	out := make([]byte, limit)
	copy(out[limit-len(b):], b)
	return out
}

// padGrant32 returns grantFlags (8 bytes) as a 32-byte slice: high 24 bytes zero, low 8 bytes = flags (big-endian).
// If flags is longer than 8 bytes, only the last 8 bytes are used; if shorter, left-padded with zero within the 8-byte low part.
func padGrant32(flags []byte) []byte {
	out := make([]byte, InnerGrantBytes)
	if len(flags) >= 8 {
		copy(out[InnerGrantBytes-8:], flags[len(flags)-8:])
	} else if len(flags) > 0 {
		copy(out[InnerGrantBytes-len(flags):], flags)
	}
	return out
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
