package grant

// Grant holds the fields for a PublishGrant + idtimestamp, aligned with
// univocity and canopy. Used for encoding/decoding and for leaf commitment inputs.
type Grant struct {
	// IDTimestamp is the 8-byte big-endian unique grant timestamp (idtimestamp).
	IDTimestamp [IDTimestampBytes]byte
	// LogId is the target log (16 bytes, UUID).
	LogId []byte
	// OwnerLogId is the authority log that owns this grant (16 bytes).
	OwnerLogId []byte
	// GrantFlags is the 8-byte flags bitmap.
	GrantFlags []byte
	// MaxHeight is the optional max size bound (0 = no limit).
	MaxHeight uint64
	// MinGrowth is the minimum growth per checkpoint.
	MinGrowth uint64
	// GrantData is opaque (e.g. signer key for first checkpoint).
	GrantData []byte
	// Signer is the key id / signer binding (canopy; not in leaf commitment).
	Signer []byte
	// Kind is the 1-byte grant kind (canopy; not in univocity leaf).
	Kind byte
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
