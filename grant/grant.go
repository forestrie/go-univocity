// Package grant provides leaf commitment and grant encoding aligned with
// univocity Solidity (LibLogState._leafCommitment) and canopy grant format.
package grant

import "errors"

// Sizes for leaf commitment (align with univocity and canopy).
const (
	IDTimestampBytes = 8
	LogIDBytes       = 16
	GrantFlagsBytes  = 8
	BoundsBytes      = 8 // maxHeight, minGrowth as uint64

	// Inner preimage sizes matching Solidity PublishGrant (abi.encodePacked).
	// logId and ownerLogId are bytes32 (32 bytes); 16-byte UUIDs are left-padded to 32.
	// grant is uint256 (32 bytes); 8-byte flags in low 8 bytes, high 24 zero.
	InnerLogIDBytes      = 32
	InnerGrantBytes      = 32
	InnerOwnerLogIDBytes = 32
)

// ErrGrantFieldSize is returned by CheckSizes when a variable-length parameter
// exceeds its fixed maximum. Callers can use errors.Is(err, ErrGrantFieldSize)
// to detect this class of error.
var ErrGrantFieldSize = errors.New("grant field size exceeds limit")

// ErrGrantObsoleteKey is returned by UnmarshalGrant when the map carries CBOR
// key 7 (the retired signer field) or key 8 (the retired kind field). The
// grant wire format is keys 0-6; grantData is the sole signer binding, and a
// decoder that accepted the retired keys would reintroduce the ambiguity
// their removal eliminated. Callers can use errors.Is(err, ErrGrantObsoleteKey).
var ErrGrantObsoleteKey = errors.New("grant carries an obsolete CBOR key (7 signer or 8 kind)")

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
	// GrantData is opaque (e.g. signer key for first checkpoint). It is the
	// sole statement-signer binding; there is no separate signer or kind field.
	GrantData []byte
}
