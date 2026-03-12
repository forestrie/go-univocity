#!/usr/bin/env python3
"""
Generate test vectors for leaf commitment and grant encoding.

Output: tests/fixtures/leaf_vectors.json, tests/fixtures/grant_vectors.json
Consumable by Go, TypeScript, and Python tests.

Grant wire format (matches grant/cborcodec.go): CBOR map with integer keys 0-8
in order. Keys 1,2,3 are fixed-length bstr (32, 32, 8 bytes); encode left-pads.
Leaf formula (univocity): inner = logId(32)||grant(32)||maxHeight(8)||minGrowth(8)||ownerLogId(32)||grantData.
leaf = sha256(grantIDTimestampBe || sha256(inner)).
"""

import hashlib
import json
import os
import sys

INNER_LOG_ID_BYTES = 32
INNER_GRANT_BYTES = 32
INNER_OWNER_LOG_ID_BYTES = 32

# Grant CBOR wire format: fixed lengths (must match grant/cborcodec.go).
CBOR_FIXED_LOG_ID_OWNER_LOG_ID_LEN = 32
CBOR_FIXED_GRANT_FLAGS_LEN = 8
CBOR_BSTR_LEN_8 = 0x48
CBOR_BSTR_LEN32_LEAD = 0x58


def u64_be(n: int) -> bytes:
    return n.to_bytes(8, "big")


def pad_left(b: bytes, limit: int) -> bytes:
    """Left-pad to limit bytes (leading zeros). If len(b) >= limit, return b or b[:limit]."""
    if len(b) >= limit:
        return b[:limit] if len(b) > limit else b
    return b"\x00" * (limit - len(b)) + b


def pad_grant32(flags: bytes) -> bytes:
    """8-byte flags in low 8 bytes of 32-byte slice (high 24 zero)."""
    out = bytearray(32)
    if len(flags) >= 8:
        out[24:32] = flags[-8:]
    elif len(flags) > 0:
        out[32 - len(flags) : 32] = flags
    return bytes(out)


def inner_hash(
    log_id: bytes,
    grant_flags: bytes,
    max_height: int,
    min_growth: int,
    owner_log_id: bytes,
    grant_data: bytes,
) -> bytes:
    """Inner hash = sha256(inner preimage). This is the ContentHash for grant-sequencing (Plan 0004 subplan 03)."""
    inner = (
        pad_left(log_id, INNER_LOG_ID_BYTES)
        + pad_grant32(grant_flags)
        + u64_be(max_height)
        + u64_be(min_growth)
        + pad_left(owner_log_id, INNER_OWNER_LOG_ID_BYTES)
        + grant_data
    )
    return hashlib.sha256(inner).digest()


def leaf_commitment(
    grant_id_timestamp_be: bytes,
    log_id: bytes,
    grant_flags: bytes,
    max_height: int,
    min_growth: int,
    owner_log_id: bytes,
    grant_data: bytes,
) -> bytes:
    inner_hash_bytes = inner_hash(
        log_id, grant_flags, max_height, min_growth, owner_log_id, grant_data
    )
    outer = grant_id_timestamp_be + inner_hash_bytes
    return hashlib.sha256(outer).digest()


# --- Grant CBOR encoding (matches grant/cborcodec.go MarshalGrant) ---


def cbor_pad_to(s: bytes | None, size: int) -> bytes:
    """Left-pad to size bytes. If len(s) > size, caller error."""
    if s is None:
        s = b""
    if len(s) > size:
        raise ValueError(f"field length {len(s)} exceeds limit {size}")
    if len(s) == size:
        return s
    return b"\x00" * (size - len(s)) + s


def append_cbor_uint(b: bytearray, v: int) -> None:
    """Append CBOR unsigned integer (Core Deterministic)."""
    if v < 24:
        b.append(v)
    elif v <= 0xFF:
        b.extend((0x18, v))
    elif v <= 0xFFFF:
        b.append(0x19)
        b.extend(v.to_bytes(2, "big"))
    elif v <= 0xFFFFFFFF:
        b.append(0x1A)
        b.extend(v.to_bytes(4, "big"))
    else:
        b.append(0x1B)
        b.extend(v.to_bytes(8, "big"))


def append_cbor_bstr(b: bytearray, s: bytes | None) -> None:
    """Append CBOR byte string (variable-length encoding)."""
    if s is None:
        s = b""
    n = len(s)
    if n < 24:
        b.append(0x40 | n)
    elif n <= 0xFF:
        b.extend((0x58, n))
    elif n <= 0xFFFF:
        b.append(0x59)
        b.extend(n.to_bytes(2, "big"))
    else:
        b.append(0x5A)
        b.extend(n.to_bytes(4, "big"))
    b.extend(s)


def marshal_grant_cbor(
    id_timestamp: bytes,
    log_id: bytes,
    owner_log_id: bytes,
    grant_flags: bytes,
    max_height: int,
    min_growth: int,
    grant_data: bytes,
    signer: bytes,
    kind: int,
) -> bytes:
    """Encode grant to CBOR bytes matching Go MarshalGrant (keys 0-8, fixed 32/32/8)."""
    if len(id_timestamp) != 8:
        raise ValueError("id_timestamp must be 8 bytes")
    log32 = cbor_pad_to(log_id, CBOR_FIXED_LOG_ID_OWNER_LOG_ID_LEN)
    owner32 = cbor_pad_to(owner_log_id, CBOR_FIXED_LOG_ID_OWNER_LOG_ID_LEN)
    flags8 = cbor_pad_to(grant_flags, CBOR_FIXED_GRANT_FLAGS_LEN)
    b = bytearray()
    b.append(0xA9)  # map with 9 pairs
    b.extend((0x00, CBOR_BSTR_LEN_8))
    b.extend(id_timestamp)
    b.extend((0x01, CBOR_BSTR_LEN32_LEAD, CBOR_FIXED_LOG_ID_OWNER_LOG_ID_LEN))
    b.extend(log32)
    b.extend((0x02, CBOR_BSTR_LEN32_LEAD, CBOR_FIXED_LOG_ID_OWNER_LOG_ID_LEN))
    b.extend(owner32)
    b.extend((0x03, CBOR_BSTR_LEN_8))
    b.extend(flags8)
    b.append(0x04)
    append_cbor_uint(b, max_height)
    b.append(0x05)
    append_cbor_uint(b, min_growth)
    b.append(0x06)
    append_cbor_bstr(b, grant_data)
    b.append(0x07)
    append_cbor_bstr(b, signer)
    b.append(0x08)
    append_cbor_uint(b, kind)
    return bytes(b)


def main() -> int:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fixtures_dir = os.path.join(script_dir, "..", "fixtures")
    os.makedirs(fixtures_dir, exist_ok=True)

    vectors = []

    # Vector 1: minimal fixed bytes
    id_ts = bytes(7) + b"\x01"
    log_id = bytes(range(16))
    grant_flags = bytes(7) + b"\x01"
    owner_log_id = bytes(range(16, 32))
    grant_data = bytes([0xAB, 0xCD])
    inner_h = inner_hash(log_id, grant_flags, 1000, 1, owner_log_id, grant_data)
    leaf = leaf_commitment(id_ts, log_id, grant_flags, 1000, 1, owner_log_id, grant_data)
    vectors.append(
        {
            "description": "minimal fixed bytes, max_height=1000 min_growth=1",
            "idtimestamp_hex": id_ts.hex(),
            "log_id_hex": log_id.hex(),
            "grant_flags_hex": grant_flags.hex(),
            "max_height": 1000,
            "min_growth": 1,
            "owner_log_id_hex": owner_log_id.hex(),
            "grant_data_hex": grant_data.hex(),
            "expected_inner_hex": inner_h.hex(),
            "expected_leaf_hex": leaf.hex(),
        }
    )

    # Vector 2: different idtimestamp and bounds
    id_ts2 = bytes(7) + b"\x02"
    log_id2 = bytes(range(1, 17))
    owner_log_id2 = bytes(range(8, 24))
    grant_data2 = bytes([0xDE, 0xAD])
    inner_h2 = inner_hash(log_id2, grant_flags, 2000, 2, owner_log_id2, grant_data2)
    leaf2 = leaf_commitment(
        id_ts2, log_id2, grant_flags, 2000, 2, owner_log_id2, grant_data2
    )
    vectors.append(
        {
            "description": "alternate idtimestamp and bounds",
            "idtimestamp_hex": id_ts2.hex(),
            "log_id_hex": log_id2.hex(),
            "grant_flags_hex": grant_flags.hex(),
            "max_height": 2000,
            "min_growth": 2,
            "owner_log_id_hex": owner_log_id2.hex(),
            "grant_data_hex": grant_data2.hex(),
            "expected_inner_hex": inner_h2.hex(),
            "expected_leaf_hex": leaf2.hex(),
        }
    )

    # Vector 3: empty grant_data
    id_ts3 = bytes(7) + b"\x03"
    inner_h3 = inner_hash(log_id, grant_flags, 0, 0, owner_log_id, b"")
    leaf3 = leaf_commitment(
        id_ts3, log_id, grant_flags, 0, 0, owner_log_id, b""
    )
    vectors.append(
        {
            "description": "empty grant_data, zero bounds",
            "idtimestamp_hex": id_ts3.hex(),
            "log_id_hex": log_id.hex(),
            "grant_flags_hex": grant_flags.hex(),
            "max_height": 0,
            "min_growth": 0,
            "owner_log_id_hex": owner_log_id.hex(),
            "grant_data_hex": "",
            "expected_inner_hex": inner_h3.hex(),
            "expected_leaf_hex": leaf3.hex(),
        }
    )

    out_path = os.path.join(fixtures_dir, "leaf_vectors.json")
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"Wrote {len(vectors)} vectors to {out_path}", file=sys.stderr)

    # --- Grant wire-format vectors (known-answer tests per plan Section 7) ---
    grant_vectors = []

    # Golden grant: all fields set to concrete values
    id_ts = bytes(7) + b"\x01"
    log_id = bytes(range(16))
    owner_log_id = bytes(range(16, 32))
    grant_flags = bytes(7) + b"\x01"
    golden_cbor = marshal_grant_cbor(
        id_ts, log_id, owner_log_id, grant_flags,
        1000, 1, bytes([0xAB, 0xCD]), bytes([0x01, 0x02]), 1,
    )
    grant_vectors.append({
        "description": "golden grant (all fields, fixed-length left-padded)",
        "idtimestamp_hex": id_ts.hex(),
        "log_id_hex": log_id.hex(),
        "owner_log_id_hex": owner_log_id.hex(),
        "grant_flags_hex": grant_flags.hex(),
        "max_height": 1000,
        "min_growth": 1,
        "grant_data_hex": "abcd",
        "signer_hex": "0102",
        "kind": 1,
        "expected_cbor_hex": golden_cbor.hex(),
    })

    # Minimal grant: required fields only (zero bounds, minimal grantData/signer)
    id_ts_min = bytes(8)  # all zero
    log_min = bytes(range(4, 20))
    owner_min = bytes(range(5, 21))
    flags_min = bytes([0x01])  # 1 byte -> left-padded to 8
    minimal_cbor = marshal_grant_cbor(
        id_ts_min, log_min, owner_min, flags_min,
        0, 0, b"", bytes([0x00]), 0,
    )
    grant_vectors.append({
        "description": "minimal grant (zero bounds, empty grantData, 1-byte signer)",
        "idtimestamp_hex": id_ts_min.hex(),
        "log_id_hex": log_min.hex(),
        "owner_log_id_hex": owner_min.hex(),
        "grant_flags_hex": flags_min.hex(),
        "max_height": 0,
        "min_growth": 0,
        "grant_data_hex": "",
        "signer_hex": "00",
        "kind": 0,
        "expected_cbor_hex": minimal_cbor.hex(),
    })

    # Fixed-length: 16-byte UUIDs padded to 32 on wire; 1-byte flags padded to 8
    id_ts_f = bytes(7) + b"\x02"
    log_f = bytes([0xAA] * 16)
    owner_f = bytes([0xBB] * 16)
    flags_f = bytes([0xFF])  # single byte
    fixed_cbor = marshal_grant_cbor(
        id_ts_f, log_f, owner_f, flags_f,
        0, 0, bytes([0x01]), bytes([0x02, 0x03]), 1,
    )
    grant_vectors.append({
        "description": "fixed-length padding (16-byte logId/ownerLogId -> 32, 1-byte flags -> 8)",
        "idtimestamp_hex": id_ts_f.hex(),
        "log_id_hex": log_f.hex(),
        "owner_log_id_hex": owner_f.hex(),
        "grant_flags_hex": flags_f.hex(),
        "max_height": 0,
        "min_growth": 0,
        "grant_data_hex": "01",
        "signer_hex": "0203",
        "kind": 1,
        "expected_cbor_hex": fixed_cbor.hex(),
    })

    # Variable-length: empty grantData, short signer
    id_ts_v = bytes(7) + b"\x03"
    variable_cbor = marshal_grant_cbor(
        id_ts_v, log_id, owner_log_id, grant_flags,
        99, 10, b"", bytes([0xEE]), 0,
    )
    grant_vectors.append({
        "description": "variable-length (empty grantData, 1-byte signer)",
        "idtimestamp_hex": id_ts_v.hex(),
        "log_id_hex": log_id.hex(),
        "owner_log_id_hex": owner_log_id.hex(),
        "grant_flags_hex": grant_flags.hex(),
        "max_height": 99,
        "min_growth": 10,
        "grant_data_hex": "",
        "signer_hex": "ee",
        "kind": 0,
        "expected_cbor_hex": variable_cbor.hex(),
    })

    grant_out_path = os.path.join(fixtures_dir, "grant_vectors.json")
    with open(grant_out_path, "w") as f:
        json.dump(grant_vectors, f, indent=2)
    print(f"Wrote {len(grant_vectors)} grant vectors to {grant_out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
