#!/usr/bin/env python3
"""
Generate test vectors for leaf commitment and grant encoding.

Output: tests/fixtures/leaf_vectors.json (and optionally grant_vectors.json)
Consumable by Go, TypeScript, and Python tests.

Formula (univocity, Solidity PublishGrant): inner = logId(32) || grant(32) || maxHeight(8) || minGrowth(8) || ownerLogId(32) || grantData.
leaf = sha256(grantIDTimestampBe || sha256(inner)).
Padding: logId and ownerLogId (16 bytes) left-padded to 32; grantFlags (8 bytes) in low 8 of 32-byte grant.
"""

import hashlib
import json
import os
import sys

INNER_LOG_ID_BYTES = 32
INNER_GRANT_BYTES = 32
INNER_OWNER_LOG_ID_BYTES = 32


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


def leaf_commitment(
    grant_id_timestamp_be: bytes,
    log_id: bytes,
    grant_flags: bytes,
    max_height: int,
    min_growth: int,
    owner_log_id: bytes,
    grant_data: bytes,
) -> bytes:
    inner = (
        pad_left(log_id, INNER_LOG_ID_BYTES)
        + pad_grant32(grant_flags)
        + u64_be(max_height)
        + u64_be(min_growth)
        + pad_left(owner_log_id, INNER_OWNER_LOG_ID_BYTES)
        + grant_data
    )
    inner_hash = hashlib.sha256(inner).digest()
    outer = grant_id_timestamp_be + inner_hash
    return hashlib.sha256(outer).digest()


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
            "expected_leaf_hex": leaf.hex(),
        }
    )

    # Vector 2: different idtimestamp and bounds
    id_ts2 = bytes(7) + b"\x02"
    log_id2 = bytes(range(1, 17))
    owner_log_id2 = bytes(range(8, 24))
    grant_data2 = bytes([0xDE, 0xAD])
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
            "expected_leaf_hex": leaf2.hex(),
        }
    )

    # Vector 3: empty grant_data
    id_ts3 = bytes(7) + b"\x03"
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
            "expected_leaf_hex": leaf3.hex(),
        }
    )

    out_path = os.path.join(fixtures_dir, "leaf_vectors.json")
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"Wrote {len(vectors)} vectors to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
