#!/usr/bin/env python3
"""
Generate test vectors for leaf commitment and grant encoding.

Output: tests/fixtures/leaf_vectors.json (and optionally grant_vectors.json)
Consumable by Go, TypeScript, and Python tests.

Formula (univocity): leaf = sha256(grantIDTimestampBe || sha256(logId || grant || maxHeight || minGrowth || ownerLogId || grantData))
All multi-byte integers are big-endian. No length prefixes (abi.encodePacked style).
"""

import hashlib
import json
import os
import sys


def u64_be(n: int) -> bytes:
    return n.to_bytes(8, "big")


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
        log_id
        + grant_flags
        + u64_be(max_height)
        + u64_be(min_growth)
        + owner_log_id
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
