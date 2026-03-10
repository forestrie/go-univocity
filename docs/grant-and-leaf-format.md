# Grant and leaf format

This document specifies the **leaf commitment** hashing and **PublishGrant** (grant) format used by the univocity Solidity contracts and by canopy/arbor. It is the authoritative spec for [go-univocity](https://github.com/forestrie/go-univocity).

**References**: univocity `LibLogState.sol` (`_leafCommitment`), `src/interfaces/types.sol` (PublishGrant); canopy [register-grant API](https://github.com/forestrie/canopy/blob/main/docs/api/register-grant.md), Plan 0001 grant codec.

---

## 1. Leaf commitment (hashing)

The authority log leaf is the 32-byte SHA-256 output of:

```
leafCommitment = sha256( grantIDTimestampBe || sha256( inner ) )
inner          = logId || grantFlags || maxHeight_be || minGrowth_be || ownerLogId || grantData
```

- **grantIDTimestampBe**: 8 bytes, big-endian uint64 (unique grant timestamp / idtimestamp).
- **logId**: 16 bytes (target log UUID).
- **grantFlags**: 8 bytes (bitmap; univocity GF_CREATE, GF_EXTEND, etc.).
- **maxHeight**: 8 bytes, big-endian uint64 (0 = no limit).
- **minGrowth**: 8 bytes, big-endian uint64.
- **ownerLogId**: 16 bytes (authority log that owns this grant).
- **grantData**: variable length (opaque; e.g. signer key for first checkpoint).

Concatenation is **without length prefixes** (Solidity `abi.encodePacked` style). The **request** (GC_AUTH_LOG / GC_DATA_LOG) is **not** in the leaf; it is supplied at `publishCheckpoint` time.

---

## 2. Grant format (PublishGrant + idtimestamp)

Fields that participate in the leaf commitment (and must be stored for inclusion proofs):

| Field          | Size / type   | Notes                          |
|----------------|---------------|---------------------------------|
| idtimestamp    | 8 bytes, BE   | Unique grant timestamp         |
| logId          | 16 bytes      | Target log                      |
| grantFlags     | 8 bytes       | GF_* bitmap                     |
| maxHeight      | 8 bytes, BE   | Optional bound (0 = none)       |
| minGrowth      | 8 bytes, BE   | Min growth per checkpoint       |
| ownerLogId     | 16 bytes      | Owner (authority) log           |
| grantData      | variable      | Opaque (e.g. signer key)        |

Canopy extends the stored grant with **signer** (signer binding for register-statement) and **kind** (1 byte); these are **not** part of the univocity leaf commitment but are in the canopy CBOR grant document.

---

## 3. Encoding / decoding examples

### 3.1 Go

```go
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/forestrie/go-univocity/grant"
)

func main() {
	idTs := [8]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logId, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	flags, _ := hex.DecodeString("0000000000000001")
	ownerLogId, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f")
	grantData, _ := hex.DecodeString("abcd")

	leaf := grant.LeafCommitment(idTs, logId, flags, 1000, 1, ownerLogId, grantData)
	fmt.Println(hex.EncodeToString(leaf[:]))
	// 46a83eb09f26cf6f9c202727f0b76e3c3b67cc12c0f14b230eb2fc73c0d793f3
}
```

Decode from hex and compute leaf (same formula):

```go
	idTsHex := "0000000000000001"
	logIdHex := "000102030405060708090a0b0c0d0e0f"
	// ... decode each with hex.DecodeString, then:
	var idTsArr [8]byte
	copy(idTsArr[:], idTs)
	leaf := grant.LeafCommitment(idTsArr, logId, flags, maxHeight, minGrowth, ownerLogId, grantData)
```

### 3.2 TypeScript

```typescript
import { createHash } from "crypto";

function u64Be(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

function leafCommitment(
  grantIDTimestampBe: Buffer,
  logId: Buffer,
  grantFlags: Buffer,
  maxHeight: number,
  minGrowth: number,
  ownerLogId: Buffer,
  grantData: Buffer
): Buffer {
  const inner = Buffer.concat([
    logId,
    grantFlags,
    u64Be(maxHeight),
    u64Be(minGrowth),
    ownerLogId,
    grantData,
  ]);
  const innerHash = createHash("sha256").update(inner).digest();
  return createHash("sha256")
    .update(Buffer.concat([grantIDTimestampBe, innerHash]))
    .digest();
}

const idTs = Buffer.from("0000000000000001", "hex");
const logId = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
const flags = Buffer.from("0000000000000001", "hex");
const ownerLogId = Buffer.from("101112131415161718191a1b1c1d1e1f", "hex");
const grantData = Buffer.from("abcd", "hex");
const leaf = leafCommitment(idTs, logId, flags, 1000, 1, ownerLogId, grantData);
console.log(leaf.toString("hex"));
// 46a83eb09f26cf6f9c202727f0b76e3c3b67cc12c0f14b230eb2fc73c0d793f3
```

### 3.3 Python

```python
import hashlib

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
    return hashlib.sha256(grant_id_timestamp_be + inner_hash).digest()

id_ts = bytes.fromhex("0000000000000001")
log_id = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
flags = bytes.fromhex("0000000000000001")
owner_log_id = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
grant_data = bytes.fromhex("abcd")
leaf = leaf_commitment(id_ts, log_id, flags, 1000, 1, owner_log_id, grant_data)
print(leaf.hex())
# 46a83eb09f26cf6f9c202727f0b76e3c3b67cc12c0f14b230eb2fc73c0d793f3
```

---

## 4. Test vectors

Run `tests/scripts/gen_testvectors.py` to generate `tests/fixtures/leaf_vectors.json`. Each entry has hex-encoded inputs and `expected_leaf_hex`. All three languages should match these vectors.

Example (vector 1):

- idtimestamp_hex: `0000000000000001`
- log_id_hex: `000102030405060708090a0b0c0d0e0f`
- grant_flags_hex: `0000000000000001`
- max_height: 1000, min_growth: 1
- owner_log_id_hex: `101112131415161718191a1b1c1d1e1f`
- grant_data_hex: `abcd`
- expected_leaf_hex: `46a83eb09f26cf6f9c202727f0b76e3c3b67cc12c0f14b230eb2fc73c0d793f3`

---

## 5. Alignment (canopy vs univocity)

| Canopy (Plan 0001) | Univocity leaf | Notes |
|--------------------|----------------|-------|
| idtimestamp (8)    | grantIDTimestampBe | Same |
| logId (16)         | logId          | Same |
| grantFlags (8)     | grant (flags)  | Same |
| maxHeight, minGrowth | maxHeight, minGrowth (size-only bounds) | Same; 8-byte BE in commitment |
| ownerLogId (16)    | ownerLogId     | Same |
| grantData          | grantData      | Same |
| signer             | —              | Canopy only; not in leaf |
| kind               | —              | Canopy only; not in leaf; request (GC_*) at publishCheckpoint |
